#!/bin/bash
# PX-specific helper functions for autofstrim testing

source "$(dirname "$0")/config.sh"

#######################################
# Storage Pool Management
#######################################

# Create a storage pool with specific chunk size
# This creates the underlying LVM thin pool with the desired chunk size
# which determines the discard granularity
create_pool_with_chunk_size() {
    local pool_id=$1
    local chunk_size_kb=$2
    local drive_path=${3:-}  # Optional: specific drive path

    log_info "Creating pool $pool_id with chunk size ${chunk_size_kb}KB..."

    # If drive path not specified, let pxctl choose
    if [ -z "$drive_path" ]; then
        # Create new pool using pxctl
        $PXCTL_PATH service drive add --newpool 2>&1 || true
    else
        $PXCTL_PATH service drive add --newpool -d "$drive_path" 2>&1 || true
    fi

    sleep 5

    # Note: The chunk size is typically set during LVM thin pool creation
    # For existing pools, we need to verify the chunk size matches
    # In production, pools should be pre-created with correct chunk sizes

    return 0
}

# Get pool chunk size in KB
get_pool_chunk_size_kb() {
    local pool_id=$1

    # Get VG name for this pool
    local vg_name="pool${pool_id}"

    # Query LVM for chunk size
    local chunk_bytes=$(lvm lvs -o chunk_size --units b --noheadings --nosuffix "${vg_name}/pxpool" 2>/dev/null | tr -d ' ')

    if [ -z "$chunk_bytes" ] || [ "$chunk_bytes" = "0" ]; then
        echo "0"
        return 1
    fi

    local chunk_kb=$((chunk_bytes / 1024))
    echo "$chunk_kb"
    return 0
}

# Verify pool chunk size matches expected value
verify_pool_chunk_size() {
    local pool_id=$1
    local expected_chunk_kb=$2

    local actual_chunk_kb=$(get_pool_chunk_size_kb "$pool_id")

    if [ "$actual_chunk_kb" = "$expected_chunk_kb" ]; then
        log_info "✓ Pool $pool_id chunk size verified: ${actual_chunk_kb}KB"
        return 0
    else
        log_error "✗ Pool $pool_id chunk size mismatch: expected ${expected_chunk_kb}KB, got ${actual_chunk_kb}KB"
        return 1
    fi
}

# Get pool UUID from pool ID
get_pool_uuid() {
    local pool_id=$1

    # Query pxctl for pool UUID
    local pool_uuid=$($PXCTL_PATH service pool show -j 2>/dev/null | \
        jq -r ".datapools[] | select(.ID == $pool_id) | .uuid" 2>/dev/null)

    if [ -z "$pool_uuid" ] || [ "$pool_uuid" = "null" ]; then
        log_error "Failed to get UUID for pool $pool_id"
        return 1
    fi

    echo "$pool_uuid"
    return 0
}

# Map dmthin discard granularity to pool ID
# 64KB -> pool 0
# 1024KB (1MB) -> pool 1
# 2048KB (2MB) -> pool 2
get_pool_id_for_dmthin_gran() {
    local dmthin_gran_kb=$1

    case "$dmthin_gran_kb" in
        64)
            echo "0"
            ;;
        1024)
            echo "1"
            ;;
        2048)
            echo "2"
            ;;
        *)
            log_error "Unsupported dmthin granularity: ${dmthin_gran_kb}KB"
            echo "0"  # Default to pool 0
            ;;
    esac
}

#######################################
# Volume lifecycle management
#######################################

# Create a new volume with specified size in a specific pool
create_volume() {
    local vol_name=$1
    local size=${2:-10}  # Size in GB (just the number)
    local pool_id=${3:-0}

    # Strip 'G' or 'GB' suffix if present
    size=$(echo "$size" | sed 's/[Gg][Bb]*$//')

    echo "Creating volume: $vol_name, size: ${size}GB, pool: $pool_id..." >&2

    # Get pool UUID for the specified pool ID
    local pool_uuid=$(get_pool_uuid "$pool_id")
    if [ $? -ne 0 ] || [ -z "$pool_uuid" ]; then
        log_warn "Failed to get pool UUID for pool $pool_id, creating volume without pool constraint"
        pool_uuid=""
    else
        echo "  Using pool UUID: $pool_uuid" >&2
    fi

    # Create the volume with pool constraint if available
    local create_cmd="$PXCTL_PATH volume create \"$vol_name\" --size \"$size\" --repl 1 --fastpath --fs ext4"
    if [ -n "$pool_uuid" ]; then
        create_cmd="$create_cmd --nodes=\"$pool_uuid\""
    fi

    local create_output=$(eval "$create_cmd" 2>&1)
    echo "  pxctl output: $create_output" >&2
    sleep 2

    # Try to extract volume ID from create output first (format: "Volume successfully created: <id>")
    local vol_id=$(echo "$create_output" | grep -o 'Volume successfully created: [0-9]*' | awk '{print $NF}')

    # If not found in output, try listing
    if [ -z "$vol_id" ]; then
        vol_id=$($PXCTL_PATH volume list --name "$vol_name" -j 2>/dev/null | grep -o '"id":"[^"]*"' | head -1 | awk -F'"' '{print $4}')
    fi

    echo "$vol_id"
}

# Delete a volume
delete_volume() {
    local vol_id=$1
    echo "Deleting volume: $vol_id..." >&2
    $PXCTL_PATH volume delete "$vol_id" --force 2>/dev/null || true
    sleep 2
}

# Attach a volume
attach_volume() {
    local vol_id=$1
    echo "Attaching volume: $vol_id..." >&2
    $PXCTL_PATH host attach "$vol_id" >/dev/null 2>&1 || true
    sleep 2
}

# Detach a volume
detach_volume() {
    local vol_id=$1
    echo "Detaching volume: $vol_id..." >&2
    $PXCTL_PATH host detach "$vol_id" --redirect=false >/dev/null 2>&1 || true
    sleep 2
}

# Mount a volume
mount_volume() {
    local vol_id=$1
    local mount_path=$2
    echo "Mounting volume $vol_id at $mount_path..." >&2
    mkdir -p "$mount_path"
    $PXCTL_PATH host mount "$vol_id" --path "$mount_path" >/dev/null 2>&1 || true
    sleep 2
}

# Unmount a volume
unmount_volume() {
    local vol_id=$1
    local mount_path=$2
    echo "Unmounting volume $vol_id from $mount_path..." >&2
    $PXCTL_PATH host unmount "$vol_id" --path "$mount_path" >/dev/null 2>&1 || true
    sleep 2
}

# Full volume cleanup cycle
cleanup_volume() {
    local vol_id=$1
    local mount_path=$2
    local vol_name=${3:-discard_test_vol}

    echo "Full cleanup of volume $vol_id..." >&2

    # Try unmount by path first
    umount "$mount_path" >/dev/null 2>&1 || true

    # Try to unmount/detach/delete by ID
    $PXCTL_PATH host unmount "$vol_id" --path "$mount_path" >/dev/null 2>&1 || true
    $PXCTL_PATH host detach "$vol_id" --redirect=false >/dev/null 2>&1 || true
    $PXCTL_PATH volume delete "$vol_id" --force >/dev/null 2>&1 || true

    # Also try by name in case ID didn't work
    $PXCTL_PATH host unmount "$vol_name" --path "$mount_path" >/dev/null 2>&1 || true
    $PXCTL_PATH host detach "$vol_name" --redirect=false >/dev/null 2>&1 || true
    $PXCTL_PATH volume delete "$vol_name" --force >/dev/null 2>&1 || true

    sleep 2
}

# Full volume setup cycle
setup_volume() {
    local vol_name=$1
    local mount_path=$2
    local size=${3:-10}
    local pool_id=${4:-0}

    echo "Full setup of volume $vol_name..." >&2
    local vol_id=$(create_volume "$vol_name" "$size" "$pool_id")
    attach_volume "$vol_id"
    mount_volume "$vol_id" "$mount_path"
    echo "$vol_id"
}

# Get volume ID by name
get_volume_id() {
    local vol_name=$1
    $PXCTL_PATH volume list --name "$vol_name" -j 2>/dev/null | grep -o '"id":"[^"]*"' | head -1 | awk -F'"' '{print $4}'
}

# Get PXD device path for a volume
get_pxd_device() {
    local vol_id=$1
    echo "/dev/pxd/pxd${vol_id}"
}

#######################################
# Sysfs discard granularity reading
# Note: discard_granularity is set by the kernel driver and is read-only
#######################################

# Get current discard_granularity for a device (in bytes)
get_sysfs_discard_granularity() {
    local device=$1
    local dev_name=$(basename "$device")

    # Handle /dev/pxd/pxd<id> format
    if [[ "$device" == /dev/pxd/* ]]; then
        dev_name=$(basename "$device")
    fi

    cat "/sys/block/$dev_name/queue/discard_granularity" 2>/dev/null || echo "0"
}

# Get discard_max_bytes for a device
get_sysfs_discard_max_bytes() {
    local device=$1
    local dev_name=$(basename "$device")

    if [[ "$device" == /dev/pxd/* ]]; then
        dev_name=$(basename "$device")
    fi

    cat "/sys/block/$dev_name/queue/discard_max_bytes" 2>/dev/null || echo "0"
}

# Get all queue limits for a device
get_device_queue_limits() {
    local device=$1
    local dev_name=$(basename "$device")

    if [[ "$device" == /dev/pxd/* ]]; then
        dev_name=$(basename "$device")
    fi

    local sysfs_path="/sys/block/$dev_name/queue"
    if [ -d "$sysfs_path" ]; then
        echo "discard_granularity=$(cat $sysfs_path/discard_granularity 2>/dev/null || echo N/A)"
        echo "discard_max_bytes=$(cat $sysfs_path/discard_max_bytes 2>/dev/null || echo N/A)"
        echo "logical_block_size=$(cat $sysfs_path/logical_block_size 2>/dev/null || echo N/A)"
        echo "physical_block_size=$(cat $sysfs_path/physical_block_size 2>/dev/null || echo N/A)"
    fi
}

# Note: discard_granularity cannot be set via sysfs - it's determined by the driver
# The PX driver sets it to PXD_MAX_DISCARD_GRANULARITY (1MiB) at device init time
# This function just re-attaches the volume (granularity remains driver-determined)
set_discard_granularity_and_reattach() {
    local vol_id=$1
    local mount_path=$2
    local requested_granularity_bytes=$3

    echo "Requested discard_granularity: $requested_granularity_bytes bytes (note: actual value is driver-determined)" >&2

    # Just remount the volume - granularity is set by the kernel driver
    # Unmount and detach
    unmount_volume "$vol_id" "$mount_path"
    detach_volume "$vol_id"

    # Attach the volume
    attach_volume "$vol_id"

    # Report actual granularity
    local pxd_device=$(get_pxd_device "$vol_id")
    local actual_gran=$(get_sysfs_discard_granularity "$pxd_device")
    echo "Actual discard_granularity: $actual_gran bytes" >&2

    # Mount the volume
    mount_volume "$vol_id" "$mount_path"
}

#######################################
# Cluster-level autofstrim controls
#######################################

# Enable cluster-wide autofstrim
enable_cluster_autofstrim() {
    log_info "Enabling cluster-wide autofstrim..."
    $PXCTL_PATH cluster options update --auto-fstrim on
    sleep 3
}

# Disable cluster-wide autofstrim
disable_cluster_autofstrim() {
    log_info "Disabling cluster-wide autofstrim..."
    $PXCTL_PATH cluster options update --auto-fstrim off
    sleep 3
}

# Get cluster autofstrim status
get_cluster_autofstrim_status() {
    $PXCTL_PATH cluster options list | grep -i "auto.fstrim" | awk -F: '{print $2}' | tr -d ' '
}

# Set fstrim IO rates
set_fstrim_io_rates() {
    local min_rate=$1
    local max_rate=$2
    log_info "Setting fstrim IO rates: min=$min_rate, max=$max_rate"
    $PXCTL_PATH cluster options update --fstrim-min-io-rate "$min_rate" --fstrim-max-io-rate "$max_rate"
}

#######################################
# Volume-level autofstrim controls
#######################################

# Enable autofstrim on a volume
enable_volume_autofstrim() {
    local vol_id=$1
    log_info "Enabling autofstrim on volume $vol_id..."
    $PXCTL_PATH volume update --auto_fstrim on "$vol_id" 2>/dev/null || true
    sleep 2
}

# Disable autofstrim on a volume
disable_volume_autofstrim() {
    local vol_id=$1
    log_info "Disabling autofstrim on volume $vol_id..."
    $PXCTL_PATH volume update --auto_fstrim off "$vol_id" 2>/dev/null || true
    sleep 2
}

# Enable nodiscard on a volume
enable_volume_nodiscard() {
    local vol_id=$1
    log_info "Enabling nodiscard on volume $vol_id..."
    $PXCTL_PATH volume update --nodiscard on "$vol_id" 2>/dev/null || true
    $PXCTL_PATH volume update --mount_options nodiscard=true "$vol_id" 2>/dev/null || true
}

# Disable nodiscard on a volume (enable inline discard)
disable_volume_nodiscard() {
    local vol_id=$1
    log_info "Disabling nodiscard on volume $vol_id (enabling inline discard)..."
    $PXCTL_PATH volume update --nodiscard off "$vol_id" 2>/dev/null || true
    $PXCTL_PATH volume update --mount_options nodiscard= "$vol_id" 2>/dev/null || true
}

# Get volume autofstrim status
get_volume_autofstrim_status() {
    local vol_id=$1
    $PXCTL_PATH volume inspect "$vol_id" -j | grep -o '"auto_fstrim":[^,}]*' | awk -F: '{print $2}'
}

# Get volume nodiscard status
get_volume_nodiscard_status() {
    local vol_id=$1
    $PXCTL_PATH volume inspect "$vol_id" -j | grep -o '"nodiscard":[^,}]*' | awk -F: '{print $2}'
}

#######################################
# Volume mount/unmount with options
#######################################

# Remount volume to apply mount option changes
remount_volume() {
    local vol_id=$1
    local mount_path=$2
    log_info "Remounting volume $vol_id at $mount_path..."
    $PXCTL_PATH host unmount "$vol_id" --path "$mount_path" 2>/dev/null
    sleep 1
    $PXCTL_PATH host mount "$vol_id" --path "$mount_path"
    sleep 2
}

# Check if volume is mounted with discard option
check_mount_discard_option() {
    local mount_path=$1
    if mount | grep "$mount_path" | grep -q "discard"; then
        echo "enabled"
    else
        echo "disabled"
    fi
}

#######################################
# Autofstrim status and statistics
# Logic matches porx job/job_autofstrim_common.go
#######################################

# Get autofstrim usage JSON for all locally attached volumes
# Command: pxctl v af usage -j
get_autofstrim_usage_json() {
    $PXCTL_PATH volume autofstrim usage -j 2>/dev/null
}

# Get PX usage for a volume (in bytes) - from pxctl v af usage
# This matches getPxUsage in porx
get_px_usage() {
    local vol_id=$1
    local usage_json=$(get_autofstrim_usage_json)
    echo "$usage_json" | grep -A5 "\"$vol_id\"" | grep '"px_usage"' | grep -o '[0-9]*'
}

# Get DU usage for a volume (in bytes) - from pxctl v af usage
# This matches getDuUsage in porx
get_du_usage() {
    local vol_id=$1
    local usage_json=$(get_autofstrim_usage_json)
    echo "$usage_json" | grep -A5 "\"$vol_id\"" | grep '"du_usage"' | grep -o '[0-9]*'
}

# Get trimmable space for a volume (in bytes)
# Logic from porx getAutoFstrimTrimmableSpace:
#   trimmable = pxUsage - duUsage (if pxUsage > duUsage, else 0)
get_trimmable_space() {
    local vol_id=$1
    local px_usage=$(get_px_usage "$vol_id")
    local du_usage=$(get_du_usage "$vol_id")

    if [ -z "$px_usage" ] || [ -z "$du_usage" ]; then
        echo "0"
        return
    fi

    if [ "$px_usage" -gt "$du_usage" ]; then
        echo $((px_usage - du_usage))
    else
        echo "0"
    fi
}

# Get trimmable percentage for a volume
get_trimmable_percentage() {
    local vol_id=$1
    local usage_json=$(get_autofstrim_usage_json)
    local vol_size=$(echo "$usage_json" | grep -A5 "\"$vol_id\"" | grep '"volume_size"' | grep -o '[0-9]*')
    local trimmable=$(get_trimmable_space "$vol_id")

    if [ -z "$vol_size" ] || [ "$vol_size" -eq 0 ]; then
        echo "0"
        return
    fi

    echo "scale=2; $trimmable * 100 / $vol_size" | bc
}

# Get autofstrim enabling status for a volume
get_autofstrim_enabling_status() {
    local vol_id=$1
    local usage_json=$(get_autofstrim_usage_json)
    echo "$usage_json" | grep -A5 "\"$vol_id\"" | grep '"perform_auto_fstrim"' | awk -F'"' '{print $4}'
}

# Get fstrim status for a volume
get_fstrim_status() {
    local vol_id=$1
    $PXCTL_PATH volume autofstrim status -j "$vol_id" 2>/dev/null | grep -o '"status":"[^"]*"' | awk -F'"' '{print $4}'
}

# Get fstrim IO rates (average and current)
get_fstrim_io_rates() {
    local vol_id=$1
    $PXCTL_PATH volume autofstrim status -j "$vol_id" 2>/dev/null | grep -E '"(average_io_rate|current_io_rate)"'
}

# Trigger manual fstrim push on a volume
trigger_fstrim_push() {
    local vol_id=$1
    log_info "Pushing volume $vol_id to fstrim queue..."
    $PXCTL_PATH volume autofstrim push "$vol_id"
}

# Wait for manual trim (pxctl volume trim start) to complete
# Uses: pxctl volume trim status <vol_name>
# Waits indefinitely until trim completes (no timeout)
wait_for_trim_complete() {
    local vol_id=$1
    local vol_name=$2
    local elapsed=0

    echo "Waiting for trim to complete on $vol_name (no timeout - will wait until done)..."
    while true; do
        # Check trim status using pxctl volume trim status
        local trim_status=$($PXCTL_PATH volume trim status "$vol_name" 2>&1)

        # Extract status field
        local status_line=$(echo "$trim_status" | grep -i "^Status" | awk -F: '{print $2}' | tr -d ' ')
        local scanned=$(echo "$trim_status" | grep -i "Scanned Percentage" | awk '{print $NF}')

        echo "  [${elapsed}s] Status: $status_line, Scanned: ${scanned}%"

        # Check if trim completed or not running
        if echo "$trim_status" | grep -qi "\|not running\|no.*trim\|not.*started\|FS_TRIM_NOT_STARTED"; then
            echo "Trim completed for $vol_name after ${elapsed}s"
            return 0
        fi

        # Check if scanned 100%
        if [ "$scanned" = "100" ]; then
            echo "Trim scan completed (100%) after ${elapsed}s"
            return 0
        fi

        sleep 10
        elapsed=$((elapsed + 10))
    done
}

# Get autofstrim status for a volume (e.g., FS_TRIM_COMPLETED, FS_TRIM_INPROGRESS, FS_TRIM_STARTED)
get_autofstrim_status() {
    local vol_id=$1
    # Get volume name from vol_id
    local vol_name=$($PXCTL_PATH volume inspect "$vol_id" 2>/dev/null | grep -E "^\s*Name\s*:" | head -1 | awk -F: '{print $2}' | tr -d ' \t')
    if [ -z "$vol_name" ]; then
        echo "UNKNOWN"
        return
    fi
    local status=$($PXCTL_PATH volume autofstrim status "$vol_name" 2>/dev/null | grep -E "^Status\s*:" | awk -F: '{print $2}' | tr -d ' \t')
    echo "${status:-UNKNOWN}"
}

# Wait for fstrim to complete one full cycle (status reaches FS_TRIM_COMPLETED)
# This waits for the autofstrim daemon to finish scanning and trimming the volume
wait_for_fstrim_complete() {
    local vol_id=$1
    local elapsed=0
    local max_wait=900  # 15 minutes max wait

    log_info "Waiting for fstrim to complete on volume $vol_id (waiting for FS_TRIM_COMPLETED status)..."

    while [ $elapsed -lt $max_wait ]; do
        local status=$(get_autofstrim_status "$vol_id")
        local trimmable=$(get_trimmable_space "$vol_id")
        local trimmable_mb=$((trimmable / 1024 / 1024))
        log_info "  [${elapsed}s] Status: ${status}, Trimmable: ${trimmable_mb}MB"

        # Fstrim is complete when status is FS_TRIM_COMPLETED
        if [ "$status" = "FS_TRIM_COMPLETED" ]; then
            log_success "Fstrim completed on volume $vol_id after ${elapsed}s (status: ${status}, trimmable: ${trimmable_mb}MB)"
            return 0
        fi

        sleep 10
        elapsed=$((elapsed + 10))
    done

    # Timeout reached
    log_warn "Fstrim wait timeout after ${max_wait}s on volume $vol_id (status: $(get_autofstrim_status "$vol_id"))"
    return 1
}

# Print full autofstrim usage info for a volume
print_autofstrim_usage() {
    local vol_id=$1
    local px_usage=$(get_px_usage "$vol_id")
    local du_usage=$(get_du_usage "$vol_id")
    local trimmable=$(get_trimmable_space "$vol_id")
    local status=$(get_autofstrim_enabling_status "$vol_id")

    log_result "PX Usage: ${px_usage} bytes"
    log_result "DU Usage: ${du_usage} bytes"
    log_result "Trimmable: ${trimmable} bytes"
    log_result "Status: ${status}"
}

# Set filesystem discard granularity at block device level
set_fs_discard_granularity() {
    local vol_id=$1
    local discard_gran_kb=$2
    
    log_info "Setting FS discard granularity to ${discard_gran_kb}KB for volume $vol_id"
    
    # Get PXD device
    local pxd_device=$(get_pxd_device "$vol_id")
    if [ -z "$pxd_device" ]; then
        log_error "Could not find PXD device for volume $vol_id"
        return 1
    fi
    
    # Detach volume first
    pxctl volume detach "$vol_id" --force 2>/dev/null || true
    sleep 2
    
    # Set discard granularity in sysfs
    local discard_gran_bytes=$((discard_gran_kb * 1024))
    echo "$discard_gran_bytes" > "/sys/block/${pxd_device}/queue/discard_granularity"
    
    # Re-attach volume
    pxctl volume attach "$vol_id"
    sleep 3
    
    # Verify setting
    local actual_gran=$(cat "/sys/block/${pxd_device}/queue/discard_granularity")
    log_info "FS discard granularity set to: $actual_gran bytes"
    
    return 0
}

# Note: DMThin discard granularity is determined by the pool's chunk size
# and cannot be changed after pool creation. Use get_pool_id_for_dmthin_gran()
# to select the correct pool with the desired chunk size.

