#!/bin/bash
# PX-specific helper functions for autofstrim testing

source "$(dirname "$0")/config.sh"

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
    $PXCTL_PATH volume update --auto_fstrim on "$vol_id"
    sleep 2
}

# Disable autofstrim on a volume
disable_volume_autofstrim() {
    local vol_id=$1
    log_info "Disabling autofstrim on volume $vol_id..."
    $PXCTL_PATH volume update --auto_fstrim off "$vol_id"
    sleep 2
}

# Enable nodiscard on a volume
enable_volume_nodiscard() {
    local vol_id=$1
    log_info "Enabling nodiscard on volume $vol_id..."
    $PXCTL_PATH volume update --nodiscard on "$vol_id"
    $PXCTL_PATH volume update --mount_options nodiscard=true "$vol_id"
}

# Disable nodiscard on a volume (enable inline discard)
disable_volume_nodiscard() {
    local vol_id=$1
    log_info "Disabling nodiscard on volume $vol_id (enabling inline discard)..."
    $PXCTL_PATH volume update --nodiscard off "$vol_id"
    $PXCTL_PATH volume update --mount_options nodiscard= "$vol_id"
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
#######################################

# Get autofstrim usage for a volume
get_autofstrim_usage() {
    local vol_id=$1
    $PXCTL_PATH volume autofstrim-usage "$vol_id" 2>/dev/null
}

# Get trimmable space for a volume (in bytes)
get_trimmable_space() {
    local vol_id=$1
    local usage=$($PXCTL_PATH volume autofstrim-usage "$vol_id" -j 2>/dev/null)
    echo "$usage" | grep -o '"trimmable_bytes":[0-9]*' | awk -F: '{print $2}'
}

# Get fstrim status for a volume
get_fstrim_status() {
    local vol_id=$1
    $PXCTL_PATH volume inspect "$vol_id" -j | grep -o '"fs_trim_status":"[^"]*"' | awk -F'"' '{print $4}'
}

# Trigger manual fstrim on a volume
trigger_manual_fstrim() {
    local vol_id=$1
    log_info "Triggering manual fstrim on volume $vol_id..."
    $PXCTL_PATH volume trim start "$vol_id"
}

# Wait for fstrim to complete
wait_for_fstrim_complete() {
    local vol_id=$1
    local timeout=${2:-300}
    local elapsed=0
    
    log_info "Waiting for fstrim to complete on volume $vol_id (timeout: ${timeout}s)..."
    while [ $elapsed -lt $timeout ]; do
        local status=$(get_fstrim_status "$vol_id")
        if [ "$status" = "FS_TRIM_COMPLETED" ] || [ "$status" = "FS_TRIM_NOT_INPROGRESS" ]; then
            log_success "Fstrim completed on volume $vol_id"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    log_warn "Fstrim did not complete within ${timeout}s"
    return 1
}

