#!/bin/bash
# Functions for collecting discard statistics at different layers

source "$(dirname "$0")/config.sh"

#######################################
# Filesystem layer statistics
#######################################

# Get filesystem block size
get_fs_block_size() {
    local mount_path=$1
    stat -f -c %S "$mount_path" 2>/dev/null || echo "4096"
}

# Get filesystem discard granularity from sysfs
get_fs_discard_granularity() {
    local device=$1
    local dev_name=$(basename "$device")
    cat "/sys/block/$dev_name/queue/discard_granularity" 2>/dev/null || echo "0"
}

# Get filesystem free space (in KB)
get_fs_free_space_kb() {
    local mount_path=$1
    df -k "$mount_path" | tail -1 | awk '{print $4}'
}

# Get filesystem used space (in KB)  
get_fs_used_space_kb() {
    local mount_path=$1
    df -k "$mount_path" | tail -1 | awk '{print $3}'
}

# Get actual disk usage using du (in KB)
get_actual_usage_kb() {
    local mount_path=$1
    du -sk "$mount_path" 2>/dev/null | awk '{print $1}'
}

#######################################
# DM-thin layer statistics
#######################################

# Get dmthin pool name for a PX pool
get_dmthin_pool_name() {
    local pool_id=$1
    echo "pwx${pool_id}/pxpool"
}

# Get dmthin chunk size (in bytes)
get_dmthin_chunk_size() {
    local pool_id=$1
    local pool_name=$(get_dmthin_pool_name "$pool_id")
    lvs -o chunk_size --units b --noheadings --nosuffix "$pool_name" 2>/dev/null | tr -d ' '
}

# Get dmthin discard granularity
get_dmthin_discard_granularity() {
    local pool_id=$1
    # Discard granularity equals chunk size for dmthin
    get_dmthin_chunk_size "$pool_id"
}

# Get dmthin pool data percent used
get_dmthin_data_percent() {
    local pool_id=$1
    local pool_name=$(get_dmthin_pool_name "$pool_id")
    lvs -o data_percent --noheadings --nosuffix "$pool_name" 2>/dev/null | tr -d ' '
}

# Get dmthin pool size (in bytes)
get_dmthin_pool_size() {
    local pool_id=$1
    local pool_name=$(get_dmthin_pool_name "$pool_id")
    lvs -o lv_size --units b --noheadings --nosuffix "$pool_name" 2>/dev/null | tr -d ' '
}

# Get dmthin pool used space (in bytes)
get_dmthin_used_bytes() {
    local pool_id=$1
    local pool_size=$(get_dmthin_pool_size "$pool_id")
    local data_percent=$(get_dmthin_data_percent "$pool_id")
    if [ -n "$pool_size" ] && [ -n "$data_percent" ]; then
        echo "scale=0; $pool_size * $data_percent / 100" | bc
    else
        echo "0"
    fi
}

# Get dmthin volume thin_id
get_thin_id() {
    local vol_name=$1
    local pool_id=$2
    local vg_name="pwx${pool_id}"
    lvs -o thin_id --noheadings "$vg_name/$vol_name" 2>/dev/null | tr -d ' '
}

# Get allocated chunks for a thin volume using thin_dump
get_allocated_chunks() {
    local pool_id=$1
    local thin_id=$2
    local meta_dev="/dev/mapper/pwx${pool_id}-pxpool_tmeta"
    
    if [ ! -e "$meta_dev" ]; then
        log_warn "Metadata device $meta_dev not found"
        echo "0"
        return
    fi
    
    # Reserve metadata snapshot, dump, then release
    dmsetup message "pwx${pool_id}-pxpool" 0 reserve_metadata_snap 2>/dev/null
    local count=$(thin_dump -m "$meta_dev" 2>/dev/null | grep -c "<range " || echo "0")
    dmsetup message "pwx${pool_id}-pxpool" 0 release_metadata_snap 2>/dev/null
    
    echo "$count"
}

#######################################
# NVMe/Block device statistics
#######################################

# Get device discard granularity
get_device_discard_granularity() {
    local device=$1
    local dev_name=$(basename "$device")
    cat "/sys/block/$dev_name/queue/discard_granularity" 2>/dev/null || echo "0"
}

# Get device discard max bytes
get_device_discard_max_bytes() {
    local device=$1
    local dev_name=$(basename "$device")
    cat "/sys/block/$dev_name/queue/discard_max_bytes" 2>/dev/null || echo "0"
}

# Check if device supports discard
device_supports_discard() {
    local device=$1
    local max_bytes=$(get_device_discard_max_bytes "$device")
    [ "$max_bytes" -gt 0 ] && echo "yes" || echo "no"
}

#######################################
# Combined statistics snapshot
#######################################

# Capture complete statistics snapshot
capture_stats_snapshot() {
    local mount_path=$1
    local pool_id=$2
    local vol_id=$3
    local label=$4
    
    log_info "=== Statistics Snapshot: $label ==="
    
    # Filesystem stats
    local fs_free=$(get_fs_free_space_kb "$mount_path")
    local fs_used=$(get_fs_used_space_kb "$mount_path")
    local actual_usage=$(get_actual_usage_kb "$mount_path")
    
    log_result "FS Free: ${fs_free}KB, FS Used: ${fs_used}KB, Actual(du): ${actual_usage}KB"
    
    # DMthin stats
    local dmthin_used=$(get_dmthin_used_bytes "$pool_id")
    local dmthin_percent=$(get_dmthin_data_percent "$pool_id")
    
    log_result "DMthin Used: ${dmthin_used}B (${dmthin_percent}%)"
    
    # PX autofstrim stats
    local trimmable=$(get_trimmable_space "$vol_id")
    local fstrim_status=$(get_fstrim_status "$vol_id")
    
    log_result "Trimmable: ${trimmable}B, Fstrim Status: $fstrim_status"
    
    echo ""
}

