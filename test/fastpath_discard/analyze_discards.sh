#!/bin/bash
# Analyze discard behavior at different layers

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/discard_stats.sh"

usage() {
    echo "Usage: $0 <mount_path> <pool_id> [vol_id]"
    echo ""
    echo "Analyze discard granularity and unallocated blocks across layers"
    exit 1
}

MOUNT_PATH=$1
POOL_ID=${2:-0}
VOL_ID=$3

[ -z "$MOUNT_PATH" ] && usage

#######################################
# Layer configuration analysis
#######################################

analyze_layer_config() {
    log_info "=========================================="
    log_info "Layer Configuration Analysis"
    log_info "=========================================="
    
    # Get device from mount
    local device=$(df "$MOUNT_PATH" | tail -1 | awk '{print $1}')
    local dev_name=$(basename "$device")
    
    log_info "Mount Path: $MOUNT_PATH"
    log_info "Device: $device"
    
    echo ""
    log_info "--- Filesystem Layer ---"
    local fs_block=$(get_fs_block_size "$MOUNT_PATH")
    log_result "Block Size: ${fs_block} bytes"
    
    # Get discard granularity from sysfs (for PXD device)
    local pxd_dev=$(echo "$device" | sed 's|/dev/||')
    if [ -d "/sys/block/$pxd_dev" ]; then
        local fs_discard_gran=$(cat "/sys/block/$pxd_dev/queue/discard_granularity" 2>/dev/null || echo "N/A")
        local fs_discard_max=$(cat "/sys/block/$pxd_dev/queue/discard_max_bytes" 2>/dev/null || echo "N/A")
        log_result "Discard Granularity: $fs_discard_gran bytes"
        log_result "Discard Max Bytes: $fs_discard_max bytes"
    fi
    
    echo ""
    log_info "--- DM-Thin Layer ---"
    local dmthin_chunk=$(get_dmthin_chunk_size "$POOL_ID")
    log_result "Chunk Size: ${dmthin_chunk} bytes ($((dmthin_chunk / 1024))KB)"
    log_result "Discard Granularity: ${dmthin_chunk} bytes (equals chunk size)"
    
    local pool_name=$(get_dmthin_pool_name "$POOL_ID")
    log_result "Pool Name: $pool_name"
    
    # Get discard setting on pool
    local discards=$(lvs -o kernel_discards --noheadings "$pool_name" 2>/dev/null | tr -d ' ')
    log_result "Pool Discards Setting: $discards"
    
    echo ""
    log_info "--- Storage Layer ---"
    # Get underlying device(s) for the pool
    local pool_dev="/dev/mapper/pwx${POOL_ID}-pxpool"
    if [ -e "$pool_dev" ]; then
        local pool_dev_name=$(basename "$pool_dev")
        local stor_discard_gran=$(cat "/sys/block/dm-*/slaves/*/queue/discard_granularity" 2>/dev/null | head -1 || echo "N/A")
        log_result "Underlying Discard Granularity: $stor_discard_gran bytes"
    fi
}

#######################################
# Unallocated space analysis
#######################################

analyze_unallocated() {
    log_info "=========================================="
    log_info "Unallocated Space Analysis"
    log_info "=========================================="
    
    echo ""
    log_info "--- Filesystem Level ---"
    local fs_free=$(get_fs_free_space_kb "$MOUNT_PATH")
    local fs_used=$(get_fs_used_space_kb "$MOUNT_PATH")
    local fs_total=$((fs_free + fs_used))
    local fs_free_percent=$((fs_free * 100 / fs_total))
    
    log_result "Total: ${fs_total}KB"
    log_result "Used: ${fs_used}KB"
    log_result "Free: ${fs_free}KB (${fs_free_percent}%)"
    
    # Actual usage vs reported
    local actual=$(get_actual_usage_kb "$MOUNT_PATH")
    local discardable=$((fs_used - actual))
    log_result "Actual Usage (du): ${actual}KB"
    log_result "Potentially Discardable: ${discardable}KB"
    
    echo ""
    log_info "--- DM-Thin Level ---"
    local pool_size=$(get_dmthin_pool_size "$POOL_ID")
    local data_percent=$(get_dmthin_data_percent "$POOL_ID")
    local used_bytes=$(get_dmthin_used_bytes "$POOL_ID")
    local free_bytes=$((pool_size - used_bytes))
    
    log_result "Pool Size: $((pool_size / 1024 / 1024))MB"
    log_result "Data Used: $((used_bytes / 1024 / 1024))MB (${data_percent}%)"
    log_result "Data Free: $((free_bytes / 1024 / 1024))MB"
    
    # Calculate chunk-level stats
    local chunk_size=$(get_dmthin_chunk_size "$POOL_ID")
    local total_chunks=$((pool_size / chunk_size))
    local used_chunks=$((used_bytes / chunk_size))
    local free_chunks=$((total_chunks - used_chunks))
    
    log_result "Total Chunks: $total_chunks"
    log_result "Used Chunks: ~$used_chunks"
    log_result "Free Chunks: ~$free_chunks"
    
    echo ""
    log_info "--- PX Autofstrim Level ---"
    if [ -n "$VOL_ID" ]; then
        local trimmable=$(get_trimmable_space "$VOL_ID")
        local status=$(get_fstrim_status "$VOL_ID")
        log_result "Trimmable Space: ${trimmable} bytes"
        log_result "Fstrim Status: $status"
    else
        log_warn "Volume ID not provided - skipping PX stats"
    fi
}

#######################################
# Discard efficiency analysis
#######################################

analyze_efficiency() {
    log_info "=========================================="
    log_info "Discard Efficiency Analysis"
    log_info "=========================================="
    
    local chunk_size=$(get_dmthin_chunk_size "$POOL_ID")
    local chunk_kb=$((chunk_size / 1024))
    
    echo ""
    log_info "Granularity Mismatch Impact:"
    
    # Analyze what happens with different file sizes
    local file_sizes=(4 20 64 1024)
    
    for size_kb in "${file_sizes[@]}"; do
        local size_bytes=$((size_kb * 1024))
        local full_chunks=$((size_bytes / chunk_size))
        local remainder=$((size_bytes % chunk_size))
        
        if [ $full_chunks -eq 0 ]; then
            log_result "${size_kb}KB file: Smaller than chunk (${chunk_kb}KB) - NO dmthin discard possible"
        elif [ $remainder -eq 0 ]; then
            log_result "${size_kb}KB file: Exactly $full_chunks chunk(s) - Full discard possible"
        else
            local wasted=$((chunk_size - remainder))
            log_result "${size_kb}KB file: $full_chunks full chunk(s) + ${remainder}B partial - ${wasted}B wasted per file"
        fi
    done
    
    echo ""
    log_info "Recommendation:"
    log_info "  - Files < ${chunk_kb}KB: Cannot reclaim dmthin space until chunk is fully free"
    log_info "  - For efficient discard: Use file sizes that are multiples of ${chunk_kb}KB"
    log_info "  - Small files benefit most from autofstrim batching"
}

#######################################
# Main
#######################################

log_info "Fastpath Discard Layer Analysis"
log_info "================================"

analyze_layer_config
echo ""
analyze_unallocated
echo ""
analyze_efficiency

log_info "=========================================="
log_info "Analysis Complete"
log_info "=========================================="

