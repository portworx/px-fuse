#!/bin/bash
# Quick single-scenario test for fast iteration

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/px_helpers.sh"
source "$SCRIPT_DIR/discard_stats.sh"
source "$SCRIPT_DIR/file_ops.sh"

usage() {
    echo "Usage: $0 <mount_path> <vol_id> [pool_id] [mode]"
    echo ""
    echo "Quick test to verify discard behavior"
    echo ""
    echo "Arguments:"
    echo "  mount_path   Path where volume is mounted"
    echo "  vol_id       PX volume ID"
    echo "  pool_id      PX pool ID (default: 0)"
    echo "  mode         autofstrim_nodiscard, autofstrim_discard, discard_only (default: autofstrim_nodiscard)"
    exit 1
}

MOUNT_PATH=$1
VOL_ID=$2
POOL_ID=${3:-0}
MODE=${4:-$MODE_AUTOFSTRIM_NODISCARD}

[ -z "$MOUNT_PATH" ] || [ -z "$VOL_ID" ] && usage

TEST_DIR="${MOUNT_PATH}/quick_discard_test"

#######################################
# Quick test functions
#######################################

take_snapshot() {
    local label=$1
    local fs_free=$(get_fs_free_space_kb "$MOUNT_PATH")
    local dmthin_percent=$(get_dmthin_data_percent "$POOL_ID")
    local px_usage=$(get_px_usage "$VOL_ID")
    local du_usage=$(get_du_usage "$VOL_ID")
    local trimmable=$(get_trimmable_space "$VOL_ID")
    echo "$label|$fs_free|$dmthin_percent|$px_usage|$du_usage|$trimmable"
}

print_snapshot() {
    local data=$1
    IFS='|' read -r label fs_free dmthin_percent px_usage du_usage trimmable <<< "$data"
    log_result "$label: FS_Free=${fs_free}KB, DMthin=${dmthin_percent}%"
    log_result "  PX_Usage=${px_usage}B, DU_Usage=${du_usage}B, Trimmable=${trimmable}B"
}

compare_snapshots() {
    local before=$1
    local after=$2

    IFS='|' read -r _ fs_before dm_before px_before du_before trim_before <<< "$before"
    IFS='|' read -r _ fs_after dm_after px_after du_after trim_after <<< "$after"

    local fs_diff=$((fs_after - fs_before))
    local px_diff=$((px_after - px_before))
    local trim_diff=$((trim_after - trim_before))

    log_info "--- Comparison ---"
    log_result "FS Free change: ${fs_diff}KB"
    log_result "DMthin: ${dm_before}% -> ${dm_after}%"
    log_result "PX Usage: ${px_before}B -> ${px_after}B (diff: ${px_diff}B)"
    log_result "Trimmable: ${trim_before}B -> ${trim_after}B (diff: ${trim_diff}B)"
}

#######################################
# Main test
#######################################

log_info "=========================================="
log_info "Quick Discard Test"
log_info "=========================================="
log_info "Mount: $MOUNT_PATH"
log_info "Volume: $VOL_ID"
log_info "Pool: $POOL_ID"
log_info "Mode: $MODE"
log_info "=========================================="

# Setup
mkdir -p "$TEST_DIR"
log_info "Test directory: $TEST_DIR"

# Configure mode
log_info "Configuring discard mode: $MODE"
case $MODE in
    "$MODE_AUTOFSTRIM_NODISCARD")
        enable_volume_nodiscard "$VOL_ID"
        enable_volume_autofstrim "$VOL_ID"
        enable_cluster_autofstrim
        ;;
    "$MODE_AUTOFSTRIM_DISCARD")
        disable_volume_nodiscard "$VOL_ID"
        enable_volume_autofstrim "$VOL_ID"
        enable_cluster_autofstrim
        ;;
    "$MODE_DISCARD_ONLY")
        disable_volume_nodiscard "$VOL_ID"
        disable_volume_autofstrim "$VOL_ID"
        disable_cluster_autofstrim
        ;;
esac
sleep 2

# Initial state
log_info ""
log_info "=== Initial State ==="
snapshot_initial=$(take_snapshot "Initial")
print_snapshot "$snapshot_initial"

# Create test files
log_info ""
log_info "=== Creating Test Files ==="
create_file "${TEST_DIR}/test_4kb.dat" 4
create_file "${TEST_DIR}/test_64kb.dat" 64
create_file "${TEST_DIR}/test_1mb.dat" 1024
create_small_files "$TEST_DIR" 20 "small"
sync
sleep 2

snapshot_after_create=$(take_snapshot "AfterCreate")
print_snapshot "$snapshot_after_create"

# Delete files
log_info ""
log_info "=== Deleting Files ==="
start_time=$(date +%s.%N)
rm -rf "${TEST_DIR:?}"/*
sync

# Wait for discard
log_info "Waiting for discard to complete..."
case $MODE in
    "$MODE_AUTOFSTRIM_NODISCARD"|"$MODE_AUTOFSTRIM_DISCARD")
        sleep 5
        wait_for_fstrim_complete "$VOL_ID" 60
        ;;
    "$MODE_DISCARD_ONLY")
        sleep 5
        ;;
esac

end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc)

snapshot_after_delete=$(take_snapshot "AfterDelete")
print_snapshot "$snapshot_after_delete"

# Summary
log_info ""
log_info "=== Summary ==="
compare_snapshots "$snapshot_after_create" "$snapshot_after_delete"
log_result "Total discard time: ${duration}s"

# Cleanup
rmdir "$TEST_DIR" 2>/dev/null || true

log_success ""
log_success "Quick test completed!"

