#!/bin/bash
# Main test runner for fastpath discard tests

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/px_helpers.sh"
source "$SCRIPT_DIR/discard_stats.sh"
source "$SCRIPT_DIR/file_ops.sh"

#######################################
# Usage and argument parsing
#######################################

usage() {
    cat << EOF
Usage: $0 <mount_path> [options]

Required:
    mount_path          Path where fast path volume is mounted

Options:
    --vol-id ID         PX volume ID (auto-detected if not provided)
    --pool-id ID        PX pool ID (default: 0)
    --scenario N        Run specific scenario (1-5), or 'all' (default: all)
    --mode MODE         Discard mode: autofstrim_nodiscard, autofstrim_discard, discard_only, or 'all' (default: all)
    --pattern PATTERN   File pattern: small_files, mixed_files, large_files, or 'all' (default: all)
    --cases-only        Only run the 4 file size cases (4KB, 20KB, 64KB, 1MB)
    --skip-setup        Skip initial setup (volume already configured)
    --dry-run           Show what would be run without executing
    --help              Show this help

Examples:
    # Run all tests on mounted volume
    $0 /mnt/pxvol

    # Run scenario 1 with autofstrim + nodiscard mode
    $0 /mnt/pxvol --scenario 1 --mode autofstrim_nodiscard

    # Run only file size cases for scenario 2
    $0 /mnt/pxvol --scenario 2 --cases-only

    # Run with specific volume and pool IDs
    $0 /mnt/pxvol --vol-id 123456789 --pool-id 0
EOF
    exit 1
}

# Parse arguments
MOUNT_PATH=""
VOL_ID=""
POOL_ID="0"
SCENARIO="all"
MODE="all"
PATTERN="all"
CASES_ONLY=false
SKIP_SETUP=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --vol-id) VOL_ID="$2"; shift 2 ;;
        --pool-id) POOL_ID="$2"; shift 2 ;;
        --scenario) SCENARIO="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --pattern) PATTERN="$2"; shift 2 ;;
        --cases-only) CASES_ONLY=true; shift ;;
        --skip-setup) SKIP_SETUP=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --help) usage ;;
        -*) echo "Unknown option: $1"; usage ;;
        *) MOUNT_PATH="$1"; shift ;;
    esac
done

[ -z "$MOUNT_PATH" ] && usage

#######################################
# Validation
#######################################

validate_environment() {
    log_info "Validating environment..."
    
    # Check mount path exists
    if [ ! -d "$MOUNT_PATH" ]; then
        log_error "Mount path does not exist: $MOUNT_PATH"
        exit 1
    fi
    
    # Check if mounted
    if ! mountpoint -q "$MOUNT_PATH"; then
        log_error "Path is not a mount point: $MOUNT_PATH"
        exit 1
    fi
    
    # Check pxctl available
    if [ ! -x "$PXCTL_PATH" ]; then
        log_error "pxctl not found at: $PXCTL_PATH"
        exit 1
    fi
    
    # Auto-detect volume ID if not provided
    if [ -z "$VOL_ID" ]; then
        # Try to get volume ID from mount
        local device=$(df "$MOUNT_PATH" | tail -1 | awk '{print $1}')
        VOL_ID=$(echo "$device" | grep -oP 'pxd\K[0-9]+' || true)
        if [ -z "$VOL_ID" ]; then
            log_error "Could not auto-detect volume ID. Please provide --vol-id"
            exit 1
        fi
        log_info "Auto-detected volume ID: $VOL_ID"
    fi
    
    log_success "Environment validation passed"
}

#######################################
# Test execution helpers
#######################################

setup_discard_mode() {
    local mode=$1
    log_info "Setting up discard mode: $mode"
    
    case $mode in
        "$MODE_AUTOFSTRIM_NODISCARD")
            enable_volume_nodiscard "$VOL_ID"
            enable_volume_autofstrim "$VOL_ID"
            enable_cluster_autofstrim
            remount_volume "$VOL_ID" "$MOUNT_PATH"
            ;;
        "$MODE_AUTOFSTRIM_DISCARD")
            disable_volume_nodiscard "$VOL_ID"
            enable_volume_autofstrim "$VOL_ID"
            enable_cluster_autofstrim
            remount_volume "$VOL_ID" "$MOUNT_PATH"
            ;;
        "$MODE_DISCARD_ONLY")
            disable_volume_nodiscard "$VOL_ID"
            disable_volume_autofstrim "$VOL_ID"
            disable_cluster_autofstrim
            remount_volume "$VOL_ID" "$MOUNT_PATH"
            ;;
    esac
    
    sleep 3
    log_success "Discard mode configured: $mode"
}

run_scenario_test() {
    local scenario_num=$1
    local mode=$2
    local pattern=$3
    
    log_info "========================================"
    log_info "Running Scenario $scenario_num, Mode: $mode, Pattern: $pattern"
    log_info "========================================"
    
    local scenario=$(get_scenario "$scenario_num")
    parse_scenario "$scenario"
    
    log_info "Configuration:"
    log_info "  FS Block Size: ${FS_BLOCK_KB}KB"
    log_info "  FS Discard Granularity: ${FS_DISCARD_KB}KB"
    log_info "  DMthin Chunk Size: ${DMTHIN_CHUNK_KB}KB"
    log_info "  DMthin Discard Granularity: ${DMTHIN_DISCARD_KB}KB"
    [ "$NVME_SECTOR_KB" -gt 0 ] && log_info "  NVMe Sector Size: ${NVME_SECTOR_KB}KB"
    
    # Setup mode
    if [ "$SKIP_SETUP" != "true" ]; then
        setup_discard_mode "$mode"
    fi
    
    # Create test directory
    local test_dir="${MOUNT_PATH}/discard_test_s${scenario_num}_${mode}_${pattern}"
    mkdir -p "$test_dir"
    
    # Capture initial stats
    capture_stats_snapshot "$MOUNT_PATH" "$POOL_ID" "$VOL_ID" "INITIAL"
    
    # Run the file pattern test
    "$SCRIPT_DIR/test_scenario.sh" "$test_dir" "$VOL_ID" "$POOL_ID" "$MOUNT_PATH" "$mode" "$pattern"
    
    # Capture final stats
    capture_stats_snapshot "$MOUNT_PATH" "$POOL_ID" "$VOL_ID" "FINAL"
    
    # Cleanup
    rm -rf "$test_dir"

    log_success "Completed Scenario $scenario_num, Mode: $mode, Pattern: $pattern"
}

#######################################
# Main execution
#######################################

main() {
    log_info "=========================================="
    log_info "Fastpath Discard Test Suite"
    log_info "=========================================="
    log_info "Mount Path: $MOUNT_PATH"
    log_info "Volume ID: $VOL_ID"
    log_info "Pool ID: $POOL_ID"
    log_info "Scenario: $SCENARIO"
    log_info "Mode: $MODE"
    log_info "Pattern: $PATTERN"
    log_info "=========================================="

    if [ "$DRY_RUN" = "true" ]; then
        log_info "DRY RUN - No tests will be executed"
        exit 0
    fi

    validate_environment

    # Build test matrix
    local scenarios=()
    if [ "$SCENARIO" = "all" ]; then
        scenarios=(1 2 3 4 5)
    else
        scenarios=($SCENARIO)
    fi

    local modes=()
    if [ "$MODE" = "all" ]; then
        modes=("$MODE_AUTOFSTRIM_NODISCARD" "$MODE_AUTOFSTRIM_DISCARD" "$MODE_DISCARD_ONLY")
    else
        modes=("$MODE")
    fi

    local patterns=()
    if [ "$CASES_ONLY" = "true" ]; then
        patterns=("cases")
    elif [ "$PATTERN" = "all" ]; then
        patterns=("$PATTERN_SMALL" "$PATTERN_MIXED" "$PATTERN_LARGE")
    else
        patterns=("$PATTERN")
    fi

    # Run tests
    local total_tests=$((${#scenarios[@]} * ${#modes[@]} * ${#patterns[@]}))
    local current_test=0

    for s in "${scenarios[@]}"; do
        for m in "${modes[@]}"; do
            for p in "${patterns[@]}"; do
                current_test=$((current_test + 1))
                log_info "Test $current_test of $total_tests"
                run_scenario_test "$s" "$m" "$p"
            done
        done
    done

    log_success "=========================================="
    log_success "All tests completed!"
    log_success "Results saved to: $LOG_FILE"
    log_success "=========================================="
}

main "$@"

