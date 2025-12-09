#!/bin/bash
# Comprehensive test runner with volume lifecycle management
# Runs 5 iterations per combination and exports to CSV for Google Sheets

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/px_helpers.sh"
source "$SCRIPT_DIR/discard_stats.sh"
source "$SCRIPT_DIR/file_ops.sh"

#######################################
# Configuration for 3-phase comprehensive testing
#######################################

# Granularity combinations
FS_DISCARD_GRANULARITIES=(4 64 1024 2048)     # KB - 4 options
DMTHIN_DISCARD_GRANULARITIES=(64 1024 2048)   # KB - 3 options
FILE_SIZES=(3 20 66 1201)                     # KB - 4 options
ITERATIONS_PER_VOLUME=5                        # 5 runs per volume

# Test patterns split into 3 phases
PHASE1_PATTERNS=("discard_create_delete" "discard_create_shrink")  # 2 patterns - discard only
PHASE2_PATTERNS=("fstrim_create_delete" "fstrim_create_shrink")    # 2 patterns - manual trim
PHASE3_PATTERNS=("autofstrim_create_delete" "autofstrim_create_shrink")  # 2 patterns - auto trim

# Volume configuration
VOL_SIZE=5  # 5GB volumes
FILESYSTEM_FILL_PERCENT=100

# Each phase: 4 FS × 3 DMThin × 2 patterns × 4 file sizes = 96 tests per phase
# Total: 288 unique test combinations across 3 phases
MAX_PARALLEL_VOLUMES=96  # 96 volumes per phase

#######################################
# Phase-specific configurations
#######################################

configure_phase1_cluster() {
    log_info "Configuring cluster for Phase 1: Discard Only"
    # Cluster autofstrim: OFF
    # Mount option: "discard"
    pxctl cluster options update --auto-fstrim=false
    sleep 10
}

configure_phase2_cluster() {
    log_info "Configuring cluster for Phase 2: Manual Trim"
    # Cluster autofstrim: OFF  
    # Mount option: "nodiscard"
    pxctl cluster options update --auto-fstrim=false
    sleep 10
}

configure_phase3_cluster() {
    log_info "Configuring cluster for Phase 3: Auto Trim"
    # Cluster autofstrim: ON
    # Mount option: "nodiscard"
    pxctl cluster options update --auto-fstrim=true
    
    log_info "Restarting PX for autofstrim to take effect..."
    systemctl restart portworx
    wait_for_px_ready 300
}

#######################################
# Phase execution functions
#######################################

run_phase1_tests() {
    log_info "=========================================="
    log_info "PHASE 1: DISCARD ONLY TESTS (96 volumes)"
    log_info "=========================================="
    
    configure_phase1_cluster
    
    local phase_num=1
    local vol_counter=1
    
    # Create all 96 volumes in parallel for Phase 1
    for fs_gran in "${FS_DISCARD_GRANULARITIES[@]}"; do
        for dm_gran in "${DMTHIN_DISCARD_GRANULARITIES[@]}"; do
            for pattern in "${PHASE1_PATTERNS[@]}"; do
                for file_size in "${FILE_SIZES[@]}"; do
                    local vol_name="phase1_vol_${vol_counter}_${fs_gran}fs_${dm_gran}dm_${pattern}_${file_size}kb"
                    
                    # Create volume with specific configuration
                    create_test_volume "$vol_name" "$VOL_SIZE" "$fs_gran" "$dm_gran" &
                    
                    vol_counter=$((vol_counter + 1))
                done
            done
        done
    done
    
    wait  # Wait for all volume creation to complete
    log_info "Phase 1: All 96 volumes created"
    
    # Run tests on all volumes in parallel
    vol_counter=1
    for fs_gran in "${FS_DISCARD_GRANULARITIES[@]}"; do
        for dm_gran in "${DMTHIN_DISCARD_GRANULARITIES[@]}"; do
            for pattern in "${PHASE1_PATTERNS[@]}"; do
                for file_size in "${FILE_SIZES[@]}"; do
                    local vol_name="phase1_vol_${vol_counter}_${fs_gran}fs_${dm_gran}dm_${pattern}_${file_size}kb"
                    
                    # Run 5 iterations on this volume
                    run_single_volume_test "$phase_num" "$vol_counter" "$pattern" "$file_size" "$vol_name" &
                    
                    vol_counter=$((vol_counter + 1))
                done
            done
        done
    done
    
    wait  # Wait for all tests to complete
    log_info "Phase 1: All tests completed, data cleared, volumes preserved"
}

run_phase2_tests() {
    log_info "=========================================="
    log_info "PHASE 2: MANUAL TRIM TESTS (96 volumes)"
    log_info "=========================================="
    
    configure_phase2_cluster
    
    local phase_num=2
    local vol_counter=1
    
    # Create all 96 volumes in parallel for Phase 2
    for fs_gran in "${FS_DISCARD_GRANULARITIES[@]}"; do
        for dm_gran in "${DMTHIN_DISCARD_GRANULARITIES[@]}"; do
            for pattern in "${PHASE2_PATTERNS[@]}"; do
                for file_size in "${FILE_SIZES[@]}"; do
                    local vol_name="phase2_vol_${vol_counter}_${fs_gran}fs_${dm_gran}dm_${pattern}_${file_size}kb"
                    
                    # Create volume with specific configuration
                    create_test_volume "$vol_name" "$VOL_SIZE" "$fs_gran" "$dm_gran" &
                    
                    vol_counter=$((vol_counter + 1))
                done
            done
        done
    done
    
    wait  # Wait for all volume creation to complete
    log_info "Phase 2: All 96 volumes created"
    
    # Run tests on all volumes in parallel
    vol_counter=1
    for fs_gran in "${FS_DISCARD_GRANULARITIES[@]}"; do
        for dm_gran in "${DMTHIN_DISCARD_GRANULARITIES[@]}"; do
            for pattern in "${PHASE2_PATTERNS[@]}"; do
                for file_size in "${FILE_SIZES[@]}"; do
                    local vol_name="phase2_vol_${vol_counter}_${fs_gran}fs_${dm_gran}dm_${pattern}_${file_size}kb"
                    
                    # Run 5 iterations on this volume
                    run_single_volume_test "$phase_num" "$vol_counter" "$pattern" "$file_size" "$vol_name" &
                    
                    vol_counter=$((vol_counter + 1))
                done
            done
        done
    done
    
    wait  # Wait for all tests to complete
    log_info "Phase 2: All tests completed, data cleared, volumes preserved"
}

run_phase3_tests() {
    log_info "=========================================="
    log_info "PHASE 3: AUTO TRIM TESTS (96 volumes)"
    log_info "=========================================="
    
    configure_phase3_cluster
    
    local phase_num=3
    local vol_counter=1
    
    # Create all 96 volumes in parallel for Phase 3
    for fs_gran in "${FS_DISCARD_GRANULARITIES[@]}"; do
        for dm_gran in "${DMTHIN_DISCARD_GRANULARITIES[@]}"; do
            for pattern in "${PHASE3_PATTERNS[@]}"; do
                for file_size in "${FILE_SIZES[@]}"; do
                    local vol_name="phase3_vol_${vol_counter}_${fs_gran}fs_${dm_gran}dm_${pattern}_${file_size}kb"
                    
                    # Create volume with specific configuration
                    create_test_volume "$vol_name" "$VOL_SIZE" "$fs_gran" "$dm_gran" &
                    
                    vol_counter=$((vol_counter + 1))
                done
            done
        done
    done
    
    wait  # Wait for all volume creation to complete
    log_info "Phase 3: All 96 volumes created"
    
    # Run tests on all volumes in parallel
    vol_counter=1
    for fs_gran in "${FS_DISCARD_GRANULARITIES[@]}"; do
        for dm_gran in "${DMTHIN_DISCARD_GRANULARITIES[@]}"; do
            for pattern in "${PHASE3_PATTERNS[@]}"; do
                for file_size in "${FILE_SIZES[@]}"; do
                    local vol_name="phase3_vol_${vol_counter}_${fs_gran}fs_${dm_gran}dm_${pattern}_${file_size}kb"
                    
                    # Run 5 iterations on this volume
                    run_single_volume_test "$phase_num" "$vol_counter" "$pattern" "$file_size" "$vol_name" &
                    
                    vol_counter=$((vol_counter + 1))
                done
            done
        done
    done
    
    wait  # Wait for all tests to complete
    log_info "Phase 3: All tests completed, data cleared, volumes preserved"
}

#######################################
# Single volume test runner (5 iterations)
#######################################

run_single_volume_test() {
    local phase_num=$1
    local vol_counter=$2
    local pattern=$3
    local file_size=$4
    local vol_name=$5
    
    log_info "Starting 5 iterations on volume: $vol_name"
    
    # Mount volume
    local mount_path="/mnt/${vol_name}"
    mkdir -p "$mount_path"
    
    # Set mount options based on phase
    local mount_opts=""
    case $phase_num in
        1) mount_opts="discard" ;;      # Phase 1: discard only
        2) mount_opts="nodiscard" ;;    # Phase 2: manual trim
        3) mount_opts="nodiscard" ;;    # Phase 3: auto trim
    esac
    
    mount -o "$mount_opts" "/dev/pxd/${vol_name}" "$mount_path"
    
    # Run 5 iterations
    for iteration in {1..5}; do
        log_info "  Volume $vol_name - Iteration $iteration/5"
        
        # Run single test case
        run_single_case "$phase_num" "$vol_counter" "$iteration" "$file_size" "$vol_name" "$mount_path" "$pattern"
        
        # Clear data but keep volume
        cleanup_volume_filesystem "$mount_path" "$vol_name"
    done
    
    # Unmount but keep volume
    umount "$mount_path"
    rmdir "$mount_path"
    
    log_info "Completed all 5 iterations on volume: $vol_name (volume preserved)"
}

#######################################
# Main execution
#######################################

main() {
    log_info "=========================================="
    log_info "3-PHASE COMPREHENSIVE DISCARD TESTS"
    log_info "Phase 1: 96 volumes (discard only)"
    log_info "Phase 2: 96 volumes (manual trim)"  
    log_info "Phase 3: 96 volumes (auto trim)"
    log_info "Total: 288 volumes × 5 iterations = 1,440 tests"
    log_info "=========================================="
    
    # Initialize CSV output
    initialize_csv_output
    
    # Run all 3 phases
    run_phase1_tests
    run_phase2_tests  
    run_phase3_tests
    
    # Generate summary
    generate_test_summary
    
    log_success "All 3-phase comprehensive tests completed!"
    log_info "Results: $CSV_OUTPUT_FILE"
    log_info "Total volumes preserved: 288 (96 per phase)"
}

#######################################
# Volume cleanup between iterations
#######################################

cleanup_volume_filesystem() {
    local mount_path=$1
    local vol_id=$2
    
    log_info "Cleaning filesystem on volume $vol_id"
    
    # Remove all files but keep filesystem
    find "$mount_path" -type f -delete 2>/dev/null || true
    find "$mount_path" -type d -empty -delete 2>/dev/null || true
    
    # Force filesystem sync and trim
    sync
    fstrim "$mount_path" 2>/dev/null || true
    
    # Wait for operations to complete
    sleep 3
}

#######################################
# Test mode definitions
#######################################

# Define the 6 specific test runs
declare -A TEST_RUNS=(
    [1]="discard_create_delete"
    [2]="fstrim_create_delete" 
    [3]="autofstrim_create_delete"
    [4]="discard_create_shrink"
    [5]="fstrim_create_shrink"
    [6]="autofstrim_create_shrink"
)

#######################################
# Test case runner
#######################################

run_single_case() {
    local run_num=$1
    local scenario_num=$2
    local file_case=$3
    local file_size_kb=$4
    local vol_id=$5
    
    local test_mode=${TEST_RUNS[$run_num]}
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    log_info "  Case: ${file_size_kb}KB file - Mode: $test_mode"
    
    # Parse test mode
    IFS='_' read -r discard_type action_type operation_type <<< "$test_mode"
    
    # Initial metrics
    sync; sleep 1
    local initial_metrics=$(collect_metrics "$vol_id" "$MOUNT_PATH" "$POOL_ID")
    parse_metrics "$initial_metrics"
    local init_fs_free=$FS_FREE
    local init_dmthin=$DMTHIN_PERCENT
    local init_px=$PX_USAGE
    local init_du=$DU_USAGE
    local init_trim=$TRIMMABLE
    
    # Configure discard mode based on test type
    case $discard_type in
        "discard")
            configure_discard_mode "$vol_id" "$MODE_DISCARD_ONLY"
            ;;
        "fstrim")
            configure_discard_mode "$vol_id" "$MODE_AUTOFSTRIM_DISCARD"
            ;;
        "autofstrim")
            configure_discard_mode "$vol_id" "$MODE_AUTOFSTRIM_DISCARD"
            ;;
    esac
    
    # Create files to fill volume
    local test_dir="${MOUNT_PATH}/test_${run_num}_${file_case}"
    mkdir -p "$test_dir"
    local file_count=$(create_files_to_fill "$test_dir" "$file_size_kb")
    sync; sleep 2
    
    local create_metrics=$(collect_metrics "$vol_id" "$MOUNT_PATH" "$POOL_ID")
    parse_metrics "$create_metrics"
    local create_fs_free=$FS_FREE
    local create_dmthin=$DMTHIN_PERCENT
    local create_px=$PX_USAGE
    local create_du=$DU_USAGE
    local create_trim=$TRIMMABLE
    
    # Perform operation based on test type
    local start_time=$(date +%s.%N)
    
    case $operation_type in
        "delete")
            # Delete 90% of files
            delete_percentage_files "$test_dir" 90 "fill_*"
            ;;
        "shrink")
            # Shrink each file to 10% of original size
            shrink_files_percentage "$test_dir" 10 "fill_*"
            ;;
    esac
    
    sync
    
    local after_op_metrics=$(collect_metrics "$vol_id" "$MOUNT_PATH" "$POOL_ID")
    parse_metrics "$after_op_metrics"
    local after_op_fs_free=$FS_FREE
    local after_op_dmthin=$DMTHIN_PERCENT
    local after_op_px=$PX_USAGE
    local after_op_du=$DU_USAGE
    local after_op_trim=$TRIMMABLE
    
    # Execute trim/discard based on mode
    case $discard_type in
        "discard")
            # Manual discard - happens automatically
            sleep 5
            ;;
        "fstrim")
            # Manual fstrim
            fstrim "$MOUNT_PATH"
            ;;
        "autofstrim")
            # Wait for auto fstrim
            sleep 3
            wait_for_fstrim_complete "$vol_id" 120 2>/dev/null || true
            ;;
    esac
    
    local end_time=$(date +%s.%N)
    local discard_time=$(echo "$end_time - $start_time" | bc)
    
    local final_metrics=$(collect_metrics "$vol_id" "$MOUNT_PATH" "$POOL_ID")
    parse_metrics "$final_metrics"
    local final_fs_free=$FS_FREE
    local final_dmthin=$DMTHIN_PERCENT
    local final_px=$PX_USAGE
    local final_du=$DU_USAGE
    local final_trim=$TRIMMABLE
    
    # Calculate reclaimed space
    local space_reclaimed=$((final_fs_free - after_op_fs_free))
    local dmthin_reclaimed=$(echo "$after_op_dmthin - $final_dmthin" | bc 2>/dev/null || echo "0")
    
    # Get actual discard granularity
    local pxd_device=$(get_pxd_device "$vol_id")
    local actual_discard_gran=$(get_sysfs_discard_granularity "$pxd_device")
    
    # Write CSV row with all 29 parameters
    local csv_row="${timestamp},${run_num},${scenario_num},${FS_BLOCK_KB},${FS_DISCARD_KB},${DMTHIN_CHUNK_KB},${DMTHIN_DISCARD_KB},${NVME_SECTOR_KB},${test_mode},${file_case},${operation_type},${init_fs_free},${init_dmthin},${init_px},${init_trim},${file_count},${create_fs_free},${create_dmthin},${create_px},${create_trim},${after_op_fs_free},${after_op_dmthin},${after_op_px},${after_op_trim},${final_fs_free},${final_dmthin},${final_px},${final_trim},${vol_id}"
    
    write_csv_row "$csv_row"
    log_result "    $test_mode: Reclaimed ${space_reclaimed}KB in ${discard_time}s"
}

#######################################
# Run all cases for a scenario/mode
#######################################

run_all_cases() {
    local run_num=$1
    local scenario_num=$2
    local mode=$3
    local vol_id=$4
    
    # File size cases: 4KB, 20KB, 64KB, 1MB
    local cases=("1:4" "2:20" "3:64" "4:1024")

    for case_item in "${cases[@]}"; do
        IFS=':' read -r case_num size_kb <<< "$case_item"
        run_single_case "$run_num" "$scenario_num" "$mode" "cases" "$case_num" "$size_kb" "$vol_id"
    done
}

#######################################
# Setup discard mode on volume
#######################################

configure_discard_mode() {
    local vol_id=$1
    local mode=$2

    log_info "Configuring discard mode: $mode"

    case $mode in
        "$MODE_AUTOFSTRIM_NODISCARD")
            enable_volume_nodiscard "$vol_id"
            enable_volume_autofstrim "$vol_id"
            enable_cluster_autofstrim
            ;;
        "$MODE_AUTOFSTRIM_DISCARD")
            disable_volume_nodiscard "$vol_id"
            enable_volume_autofstrim "$vol_id"
            enable_cluster_autofstrim
            ;;
        "$MODE_DISCARD_ONLY")
            disable_volume_nodiscard "$vol_id"
            disable_volume_autofstrim "$vol_id"
            disable_cluster_autofstrim
            ;;
    esac
    sleep 3
}

#######################################
# Main test loop
#######################################

run_comprehensive_tests() {
    log_info "=========================================="
    log_info "Comprehensive Discard Test Suite"
    log_info "6 specific test runs (try-1 through try-6)"
    log_info "=========================================="

    init_csv

    # Run exactly 6 tests as specified
    for run_num in {1..6}; do
        local test_mode=${TEST_RUNS[$run_num]}
        log_info ""
        log_info "=========================================="
        log_info "Run $run_num: $test_mode"
        log_info "=========================================="
        
        # Create unique volume for this run
        local vol_name="${VOL_NAME}_run${run_num}"
        local mount_path="/var/lib/osd/mounts/${vol_name}"
        
        log_info "Creating volume: $vol_name"
        local vol_id=$(setup_volume "$vol_name" "$mount_path" "$VOL_SIZE" "$POOL_ID")
        
        if [ -z "$vol_id" ]; then
            log_error "Failed to create volume for run $run_num"
            continue
        fi
        
        # Run all file size cases for this test mode
        local cases=("1:3" "2:20" "3:66" "4:1201")
        for case_item in "${cases[@]}"; do
            IFS=':' read -r case_num size_kb <<< "$case_item"
            run_single_case "$run_num" "1" "$case_num" "$size_kb" "$vol_id"
        done
        
        log_success "Completed run $run_num: $test_mode"
        # Note: Not cleaning up volume as requested
    done
    
    log_success "All 6 test runs completed!"
}

#######################################
# Usage and argument parsing
#######################################

usage() {
    cat << EOF
Usage: $0 [options]

Comprehensive discard test runner with volume lifecycle management.
Runs 5 iterations per combination and exports results to CSV.

Options:
    --runs N            Number of runs per combination (default: 5)
    --vol-name NAME     Volume name to use (default: discard_test_vol)
    --vol-size SIZE     Volume size (default: 10G)
    --mount-path PATH   Mount path (default: /var/lib/osd/mounts/discard_test_vol)
    --pool-id ID        Pool ID (default: 0)
    --scenario N        Run specific scenario only (1-5)
    --mode MODE         Run specific mode only
    --help              Show this help

Examples:
    # Run all tests with default settings
    $0

    # Run 3 iterations per combination
    $0 --runs 3

    # Run only scenario 1
    $0 --scenario 1

    # Run with custom volume settings
    $0 --vol-name my_test_vol --vol-size 20G
EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --runs) RUNS_PER_COMBINATION="$2"; shift 2 ;;
        --vol-name) VOL_NAME="$2"; MOUNT_PATH="/var/lib/osd/mounts/${VOL_NAME}"; shift 2 ;;
        --vol-size) VOL_SIZE="$2"; shift 2 ;;
        --mount-path) MOUNT_PATH="$2"; shift 2 ;;
        --pool-id) POOL_ID="$2"; shift 2 ;;
        --scenario) SPECIFIC_SCENARIO="$2"; shift 2 ;;
        --mode) SPECIFIC_MODE="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# Run the tests
run_comprehensive_tests

