#!/bin/bash
# Individual scenario test execution

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/px_helpers.sh"
source "$SCRIPT_DIR/discard_stats.sh"
source "$SCRIPT_DIR/file_ops.sh"

# Arguments
TEST_DIR=$1
VOL_ID=$2
POOL_ID=$3
MOUNT_PATH=$4
MODE=$5
PATTERN=$6

#######################################
# Test callback for stats collection
#######################################

collect_stats_callback() {
    local label=$1
    log_info "--- Stats after: $label ---"
    
    # Get filesystem stats
    local fs_free=$(get_fs_free_space_kb "$MOUNT_PATH")
    local actual=$(get_actual_usage_kb "$MOUNT_PATH")
    
    # Get dmthin stats
    local dmthin_percent=$(get_dmthin_data_percent "$POOL_ID")
    local dmthin_used=$(get_dmthin_used_bytes "$POOL_ID")
    
    # Get trimmable space from PX
    local trimmable=$(get_trimmable_space "$VOL_ID")
    
    log_result "$label: FS_Free=${fs_free}KB, Actual=${actual}KB, DMthin=${dmthin_percent}%, Trimmable=${trimmable}B"
}

#######################################
# Wait for discard operations
#######################################

wait_for_discard() {
    local mode=$1
    
    case $mode in
        "$MODE_AUTOFSTRIM_NODISCARD"|"$MODE_AUTOFSTRIM_DISCARD")
            log_info "Waiting for autofstrim to process..."
            # Give autofstrim time to detect and process
            sleep $FSTRIM_WAIT_SECONDS
            # Check if fstrim is in progress and wait
            wait_for_fstrim_complete "$VOL_ID" 120
            ;;
        "$MODE_DISCARD_ONLY")
            log_info "Inline discard mode - waiting for settle..."
            sleep $DISCARD_SETTLE_SECONDS
            ;;
    esac
}

#######################################
# Measure discard performance
#######################################

measure_discard_time() {
    local start_time=$1
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    log_result "Discard operation took: ${duration}s"
}

#######################################
# Run file size cases (4KB, 20KB, 64KB, 1MB)
#######################################

run_cases() {
    log_info "Running file size test cases..."
    
    local cases=("4:4KB" "20:20KB" "64:64KB" "1024:1MB")
    
    for case_item in "${cases[@]}"; do
        IFS=':' read -r size_kb label <<< "$case_item"
        
        log_info "=== Case: $label file ==="
        
        # Capture before stats
        collect_stats_callback "Before_${label}"
        
        # Create file
        local filename="${TEST_DIR}/case_${label}.dat"
        log_info "Creating ${size_kb}KB file..."
        create_file "$filename" "$size_kb"
        sync
        sleep 1
        
        collect_stats_callback "AfterCreate_${label}"
        
        # Delete file
        log_info "Deleting ${size_kb}KB file..."
        local start_time=$(date +%s.%N)
        rm -f "$filename"
        sync
        
        # Wait for discard
        wait_for_discard "$MODE"
        measure_discard_time "$start_time"
        
        collect_stats_callback "AfterDelete_${label}"
        
        echo ""
    done
}

#######################################
# Run pattern-based tests
#######################################

run_pattern_test() {
    local pattern=$1
    
    log_info "Running pattern test: $pattern"
    
    # Initial stats
    collect_stats_callback "PatternStart_${pattern}"
    
    local start_time=$(date +%s.%N)
    
    case $pattern in
        "$PATTERN_SMALL")
            # Create and delete small files repeatedly
            for iter in $(seq 1 $REPEAT_COUNT); do
                log_info "Iteration $iter: Creating small files..."
                create_small_files "$TEST_DIR" 30 "iter${iter}"
                sync
                sleep 1
                
                collect_stats_callback "AfterCreate_iter${iter}"
                
                log_info "Iteration $iter: Deleting small files..."
                delete_all_files "$TEST_DIR"
                wait_for_discard "$MODE"
                
                collect_stats_callback "AfterDelete_iter${iter}"
            done
            ;;
        "$PATTERN_MIXED")
            # Create mixed files across different dmthin blocks
            for iter in $(seq 1 $REPEAT_COUNT); do
                log_info "Iteration $iter: Creating mixed files..."
                create_mixed_files "$TEST_DIR" 25 15
                sync
                sleep 1
                
                collect_stats_callback "AfterCreate_iter${iter}"
                
                log_info "Iteration $iter: Deleting mixed files..."
                delete_all_files "$TEST_DIR"
                wait_for_discard "$MODE"
                
                collect_stats_callback "AfterDelete_iter${iter}"
            done
            ;;
        "$PATTERN_LARGE")
            # Large files spanning multiple dmthin chunks
            for iter in $(seq 1 $REPEAT_COUNT); do
                log_info "Iteration $iter: Creating large files..."
                create_large_files "$TEST_DIR" 5 "iter${iter}"
                sync
                sleep 1
                
                collect_stats_callback "AfterCreate_iter${iter}"
                
                log_info "Iteration $iter: Deleting large files..."
                delete_all_files "$TEST_DIR"
                wait_for_discard "$MODE"
                
                collect_stats_callback "AfterDelete_iter${iter}"
            done
            ;;
    esac
    
    measure_discard_time "$start_time"
    collect_stats_callback "PatternEnd_${pattern}"
}

#######################################
# Main
#######################################

log_info "Starting scenario test in: $TEST_DIR"
log_info "Mode: $MODE, Pattern: $PATTERN"

mkdir -p "$TEST_DIR"

if [ "$PATTERN" = "cases" ]; then
    run_cases
else
    run_pattern_test "$PATTERN"
fi

log_success "Scenario test completed"

