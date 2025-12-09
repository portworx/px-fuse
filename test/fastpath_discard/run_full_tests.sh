#!/bin/bash
# Full comprehensive test runner with px-fuse rebuild for each discard granularity
# This script modifies PXD_MAX_DISCARD_GRANULARITY, rebuilds px-fuse, reloads the module

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PX_FUSE_DIR="/home/kagarwal/go/src/github.com/portworx/px-fuse"
PXD_HEADER="${PX_FUSE_DIR}/pxd.h"

source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/px_helpers.sh"
source "$SCRIPT_DIR/discard_stats.sh"
source "$SCRIPT_DIR/file_ops.sh"

#######################################
# Configuration
#######################################

RUNS_PER_COMBINATION=5
VOL_NAME="discard_test_vol"
VOL_SIZE=10
MOUNT_PATH="/var/lib/osd/mounts/${VOL_NAME}"
POOL_ID=0

# Results CSV file - descriptive naming
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_CSV="${SCRIPT_DIR}/discard_granularity_test_results_${TIMESTAMP}.csv"
RUN_LOG="${SCRIPT_DIR}/discard_granularity_test_run_${TIMESTAMP}.log"

# CSV Header
CSV_HEADER="Timestamp,Run,Scenario,FS_Block_KB,FS_Discard_Gran_KB,DMthin_Chunk_KB,DMthin_Discard_Gran_KB,NVMe_Sector_KB,Mode,File_Case,File_Type,File_Count,Total_Size_KB,Initial_FS_Free_KB,Initial_DMthin_Percent,Initial_PX_Usage_B,Initial_DU_Usage_B,Initial_Trimmable_B,AfterCreate_FS_Free_KB,AfterCreate_DMthin_Percent,AfterCreate_PX_Usage_B,AfterCreate_DU_Usage_B,AfterCreate_Trimmable_B,AfterDelete_FS_Free_KB,AfterDelete_DMthin_Percent,AfterDelete_PX_Usage_B,AfterDelete_DU_Usage_B,AfterDelete_Trimmable_B,Discard_Time_Sec,Space_Reclaimed_KB,DMthin_Reclaimed_Percent,Actual_Discard_Gran_B,Volume_ID"

#######################################
# Logging
#######################################

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" | tee -a "$RUN_LOG"
}

log_info() { log "[INFO] $1"; }
log_success() { log "[PASS] $1"; }
log_error() { log "[FAIL] $1"; }
log_warn() { log "[WARN] $1"; }

#######################################
# px-fuse rebuild functions
#######################################

# Backup original pxd.h
backup_pxd_header() {
    if [ ! -f "${PXD_HEADER}.orig" ]; then
        cp "$PXD_HEADER" "${PXD_HEADER}.orig"
        log_info "Backed up original pxd.h"
    fi
}

# Restore original pxd.h
restore_pxd_header() {
    if [ -f "${PXD_HEADER}.orig" ]; then
        cp "${PXD_HEADER}.orig" "$PXD_HEADER"
        log_info "Restored original pxd.h"
    fi
}

# Set PXD_MAX_DISCARD_GRANULARITY in pxd.h
set_discard_granularity_in_source() {
    local granularity_bytes=$1
    local granularity_expr
    
    # Convert to appropriate expression
    if [ "$granularity_bytes" -eq 4096 ]; then
        granularity_expr="(4 << 10)"
    elif [ "$granularity_bytes" -eq 65536 ]; then
        granularity_expr="(64 << 10)"
    elif [ "$granularity_bytes" -eq 1048576 ]; then
        granularity_expr="(1 << 20)"
    else
        granularity_expr="$granularity_bytes"
    fi
    
    log_info "Setting PXD_MAX_DISCARD_GRANULARITY to $granularity_expr ($granularity_bytes bytes)"
    
    # Use sed to replace the definition
    sed -i "s/#define PXD_MAX_DISCARD_GRANULARITY.*/#define PXD_MAX_DISCARD_GRANULARITY\t\t${granularity_expr} \/**< discard granularity for test *\//" "$PXD_HEADER"
    
    # Verify the change
    grep "PXD_MAX_DISCARD_GRANULARITY" "$PXD_HEADER" | head -1
}

# Build px-fuse
build_px_fuse() {
    log_info "Building px-fuse..."
    cd "$PX_FUSE_DIR"

    # Run configure if Makefile doesn't exist
    if [ ! -f "${PX_FUSE_DIR}/Makefile" ]; then
        log_info "Running configure..."
        ./configure 2>&1 | tail -5
    fi

    make clean 2>&1 | tail -5
    make 2>&1 | tail -20

    if [ -f "${PX_FUSE_DIR}/px.ko" ]; then
        log_success "px-fuse built successfully"
        return 0
    else
        log_error "px-fuse build failed"
        return 1
    fi
}

# Stop portworx
stop_portworx() {
    log_info "Stopping portworx..."
    systemctl stop portworx 2>&1 || true
    sleep 10
    # Make sure it's really stopped
    local retries=0
    while systemctl is-active portworx >/dev/null 2>&1 && [ $retries -lt 6 ]; do
        log_info "  Waiting for portworx to stop... (${retries})"
        sleep 5
        retries=$((retries + 1))
    done
    log_success "Portworx stopped"
}

# Remove and insert px module
reload_px_module() {
    log_info "Removing px module..."
    local retries=0
    while lsmod | grep -q "^px " && [ $retries -lt 10 ]; do
        rmmod px 2>&1 || true
        sleep 3
        retries=$((retries + 1))
        if lsmod | grep -q "^px "; then
            log_info "  Module still loaded, retry $retries..."
        fi
    done

    if lsmod | grep -q "^px "; then
        log_error "Failed to remove px module after $retries attempts"
        return 1
    fi

    log_info "Inserting new px module..."
    cd "$PX_FUSE_DIR"
    insmod px.ko 2>&1
    sleep 2
    log_success "px module reloaded"
}

# Start portworx
start_portworx() {
    log_info "Starting portworx..."
    systemctl start portworx 2>&1
    log_info "Waiting for portworx to be operational..."
}

# Wait for pxctl to be operational
wait_for_pxctl_ready() {
    local timeout=${1:-300}
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        local status=$($PXCTL_PATH status 2>&1 | grep -i "Status:" | head -1 || echo "")
        if echo "$status" | grep -qi "operational"; then
            log_success "Portworx is operational"
            return 0
        fi
        log_info "  Waiting... ($elapsed s) - $status"
        sleep 10
        elapsed=$((elapsed + 10))
    done
    
    log_error "Portworx did not become operational within ${timeout}s"
    return 1
}

# Full cycle: set granularity, rebuild, reload
apply_discard_granularity() {
    local granularity_bytes=$1

    log_info "=========================================="
    log_info "Applying discard granularity: $granularity_bytes bytes"
    log_info "=========================================="

    backup_pxd_header
    set_discard_granularity_in_source "$granularity_bytes"
    build_px_fuse
    stop_portworx
    reload_px_module
    start_portworx
    wait_for_pxctl_ready 300

    log_success "Discard granularity applied: $granularity_bytes bytes"
}

#######################################
# CSV functions
#######################################

init_csv() {
    echo "$CSV_HEADER" > "$RESULTS_CSV"
    log_info "Results will be saved to: $RESULTS_CSV"
}

write_csv_row() {
    echo "$1" >> "$RESULTS_CSV"
}

#######################################
# Metrics collection
#######################################

collect_metrics() {
    local vol_id=$1
    local mount_path=$2
    local pool_id=$3

    local fs_free=$(get_fs_free_space_kb "$mount_path" 2>/dev/null || echo "0")
    local dmthin_percent=$(get_dmthin_data_percent "$pool_id" 2>/dev/null || echo "0")
    local px_usage=$(get_px_usage "$vol_id" 2>/dev/null || echo "0")
    local du_usage=$(get_du_usage "$vol_id" 2>/dev/null || echo "0")
    local trimmable=$(get_trimmable_space "$vol_id" 2>/dev/null || echo "0")

    echo "${fs_free}|${dmthin_percent}|${px_usage}|${du_usage}|${trimmable}"
}

#######################################
# Test execution
#######################################

#######################################
# Fragmented file creation - creates complex block distribution
# Pattern: Create large files -> Overwrite with much smaller data -> Repeat
# This creates fragmentation by shrinking files in place
# All progress output goes to stderr, only result goes to stdout
#######################################

create_fragmented_files() {
    local test_dir=$1
    local file_type=$2
    local min_kb max_kb batch_size

    case $file_type in
        "small")
            min_kb=$SMALL_FILE_MIN_KB
            max_kb=$SMALL_FILE_MAX_KB
            batch_size=$SMALL_BATCH_SIZE
            ;;
        "medium")
            min_kb=$MEDIUM_FILE_MIN_KB
            max_kb=$MEDIUM_FILE_MAX_KB
            batch_size=$MEDIUM_BATCH_SIZE
            ;;
        "large")
            min_kb=$LARGE_FILE_MIN_KB
            max_kb=$LARGE_FILE_MAX_KB
            batch_size=$LARGE_BATCH_SIZE
            ;;
        *)
            min_kb=10
            max_kb=100
            batch_size=50
            ;;
    esac

    local target_bytes=$((TARGET_SIZE_MB * 1024 * 1024))
    local total_written=0
    local file_count=0
    local cycle=0

    # Calculate large file sizes (3x to 5x the max size for the file type)
    local large_min_kb=$((max_kb * 3))
    local large_max_kb=$((max_kb * 5))

    mkdir -p "$test_dir"
    # Progress to stderr
    echo "    Creating fragmented files: target=${TARGET_SIZE_MB}MB, ${file_type} (${min_kb}-${max_kb}KB), ${CREATE_DELETE_CYCLES} cycles" >&2
    echo "    Pattern: Create large files (${large_min_kb}-${large_max_kb}KB) -> Overwrite with smaller (${min_kb}-${max_kb}KB)" >&2

    while [ $total_written -lt $target_bytes ] && [ $cycle -lt $CREATE_DELETE_CYCLES ]; do
        cycle=$((cycle + 1))
        echo "      Cycle $cycle: Creating batch of $batch_size large files..." >&2

        # Create a batch of LARGE files
        local batch_start=$file_count
        for i in $(seq 1 $batch_size); do
            # Generate large file size (3x-5x the normal max)
            local large_range=$((large_max_kb - large_min_kb + 1))
            local large_size=$((large_min_kb + RANDOM % large_range))
            local size_bytes=$((large_size * 1024))
            total_written=$((total_written + size_bytes))
            file_count=$((file_count + 1))
            local fname="${test_dir}/file_${file_count}.bin"
            dd if=/dev/urandom of="$fname" bs=1024 count=$large_size 2>/dev/null

            # Check if we've reached target
            if [ $total_written -ge $target_bytes ]; then
                break
            fi
        done
        sync

        # Overwrite SHRINK_PERCENTAGE% of existing files with much smaller data
        if [ $cycle -lt $CREATE_DELETE_CYCLES ] && [ $file_count -gt 0 ]; then
            local num_to_shrink=$((file_count * SHRINK_PERCENTAGE / 100))
            if [ $num_to_shrink -gt 0 ]; then
                echo "      Cycle $cycle: Shrinking $num_to_shrink random files (${SHRINK_PERCENTAGE}%)..." >&2
                # Get list of existing files and shuffle, shrink first N
                local shrunk=0
                for f in $(ls "$test_dir"/*.bin 2>/dev/null | shuf | head -n $num_to_shrink); do
                    # Generate small file size within original range
                    local small_range=$((max_kb - min_kb + 1))
                    local small_size=$((min_kb + RANDOM % small_range))
                    # Overwrite with smaller data (truncates the file)
                    dd if=/dev/urandom of="$f" bs=1024 count=$small_size 2>/dev/null
                    shrunk=$((shrunk + 1))
                done
                sync
                echo "      Shrunk $shrunk files to ${min_kb}-${max_kb}KB" >&2
            fi
        fi

        echo "      Cycle $cycle: total_written=$((total_written / 1024 / 1024))MB, files=$file_count" >&2
    done

    # Return final count and size - ONLY this goes to stdout
    local final_count=$(ls -1 "$test_dir"/*.bin 2>/dev/null | wc -l)
    local final_size_kb=$(($(du -sk "$test_dir" 2>/dev/null | cut -f1) ))
    echo "${final_count}|${final_size_kb}"
}

run_single_case() {
    local run_num=$1
    local scenario_num=$2
    local mode=$3
    local file_case=$4
    local file_type=$5  # "small", "medium", or "large"
    local vol_id=$6
    local mount_path=${7:-$MOUNT_PATH}
    local vol_name=${8:-$VOL_NAME}

    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    echo "  Case $file_case: ${file_type} files (fragmented pattern)"

    # Initial metrics
    sync; sleep 1
    local init_metrics=$(collect_metrics "$vol_id" "$mount_path" "$POOL_ID")
    IFS='|' read -r init_fs init_dm init_px init_du init_trim <<< "$init_metrics"

    # Create fragmented files with random sizes for complex block distribution
    local test_dir="${mount_path}/test_${file_type}"
    local frag_result=$(create_fragmented_files "$test_dir" "$file_type")
    IFS='|' read -r file_count total_size_kb <<< "$frag_result"

    sync; sleep 2

    echo "    Final: ${file_count} files, total size: ${total_size_kb}KB"

    local create_metrics=$(collect_metrics "$vol_id" "$mount_path" "$POOL_ID")
    IFS='|' read -r create_fs create_dm create_px create_du create_trim <<< "$create_metrics"

    # Delete all remaining files and measure discard time
    local start_time=$(date +%s.%N)
    rm -rf "$test_dir"
    sync

    # Wait for discard based on mode
    case $mode in
        "$MODE_DISCARD_ONLY")
            # Inline discard should be immediate with sync
            sleep 10
            ;;
        "$MODE_MANUAL_TRIM")
            # Manual trim with pxctl volume trim start (autofstrim is off)
            echo "    Starting manual trim: $vol_name"
            $PXCTL_PATH volume trim start "$vol_name" 2>&1 || true
            # Wait for trim to complete (no timeout - waits until done)
            wait_for_trim_complete "$vol_id" "$vol_name" || true
            ;;
        "$MODE_AUTOFSTRIM_NODISCARD"|"$MODE_AUTOFSTRIM_DISCARD")
            # Autofstrim modes - wait for autofstrim daemon to run
            echo "    Waiting for autofstrim daemon on: $vol_name"
            $PXCTL_PATH volume autofstrim push "$vol_id" 2>&1 || true
            wait_for_fstrim_complete "$vol_id" || true
            ;;
    esac

    local end_time=$(date +%s.%N)
    local discard_time=$(echo "$end_time - $start_time" | bc)

    local delete_metrics=$(collect_metrics "$vol_id" "$mount_path" "$POOL_ID")
    IFS='|' read -r del_fs del_dm del_px del_du del_trim <<< "$delete_metrics"

    # Calculate reclaimed space
    local space_reclaimed=$((del_fs - create_fs))
    local dmthin_reclaimed=$(echo "$create_dm - $del_dm" | bc 2>/dev/null || echo "0")

    # Get actual discard granularity
    local pxd_device=$(get_pxd_device "$vol_id")
    local actual_discard_gran=$(get_sysfs_discard_granularity "$pxd_device")

    # Write CSV row
    local csv_row="${timestamp},${run_num},${scenario_num},${FS_BLOCK_KB},${FS_DISCARD_KB},${DMTHIN_CHUNK_KB},${DMTHIN_DISCARD_KB},${NVME_SECTOR_KB},${mode},${file_case},${file_type},${file_count},${total_size_kb},${init_fs},${init_dm},${init_px},${init_du},${init_trim},${create_fs},${create_dm},${create_px},${create_du},${create_trim},${del_fs},${del_dm},${del_px},${del_du},${del_trim},${discard_time},${space_reclaimed},${dmthin_reclaimed},${actual_discard_gran},${vol_id}"

    write_csv_row "$csv_row"
    echo "    Reclaimed: ${space_reclaimed}KB in ${discard_time}s"
}

run_all_cases() {
    local run_num=$1
    local scenario_num=$2
    local mode=$3
    local vol_id=$4
    local mount_path=${5:-$MOUNT_PATH}
    local vol_name=${6:-$VOL_NAME}

    # File type cases: small (3-7KB), medium (20-100KB), large (259-2090KB)
    local cases=("1:small" "2:medium" "3:large")

    for case_item in "${cases[@]}"; do
        IFS=':' read -r case_num file_type <<< "$case_item"
        run_single_case "$run_num" "$scenario_num" "$mode" "$case_num" "$file_type" "$vol_id" "$mount_path" "$vol_name"
    done
}

configure_discard_mode() {
    local vol_id=$1
    local mode=$2

    log_info "Configuring discard mode: $mode"

    case $mode in
        "$MODE_DISCARD_ONLY")
            # Inline discard on file delete (mount -o discard)
            disable_volume_nodiscard "$vol_id"
            disable_volume_autofstrim "$vol_id"
            disable_cluster_autofstrim
            ;;
        "$MODE_MANUAL_TRIM")
            # Manual trim with pxctl volume trim start (autofstrim off)
            disable_volume_nodiscard "$vol_id"
            disable_volume_autofstrim "$vol_id"
            disable_cluster_autofstrim
            ;;
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
    esac
    sleep 3
}

#######################################
# Run single mode test (for parallel execution)
#######################################
run_mode_test() {
    local scenario_num=$1
    local mode=$2
    local run_num=$3
    local vol_name=$4
    local mount_path=$5
    local log_file="${SCRIPT_DIR}/scenario${scenario_num}_${mode}_run${run_num}_${TIMESTAMP}.log"

    exec > >(tee -a "$log_file") 2>&1

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting: S${scenario_num} ${mode} Run${run_num}"

    # Create volume
    local vol_id=$(setup_volume "$vol_name" "$mount_path" "$VOL_SIZE" "$POOL_ID")
    if [ -z "$vol_id" ]; then
        echo "[ERROR] Failed to create volume $vol_name"
        return 1
    fi
    echo "Volume ID: $vol_id"

    # Configure mode
    configure_discard_mode "$vol_id" "$mode"

    # Run test cases (pass mount_path and vol_name)
    run_all_cases "$run_num" "$scenario_num" "$mode" "$vol_id" "$mount_path" "$vol_name"

    # Cleanup
    cleanup_volume "$vol_id" "$mount_path" "$vol_name"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Completed: S${scenario_num} ${mode} Run${run_num}"
}

#######################################
# Manual trim parallel test - creates volumes with different file types
# and runs trim on all of them in parallel
#######################################

# Create volume and fragmented files, return vol_id
# Progress goes to stderr, only vol_id to stdout
setup_manual_trim_volume() {
    local vol_name=$1
    local mount_path=$2
    local file_type=$3
    local scenario_num=$4

    local vol_id=$(setup_volume "$vol_name" "$mount_path" "$VOL_SIZE" "$POOL_ID")
    if [ -z "$vol_id" ]; then
        echo "ERROR"
        return 1
    fi

    configure_discard_mode "$vol_id" "$MODE_MANUAL_TRIM" >&2

    # Create fragmented files - progress goes to stderr
    local test_dir="${mount_path}/test_${file_type}"
    local frag_result=$(create_fragmented_files "$test_dir" "$file_type")
    echo "      Files created: $frag_result" >&2
    sync; sleep 2

    # Only vol_id goes to stdout
    echo "$vol_id"
}

# Run trim and wait for completion, write results
run_single_trim_and_measure() {
    local vol_id=$1
    local vol_name=$2
    local mount_path=$3
    local file_type=$4
    local run_num=$5
    local scenario_num=$6
    local file_case=$7

    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local test_dir="${mount_path}/test_${file_type}"

    # Collect metrics before trim
    local init_metrics=$(collect_metrics "$vol_id" "$mount_path" "$POOL_ID")
    IFS='|' read -r init_fs init_dm init_px init_du init_trim <<< "$init_metrics"

    # Get file count and size
    local file_count=$(ls -1 "$test_dir"/*.bin 2>/dev/null | wc -l)
    local total_size_kb=$(($(du -sk "$test_dir" 2>/dev/null | cut -f1) ))

    local create_metrics=$(collect_metrics "$vol_id" "$mount_path" "$POOL_ID")
    IFS='|' read -r create_fs create_dm create_px create_du create_trim <<< "$create_metrics"

    # Delete files and measure time
    local start_time=$(date +%s.%N)
    rm -rf "$test_dir"
    sync

    # Start trim and wait
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting trim: $vol_name"
    $PXCTL_PATH volume trim start "$vol_name" 2>&1 || true
    wait_for_trim_complete "$vol_id" "$vol_name" || true

    local end_time=$(date +%s.%N)
    local discard_time=$(echo "$end_time - $start_time" | bc)

    local delete_metrics=$(collect_metrics "$vol_id" "$mount_path" "$POOL_ID")
    IFS='|' read -r del_fs del_dm del_px del_du del_trim <<< "$delete_metrics"

    # Calculate reclaimed space
    local space_reclaimed=$((del_fs - create_fs))
    local dmthin_reclaimed=$(echo "$create_dm - $del_dm" | bc 2>/dev/null || echo "0")

    # Get actual discard granularity
    local pxd_device=$(get_pxd_device "$vol_id")
    local actual_discard_gran=$(get_sysfs_discard_granularity "$pxd_device")

    # Write CSV row
    local csv_row="${timestamp},${run_num},${scenario_num},${FS_BLOCK_KB},${FS_DISCARD_KB},${DMTHIN_CHUNK_KB},${DMTHIN_DISCARD_KB},${NVME_SECTOR_KB},${MODE_MANUAL_TRIM},${file_case},${file_type},${file_count},${total_size_kb},${init_fs},${init_dm},${init_px},${init_du},${init_trim},${create_fs},${create_dm},${create_px},${create_du},${create_trim},${del_fs},${del_dm},${del_px},${del_du},${del_trim},${discard_time},${space_reclaimed},${dmthin_reclaimed},${actual_discard_gran},${vol_id}"

    write_csv_row "$csv_row"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Completed: $vol_name (${file_type}) Reclaimed: ${space_reclaimed}KB in ${discard_time}s"
}

# Run parallel manual_trim for a scenario
# Creates volumes for all file_types x runs, then runs trim in parallel
run_parallel_manual_trim() {
    local scenario_num=$1

    log_info ""
    log_info "Scenario $scenario_num - Mode: manual_trim (PARALLEL across file types and runs)"

    local file_types=("small" "medium" "large")

    # Use temp file to store volume info (avoids issues with colon-separated parsing)
    local vol_info_file=$(mktemp)
    local vol_count=0

    # Phase 1: Create all volumes and fragmented files (sequentially for safety)
    log_info "  Phase 1: Creating volumes and fragmented files..."
    local file_case=0
    for file_type in "${file_types[@]}"; do
        file_case=$((file_case + 1))
        for run in $(seq 1 $RUNS_PER_COMBINATION); do
            local vol_name="${VOL_NAME}_s${scenario_num}_mt_${file_type}_r${run}"
            local mount_path="/var/lib/osd/mounts/${vol_name}"
            log_info "    Creating: ${vol_name} (${file_type})"

            local vol_id=$(setup_manual_trim_volume "$vol_name" "$mount_path" "$file_type" "$scenario_num")
            if [ "$vol_id" == "ERROR" ] || [ -z "$vol_id" ]; then
                log_error "    Failed to create volume $vol_name"
                continue
            fi

            # Store in temp file: tab-separated for reliable parsing
            echo -e "${vol_id}\t${vol_name}\t${mount_path}\t${file_type}\t${run}\t${file_case}" >> "$vol_info_file"
            vol_count=$((vol_count + 1))
            log_info "    Created: ${vol_name} -> ${vol_id}"
        done
    done

    log_info "  Created ${vol_count} volumes with fragmented files"

    # Phase 2: Run trim on all volumes in parallel
    log_info "  Phase 2: Starting trim on all volumes in parallel..."
    local pids=()
    while IFS=$'\t' read -r vol_id vol_name mount_path file_type run_num file_case; do
        local log_file="${SCRIPT_DIR}/scenario${scenario_num}_mt_${file_type}_run${run_num}_${TIMESTAMP}.log"
        (
            exec > >(tee -a "$log_file") 2>&1
            run_single_trim_and_measure "$vol_id" "$vol_name" "$mount_path" "$file_type" "$run_num" "$scenario_num" "$file_case"
        ) &
        pids+=($!)
        log_info "    Launched trim: ${vol_name} (pid $!)"
    done < "$vol_info_file"

    log_info "  Waiting for ${#pids[@]} parallel trims to complete..."
    for pid in "${pids[@]}"; do
        wait $pid || log_warn "    Trim pid $pid failed"
    done

    # Phase 3: Cleanup all volumes
    log_info "  Phase 3: Cleaning up volumes..."
    while IFS=$'\t' read -r vol_id vol_name mount_path file_type run_num file_case; do
        cleanup_volume "$vol_id" "$mount_path" "$vol_name"
    done < "$vol_info_file"

    # Cleanup temp file
    rm -f "$vol_info_file"

    log_success "  Mode manual_trim completed for scenario $scenario_num"
}

#######################################
# Main test loop (MAXIMIZED PARALLELIZATION)
# Structure: For each scenario (granularity):
#   1. Run ALL discard_only runs in parallel (5 runs x 3 file types = 15 volumes)
#   2. Run ALL manual_trim runs in parallel (5 runs x 3 file types = 15 volumes)
#      - Create all volumes with fragmented files first
#      - Start trim on all simultaneously
#      - Wait for all to complete
#######################################
run_full_tests() {
    log_info "=========================================="
    log_info "Full Discard Test Suite (Fragmented Files)"
    log_info "=========================================="
    log_info "Runs per combination: $RUNS_PER_COMBINATION"
    log_info "Target size per volume: ${TARGET_SIZE_MB}MB"
    log_info "Fragmentation: ${CREATE_DELETE_CYCLES} cycles, ${SHRINK_PERCENTAGE}% files shrunk per cycle"
    log_info "PX-Fuse dir: $PX_FUSE_DIR"
    log_info "=========================================="

    init_csv
    backup_pxd_header

    local scenarios=(1 2 3 4 5)
    local last_granularity=0

    for scenario_num in "${scenarios[@]}"; do
        local scenario=$(get_scenario "$scenario_num")
        parse_scenario "$scenario"
        local discard_gran_bytes=$((FS_DISCARD_KB * 1024))

        log_info ""
        log_info "=========================================="
        log_info "Scenario $scenario_num"
        log_info "  FS Discard Granularity: ${FS_DISCARD_KB}KB ($discard_gran_bytes bytes)"
        log_info "=========================================="

        # Rebuild px-fuse if granularity changed (global param - must be done before any tests)
        if [ "$discard_gran_bytes" -ne "$last_granularity" ]; then
            apply_discard_granularity "$discard_gran_bytes"
            last_granularity=$discard_gran_bytes
        fi

        # MODE 1: discard_only - Run ALL runs in PARALLEL (5 runs x 3 types = 15 volumes)
        log_info ""
        log_info "Scenario $scenario_num - Mode: discard_only (${RUNS_PER_COMBINATION} runs in PARALLEL)"
        local pids=()
        for run in $(seq 1 $RUNS_PER_COMBINATION); do
            local vol_name="${VOL_NAME}_s${scenario_num}_discard_only_r${run}"
            local mount_path="/var/lib/osd/mounts/${vol_name}"
            log_info "  Launching: Run $run -> $vol_name"
            run_mode_test "$scenario_num" "$MODE_DISCARD_ONLY" "$run" "$vol_name" "$mount_path" &
            pids+=($!)
        done
        log_info "  Waiting for ${#pids[@]} parallel discard_only runs..."
        for pid in "${pids[@]}"; do
            wait $pid || log_warn "  Test pid $pid failed"
        done
        log_success "  Mode discard_only completed for scenario $scenario_num"

        # MODE 2: manual_trim - Run in PARALLEL (creates volumes, then runs all trims together)
        run_parallel_manual_trim "$scenario_num"
    done

    restore_pxd_header
    log_success "All tests completed! Results: $RESULTS_CSV"
}

#######################################
# Usage
#######################################

usage() {
    cat << EOF
Usage: $0 [options]

Full discard test runner that rebuilds px-fuse for each discard granularity setting.

Options:
    --runs N            Number of runs per combination (default: 5)
    --vol-size SIZE     Volume size in GB (default: 10)
    --help              Show this help

Examples:
    $0
    $0 --runs 3
EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --runs) RUNS_PER_COMBINATION="$2"; shift 2 ;;
        --vol-size) VOL_SIZE="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# Run tests
run_full_tests
