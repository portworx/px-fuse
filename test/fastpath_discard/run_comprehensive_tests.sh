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
# Helper Functions
#######################################

# Wait for PX to be ready after restart
wait_for_px_ready() {
    local max_wait=${1:-300}  # Default 5 minutes
    local elapsed=0

    log_info "Waiting for PX to be ready (max ${max_wait}s)..."

    while [ $elapsed -lt $max_wait ]; do
        if pxctl status 2>/dev/null | grep -q "Status: PX is operational"; then
            log_success "PX is ready after ${elapsed}s"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done

    log_error "PX did not become ready within ${max_wait}s"
    return 1
}

# Fill volume with fio using low compressibility data
# Parameters:
#   $1 - target directory
#   $2 - file size in KB
#   $3 - number of files to create
# Returns: actual number of files created
fill_volume_with_fio() {
    local target_dir=$1
    local file_size_kb=$2
    local file_count=$3
    local num_jobs=${4:-10}      # Default 10 parallel threads
    local iodepth=${5:-16}        # Default queue depth 16

    mkdir -p "$target_dir"

    # Generate unique random seed based on current time
    local randseed=$(date +%s%N)

    log_info "Using fio to create $file_count files of ${file_size_kb}KB (jobs=$num_jobs, iodepth=$iodepth)"

    # FIO parameters for low compressibility and high performance:
    # --randrepeat=0: Don't repeat random I/O pattern (more randomness)
    # --norandommap: Don't use random map (allows true random access)
    # --randseed: Unique seed for random number generator
    # --refill_buffers: Refill I/O buffers on every submit (prevents pattern reuse)
    # --scramble_buffers=1: Scramble buffer contents (ensures low compressibility)
    # NOTE: We do NOT set buffer_compress_percentage as it defaults to unset,
    #       which generates random incompressible data. Setting it to 0 would
    #       create 100% compressible data (all zeros/patterns), which is wrong!
    # --direct=1: Use O_DIRECT (bypass page cache)
    # --ioengine=libaio: Linux native asynchronous I/O
    # --iodepth: Number of I/O units to keep in flight per job
    # --numjobs: Number of parallel threads
    fio --name=fill_volume \
        --directory="$target_dir" \
        --ioengine=libaio \
        --direct=1 \
        --bs=${file_size_kb}k \
        --size=${file_size_kb}k \
        --nrfiles=$file_count \
        --numjobs=$num_jobs \
        --iodepth=$iodepth \
        --rw=write \
        --randrepeat=0 \
        --norandommap \
        --randseed=$randseed \
        --refill_buffers \
        --scramble_buffers=1 \
        --group_reporting \
        --create_on_open=1 \
        --fallocate=none \
        --end_fsync=1 \
        --output-format=normal \
        2>&1 | grep -E "(write:|WRITE:|err|error)" || true

    sync

    # Return actual file count
    find "$target_dir" -type f | wc -l
}

# Create a test volume with specific block device discard granularity and DMThin granularities
create_test_volume() {
    local vol_name=$1
    local size=${2:-5}  # Size in GB
    local blkdev_discard_gran_kb=${3:-4}  # Block device discard granularity in KB
    local dm_gran_kb=${4:-64}  # DMThin discard granularity in KB

    # Determine the correct pool based on dmthin granularity
    # Pool chunk size = dmthin discard granularity
    local pool_id=$(get_pool_id_for_dmthin_gran "$dm_gran_kb")

    log_info "Creating volume: $vol_name (size=${size}G, blkdev_discard_gran=${blkdev_discard_gran_kb}KB, dm_gran=${dm_gran_kb}KB, pool=$pool_id)"

    # Create volume using px_helpers.sh function (creates with default ext4 filesystem)
    local vol_id=$(create_volume "$vol_name" "$size" "$pool_id")

    if [ -z "$vol_id" ]; then
        log_error "Failed to create volume $vol_name"
        return 1
    fi

    # Attach the volume
    log_info "Attaching volume $vol_name (vol_id=$vol_id)"
    pxctl host attach "$vol_id" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        log_error "Failed to attach volume $vol_name"
        return 1
    fi

    # Wait for device to appear after attach
    local dev_path="/dev/pxd/pxd${vol_id}"
    local wait_count=0
    while [ ! -b "$dev_path" ] && [ $wait_count -lt 60 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done

    if [ ! -b "$dev_path" ]; then
        log_error "Device $dev_path did not appear after attach"
        return 1
    fi

    # NOTE: We do NOT format the volume here - it's already formatted with default ext4 by pxctl
    # The filesystem block size remains at the default (4KB)
    # We only vary the block device discard granularity, not the FS block size

    # Mount the volume
    local mount_path="/var/lib/osd/mounts/$vol_name"
    mkdir -p "$mount_path"
    log_info "Mounting volume $vol_name to $mount_path"
    pxctl host mount "$vol_name" --path "$mount_path" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        log_error "Failed to mount volume $vol_name"
        return 1
    fi

    # Verify volume configuration
    log_info "Verifying volume $vol_name configuration..."
    echo "========== Volume Inspect: $vol_name ==========" >> "$LOG_FILE"
    pxctl volume inspect "$vol_name" 2>&1 | tee -a "$LOG_FILE"
    echo "===============================================" >> "$LOG_FILE"

    local inspect_output=$(pxctl volume inspect "$vol_name" 2>/dev/null)

    # Check for fastpath
    if ! echo "$inspect_output" | grep -q "fastpath"; then
        log_warn "Volume $vol_name may not have fastpath enabled"
    fi

    # Display relevant volume info
    echo "$inspect_output" | grep -E "(Fastpath|Auto fstrim|Mount|Attached)" || true

    log_success "Volume $vol_name created, attached, and mounted successfully (vol_id=$vol_id)"
    return 0
}

#######################################
# CSV Output Functions
#######################################

# CSV output file
CSV_OUTPUT_FILE="comprehensive_test_results_$(date +%Y%m%d_%H%M%S).csv"

# Initialize CSV with header
initialize_csv_output() {
    log_info "Initializing CSV output: $CSV_OUTPUT_FILE"
    echo "Timestamp,Run,Scenario,BlockDev_Discard_Gran_KB,DMthin_Chunk_KB,DMthin_Discard_Gran_KB,NVMe_Sector_KB,Mode,File_Case,File_Type,Initial_FS_Usage_MB,Initial_DMthin_Usage_MB,Initial_PX_Usage_MB,Initial_Trimmable_MB,File_Count,After_Write_FS_Usage_MB,After_Write_DMthin_Usage_MB,After_Write_PX_Usage_MB,After_Write_Trimmable_MB,After_Delete_FS_Usage_MB,After_Delete_DMthin_Usage_MB,After_Delete_PX_Usage_MB,After_Delete_Trimmable_MB,After_Trim_FS_Usage_MB,After_Trim_DMthin_Usage_MB,After_Trim_PX_Usage_MB,After_Trim_Trimmable_MB,Volume_ID" > "$CSV_OUTPUT_FILE"
}

# Write a row to CSV
write_csv_row() {
    local row=$1
    echo "$row" >> "$CSV_OUTPUT_FILE"
}

# Generate test summary
generate_test_summary() {
    log_info "=========================================="
    log_info "TEST SUMMARY"
    log_info "=========================================="
    log_info "CSV Results: $CSV_OUTPUT_FILE"

    if [ -f "$CSV_OUTPUT_FILE" ]; then
        local total_rows=$(wc -l < "$CSV_OUTPUT_FILE")
        local test_rows=$((total_rows - 1))  # Subtract header
        log_info "Total test results: $test_rows"
    fi
}

#######################################
# Configuration for 3-phase comprehensive testing
#######################################

# Granularity combinations
BLKDEV_DISCARD_GRANULARITIES=(4 64 1024 2048)  # KB - 4 options (block device discard granularity)
DMTHIN_DISCARD_GRANULARITIES=(64 1024 2048)    # KB - 3 options
FILE_SIZES=(3 20 66 1201)                      # KB - 4 options
ITERATIONS_PER_VOLUME=5                         # 5 runs per volume

# Test patterns split into 3 phases
# NOTE: Only running create-shrink patterns, create-delete patterns are commented out
PHASE1_PATTERNS=("discard_create_shrink")  # 1 pattern - discard only (create-delete commented out)
# PHASE1_PATTERNS=("discard_create_delete" "discard_create_shrink")  # 2 patterns - discard only
PHASE2_PATTERNS=("fstrim_create_shrink")    # 1 pattern - manual trim (create-delete commented out)
# PHASE2_PATTERNS=("fstrim_create_delete" "fstrim_create_shrink")    # 2 patterns - manual trim
PHASE3_PATTERNS=("autofstrim_create_shrink")  # 1 pattern - auto trim (create-delete commented out)
# PHASE3_PATTERNS=("autofstrim_create_delete" "autofstrim_create_shrink")  # 2 patterns - auto trim

# Volume configuration
VOL_SIZE=5  # 5GB volumes
FILESYSTEM_FILL_PERCENT=100

# Each phase: 4 BlkDev Discard Gran × 3 DMThin × 1 pattern × 4 file sizes = 48 tests per phase
# Total: 144 unique test combinations across 3 phases (only create-shrink pattern)
# NOTE: Was 96 per phase (288 total) when running both create-delete and create-shrink
MAX_PARALLEL_VOLUMES=48  # 48 volumes per phase (only create-shrink pattern)

#######################################
# Phase-specific configurations
#######################################

configure_phase1_cluster() {
    log_info "Configuring cluster for Phase 1: Discard Only"
    # Cluster autofstrim: OFF
    # Mount option: "discard"
    pxctl cluster options update --auto-fstrim off
    sleep 10
}

configure_phase2_cluster() {
    log_info "Configuring cluster for Phase 2: Manual Trim"
    # Cluster autofstrim: OFF
    # Mount option: "nodiscard"
    pxctl cluster options update --auto-fstrim off
    sleep 10
}

configure_phase3_cluster() {
    log_info "Configuring cluster for Phase 3: Auto Trim"
    # Cluster autofstrim: ON
    # Mount option: "nodiscard"
    pxctl cluster options update --auto-fstrim on

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
    local batch_size=24
    local total_volumes=96
    local batch_num=1

    # Build array of all volume configurations
    local -a all_vol_configs=()
    for blkdev_gran in "${BLKDEV_DISCARD_GRANULARITIES[@]}"; do
        for dm_gran in "${DMTHIN_DISCARD_GRANULARITIES[@]}"; do
            for pattern in "${PHASE1_PATTERNS[@]}"; do
                for file_size in "${FILE_SIZES[@]}"; do
                    all_vol_configs+=("$vol_counter:$blkdev_gran:$dm_gran:$pattern:$file_size")
                    vol_counter=$((vol_counter + 1))
                done
            done
        done
    done

    # Process volumes in batches of 24
    local total_configs=${#all_vol_configs[@]}
    for ((batch_start=0; batch_start<total_configs; batch_start+=batch_size)); do
        local batch_end=$((batch_start + batch_size - 1))
        if [ $batch_end -ge $total_configs ]; then
            batch_end=$((total_configs - 1))
        fi

        log_info "Phase 1: Processing batch $batch_num (configs $((batch_start+1)) to $((batch_end+1)))"

        # Arrays to track volumes in this batch
        local -a batch_vol_names=()
        local -a batch_vol_configs=()

        # Create volumes in this batch
        for ((i=batch_start; i<=batch_end; i++)); do
            IFS=':' read -r vol_num blkdev_gran dm_gran pattern file_size <<< "${all_vol_configs[$i]}"
            local vol_name="phase1_vol_${vol_num}_${blkdev_gran}bd_${dm_gran}dm_${pattern}_${file_size}kb"
            batch_vol_names+=("$vol_name")
            batch_vol_configs+=("$vol_num:$blkdev_gran:$dm_gran:$pattern:$file_size")

            # Create volume with specific configuration
            create_test_volume "$vol_name" "$VOL_SIZE" "$blkdev_gran" "$dm_gran" &
        done

        wait  # Wait for batch volume creation to complete
        log_info "Phase 1: Batch $batch_num volumes created (${#batch_vol_names[@]} volumes)"

        # Run tests on this batch
        for ((i=0; i<${#batch_vol_names[@]}; i++)); do
            IFS=':' read -r vol_num blkdev_gran dm_gran pattern file_size <<< "${batch_vol_configs[$i]}"
            run_single_volume_test "$phase_num" "$vol_num" "$pattern" "$file_size" "${batch_vol_names[$i]}" &
        done

        wait  # Wait for batch tests to complete
        log_info "Phase 1: Batch $batch_num tests completed"

        # Delete volumes in this batch
        for vol_name in "${batch_vol_names[@]}"; do
            local vol_id=$(pxctl volume list --name "$vol_name" -j 2>/dev/null | grep -o '"id":"[^"]*"' | head -1 | awk -F'"' '{print $4}')
            if [ -n "$vol_id" ]; then
                pxctl volume delete "$vol_id" --force 2>/dev/null || true
            fi
        done

        log_info "Phase 1: Batch $batch_num volumes deleted"
        batch_num=$((batch_num + 1))
    done

    log_info "Phase 1: All tests completed, all volumes deleted"
}

run_phase2_tests() {
    log_info "=========================================="
    log_info "PHASE 2: MANUAL TRIM TESTS (96 volumes)"
    log_info "=========================================="

    configure_phase2_cluster

    local phase_num=2
    local vol_counter=1
    local batch_size=24
    local total_volumes=96
    local batch_num=1

    # Build array of all volume configurations
    local -a all_vol_configs=()
    for blkdev_gran in "${BLKDEV_DISCARD_GRANULARITIES[@]}"; do
        for dm_gran in "${DMTHIN_DISCARD_GRANULARITIES[@]}"; do
            for pattern in "${PHASE2_PATTERNS[@]}"; do
                for file_size in "${FILE_SIZES[@]}"; do
                    all_vol_configs+=("$vol_counter:$blkdev_gran:$dm_gran:$pattern:$file_size")
                    vol_counter=$((vol_counter + 1))
                done
            done
        done
    done

    # Process volumes in batches of 24
    local total_configs=${#all_vol_configs[@]}
    for ((batch_start=0; batch_start<total_configs; batch_start+=batch_size)); do
        local batch_end=$((batch_start + batch_size - 1))
        if [ $batch_end -ge $total_configs ]; then
            batch_end=$((total_configs - 1))
        fi

        log_info "Phase 2: Processing batch $batch_num (configs $((batch_start+1)) to $((batch_end+1)))"

        # Arrays to track volumes in this batch
        local -a batch_vol_names=()
        local -a batch_vol_configs=()

        # Create volumes in this batch
        for ((i=batch_start; i<=batch_end; i++)); do
            IFS=':' read -r vol_num blkdev_gran dm_gran pattern file_size <<< "${all_vol_configs[$i]}"
            local vol_name="phase2_vol_${vol_num}_${blkdev_gran}bd_${dm_gran}dm_${pattern}_${file_size}kb"
            batch_vol_names+=("$vol_name")
            batch_vol_configs+=("$vol_num:$blkdev_gran:$dm_gran:$pattern:$file_size")

            # Create volume with specific configuration
            create_test_volume "$vol_name" "$VOL_SIZE" "$blkdev_gran" "$dm_gran" &
        done

        wait  # Wait for batch volume creation to complete
        log_info "Phase 2: Batch $batch_num volumes created (${#batch_vol_names[@]} volumes)"

        # Run tests on this batch
        for ((i=0; i<${#batch_vol_names[@]}; i++)); do
            IFS=':' read -r vol_num blkdev_gran dm_gran pattern file_size <<< "${batch_vol_configs[$i]}"
            run_single_volume_test "$phase_num" "$vol_num" "$pattern" "$file_size" "${batch_vol_names[$i]}" &
        done

        wait  # Wait for batch tests to complete
        log_info "Phase 2: Batch $batch_num tests completed"

        # Delete volumes in this batch
        for vol_name in "${batch_vol_names[@]}"; do
            local vol_id=$(pxctl volume list --name "$vol_name" -j 2>/dev/null | grep -o '"id":"[^"]*"' | head -1 | awk -F'"' '{print $4}')
            if [ -n "$vol_id" ]; then
                pxctl volume delete "$vol_id" --force 2>/dev/null || true
            fi
        done

        log_info "Phase 2: Batch $batch_num volumes deleted"
        batch_num=$((batch_num + 1))
    done

    log_info "Phase 2: All tests completed, all volumes deleted"
}

run_phase3_tests() {
    log_info "=========================================="
    log_info "PHASE 3: AUTO TRIM TESTS (96 volumes)"
    log_info "=========================================="

    configure_phase3_cluster

    local phase_num=3
    local vol_counter=1
    local batch_size=24
    local total_volumes=96
    local batch_num=1

    # Build array of all volume configurations
    local -a all_vol_configs=()
    for blkdev_gran in "${BLKDEV_DISCARD_GRANULARITIES[@]}"; do
        for dm_gran in "${DMTHIN_DISCARD_GRANULARITIES[@]}"; do
            for pattern in "${PHASE3_PATTERNS[@]}"; do
                for file_size in "${FILE_SIZES[@]}"; do
                    all_vol_configs+=("$vol_counter:$blkdev_gran:$dm_gran:$pattern:$file_size")
                    vol_counter=$((vol_counter + 1))
                done
            done
        done
    done

    # Process volumes in batches of 24
    local total_configs=${#all_vol_configs[@]}
    for ((batch_start=0; batch_start<total_configs; batch_start+=batch_size)); do
        local batch_end=$((batch_start + batch_size - 1))
        if [ $batch_end -ge $total_configs ]; then
            batch_end=$((total_configs - 1))
        fi

        log_info "Phase 3: Processing batch $batch_num (configs $((batch_start+1)) to $((batch_end+1)))"

        # Arrays to track volumes in this batch
        local -a batch_vol_names=()
        local -a batch_vol_configs=()

        # Create volumes in this batch
        for ((i=batch_start; i<=batch_end; i++)); do
            IFS=':' read -r vol_num blkdev_gran dm_gran pattern file_size <<< "${all_vol_configs[$i]}"
            local vol_name="phase3_vol_${vol_num}_${blkdev_gran}bd_${dm_gran}dm_${pattern}_${file_size}kb"
            batch_vol_names+=("$vol_name")
            batch_vol_configs+=("$vol_num:$blkdev_gran:$dm_gran:$pattern:$file_size")

            # Create volume with specific configuration
            create_test_volume "$vol_name" "$VOL_SIZE" "$blkdev_gran" "$dm_gran" &
        done

        wait  # Wait for batch volume creation to complete
        log_info "Phase 3: Batch $batch_num volumes created (${#batch_vol_names[@]} volumes)"

        # Run tests on this batch
        for ((i=0; i<${#batch_vol_names[@]}; i++)); do
            IFS=':' read -r vol_num blkdev_gran dm_gran pattern file_size <<< "${batch_vol_configs[$i]}"
            run_single_volume_test "$phase_num" "$vol_num" "$pattern" "$file_size" "${batch_vol_names[$i]}" &
        done

        wait  # Wait for batch tests to complete
        log_info "Phase 3: Batch $batch_num tests completed"

        # Delete volumes in this batch
        for vol_name in "${batch_vol_names[@]}"; do
            local vol_id=$(pxctl volume list --name "$vol_name" -j 2>/dev/null | grep -o '"id":"[^"]*"' | head -1 | awk -F'"' '{print $4}')
            if [ -n "$vol_id" ]; then
                pxctl volume delete "$vol_id" --force 2>/dev/null || true
            fi
        done

        log_info "Phase 3: Batch $batch_num volumes deleted"
        batch_num=$((batch_num + 1))
    done

    log_info "Phase 3: All tests completed, all volumes deleted"
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
    local vol_id=$(pxctl volume inspect "$vol_name" -j 2>/dev/null | grep '"id":' | head -1 | awk -F'"' '{print $4}')
    
    if [ -z "$vol_id" ]; then
        log_error "Failed to get volume ID for $vol_name"
        return 1
    fi
    
    log_info "Volume $vol_name has ID: $vol_id"

    log_info "Starting 5 iterations on volume: $vol_name"
    
    # Mount volume
    local mount_path="/var/lib/osd/mounts/${vol_name}"
    mkdir -p "$mount_path"
    
    # Set mount options based on phase
    local mount_opts=""
    case $phase_num in
        1) mount_opts="discard" ;;      # Phase 1: discard only
        2) mount_opts="discard" ;;    # Phase 2: manual trim
        3) mount_opts="nodiscard" ;;    # Phase 3: auto trim
    esac
    
    # mount -o "$mount_opts" "/dev/pxd/${vol_name}" "$mount_path"
    if [ "$phase_num" -eq 3 ]; then
        pxctl volume update --auto_fstrim on "$vol_name" 2>/dev/null || echo "Failed to enable autofstrim on $vol_name"
        pxctl volume update --nodiscard on "$vol_id" 2>/dev/null || echo "Failed to enable nodiscard on $vol_name"
    else 
        pxctl volume update --auto_fstrim off "$vol_name" 2>/dev/null || true
    fi
    pxctl host unmount --path /var/lib/osd/mounts/$vol_name "$vol_name" 2>/dev/null || echo "Failed to unmount $vol_name"
    pxctl host detach "$vol_name" 2>/dev/null || echo "Failed to detach $vol_name"
    pxctl host attach "$vol_name" 2>/dev/null || echo "Failed to attach $vol_name"
    mkdir -p "$mount_path"
    pxctl host mount "$vol_name" --path "$mount_path" 2>/dev/null || echo "Failed to mount $vol_name"
    
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
# Pool initialization and verification
#######################################

# Initialize storage pools with specific chunk sizes
initialize_pools() {
    log_info "=========================================="
    log_info "INITIALIZING STORAGE POOLS"
    log_info "=========================================="

    # Define pool configurations
    # Pool 0: 64KB chunk size (for 64KB dmthin granularity)
    # Pool 1: 1MB (1024KB) chunk size (for 1MB dmthin granularity)
    # Pool 2: 2MB (2048KB) chunk size (for 2MB dmthin granularity)

    declare -A POOL_CHUNK_SIZES
    POOL_CHUNK_SIZES[0]=64
    POOL_CHUNK_SIZES[1]=1024
    POOL_CHUNK_SIZES[2]=2048

    log_info "Required pools:"
    log_info "  Pool 0: 64KB chunk size"
    log_info "  Pool 1: 1024KB (1MB) chunk size"
    log_info "  Pool 2: 2048KB (2MB) chunk size"
    log_info ""

    # Check existing pools
    log_info "Checking existing storage pools..."
    $PXCTL_PATH service pool show 2>&1 | head -20 || true
    log_info ""

    # Verify pool chunk sizes
    log_info "Verifying pool chunk sizes..."
    local all_pools_ok=true

    for pool_id in 0 1 2; do
        local expected_chunk=${POOL_CHUNK_SIZES[$pool_id]}
        local actual_chunk=$(get_pool_chunk_size_kb "$pool_id" 2>/dev/null || echo "0")

        if [ "$actual_chunk" = "$expected_chunk" ]; then
            log_success "✓ Pool $pool_id: chunk size ${actual_chunk}KB (matches expected ${expected_chunk}KB)"
        elif [ "$actual_chunk" = "0" ]; then
            log_warn "⚠ Pool $pool_id: not found or not accessible"
            log_info "  Please ensure pool $pool_id exists with ${expected_chunk}KB chunk size"
            all_pools_ok=false
        else
            log_error "✗ Pool $pool_id: chunk size ${actual_chunk}KB (expected ${expected_chunk}KB)"
            log_error "  DMThin discard granularity will be ${actual_chunk}KB instead of ${expected_chunk}KB"
            all_pools_ok=false
        fi
    done

    log_info ""
    if [ "$all_pools_ok" = true ]; then
        log_success "All pools verified successfully!"
    else
        log_warn "Some pools have mismatched chunk sizes or are not accessible"
        log_warn "Tests will continue but results may not match expected dmthin granularities"
        log_warn "To create pools with correct chunk sizes, use LVM commands:"
        log_warn "  lvcreate --type thin-pool --chunksize 64K ..."
        log_warn "  lvcreate --type thin-pool --chunksize 1024K ..."
        log_warn "  lvcreate --type thin-pool --chunksize 2048K ..."
    fi
    log_info "=========================================="
    log_info ""
}

#######################################
# Main execution
#######################################

main() {
    log_info "=========================================="
    log_info "3-PHASE COMPREHENSIVE DISCARD TESTS"
    log_info "Phase 1: 48 volumes (discard only - create-shrink pattern)"
    log_info "Phase 2: 48 volumes (manual trim - create-shrink pattern)"
    log_info "Phase 3: 48 volumes (auto trim - create-shrink pattern)"
    log_info "Total: 144 volumes × 5 iterations = 720 tests"
    log_info "NOTE: Only running create-shrink pattern (create-delete commented out)"
    log_info "=========================================="
    log_info ""

    # Initialize and verify storage pools
    initialize_pools

    # Initialize CSV output
    initialize_csv_output

    # Run all 3 phases
    run_phase1_tests
    run_phase2_tests
    pxctl cluster option update --auto-fstrim on || echo "clusterwide autofstrim is can not be turned on"
    run_phase3_tests

    # Generate summary
    generate_test_summary

    log_success "All 3-phase comprehensive tests completed!"
    log_info "Results: $CSV_OUTPUT_FILE"
    log_info "Total volumes preserved: 144 (48 per phase - create-shrink pattern only)"
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
    local vol_name=$5  # Changed from vol_id to vol_name
    local mount_path=${6:-$MOUNT_PATH}  # Use provided mount path or default
    local pattern=${7:-""}  # Optional pattern parameter

    # Extract vol_id from volume name using pxctl
    local vol_id=$(pxctl volume list | grep "$vol_name" | awk '{print $1}' | head -1)
    if [ -z "$vol_id" ]; then
        log_error "Could not find volume ID for $vol_name"
        return 1
    fi

    local test_mode=${TEST_RUNS[$run_num]:-$pattern}
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    log_info "  Case: ${file_size_kb}KB file - Mode: $test_mode"

    # Parse test mode
    IFS='_' read -r discard_type action_type operation_type <<< "$test_mode"

    # Determine file type based on size
    local file_type="unknown"
    if [ "$file_size_kb" -eq 3 ]; then
        file_type="small"
    elif [ "$file_size_kb" -eq 20 ] || [ "$file_size_kb" -eq 66 ]; then
        file_type="medium"
    elif [ "$file_size_kb" -eq 1201 ]; then
        file_type="large"
    fi

    # Extract block device discard granularity and DMThin granularities from volume name
    # Volume name format: phase1_vol_1_4bd_64dm_discard_create_shrink_3kb
    local blkdev_discard_kb=$(echo "$vol_name" | grep -oP '\d+(?=bd)' || echo "4")
    local dmthin_chunk_kb=$(echo "$vol_name" | grep -oP '\d+(?=dm)' || echo "64")
    local dmthin_discard_kb=$dmthin_chunk_kb
    local nvme_sector_kb=${NVME_SECTOR_KB:-0}

    # Initial metrics (before any files created)
    sync; sleep 1

    # Get FS usage in KB, then convert to MB
    local fs_used_kb=$(get_fs_used_space_kb "$mount_path" 2>/dev/null || echo "0")
    local init_fs_usage_mb=$(echo "scale=2; $fs_used_kb / 1024" | bc 2>/dev/null || echo "0")

    # Get DMthin usage in bytes, then convert to MB
    local dmthin_used_bytes=$(get_dmthin_used_bytes "${POOL_ID:-0}" 2>/dev/null || echo "0")
    local init_dmthin_usage_mb=$(echo "scale=2; $dmthin_used_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")

    # Get PX usage in bytes, then convert to MB
    local px_usage_bytes=$(get_px_usage "$vol_id" 2>/dev/null || echo "0")
    local init_px_usage_mb=$(echo "scale=2; $px_usage_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")

    # Get trimmable space in bytes, then convert to MB
    local trimmable_bytes=$(get_trimmable_space "$vol_id" 2>/dev/null || echo "0")
    local init_trimmable_mb=$(echo "scale=2; $trimmable_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")
    
    # Configure discard mode based on test type (if function exists)
    if command -v configure_discard_mode &> /dev/null; then
        case $discard_type in
            "discard")
                configure_discard_mode "$vol_id" "$MODE_DISCARD_ONLY" 2>/dev/null || true
                ;;
            "fstrim")
                configure_discard_mode "$vol_id" "$MODE_AUTOFSTRIM_DISCARD" 2>/dev/null || true
                ;;
            "autofstrim")
                configure_discard_mode "$vol_id" "$MODE_AUTOFSTRIM_DISCARD" 2>/dev/null || true
                ;;
        esac
    fi

    # Create files to fill entire volume using fio with low compressibility
    local test_dir="${mount_path}/test_${run_num}_${file_case}"

    log_info "    Creating ${file_size_kb}KB files until volume is full using fio..."

    # Get available space to calculate target size
    local available_kb=$(df "$mount_path" | tail -1 | awk '{print $4}')
    local target_size_kb=$((available_kb * 99 / 100))  # Fill to 99%
    local target_file_count=$((target_size_kb / file_size_kb))

    # Limit file count to avoid too many files
    if [ $target_file_count -gt 10000 ]; then
        target_file_count=10000
    fi

    # Use helper function with 10 parallel jobs and iodepth of 16
    file_count=$(fill_volume_with_fio "$test_dir" "$file_size_kb" "$target_file_count" 10 16)

    sleep 2
    log_info "    Created $file_count files of ${file_size_kb}KB each using fio"

    # After write metrics
    # Get FS usage in KB, then convert to MB
    fs_used_kb=$(get_fs_used_space_kb "$mount_path" 2>/dev/null || echo "0")
    local after_write_fs_usage_mb=$(echo "scale=2; $fs_used_kb / 1024" | bc 2>/dev/null || echo "0")

    # Get DMthin usage in bytes, then convert to MB
    dmthin_used_bytes=$(get_dmthin_used_bytes "${POOL_ID:-0}" 2>/dev/null || echo "0")
    local after_write_dmthin_usage_mb=$(echo "scale=2; $dmthin_used_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")

    # Get PX usage in bytes, then convert to MB
    px_usage_bytes=$(get_px_usage "$vol_id" 2>/dev/null || echo "0")
    local after_write_px_usage_mb=$(echo "scale=2; $px_usage_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")

    # Get trimmable space in bytes, then convert to MB
    trimmable_bytes=$(get_trimmable_space "$vol_id" 2>/dev/null || echo "0")
    local after_write_trimmable_mb=$(echo "scale=2; $trimmable_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")
    
    # Perform delete/shrink operation (90% of files or shrink to 10% size)
    log_info "    Performing ${operation_type} operation..."

    case $operation_type in
        "delete")
            # Delete 90% of files
            local files_to_delete=$((file_count * 90 / 100))
            log_info "    Deleting $files_to_delete out of $file_count files (90%)"
            for i in $(seq 0 $((files_to_delete - 1))); do
                rm -f "${test_dir}/fill_${i}.dat" 2>/dev/null || true
            done
            ;;
        "shrink")
            # Shrink each file to 10% of original size
            local new_size_kb=$((file_size_kb * 10 / 100))
            log_info "    Shrinking files from ${file_size_kb}KB to ${new_size_kb}KB (10%)"
            for i in $(seq 0 $((file_count - 1))); do
                local file_path="${test_dir}/fill_${i}.dat"
                if [ -f "$file_path" ]; then
                    truncate -s $((new_size_kb * 1024)) "$file_path" 2>/dev/null || true
                fi
            done
            ;;
    esac

    sync; sleep 2

    # After delete metrics
    # Get FS usage in KB, then convert to MB
    fs_used_kb=$(get_fs_used_space_kb "$mount_path" 2>/dev/null || echo "0")
    local after_delete_fs_usage_mb=$(echo "scale=2; $fs_used_kb / 1024" | bc 2>/dev/null || echo "0")

    # Get DMthin usage in bytes, then convert to MB
    dmthin_used_bytes=$(get_dmthin_used_bytes "${POOL_ID:-0}" 2>/dev/null || echo "0")
    local after_delete_dmthin_usage_mb=$(echo "scale=2; $dmthin_used_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")

    # Get PX usage in bytes, then convert to MB
    px_usage_bytes=$(get_px_usage "$vol_id" 2>/dev/null || echo "0")
    local after_delete_px_usage_mb=$(echo "scale=2; $px_usage_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")

    # Get trimmable space in bytes, then convert to MB
    trimmable_bytes=$(get_trimmable_space "$vol_id" 2>/dev/null || echo "0")
    local after_delete_trimmable_mb=$(echo "scale=2; $trimmable_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")

    # Execute trim/discard based on mode
    log_info "    Running ${discard_type} operation..."

    case $discard_type in
        "discard")
            # Inline discard - happens automatically on delete
            log_info "    Waiting for inline discard to complete..."
            sleep 5
            ;;
        "fstrim")
            # Manual fstrim
            log_info "    Running manual fstrim..."
            fstrim "$mount_path" 2>/dev/null || true
            sleep 2
            ;;
        "autofstrim")
            # Wait for auto fstrim
            log_info "    Waiting for autofstrim to complete..."
            sleep 3
            if command -v wait_for_fstrim_complete &> /dev/null; then
                wait_for_fstrim_complete "$vol_id" 120 2>/dev/null || true
            else
                sleep 10
            fi
            ;;
    esac

    sync; sleep 2

    # After trim complete metrics
    # Get FS usage in KB, then convert to MB
    fs_used_kb=$(get_fs_used_space_kb "$mount_path" 2>/dev/null || echo "0")
    local after_trim_fs_usage_mb=$(echo "scale=2; $fs_used_kb / 1024" | bc 2>/dev/null || echo "0")

    # Get DMthin usage in bytes, then convert to MB
    dmthin_used_bytes=$(get_dmthin_used_bytes "${POOL_ID:-0}" 2>/dev/null || echo "0")
    local after_trim_dmthin_usage_mb=$(echo "scale=2; $dmthin_used_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")

    # Get PX usage in bytes, then convert to MB
    px_usage_bytes=$(get_px_usage "$vol_id" 2>/dev/null || echo "0")
    local after_trim_px_usage_mb=$(echo "scale=2; $px_usage_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")

    # Get trimmable space in bytes, then convert to MB
    trimmable_bytes=$(get_trimmable_space "$vol_id" 2>/dev/null || echo "0")
    local after_trim_trimmable_mb=$(echo "scale=2; $trimmable_bytes / 1024 / 1024" | bc 2>/dev/null || echo "0")

    # Write CSV row matching our header format
    # Header: Timestamp,Run,Scenario,BlockDev_Discard_Gran_KB,DMthin_Chunk_KB,DMthin_Discard_Gran_KB,NVMe_Sector_KB,Mode,File_Case,File_Type,Initial_FS_Usage_MB,Initial_DMthin_Usage_MB,Initial_PX_Usage_MB,Initial_Trimmable_MB,File_Count,After_Write_FS_Usage_MB,After_Write_DMthin_Usage_MB,After_Write_PX_Usage_MB,After_Write_Trimmable_MB,After_Delete_FS_Usage_MB,After_Delete_DMthin_Usage_MB,After_Delete_PX_Usage_MB,After_Delete_Trimmable_MB,After_Trim_FS_Usage_MB,After_Trim_DMthin_Usage_MB,After_Trim_PX_Usage_MB,After_Trim_Trimmable_MB,Volume_ID
    local csv_row="${timestamp},${run_num},${scenario_num},${blkdev_discard_kb},${dmthin_chunk_kb},${dmthin_discard_kb},${nvme_sector_kb},${test_mode},${file_case},${file_type},${init_fs_usage_mb},${init_dmthin_usage_mb},${init_px_usage_mb},${init_trimmable_mb},${file_count},${after_write_fs_usage_mb},${after_write_dmthin_usage_mb},${after_write_px_usage_mb},${after_write_trimmable_mb},${after_delete_fs_usage_mb},${after_delete_dmthin_usage_mb},${after_delete_px_usage_mb},${after_delete_trimmable_mb},${after_trim_fs_usage_mb},${after_trim_dmthin_usage_mb},${after_trim_px_usage_mb},${after_trim_trimmable_mb},${vol_id}"

    write_csv_row "$csv_row"

    # Calculate space reclaimed for logging
    local space_reclaimed_mb=$(echo "scale=2; $after_delete_fs_usage_mb - $after_trim_fs_usage_mb" | bc 2>/dev/null || echo "0")
    log_result "    $test_mode: File count=$file_count, Space reclaimed=${space_reclaimed_mb}MB"
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

    initialize_csv_output

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

    # Generate summary
    generate_test_summary

    log_success "All 6 test runs completed!"
    log_info "Results saved to: $CSV_OUTPUT_FILE"
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
main

