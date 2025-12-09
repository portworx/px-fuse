#!/bin/bash
# Discard/Trim test runner - supports multiple modes:
# - autofstrim: cluster + volume autofstrim enabled, nodiscard mount
# - discard_only: inline discard enabled (no nodiscard), cluster autofstrim OFF
# - manual_trim: nodiscard mount, cluster autofstrim OFF, run fstrim manually

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

RUNS_PER_COMBINATION=6  # This ensures try-1 through try-6
VOL_NAME="discard_test_vol"
VOL_SIZE=1  # 1GB volume for faster testing
MOUNT_PATH="/var/lib/osd/mounts/${VOL_NAME}"
POOL_ID=0
TRY_NUM=${TRY_NUM:-1}  # Set via environment: TRY_NUM=1, TRY_NUM=2, etc.

# Test mode: autofstrim, discard_only, or manual_trim
# - autofstrim: cluster autofstrim ON, volume autofstrim ON, nodiscard mount
# - discard_only: cluster autofstrim OFF, inline discard ON (default mount options)
# - manual_trim: cluster autofstrim OFF, nodiscard mount, run fstrim manually after deletions
TEST_MODE=${TEST_MODE:-"autofstrim"}

# Test pattern: create_delete or create_shrink
# - create_delete: Fill volume to 10GB, then delete all files
# - create_shrink: Fill volume to 10GB using create-shrink cycles (creates fragmentation)
TEST_PATTERN=${TEST_PATTERN:-"create_delete"}

# Override TARGET_SIZE_MB to fill entire volume (leave 512MB for FS overhead)
VOLUME_FILL_SIZE_MB=$((VOL_SIZE * 1024 - 512))  # For 1GB: ~512MB usable

# Short mode name for directory/file naming
case $TEST_MODE in
    "autofstrim") MODE_SHORT="af" ;;
    "discard_only") MODE_SHORT="discard" ;;
    "manual_trim") MODE_SHORT="fstrim" ;;
    *) MODE_SHORT="$TEST_MODE" ;;
esac

# Results directory and files - labeled by mode and pattern
RESULTS_DIR="${SCRIPT_DIR}/try_${TRY_NUM}_${MODE_SHORT}_${TEST_PATTERN}"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_CSV="${RESULTS_DIR}/${TEST_MODE}_test_results_${TIMESTAMP}.csv"
RUN_LOG="${RESULTS_DIR}/${TEST_MODE}_test_run_${TIMESTAMP}.log"

# CSV Header - all sizes in MB for readability
# Added: FS_Freed_MB, DMthin_Unused_MB, Wasted_MB, Discard_Efficiency_Pct for tracking unallocated blocks
CSV_HEADER="Timestamp,Run,Scenario,FS_Block_KB,FS_Discard_Gran_KB,DMthin_Chunk_KB,DMthin_Discard_Gran_KB,NVMe_Sector_KB,Mode,File_Case,File_Type,File_Count,Total_Size_MB,Initial_FS_Free_MB,Initial_DMthin_Percent,Initial_PX_Usage_MB,Initial_DU_Usage_MB,Initial_Trimmable_MB,AfterCreate_FS_Free_MB,AfterCreate_DMthin_Percent,AfterCreate_PX_Usage_MB,AfterCreate_DU_Usage_MB,AfterCreate_Trimmable_MB,AfterDelete_FS_Free_MB,AfterDelete_DMthin_Percent,AfterDelete_PX_Usage_MB,AfterDelete_DU_Usage_MB,AfterDelete_Trimmable_MB,Discard_Time_Sec,Space_Reclaimed_MB,DMthin_Reclaimed_Percent,FS_Freed_MB,DMthin_Unused_MB,Wasted_MB,Discard_Efficiency_Pct,Actual_Discard_Gran_KB,Volume_ID"

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
# Metrics collection - returns values in MB for readability
#######################################

# Convert bytes to MB (integer division)
bytes_to_mb() {
    local bytes=${1:-0}
    echo $((bytes / 1024 / 1024))
}

# Convert KB to MB (integer division)
kb_to_mb() {
    local kb=${1:-0}
    echo $((kb / 1024))
}

collect_metrics() {
    local vol_id=$1
    local mount_path=$2
    local pool_id=$3

    # Get raw values
    local fs_free_kb=$(get_fs_free_space_kb "$mount_path" 2>/dev/null || echo "0")
    local dmthin_percent=$(get_dmthin_data_percent "$pool_id" 2>/dev/null || echo "0")
    local px_usage_bytes=$(get_px_usage "$vol_id" 2>/dev/null || echo "0")
    local du_usage_bytes=$(get_du_usage "$vol_id" 2>/dev/null || echo "0")
    local trimmable_bytes=$(get_trimmable_space "$vol_id" 2>/dev/null || echo "0")

    # Convert to MB
    local fs_free_mb=$(kb_to_mb "$fs_free_kb")
    local px_usage_mb=$(bytes_to_mb "$px_usage_bytes")
    local du_usage_mb=$(bytes_to_mb "$du_usage_bytes")
    local trimmable_mb=$(bytes_to_mb "$trimmable_bytes")

    echo "${fs_free_mb}|${dmthin_percent}|${px_usage_mb}|${du_usage_mb}|${trimmable_mb}"
}

#######################################
# File creation - fills volume to capacity with hole creation
# Both patterns: Fill to 10GB, delete 90%, repeat to create holes
#######################################

# Number of fill-delete cycles to create holes in dmthin chunks
HOLE_CREATION_CYCLES=${HOLE_CREATION_CYCLES:-2}  # Reduced from 3 for faster testing
# Percentage of files to keep after each delete cycle (10% = keep 10%, delete 90%)
KEEP_PERCENTAGE=${KEEP_PERCENTAGE:-10}

# Get filesystem usage percentage from df
get_fs_usage_percent() {
    local mount_path=$1
    df "$mount_path" 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}'
}

# Get filesystem free space in KB from df
get_fs_free_kb() {
    local mount_path=$1
    df "$mount_path" 2>/dev/null | awk 'NR==2 {print $4}'
}

# Create-delete pattern: Fill volume to 100% (verified via df), delete 90%, repeat
# Multiple cycles create fragmented holes in dmthin chunks
create_files_to_fill_volume() {
    local test_dir=$1
    local file_type=$2
    local mount_path=$(dirname "$test_dir")
    local min_kb max_kb

    case $file_type in
        "small")
            min_kb=$SMALL_FILE_MIN_KB
            max_kb=$SMALL_FILE_MAX_KB
            ;;
        "medium")
            min_kb=$MEDIUM_FILE_MIN_KB
            max_kb=$MEDIUM_FILE_MAX_KB
            ;;
        "mixed")
            # Will alternate between small and medium
            min_kb=$SMALL_FILE_MIN_KB
            max_kb=$MEDIUM_FILE_MAX_KB
            ;;
        "large")
            min_kb=$LARGE_FILE_MIN_KB
            max_kb=$LARGE_FILE_MAX_KB
            ;;
        # Exact file size cases for per-file discard testing
        "4kb")
            min_kb=$FILE_SIZE_CASE_1_KB
            max_kb=$FILE_SIZE_CASE_1_KB
            ;;
        "20kb")
            min_kb=$FILE_SIZE_CASE_2_KB
            max_kb=$FILE_SIZE_CASE_2_KB
            ;;
        "64kb")
            min_kb=$FILE_SIZE_CASE_3_KB
            max_kb=$FILE_SIZE_CASE_3_KB
            ;;
        "1mb")
            min_kb=$FILE_SIZE_CASE_4_KB
            max_kb=$FILE_SIZE_CASE_4_KB
            ;;
        *)
            min_kb=10
            max_kb=100
            ;;
    esac

    mkdir -p "$test_dir"
    echo "    CREATE-DELETE: ${HOLE_CREATION_CYCLES} cycles, fill to 100% (df), delete 90%" >&2
    echo "      File size range: ${min_kb}-${max_kb}KB, keeping ${KEEP_PERCENTAGE}% after each delete" >&2

    local cycle
    for cycle in $(seq 1 $HOLE_CREATION_CYCLES); do
        echo "      Cycle $cycle/$HOLE_CREATION_CYCLES: Filling volume to 100%..." >&2

        local file_count=$(ls -1 "$test_dir"/*.bin 2>/dev/null | wc -l 2>/dev/null || echo 0)
        local fs_usage=$(get_fs_usage_percent "$mount_path")
        local consecutive_fails=0

        # Fill until df shows >= 98% usage (leaving tiny room for FS overhead)
        while [ "${fs_usage:-0}" -lt 98 ] && [ $consecutive_fails -lt 5 ]; do
            local range=$((max_kb - min_kb + 1))
            local file_size
            if [ "$file_type" = "mixed" ]; then
                # Alternate between small and medium
                if [ $((file_count % 2)) -eq 0 ]; then
                    file_size=$((SMALL_FILE_MIN_KB + RANDOM % (SMALL_FILE_MAX_KB - SMALL_FILE_MIN_KB + 1)))
                else
                    file_size=$((MEDIUM_FILE_MIN_KB + RANDOM % (MEDIUM_FILE_MAX_KB - MEDIUM_FILE_MIN_KB + 1)))
                fi
            else
                file_size=$((min_kb + RANDOM % range))
            fi

            file_count=$((file_count + 1))
            local fname="${test_dir}/file_${file_count}.bin"

            # Try to create file, handle ENOSPC gracefully
            if ! dd if=/dev/urandom of="$fname" bs=1024 count=$file_size 2>/dev/null; then
                consecutive_fails=$((consecutive_fails + 1))
                rm -f "$fname" 2>/dev/null
            else
                consecutive_fails=0
            fi

            # Check df every 100 files to avoid excessive overhead
            if [ $((file_count % 100)) -eq 0 ]; then
                sync
                fs_usage=$(get_fs_usage_percent "$mount_path")
                local current_size_kb=$(du -sk "$test_dir" 2>/dev/null | cut -f1 || echo 0)
                local current_mb=$((current_size_kb / 1024))
                echo "        Progress: ${file_count} files, ${current_mb}MB, df=${fs_usage}%" >&2
            fi
        done
        sync

        local filled_count=$(ls -1 "$test_dir"/*.bin 2>/dev/null | wc -l)
        local filled_size_kb=$(du -sk "$test_dir" 2>/dev/null | cut -f1)
        local final_usage=$(get_fs_usage_percent "$mount_path")
        echo "      Cycle $cycle: Filled to ${filled_size_kb}KB (${filled_count} files), df=${final_usage}%" >&2

        # Delete 90% of files (keep only 10%)
        local num_to_keep=$((filled_count * KEEP_PERCENTAGE / 100))
        [ $num_to_keep -lt 1 ] && num_to_keep=1
        local num_to_delete=$((filled_count - num_to_keep))
        echo "      Cycle $cycle: Deleting ${num_to_delete} files (keeping ${num_to_keep})..." >&2

        # Randomly select files to delete
        ls "$test_dir"/*.bin 2>/dev/null | shuf | head -n $num_to_delete | xargs rm -f
        sync

        local remaining_count=$(ls -1 "$test_dir"/*.bin 2>/dev/null | wc -l)
        local remaining_size_kb=$(du -sk "$test_dir" 2>/dev/null | cut -f1)
        local after_del_usage=$(get_fs_usage_percent "$mount_path")
        echo "      Cycle $cycle: After delete: ${remaining_size_kb}KB (${remaining_count} files), df=${after_del_usage}%" >&2
    done

    local final_count=$(ls -1 "$test_dir"/*.bin 2>/dev/null | wc -l)
    local final_size_kb=$(du -sk "$test_dir" 2>/dev/null | cut -f1)
    local final_usage=$(get_fs_usage_percent "$mount_path")
    echo "    Final: ${final_count} files, ${final_size_kb}KB ($(( final_size_kb / 1024 ))MB), df=${final_usage}%" >&2
    echo "${final_count}|${final_size_kb}"
}

# Create-shrink pattern: Fill volume 100% (verified via df), shrink ALL files to tiny sizes, repeat
# Creates MAXIMUM fragmentation: Create GB-sized files, shrink to bytes/KB
# Goal: Initial 100% usage -> after shrink -> 10% filesystem usage but dmthin still allocated
create_shrink_files_to_fill_volume() {
    local test_dir=$1
    local file_type=$2
    local mount_path=$(dirname "$test_dir")

    # EXTREME CREATE-SHRINK PATTERN:
    # 1. Fill 100% of disk with HUGE files (500MB - 2GB each) - verified via df
    # 2. Shrink ALL files to TINY sizes (100 bytes - 4KB)
    # 3. Result: filesystem shows ~10% usage, but dmthin chunks are fragmented

    # File sizes based on type - all are VERY LARGE initially
    local large_min_mb large_max_mb
    # Shrunk sizes - EXTREMELY small (bytes to few KB)
    local shrink_min_bytes shrink_max_bytes

    case $file_type in
        "small")
            large_min_mb=500
            large_max_mb=1024
            shrink_min_bytes=100
            shrink_max_bytes=512
            ;;
        "medium"|"mixed")
            large_min_mb=1024
            large_max_mb=1536
            shrink_min_bytes=512
            shrink_max_bytes=2048
            ;;
        "large")
            large_min_mb=1536
            large_max_mb=2048
            shrink_min_bytes=1024
            shrink_max_bytes=4096
            ;;
        # For exact size cases, still create large files but with specific shrink targets
        "4kb"|"20kb"|"64kb"|"1mb")
            large_min_mb=500
            large_max_mb=1024
            shrink_min_bytes=100
            shrink_max_bytes=512
            ;;
        *)
            large_min_mb=500
            large_max_mb=1024
            shrink_min_bytes=100
            shrink_max_bytes=1024
            ;;
    esac

    mkdir -p "$test_dir"
    echo "    CREATE-SHRINK (GB->BYTES): ${HOLE_CREATION_CYCLES} cycles, fill to 100% (df)" >&2
    echo "      Initial HUGE files: ${large_min_mb}MB - ${large_max_mb}MB" >&2
    echo "      Shrink ALL to: ${shrink_min_bytes} - ${shrink_max_bytes} bytes" >&2

    local main_cycle
    for main_cycle in $(seq 1 $HOLE_CREATION_CYCLES); do
        echo "      Main Cycle $main_cycle/$HOLE_CREATION_CYCLES: Filling to 100% (df)..." >&2

        local file_count=$(ls -1 "$test_dir"/*.bin 2>/dev/null | wc -l 2>/dev/null || echo 0)
        local fs_usage=$(get_fs_usage_percent "$mount_path")
        local consecutive_fails=0

        # Fill until df shows >= 98% usage
        while [ "${fs_usage:-0}" -lt 98 ] && [ $consecutive_fails -lt 3 ]; do
            local large_range=$((large_max_mb - large_min_mb + 1))
            local large_size_mb=$((large_min_mb + RANDOM % large_range))

            # Cap at available free space
            local free_kb=$(get_fs_free_kb "$mount_path")
            local free_mb=$((free_kb / 1024))
            if [ $large_size_mb -gt $free_mb ] && [ $free_mb -gt 50 ]; then
                large_size_mb=$free_mb
            elif [ $free_mb -le 50 ]; then
                break
            fi

            file_count=$((file_count + 1))
            local fname="${test_dir}/file_${file_count}.bin"

            # Write large file, handle ENOSPC
            if ! dd if=/dev/urandom of="$fname" bs=1M count=$large_size_mb 2>/dev/null; then
                consecutive_fails=$((consecutive_fails + 1))
                rm -f "$fname" 2>/dev/null
            else
                consecutive_fails=0
                local progress_mb=$(($(du -sk "$test_dir" | cut -f1) / 1024))
                fs_usage=$(get_fs_usage_percent "$mount_path")
                echo "        Created file_${file_count}.bin: ${large_size_mb}MB (Total: ${progress_mb}MB, df=${fs_usage}%)" >&2
            fi
        done
        sync

        local filled_count=$(ls -1 "$test_dir"/*.bin 2>/dev/null | wc -l)
        local filled_size_kb=$(du -sk "$test_dir" 2>/dev/null | cut -f1)
        local filled_size_mb=$((filled_size_kb / 1024))
        local final_usage=$(get_fs_usage_percent "$mount_path")
        echo "      Main Cycle $main_cycle: Filled: ${filled_size_mb}MB (${filled_count} files), df=${final_usage}%" >&2

        # Shrink ALL files to TINY sizes
        echo "      Main Cycle $main_cycle: Shrinking ALL ${filled_count} files to bytes..." >&2

        local shrunk_count=0
        for f in "$test_dir"/*.bin; do
            [ -f "$f" ] || continue
            local shrink_range=$((shrink_max_bytes - shrink_min_bytes + 1))
            local shrink_size=$((shrink_min_bytes + RANDOM % shrink_range))
            truncate -s $shrink_size "$f"
            shrunk_count=$((shrunk_count + 1))
            if [ $((shrunk_count % 5)) -eq 0 ]; then
                echo "        Shrunk ${shrunk_count}/${filled_count} files..." >&2
            fi
        done
        sync

        local after_shrink_kb=$(du -sk "$test_dir" 2>/dev/null | cut -f1)
        local after_shrink_mb=$((after_shrink_kb / 1024))
        local after_usage=$(get_fs_usage_percent "$mount_path")
        echo "      Main Cycle $main_cycle: After shrink: ${after_shrink_mb}MB, df=${after_usage}%" >&2
    done

    local final_count=$(ls -1 "$test_dir"/*.bin 2>/dev/null | wc -l)
    local final_size_kb=$(du -sk "$test_dir" 2>/dev/null | cut -f1)
    local final_size_mb=$((final_size_kb / 1024))
    local final_usage=$(get_fs_usage_percent "$mount_path")
    echo "    Final: ${final_count} tiny files, ${final_size_mb}MB, df=${final_usage}%" >&2
    echo "${final_count}|${final_size_kb}"
}

#######################################
# Test execution
#######################################

run_single_case() {
    local run_num=$1
    local scenario_num=$2
    local mode=$3
    local file_case=$4
    local file_type=$5
    local vol_id=$6
    local mount_path=${7:-$MOUNT_PATH}
    local vol_name=${8:-$VOL_NAME}

    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    echo "  Case $file_case: ${file_type} files (${TEST_PATTERN} pattern, filling ${VOLUME_FILL_SIZE_MB}MB)"

    # Initial metrics (already in MB from collect_metrics)
    sync; sleep 1
    local init_metrics=$(collect_metrics "$vol_id" "$mount_path" "$POOL_ID")
    IFS='|' read -r init_fs init_dm init_px init_du init_trim <<< "$init_metrics"

    # Create files based on pattern type
    # The fill functions run N cycles: fill to 10GB, then delete 90% on each cycle
    # After completion, only ~10% of files remain (with fragmented holes)
    local test_dir="${mount_path}/test_${file_type}"
    local frag_result

    if [ "$TEST_PATTERN" = "create_shrink" ]; then
        frag_result=$(create_shrink_files_to_fill_volume "$test_dir" "$file_type")
    else
        # Default: create_delete pattern
        frag_result=$(create_files_to_fill_volume "$test_dir" "$file_type")
    fi
    IFS='|' read -r file_count total_size_kb <<< "$frag_result"
    local total_size_mb=$((total_size_kb / 1024))

    sync; sleep 2

    echo "    After 90% delete: ${file_count} files remaining, size: ${total_size_mb}MB"

    # Measure after the 90% deletion
    # This captures the state right after deletions (before any explicit trim)
    local create_metrics=$(collect_metrics "$vol_id" "$mount_path" "$POOL_ID")
    IFS='|' read -r create_fs create_dm create_px create_du create_trim <<< "$create_metrics"

    # Print explicit du and df usage after delete (before trim)
    echo "    [Before Trim] df free: ${create_fs}MB, du usage: ${create_du}MB, px usage: ${create_px}MB, trimmable: ${create_trim}MB"

    # Trigger space reclamation based on TEST_MODE
    local start_time=$(date +%s.%N)
    case $TEST_MODE in
        "autofstrim")
            echo "    Triggering autofstrim to reclaim space..."
            $PXCTL_PATH volume autofstrim push "$vol_id" 2>&1 || true
            wait_for_fstrim_complete "$vol_id" || true
            ;;
        "discard_only")
            # Inline discard should have already happened during file deletion
            # Just wait a bit for any pending discards to complete
            echo "    Discard_only mode: inline discards issued during deletion, waiting..."
            sleep 5
            sync
            ;;
        "manual_trim")
            echo "    Running manual fstrim on ${mount_path}..."
            fstrim -v "$mount_path" 2>&1 || true
            sync
            sleep 2
            ;;
        *)
            echo "    Unknown mode: $TEST_MODE, skipping trim"
            ;;
    esac

    local end_time=$(date +%s.%N)
    local discard_time=$(echo "$end_time - $start_time" | bc)

    local delete_metrics=$(collect_metrics "$vol_id" "$mount_path" "$POOL_ID")
    IFS='|' read -r del_fs del_dm del_px del_du del_trim <<< "$delete_metrics"

    # Print explicit du and df usage after trim
    echo "    [After Trim]  df free: ${del_fs}MB, du usage: ${del_du}MB, px usage: ${del_px}MB, trimmable: ${del_trim}MB"

    # Get discard efficiency metrics (unallocated blocks tracking)
    local efficiency_metrics=$(get_discard_efficiency "$mount_path" "$POOL_ID" "$vol_id")
    IFS='|' read -r fs_freed_kb dmthin_unused_kb wasted_kb efficiency_pct <<< "$efficiency_metrics"
    local fs_freed_mb=$((fs_freed_kb / 1024))
    local dmthin_unused_mb=$((dmthin_unused_kb / 1024))
    local wasted_mb=$((wasted_kb / 1024))

    # Clean up remaining files for next test case
    rm -rf "$test_dir"
    sync

    # Calculate reclaimed space (values are already in MB)
    local space_reclaimed_mb=$((del_fs - create_fs))
    local dmthin_reclaimed=$(echo "$create_dm - $del_dm" | bc 2>/dev/null || echo "0")

    # Get actual discard granularity (convert bytes to KB for readability)
    local pxd_device=$(get_pxd_device "$vol_id")
    local actual_discard_gran_bytes=$(get_sysfs_discard_granularity "$pxd_device")
    local actual_discard_gran_kb=$((actual_discard_gran_bytes / 1024))

    # Write CSV row - all sizes in MB, granularity in KB
    # Added: fs_freed_mb, dmthin_unused_mb, wasted_mb, efficiency_pct for unallocated blocks tracking
    local csv_row="${timestamp},${run_num},${scenario_num},${FS_BLOCK_KB},${FS_DISCARD_KB},${DMTHIN_CHUNK_KB},${DMTHIN_DISCARD_KB},${NVME_SECTOR_KB},${mode},${file_case},${file_type},${file_count},${total_size_mb},${init_fs},${init_dm},${init_px},${init_du},${init_trim},${create_fs},${create_dm},${create_px},${create_du},${create_trim},${del_fs},${del_dm},${del_px},${del_du},${del_trim},${discard_time},${space_reclaimed_mb},${dmthin_reclaimed},${fs_freed_mb},${dmthin_unused_mb},${wasted_mb},${efficiency_pct},${actual_discard_gran_kb},${vol_id}"

    write_csv_row "$csv_row"
    echo "    Reclaimed: ${space_reclaimed_mb}MB in ${discard_time}s, Efficiency: ${efficiency_pct}%"
}

run_all_cases() {
    local run_num=$1
    local scenario_num=$2
    local mode=$3
    local vol_id=$4
    local mount_path=${5:-$MOUNT_PATH}
    local vol_name=${6:-$VOL_NAME}

    # File size cases: 4KB, 20KB, 64KB, 1MB (per user requirements)
    # These match exact discard granularity boundaries for testing
    local cases=("1:4kb" "2:20kb" "3:64kb" "4:1mb")

    for case_item in "${cases[@]}"; do
        IFS=':' read -r case_num file_type <<< "$case_item"
        run_single_case "$run_num" "$scenario_num" "$mode" "$case_num" "$file_type" "$vol_id" "$mount_path" "$vol_name"
    done
}

# Run all file pattern cases (small, mixed, large fragmentation patterns)
run_all_pattern_cases() {
    local run_num=$1
    local scenario_num=$2
    local mode=$3
    local vol_id=$4
    local mount_path=${5:-$MOUNT_PATH}
    local vol_name=${6:-$VOL_NAME}

    # Fragmentation patterns: small files, mixed small+medium, large multi-chunk files
    local cases=("1:small" "2:mixed" "3:large")

    for case_item in "${cases[@]}"; do
        IFS=':' read -r case_num file_type <<< "$case_item"
        run_single_case "$run_num" "$scenario_num" "$mode" "$case_num" "$file_type" "$vol_id" "$mount_path" "$vol_name"
    done
}

# Configure volume based on TEST_MODE
# - autofstrim: cluster autofstrim ON, volume autofstrim ON, nodiscard mount
# - discard_only: cluster autofstrim OFF, inline discard ON (default mount)
# - manual_trim: cluster autofstrim OFF, nodiscard mount, fstrim run manually
configure_volume_mode() {
    local vol_id=$1
    local mode=$2

    case $mode in
        "autofstrim")
            log_info "Configuring autofstrim mode (cluster + volume autofstrim ON, nodiscard)"
            # Cluster autofstrim already enabled in main loop
            enable_volume_nodiscard "$vol_id"
            enable_volume_autofstrim "$vol_id"
            ;;
        "discard_only")
            log_info "Configuring discard_only mode (inline discard ON, no nodiscard)"
            # Cluster autofstrim already disabled in main loop
            # Default mount has inline discard enabled, no special config needed
            # Just make sure nodiscard is OFF (default)
            ;;
        "manual_trim")
            log_info "Configuring manual_trim mode (nodiscard, fstrim run manually)"
            # Cluster autofstrim already disabled in main loop
            enable_volume_nodiscard "$vol_id"
            # Disable volume-level autofstrim explicitly
            $PXCTL_PATH volume update --auto_fstrim off "$vol_id" 2>/dev/null || true
            ;;
        *)
            log_warn "Unknown mode: $mode, using autofstrim defaults"
            enable_volume_nodiscard "$vol_id"
            enable_volume_autofstrim "$vol_id"
            ;;
    esac

    sleep 3
}

#######################################
# Run single mode test (for parallel execution)
#######################################
run_mode_test() {
    local scenario_num=$1
    local run_num=$2
    local vol_name=$3
    local mount_path=$4
    local log_file="${RESULTS_DIR}/scenario${scenario_num}_${MODE_SHORT}_run${run_num}_${TIMESTAMP}.log"

    exec > >(tee -a "$log_file") 2>&1

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting: S${scenario_num} ${TEST_MODE} Run${run_num}"

    # Create volume
    local vol_id=$(setup_volume "$vol_name" "$mount_path" "$VOL_SIZE" "$POOL_ID")
    if [ -z "$vol_id" ]; then
        echo "[ERROR] Failed to create volume $vol_name"
        return 1
    fi
    echo "Volume ID: $vol_id"

    # Configure volume based on mode
    configure_volume_mode "$vol_id" "$TEST_MODE"

    # Run test cases - mode name includes pattern
    local mode_name="${TEST_MODE}_${TEST_PATTERN}"
    run_all_cases "$run_num" "$scenario_num" "$mode_name" "$vol_id" "$mount_path" "$vol_name"

    # Cleanup
    cleanup_volume "$vol_id" "$mount_path" "$vol_name"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Completed: S${scenario_num} ${TEST_MODE} Run${run_num}"
}

#######################################
# px-fuse rebuild functions (same as run_full_tests.sh)
#######################################

backup_pxd_header() {
    if [ ! -f "${PXD_HEADER}.orig" ]; then
        cp "$PXD_HEADER" "${PXD_HEADER}.orig"
        log_info "Backed up original pxd.h"
    fi
}

restore_pxd_header() {
    if [ -f "${PXD_HEADER}.orig" ]; then
        cp "${PXD_HEADER}.orig" "$PXD_HEADER"
        log_info "Restored original pxd.h"
    fi
}

set_discard_granularity_in_source() {
    local granularity_bytes=$1
    local granularity_expr

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

    sed -i "s/#define PXD_MAX_DISCARD_GRANULARITY.*/#define PXD_MAX_DISCARD_GRANULARITY\t\t${granularity_expr} \/**< discard granularity for test *\//" "$PXD_HEADER"

    grep "PXD_MAX_DISCARD_GRANULARITY" "$PXD_HEADER" | head -1
}

build_px_fuse() {
    log_info "Building px-fuse..."
    cd "$PX_FUSE_DIR"

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

stop_portworx() {
    log_info "Stopping portworx..."
    systemctl stop portworx 2>&1 || true
    sleep 10
    local retries=0
    while systemctl is-active portworx >/dev/null 2>&1 && [ $retries -lt 6 ]; do
        log_info "  Waiting for portworx to stop... (${retries})"
        sleep 5
        retries=$((retries + 1))
    done
    log_success "Portworx stopped"
}

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

start_portworx() {
    log_info "Starting portworx..."
    systemctl start portworx 2>&1
    log_info "Waiting for portworx to be operational..."
}

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
# Main test loop
#######################################
run_tests() {
    log_info "=========================================="
    log_info "Discard/Trim Test Suite - Try ${TRY_NUM}"
    log_info "  Mode: ${TEST_MODE}"
    log_info "  Pattern: ${TEST_PATTERN}"
    log_info "=========================================="

    case $TEST_MODE in
        "autofstrim")
            log_info "Mode: autofstrim (cluster + volume autofstrim ON, nodiscard mount)"
            ;;
        "discard_only")
            log_info "Mode: discard_only (inline discard ON, cluster autofstrim OFF)"
            ;;
        "manual_trim")
            log_info "Mode: manual_trim (nodiscard mount, cluster autofstrim OFF, fstrim manual)"
            ;;
    esac

    log_info "Test Pattern: ${TEST_PATTERN}"
    log_info "Hole Creation Strategy:"
    log_info "  - ${HOLE_CREATION_CYCLES} cycles of: fill to 100% (df) -> delete/shrink 90%"
    log_info "  - create_delete: Fill 100%, delete 90%, repeat"
    log_info "  - create_shrink: Fill 100% with GB files, shrink to bytes"
    log_info "Volume fill size: ${VOLUME_FILL_SIZE_MB}MB (~${VOL_SIZE}GB)"
    log_info "File size cases: 4KB, 20KB, 64KB, 1MB"
    log_info "Runs per combination: $RUNS_PER_COMBINATION"
    log_info "Results directory: $RESULTS_DIR"
    log_info "=========================================="

    init_csv
    backup_pxd_header

    # Configure cluster-level autofstrim based on mode
    case $TEST_MODE in
        "autofstrim")
            log_info "Enabling cluster-level autofstrim..."
            enable_cluster_autofstrim
            ;;
        "discard_only"|"manual_trim")
            log_info "Disabling cluster-level autofstrim..."
            disable_cluster_autofstrim
            ;;
    esac

    # All 5 scenarios with different granularity configurations
    # Scenario 1: FS 4KB, DMthin 64KB, NVMe 0
    # Scenario 2: FS 64KB, DMthin 64KB, NVMe 1MB
    # Scenario 3: FS 4KB, DMthin 1MB
    # Scenario 4: FS 64KB, DMthin 1MB
    # Scenario 5: FS 1MB, DMthin 64KB
    local scenarios=(1 2 3 4 5)
    local last_granularity=0

    for scenario_num in "${scenarios[@]}"; do
        local scenario=$(get_scenario "$scenario_num")
        parse_scenario "$scenario"
        local discard_gran_bytes=$((FS_DISCARD_KB * 1024))

        log_info ""
        log_info "=========================================="
        log_info "Scenario $scenario_num - Mode: ${TEST_MODE} - Pattern: ${TEST_PATTERN}"
        log_info "  FS Block: ${FS_BLOCK_KB}KB, FS Discard Gran: ${FS_DISCARD_KB}KB"
        log_info "  DMthin Chunk: ${DMTHIN_CHUNK_KB}KB, DMthin Discard Gran: ${DMTHIN_DISCARD_KB}KB"
        log_info "  NVMe Sector: ${NVME_SECTOR_KB}KB"
        log_info "=========================================="

        # Rebuild px-fuse if granularity changed
        if [ "$discard_gran_bytes" -ne "$last_granularity" ]; then
            apply_discard_granularity "$discard_gran_bytes"
            last_granularity=$discard_gran_bytes
        fi

        # Run ALL runs in PARALLEL
        log_info ""
        log_info "Scenario $scenario_num - ${TEST_MODE}_${TEST_PATTERN} (${RUNS_PER_COMBINATION} runs in PARALLEL)"
        local pids=()
        for run in $(seq 1 $RUNS_PER_COMBINATION); do
            local vol_name="${VOL_NAME}_s${scenario_num}_${MODE_SHORT}_r${run}"
            local mount_path="/var/lib/osd/mounts/${vol_name}"
            log_info "  Launching: Run $run -> $vol_name"
            run_mode_test "$scenario_num" "$run" "$vol_name" "$mount_path" &
            pids+=($!)
        done
        log_info "  Waiting for ${#pids[@]} parallel runs..."
        for pid in "${pids[@]}"; do
            wait $pid || log_warn "  Test pid $pid failed"
        done
        log_success "  ${TEST_MODE} mode completed for scenario $scenario_num"
    done

    restore_pxd_header
    log_success ""
    log_success "=========================================="
    log_success "All ${TEST_MODE} tests completed!"
    log_success "Mode: ${TEST_MODE}"
    log_success "Pattern: ${TEST_PATTERN}"
    log_success "Results saved to: $RESULTS_CSV"
    log_success "=========================================="
}

#######################################
# Usage
#######################################

usage() {
    cat << EOF
Usage: TRY_NUM=N TEST_MODE=<mode> TEST_PATTERN=<pattern> $0 [options]

Discard/Trim test runner - supports multiple modes for space reclamation testing.

TEST_MODE options:
  - autofstrim:   Cluster + volume autofstrim enabled, nodiscard mount
  - discard_only: Inline discard ON (default mount), cluster autofstrim OFF
  - manual_trim:  Nodiscard mount, cluster autofstrim OFF, run fstrim manually

TEST_PATTERN options:
  - create_delete: Fill volume to 10GB, delete 90%, repeat N cycles
  - create_shrink: Create GB-sized files, shrink ALL to bytes (extreme fragmentation)

Behavior (creates holes in dmthin chunks):
  Both patterns run ${HOLE_CREATION_CYCLES} cycles of:
    1. Fill volume to ~10GB
    2. Delete/shrink 90% of data
    3. Repeat to create fragmented holes in dmthin chunks
    4. Trigger space reclamation (based on mode)
    5. Measure reclamation effectiveness

Environment:
    TRY_NUM=N                  Set try number (1, 2, 3, etc.)
    TEST_MODE=<mode>           Set test mode (autofstrim, discard_only, manual_trim)
    TEST_PATTERN=<pattern>     Set test pattern (create_delete, create_shrink)
    HOLE_CREATION_CYCLES=N     Number of fill-delete cycles (default: 3)
    KEEP_PERCENTAGE=N          Percentage to keep after each delete (default: 10)

Results are saved to: try_<N>_<mode_short>_<pattern>/

Options:
    --runs N            Number of runs per combination (default: 5)
    --vol-size SIZE     Volume size in GB (default: 10)
    --mode MODE         Test mode (autofstrim, discard_only, manual_trim)
    --pattern PATTERN   Test pattern (create_delete, create_shrink)
    --cycles N          Number of fill-delete cycles (default: 3)
    --keep-pct N        Percentage to keep after each delete (default: 10)
    --help              Show this help

Examples:
    # Autofstrim test with create-delete pattern
    TRY_NUM=1 TEST_MODE=autofstrim TEST_PATTERN=create_delete $0

    # Inline discard test with create-shrink pattern
    TRY_NUM=3 TEST_MODE=discard_only TEST_PATTERN=create_shrink $0

    # Manual fstrim test with create-shrink pattern
    TRY_NUM=4 TEST_MODE=manual_trim TEST_PATTERN=create_shrink $0
EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --runs) RUNS_PER_COMBINATION="$2"; shift 2 ;;
        --vol-size) VOL_SIZE="$2"; VOLUME_FILL_SIZE_MB=$((VOL_SIZE * 1024 - 512)); shift 2 ;;
        --mode) TEST_MODE="$2"; shift 2 ;;
        --pattern) TEST_PATTERN="$2"; shift 2 ;;
        --cycles) HOLE_CREATION_CYCLES="$2"; shift 2 ;;
        --keep-pct) KEEP_PERCENTAGE="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# Run tests
run_tests

