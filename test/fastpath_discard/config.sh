#!/bin/bash
# Configuration for fastpath discard tests

# PX paths
PXCTL_PATH="${PXCTL_PATH:-/opt/pwx/bin/pxctl}"
FSTRIM_PATH="${FSTRIM_PATH:-/opt/pwx/oci/rootfs/sbin/fstrim}"

# Size constants (in bytes)
KB=1024
MB=$((1024 * KB))

# Default block/chunk sizes
FS_BLOCK_SIZE_4K=4096
FS_BLOCK_SIZE_64K=65536
FS_BLOCK_SIZE_1M=$((1 * MB))

DMTHIN_CHUNK_SIZE_64K=65536
DMTHIN_CHUNK_SIZE_1M=$((1 * MB))

# File size categories (in KB) - for file creation patterns
# These are for the "small", "mixed", "large" fragmentation patterns
SMALL_FILE_MIN_KB=3
SMALL_FILE_MAX_KB=7
MEDIUM_FILE_MIN_KB=20
MEDIUM_FILE_MAX_KB=100
LARGE_FILE_MIN_KB=259
LARGE_FILE_MAX_KB=2090

# Exact file size cases for per-file discard testing (in KB)
# Case 1: 4KB (1 FS block, 1/16th of 64KB dmthin chunk)
# Case 2: 20KB (5 FS blocks, ~1/3 of 64KB dmthin chunk)
# Case 3: 64KB (16 FS blocks, 1 full 64KB dmthin chunk)
# Case 4: 1MB (256 FS blocks, 16 x 64KB dmthin chunks)
FILE_SIZE_CASE_1_KB=4
FILE_SIZE_CASE_2_KB=20
FILE_SIZE_CASE_3_KB=64
FILE_SIZE_CASE_4_KB=1024

# Target size per volume (creates files until target reached)
TARGET_SIZE_MB=500  # Target ~500MB of files per volume for complex fragmentation

# File counts per batch (used in iterative create-delete cycles)
SMALL_BATCH_SIZE=200     # Create 200 small files per batch
MEDIUM_BATCH_SIZE=50     # Create 50 medium files per batch
LARGE_BATCH_SIZE=10      # Create 10 large files per batch

# Fragmentation pattern: percentage of files to shrink each cycle
# Pattern: Create large files -> Overwrite with smaller data -> Repeat
SHRINK_PERCENTAGE=40     # Shrink 40% of files by overwriting with smaller data
CREATE_DELETE_CYCLES=5   # Number of create->shrink cycles before final deletion
DELETE_PERCENTAGE=40     # Legacy - kept for compatibility

# Test iterations per scenario
REPEAT_COUNT=5

# Timing
FSTRIM_WAIT_SECONDS=5
DISCARD_SETTLE_SECONDS=3

# Scenario configurations (fs_block_kb:fs_discard_kb:dmthin_chunk_kb:dmthin_discard_kb:nvme_sector_kb)
# Scenario 1: Small discards - FS 4KB, DMthin 64KB, NVMe sector 0
SCENARIO_1="4:4:64:64:0"
# Scenario 2: FS 64KB discard, NVMe 1MB sector - tests coalescing
SCENARIO_2="4:64:64:64:1024"
# Scenario 3: FS 4KB, DMthin 1MB discard granularity
SCENARIO_3="4:4:64:1024:0"
# Scenario 4: FS 64KB, DMthin 1MB discard granularity
SCENARIO_4="4:64:64:1024:0"
# Scenario 5: FS 1MB discard gran, DMthin 64KB - large FS discards
SCENARIO_5="4:1024:64:64:0"

# Discard modes (order: fast modes first, autofstrim last since they need daemon)
MODE_DISCARD_ONLY="discard_only"              # inline discard on file delete (mount -o discard)
MODE_MANUAL_TRIM="manual_trim"                # manual pxctl volume trim start (autofstrim off)
MODE_AUTOFSTRIM_NODISCARD="autofstrim_nodiscard"  # autofstrim enabled, inline discard disabled
MODE_AUTOFSTRIM_DISCARD="autofstrim_discard"      # autofstrim enabled, inline discard enabled

# File patterns
PATTERN_SMALL="small_files"
PATTERN_MIXED="mixed_files"
PATTERN_LARGE="large_files"

# Legacy file counts (kept for reference, not used in new fragmentation pattern)
SMALL_FILE_COUNT=100    # Replaced by TARGET_SIZE_MB + batches
MEDIUM_FILE_COUNT=50    # Replaced by TARGET_SIZE_MB + batches
LARGE_FILE_COUNT=20     # Replaced by TARGET_SIZE_MB + batches

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="discard_test_$(date +%Y%m%d_%H%M%S).log"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "$LOG_FILE"
}

log_result() {
    echo -e "${GREEN}[RESULT]${NC} $1" | tee -a "$LOG_FILE"
}

# Parse scenario string into variables
parse_scenario() {
    local scenario=$1
    IFS=':' read -r FS_BLOCK_KB FS_DISCARD_KB DMTHIN_CHUNK_KB DMTHIN_DISCARD_KB NVME_SECTOR_KB <<< "$scenario"
    export FS_BLOCK_KB FS_DISCARD_KB DMTHIN_CHUNK_KB DMTHIN_DISCARD_KB NVME_SECTOR_KB
}

# Get scenario by number
get_scenario() {
    local num=$1
    case $num in
        1) echo "$SCENARIO_1" ;;
        2) echo "$SCENARIO_2" ;;
        3) echo "$SCENARIO_3" ;;
        4) echo "$SCENARIO_4" ;;
        5) echo "$SCENARIO_5" ;;
        *) echo "" ;;
    esac
}

# Generate random number in range
random_in_range() {
    local min=$1
    local max=$2
    echo $(( RANDOM % (max - min + 1) + min ))
}

# Generate random file size in KB for pattern
get_random_file_size_kb() {
    local pattern=$1
    case $pattern in
        "$PATTERN_SMALL")
            random_in_range $SMALL_FILE_MIN_KB $SMALL_FILE_MAX_KB
            ;;
        "$PATTERN_MIXED")
            if [ $(random_in_range 0 1) -eq 0 ]; then
                random_in_range $SMALL_FILE_MIN_KB $SMALL_FILE_MAX_KB
            else
                random_in_range $MEDIUM_FILE_MIN_KB $MEDIUM_FILE_MAX_KB
            fi
            ;;
        "$PATTERN_LARGE")
            random_in_range $LARGE_FILE_MIN_KB $LARGE_FILE_MAX_KB
            ;;
        *)
            random_in_range $SMALL_FILE_MIN_KB $SMALL_FILE_MAX_KB
            ;;
    esac
}

