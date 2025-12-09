#!/bin/bash
# Master script to run all discard test combinations
# This runs each TEST_MODE × TEST_PATTERN combination sequentially
# Each combination runs all 5 scenarios × 4 file cases × 5 parallel runs

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/run_all_discard_tests_$(date +%Y%m%d_%H%M%S).log"

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" | tee -a "$LOG_FILE"
}

# Test modes (sequential - cluster settings change between modes)
# 1. discard_only: mount option=discard (inline discards), autofstrim OFF
# 2. manual_trim: mount option=nodiscard, run fstrim manually, autofstrim OFF
# 3. autofstrim: mount option=nodiscard, autofstrim ON (auto trim by portworx)
MODES=("discard_only" "manual_trim" "autofstrim")

# Test patterns (data reduction patterns)
# 1. create_delete: Fill 100% → delete 90% → repeat
# 2. create_shrink: Fill 100% with GB files → shrink to bytes
PATTERNS=("create_delete" "create_shrink")

log "=========================================="
log "COMPREHENSIVE DISCARD TEST SUITE"
log "=========================================="
log "Modes: ${MODES[*]}"
log "Patterns: ${PATTERNS[*]}"
log "Scenarios: 1-5 (different granularity configs)"
log "File Cases: 4KB, 20KB, 64KB, 1MB"
log "Parallel Runs: 5 per scenario"
log "=========================================="

TRY_NUM=1

for pattern in "${PATTERNS[@]}"; do
    for mode in "${MODES[@]}"; do
        log ""
        log "=========================================="
        log "Starting: TRY_NUM=$TRY_NUM MODE=$mode PATTERN=$pattern"
        log "=========================================="
        
        cd "$SCRIPT_DIR"
        
        # Run the test
        if TRY_NUM=$TRY_NUM TEST_MODE=$mode TEST_PATTERN=$pattern ./run_autofstrim_tests.sh 2>&1 | tee -a "$LOG_FILE"; then
            log "[PASS] Completed: TRY_NUM=$TRY_NUM MODE=$mode PATTERN=$pattern"
        else
            log "[FAIL] Failed: TRY_NUM=$TRY_NUM MODE=$mode PATTERN=$pattern"
        fi
        
        TRY_NUM=$((TRY_NUM + 1))
        
        # Brief pause between test runs
        sleep 10
    done
done

log ""
log "=========================================="
log "ALL TESTS COMPLETED"
log "=========================================="
log "Results directories:"
ls -d "${SCRIPT_DIR}"/try_* 2>/dev/null | tee -a "$LOG_FILE"
log "=========================================="

