#!/bin/bash
# Script to clean up all test volumes before running comprehensive tests

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_info "=========================================="
log_info "CLEANING UP ALL TEST VOLUMES"
log_info "=========================================="

# Get list of all phase volumes
log_info "Finding all test volumes (phase1_vol*, phase2_vol*, phase3_vol*)..."
all_volumes=$(pxctl volume list 2>/dev/null | grep -E "phase[123]_vol" | awk '{print $1}' || true)

if [ -z "$all_volumes" ]; then
    log_success "No test volumes found. Nothing to clean up."
    exit 0
fi

# Count volumes
volume_count=$(echo "$all_volumes" | wc -l)
log_info "Found $volume_count test volumes to clean up"

# Clean up each volume
counter=1
for vol_id in $all_volumes; do
    log_info "[$counter/$volume_count] Cleaning up volume: $vol_id"
    
    # Get volume name
    vol_name=$(pxctl volume list | grep "$vol_id" | awk '{print $2}' || echo "unknown")
    
    # Try to unmount
    mount_path="/var/lib/osd/mounts/$vol_name"
    if [ -d "$mount_path" ]; then
        log_info "  Unmounting from $mount_path..."
        umount "$mount_path" 2>/dev/null || true
        pxctl host unmount --path "$mount_path" "$vol_id" 2>/dev/null || true
        rmdir "$mount_path" 2>/dev/null || true
    fi
    
    # Try to detach
    log_info "  Detaching volume..."
    pxctl host detach "$vol_id" 2>/dev/null || true
    sleep 1
    
    # Delete volume
    log_info "  Deleting volume..."
    pxctl volume delete "$vol_id" --force 2>/dev/null || true
    
    counter=$((counter + 1))
done

log_success "=========================================="
log_success "CLEANUP COMPLETE"
log_success "Deleted $volume_count volumes"
log_success "=========================================="

# Verify cleanup
remaining=$(pxctl volume list 2>/dev/null | grep -E "phase[123]_vol" | wc -l || echo "0")
if [ "$remaining" -eq 0 ]; then
    log_success "All test volumes successfully removed!"
else
    log_warn "Warning: $remaining test volumes still remain"
    log_warn "You may need to manually clean them up"
fi

