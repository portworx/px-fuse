# Fastpath Volume Discard Tests

Standalone tests for evaluating discard behavior on fast path volumes with various
filesystem and dmthin configurations. These tests use `pxctl` commands to control
PX's autofstrim logic while keeping the test execution simple and independent.

## Overview

These tests evaluate discard (TRIM) operations across different layers:
- Filesystem layer (ext4/xfs) - controlled via mount options
- PX autofstrim daemon - controlled via `pxctl` commands
- DM-thin layer - chunk-based space reclamation
- NVMe/storage layer - backend discard support

## Quick Start

```bash
# Make scripts executable
chmod +x *.sh

# Run a quick test
./quick_test.sh /mnt/pxvol <volume_id> [pool_id] [mode]

# Analyze current discard configuration
./analyze_discards.sh /mnt/pxvol <pool_id> [volume_id]

# Run full test suite
./run_tests.sh /mnt/pxvol --vol-id <volume_id>
```

## Test Scenarios

### Scenario 1
- FS block size: 4KB
- FS discard granularity: 4KB
- DMthin chunk size: 64KB
- DMthin discard granularity: 64KB

### Scenario 2
- FS block size: 4KB
- FS discard granularity: 64KB
- DMthin chunk size: 64KB
- DMthin discard granularity: 64KB
- NVMe sector size: 1MB

### Scenario 3
- FS block size: 4KB
- FS discard granularity: 4KB
- DMthin chunk size: 64KB
- DMthin discard granularity: 1MB

### Scenario 4
- FS block size: 4KB
- FS discard granularity: 64KB
- DMthin chunk size: 64KB
- DMthin discard granularity: 1MB

### Scenario 5
- FS block size: 4KB
- FS discard granularity: 1MB
- DMthin chunk size: 64KB
- DMthin discard granularity: 64KB

## Discard Modes

1. **autofstrim_nodiscard**: Run autofstrim without filesystem's discard mount option
2. **autofstrim_discard**: Run autofstrim with filesystem's discard mount option
3. **discard_only**: Only filesystem discard, autofstrim turned off

## File Size Patterns

1. **small_files**: 3-7KB files created and deleted repeatedly
2. **mixed_files**: Combination of small (3-7KB) and medium (20-100KB) files
3. **large_files**: Large files (256KB-2MB) spanning multiple dmthin chunks

## Usage

```bash
# Run all tests on mounted volume
./run_tests.sh /mnt/pxvol --vol-id 123456789

# Run specific scenario with specific mode
./run_tests.sh /mnt/pxvol --vol-id 123456789 --scenario 1 --mode autofstrim_nodiscard

# Run only file size cases (4KB, 20KB, 64KB, 1MB)
./run_tests.sh /mnt/pxvol --vol-id 123456789 --scenario 2 --cases-only

# Run with specific file pattern
./run_tests.sh /mnt/pxvol --vol-id 123456789 --pattern small_files

# Quick single test for fast iteration
./quick_test.sh /mnt/pxvol 123456789 0 autofstrim_nodiscard

# Analyze discard configuration and efficiency
./analyze_discards.sh /mnt/pxvol 0 123456789
```

## Requirements

- Root access (for pxctl and sysfs access)
- PX installed and running
- Fast path volume created and mounted
- `pxctl` available at /opt/pwx/bin/pxctl

## How It Works

1. **Configuration**: Scripts use `pxctl` to configure autofstrim and nodiscard settings
2. **File Operations**: Creates/deletes files of various sizes
3. **Discard Modes**:
   - `autofstrim_nodiscard`: Volume mounted without discard, PX autofstrim handles TRIM
   - `autofstrim_discard`: Volume mounted with discard + PX autofstrim
   - `discard_only`: Inline filesystem discard, no autofstrim
4. **Statistics**: Collects metrics from filesystem, dmthin, and PX layers
5. **Analysis**: Compares space before/after to measure discard efficiency

## Output

Tests output:
- Discarded blocks/chunks at each layer
- Unallocated space statistics
- Discard operation timing
- Space reclamation efficiency
- Granularity mismatch impact analysis

Results are saved to `discard_test_<timestamp>.log`

## Files

- `run_tests.sh` - Main test runner for full test matrix
- `quick_test.sh` - Quick single test for fast iteration
- `analyze_discards.sh` - Analyze discard config and efficiency
- `test_scenario.sh` - Individual scenario execution
- `px_helpers.sh` - PX/pxctl helper functions
- `discard_stats.sh` - Statistics collection functions
- `file_ops.sh` - File creation/deletion helpers
- `config.sh` - Configuration and constants

