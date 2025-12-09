#!/bin/bash
# File operation helpers for discard testing

source "$(dirname "$0")/config.sh"

#######################################
# File creation functions
#######################################

# Create a single file of specific size
create_file() {
    local path=$1
    local size_kb=$2
    dd if=/dev/urandom of="$path" bs=1K count="$size_kb" conv=fsync status=none 2>/dev/null
}

# Create multiple small files (3-7KB)
create_small_files() {
    local base_path=$1
    local count=${2:-$SMALL_FILE_COUNT}
    local prefix=${3:-"small"}
    
    log_info "Creating $count small files (3-7KB) at $base_path..."
    mkdir -p "$base_path"
    
    for i in $(seq 1 $count); do
        local size=$(random_in_range $SMALL_FILE_MIN_KB $SMALL_FILE_MAX_KB)
        create_file "${base_path}/${prefix}_${i}.dat" "$size"
    done
    sync
    log_info "Created $count small files"
}

# Create multiple medium files (20-100KB)
create_medium_files() {
    local base_path=$1
    local count=${2:-$MEDIUM_FILE_COUNT}
    local prefix=${3:-"medium"}
    
    log_info "Creating $count medium files (20-100KB) at $base_path..."
    mkdir -p "$base_path"
    
    for i in $(seq 1 $count); do
        local size=$(random_in_range $MEDIUM_FILE_MIN_KB $MEDIUM_FILE_MAX_KB)
        create_file "${base_path}/${prefix}_${i}.dat" "$size"
    done
    sync
    log_info "Created $count medium files"
}

# Create multiple large files (256KB-2MB)
create_large_files() {
    local base_path=$1
    local count=${2:-$LARGE_FILE_COUNT}
    local prefix=${3:-"large"}
    
    log_info "Creating $count large files (256KB-2MB) at $base_path..."
    mkdir -p "$base_path"
    
    for i in $(seq 1 $count); do
        local size=$(random_in_range $LARGE_FILE_MIN_KB $LARGE_FILE_MAX_KB)
        create_file "${base_path}/${prefix}_${i}.dat" "$size"
    done
    sync
    log_info "Created $count large files"
}

# Create mixed file set (small + medium interleaved)
create_mixed_files() {
    local base_path=$1
    local small_count=${2:-$SMALL_FILE_COUNT}
    local medium_count=${3:-$MEDIUM_FILE_COUNT}
    
    log_info "Creating mixed files: $small_count small + $medium_count medium..."
    mkdir -p "$base_path"
    
    local total=$((small_count + medium_count))
    local small_created=0
    local medium_created=0
    
    for i in $(seq 1 $total); do
        # Alternate between small and medium, with some randomness
        if [ $((RANDOM % 2)) -eq 0 ] && [ $small_created -lt $small_count ]; then
            local size=$(random_in_range $SMALL_FILE_MIN_KB $SMALL_FILE_MAX_KB)
            create_file "${base_path}/mixed_s${small_created}.dat" "$size"
            small_created=$((small_created + 1))
        elif [ $medium_created -lt $medium_count ]; then
            local size=$(random_in_range $MEDIUM_FILE_MIN_KB $MEDIUM_FILE_MAX_KB)
            create_file "${base_path}/mixed_m${medium_created}.dat" "$size"
            medium_created=$((medium_created + 1))
        elif [ $small_created -lt $small_count ]; then
            local size=$(random_in_range $SMALL_FILE_MIN_KB $SMALL_FILE_MAX_KB)
            create_file "${base_path}/mixed_s${small_created}.dat" "$size"
            small_created=$((small_created + 1))
        fi
    done
    sync
    log_info "Created mixed files: $small_created small + $medium_created medium"
}

# Create files with truly random, non-compressible data - Fill to 100%
create_files_to_fill() {
    local base_path=$1
    local file_size_kb=$2
    local target_fill_percent=${3:-100}  # Fill to 100% by default
    
    local available_kb=$(get_fs_free_space_kb "$(dirname "$base_path")")
    local target_usage_kb=$((available_kb * target_fill_percent / 100))
    local file_count=$((target_usage_kb / file_size_kb))
    
    log_info "Creating $file_count files of ${file_size_kb}KB each (filling to ${target_fill_percent}%)"
    
    for i in $(seq 1 "$file_count"); do
        # Use /dev/urandom for truly random, non-compressible data
        dd if=/dev/urandom of="${base_path}/fill_${i}.dat" bs=1024 count="$file_size_kb" 2>/dev/null
        
        if [ $((i % 100)) -eq 0 ]; then
            log_info "  Created $i/$file_count files..."
        fi
    done
    
    sync
    echo "$file_count"
}

#######################################
# File deletion functions
#######################################

# Delete all files in a directory
delete_all_files() {
    local path=$1
    log_info "Deleting all files in $path..."
    rm -rf "${path:?}"/*
    sync
}

# Delete files matching a pattern
delete_files_pattern() {
    local path=$1
    local pattern=$2
    log_info "Deleting files matching $pattern in $path..."
    rm -f "${path}"/${pattern}
    sync
}

# Delete specific file sizes (for Case tests)
delete_file_of_size() {
    local base_path=$1
    local size_kb=$2
    local filename="testfile_${size_kb}kb.dat"
    
    # Create file first
    log_info "Creating file of ${size_kb}KB..."
    create_file "${base_path}/${filename}" "$size_kb"
    sync
    sleep 1
    
    # Then delete
    log_info "Deleting file of ${size_kb}KB..."
    rm -f "${base_path}/${filename}"
    sync
}

#######################################
# File patterns for specific test cases
#######################################

# Run Case 1-4 file operations (4KB, 20KB, 64KB, 1MB)
run_file_size_cases() {
    local base_path=$1
    local callback=$2  # Function to call after each delete
    
    log_info "Running file size test cases..."
    
    # Case 1: 4KB file
    log_info "Case 1: 4KB file"
    delete_file_of_size "$base_path" 4
    [ -n "$callback" ] && $callback "Case1_4KB"
    
    # Case 2: 20KB file
    log_info "Case 2: 20KB file"
    delete_file_of_size "$base_path" 20
    [ -n "$callback" ] && $callback "Case2_20KB"
    
    # Case 3: 64KB file
    log_info "Case 3: 64KB file"
    delete_file_of_size "$base_path" 64
    [ -n "$callback" ] && $callback "Case3_64KB"
    
    # Case 4: 1MB file
    log_info "Case 4: 1MB (1024KB) file"
    delete_file_of_size "$base_path" 1024
    [ -n "$callback" ] && $callback "Case4_1MB"
}

# Repeated create-delete cycle
run_create_delete_cycle() {
    local base_path=$1
    local pattern=$2
    local iterations=${3:-$REPEAT_COUNT}
    local callback=$4
    
    log_info "Running $iterations create-delete cycles with pattern: $pattern"
    
    for i in $(seq 1 $iterations); do
        log_info "Cycle $i of $iterations"
        
        case $pattern in
            "$PATTERN_SMALL")
                create_small_files "$base_path" 30 "cycle${i}"
                ;;
            "$PATTERN_MIXED")
                create_mixed_files "$base_path" 20 10
                ;;
            "$PATTERN_LARGE")
                create_large_files "$base_path" 5 "cycle${i}"
                ;;
        esac
        
        sleep 1
        delete_all_files "$base_path"
        
        [ -n "$callback" ] && $callback "Cycle_${i}"
        sleep $DISCARD_SETTLE_SECONDS
    done
}

