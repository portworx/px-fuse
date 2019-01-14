#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage $0 <base test name> <target1> <target2> <target3> ..."
    exit 1
fi

groupreporting="--group_reporting"

testname=$1    # base_name for the test
ARGS=("$@")
echo length of ARGS: ${#ARGS}

for ((i=1; i<$#; i++))
do
    echo target: ${ARGS[$i]}
    jobs_options="$jobs_options --name=${ARGS[$i]}"
done
echo $jobs_options

skip_prepopulate=true # skip population of device
test_readonly=false    # readonly test, true or false
test_mix=false       # enable test for readwrite mix traffic
test_4konly=false     # 4k tests only, true or false
rw_range="read" # limit to few profiles if needed

runtime=30  # default 30 (seconds)
ramp_time=5  # default 5
size=40G
size_prepopulate=75G
runtime_prepopulate=300  # default 300 (seconds)
# fio="echo fio"  # for dry-run
fio="fio"
iodepth_range="64"  # for dry-run
#iodepth_range="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 18 20 22 24 26 28 30 32 36 40 44 48 52 56 60 64"
#iodepth_range="1 8 16 32 64"

# global options for fio command
global_options="$groupreporting --output-format=json --ioengine=libaio --time_based --direct=1 --invalidate=1 --filename_format=\$jobname"
global_options_prepopulate="$global_options --runtime=$runtime_prepopulate --size=$size_prepopulate --end_fsync=1"
global_options_run="$global_options --runtime=$runtime --ramp_time=$ramp_time --size=$size"

set -x  # echo commands

# initialize the volume
if [ "$skip_prepopulate" != true ]; then
    $fio --rw=write --iodepth=32 --bs=16k $global_options_prepopulate $jobs_options
fi

fn_results=${testname}_results.txt
cat /dev/null > $fn_results  # empty the results file

# sequential and random read/write
if [ "$rw_range" == "" ]; then
    rw_range="read write randread randwrite"

    if [ "$test_readonly" = true ]; then
        rw_range="read randread"
    fi
fi

for rw in $rw_range ; do
    for iodepth in $iodepth_range ; do $fio --rw=$rw --iodepth=$iodepth --bs=4k $global_options_run $jobs_options 1>>${fn_results}  ; done
    if [ "$test_4konly" != true ]; then
        for iodepth in $iodepth_range ; do $fio --rw=$rw --iodepth=$iodepth --bs=16k $global_options_run --iodepth=$iodepth $jobs_options 1>>${fn_results} ; done
    fi
done

if [ "$test_readonly" != true ] && [ "$test_mix" = true ]; then
    # random read-and-write, 4k
    for iodepth in $iodepth_range ; do $fio --rw=randrw --rwmixwrite=50 --iodepth=$iodepth --bs=4k $global_options_run $jobs_options 1>>${fn_results} ; done
    for iodepth in $iodepth_range ; do $fio --rw=randrw --rwmixwrite=20 --iodepth=$iodepth --bs=4k $global_options_run $jobs_options 1>>${fn_results} ; done
fi

if [ "$test_readonly" != true ] && [ "$test_mix" = true ]; then
    for iodepth in $iodepth_range ; do $fio --rw=randrw --rwmixwrite=50 --iodepth=$iodepth --bs=16k $global_options_run $jobs_options 1>>${fn_results} ; done
    for iodepth in $iodepth_range ; do $fio --rw=randrw --rwmixwrite=20 --iodepth=$iodepth --bs=16k $global_options_run $jobs_options 1>>${fn_results} ; done
fi

