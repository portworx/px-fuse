#!/bin/bash

KVERSION=`uname -r`
CHECK_PATHS="$KERNELPATH /usr/src/kernels/$KVERSION /usr/src/linux-headers-$KVERSION"

function check_kernel_headers() {
    for p in $CHECK_PATHS
    do
        echo checking $p
        if [  -d $p ]; then
            KERNELPATH=$p
            echo found $p
            break
        fi
    done
}


check_kernel_headers

if [ -z $KERNELPATH ]; then
	apt-get install linux-headers-$KVERSION
	check_kernel_headers
fi

if [ -z $KERNELPATH ]; then
	echo "Failed to install/locate kernel headers for $KVERSION"
	exit 1
fi

export KERNELPATH
exec "$@"
