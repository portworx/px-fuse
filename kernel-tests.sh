#!/bin/bash
# test various Linux kernel headers against px-fuse [201607.05MeV]

FILENAME=${0##*/}
DEF_URL=http://kernel.ubuntu.com/~kernel-ppa/mainline/
DEF_SEARCH="4.[4567]"

usage () {
	echo "usage: ${FILENAME} -huvn [regex-string]"
	echo ""
	echo " where"
	echo "    -h	print this message"
	echo "    -l	output to log file [default: STIN]"
	echo "    -n	perform scan for directories but DO NO actually test"
	#echo "    -s	specify regex to use to search for linux header directories [default: ${DEF_SEARCH}]"
	echo "    -u	use alternative URL to scan for linux headers [default: ${DEF_URL}]"
	echo "    -v	verbose error messages"
	echo "    [regex-string] is the optional string used to search the linux header "
	echo "          directory names to select them for testing [default: ${DEF_SEARCH}]"
	exit 2
}

OPT_N=0	# really perform test
OPT_V=0
OPT_L=
SEARCH=${DEF_SEARCH}
URL=${DEF_URL}
while getopts ":hl:ns:u:v" opt; do
	case $opt in
	l) OPT_L=$OPTARG;;
	n) OPT_N=1;;	# disable actual test
	s) SEARCH=$OPTARG;;
	u) URL=$OPTARG;;
	v) OPT_V=1;;
	h|\?) usage;;
	esac
done
[ "$SEARCH" == "" ] && echo "-s cannot be blank" && exit 2
shift $((OPTIND-1))		# point $@ to regex-string
if [ "$@" != "" ]; then SEARCH=$@; fi

test_kernel () {
# $1=single kernel package to test against (won't work if there's multiples)
	autoreconf && ./configure
	export KERNELPATH="/usr/src/${1}"
	make
	if [ $? -eq 0 ]; then 
		echo "--- PASS: ${1}"
	else
		echo "--- FAIL: ${1}"
	fi
	make clean
	# don't bother testing if px.ko can be installed since it probably can't
	# unless the linux kernel matches what's currently running
	#insmod px.ko
	#if [ $? -eq 0 ]; then
	# 	echo "    PASS: insmod ${1}"
	# 	rmmod px.ko
	#else
	# 	echo "    FAIL: insmod ${1}"
	#fi
}

get_deb () {
# $1 - URL of linux header deb files
	debs=`curl -s ${1} | grep "^<tr>" | sed -e "s/^.*href=\"//" -e "s/\">.*$//" | grep linux-headers | egrep "all.deb|generic.*amd64" `
	[ "${debs}" == "" ] && return 0
	# this is a list of at least 2 deb files...download and install them together
	deb_files=
	packages=
	for d in ${debs} ; do
		wget -q "${1}${d}"
		d=`echo ${1}${d} | sed -e "s/^.*linux-headers/linux-headers/"`
		# deb file isn't necessarily packages name, so extract using dpkg -I
		p=`dpkg -I ${d} | awk '/Package/{print $2}'`
		deb_files="${deb_files} ${d}"
		packages="${packages} ${p}"
	done
	dpkg -i ${deb_files}
	# test each header individually, although that may not be necessary
	# only the generic header will build, only allow that one to to test
	for p in ${packages}; do
		if [ "`echo ${p} | grep generic`X" != "X" ]; then test_kernel ${p}; fi
	done
	dpkg -r ${packages}
	rm -f ${deb_files}
}

# will return blank if nothing found
# NOTE: all the linux header directories start with "v"
dirs=`curl -s ${URL} | grep "^<tr>" | sed -e "s/^.*href=\"//" -e "s/\">.*$//" | egrep "^v${SEARCH}"`
if [ "$dirs" == "" ]; then
	printf "no linux headers found for '%s'\n" $SEARCH
	exit 1
fi
# note: w/o "", shell converts to a single line with entries separated by space
TOTAL=`echo "${dirs}" | wc -l`
[ $OPT_V -ne 0 ] && echo "${TOTAL} linux header directories found"

# loop through directories found
typeset -F SECONDS
COUNT=1
for d in ${dirs}; do
	echo -n "=== RUN ${COUNT}/${TOTAL} ${d} "
	start=`date +%s.%N`
	get_deb ${DEF_URL}${d}
	stop=`date +%s.%N`
	duration=$( echo "$stop - $start" | bc -l )
	echo " (${duration}s)"
	COUNT=$((COUNT + 1))
done

# these directories contain patched headers that require the base headers, some of which aren't available or I can't find
## get_dir http://kernel.ubuntu.com/~kernel-ppa/mainline/daily/
## get_dir http://kernel.ubuntu.com/~kernel-ppa/mainline/drm-intel-next/
## get_dir http://kernel.ubuntu.com/~kernel-ppa/mainline/drm-intel-nightly/
## get_dir http://kernel.ubuntu.com/~kernel-ppa/mainline/drm-next/
## get_dir http://kernel.ubuntu.com/~kernel-ppa/mainline/linux-3.13.y.z-queue/
## get_dir http://kernel.ubuntu.com/~kernel-ppa/mainline/linux-3.13.y.z-review/
## get_dir http://kernel.ubuntu.com/~kernel-ppa/mainline/linux-3.16.y.z-queue/
## get_dir http://kernel.ubuntu.com/~kernel-ppa/mainline/linux-3.16.y.z-review/
## get_dir http://kernel.ubuntu.com/~kernel-ppa/mainline/linux-3.19.y.z-queue/
## get_dir http://kernel.ubuntu.com/~kernel-ppa/mainline/linux-3.19.y.z-review/
