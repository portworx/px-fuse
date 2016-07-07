#!/bin/bash
# test various Linux kernel headers against px-fuse [201607.07MeV]
# requires dh-reconfig and bc packages on Ubuntu
# requires root because it installs packages

[ "`id | grep 'uid=0(root)'`x" == "x" ] && echo "must be run as root" && exit 2

FILENAME=${0##*/}
DEF_URL=http://kernel.ubuntu.com/~kernel-ppa/mainline/
DEF_SEARCH="4.[4567]"

usage () {
	echo "usage: ${FILENAME} -huvn [regex-string]"
	echo ""
	echo " where"
	echo "    -h	print this message"
	echo "    -l	output to log file"
	echo "    -n	perform scan for directories but DO NO actually test"
	echo "    -s	specify regex to use to search for linux header directories [default: ${DEF_SEARCH}]"
	echo "    -u	use alternative URL to scan for linux headers [default: ${DEF_URL}]"
	echo "    -v	verbose error messages"
	echo "    [regex-string] is the optional string used to search the linux header "
	echo "    directory names to select them for testing [default: ${DEF_SEARCH}]"
	exit 2
}

OPT_N=0	# really perform test
OPT_V=0
OPT_L=
SEARCH=${DEF_SEARCH}
URL=${DEF_URL}
while getopts ":hl:ns:u:v" opt; do
	case $opt in
	l) OPT_L=$OPTARG; cat /dev/null > $OPTARG;; # clear out file so it start empty
	n) OPT_N=1;;	# disable actual test
	s) SEARCH=$OPTARG;;
	u) URL=$OPTARG;;
	v) OPT_V=1;;
	h|\?) usage;;
	esac
done
shift $((OPTIND-1))		# point $@ to regex-string
[ "$SEARCH" == "" ] && echo "-s cannot be blank" && exit 2
if [ "${@}x" != "x" ]; then SEARCH=$@; fi

test_kernel () {
# $1=single kernel package to test against (won't work if there's multiples)
# outputs FINAL_STATUS variable to 1 if a build failure happened
	tmp_deb=`mktemp`
	kstart=`date +%s.%N`
	autoreconf && ./configure
	export KERNELPATH="/usr/src/${1}"
	make
	ret=$?
	kstop=`date +%s.%N`
	kdur=$( echo "$kstop - $kstart" | bc -l )
	if [ $ret -eq 0 ]; then 
		printf "%s %s (%.2fs)\n" "--- PASS:" ${1} ${kdur}
	else
		printf "%s %s (%.2fs)\n" "--- FAIL:" ${1} ${kdur}
		FINAL_STATUS=1
	fi
	make clean
	rm $tmp_deb
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
		if [ "`echo ${p} | grep generic`X" != "X" ]; then 
			test_kernel ${p}
		fi
	done
	dpkg -r ${packages}
	rm -f ${deb_files}
}

#================================================================================
# will return blank if nothing found
# NOTE: all the linux header directories start with "v"
dirs=`curl -s ${URL} | grep "^<tr>" | sed -e "s/^.*href=\"//" -e "s/\">.*$//" | egrep "^v${SEARCH}"`
[ "$dirs" == "" ] && printf "no linux headers found for v'%s'\n" $SEARCH && exit 1

# w/o "", shell converts to a single line with entries separated by space
TOTAL=`echo "${dirs}" | wc -l`

FINAL_STATUS=0		# assume all will complete OK
tmp_file=`mktemp`
COUNT=1

# loop through directories found
for d in ${dirs}; do
	echo -n "=== RUN ${COUNT}/${TOTAL} ${d} "
	[ $OPT_L ] && echo -n "=== RUN ${COUNT}/${TOTAL} ${d} " >> $OPT_L

	start=`date +%s.%N`
	[ $OPT_N -eq 0 ] && get_deb ${DEF_URL}${d} > ${tmp_file} 2>&1
	stop=`date +%s.%N`
	deb_dur=$( echo "$stop - $start" | bc -l )
	if [ $OPT_N -eq 0 ]; then
		printf " (%.2fs)\n" ${deb_dur}
	else
		printf " (%fs) [noop]\n" ${deb_dur}
	fi
	[ $OPT_L ] &&  printf " (%.2fs)\n" ${deb_dur} >> $OPT_L

	#print to terminal if there's a build fail or if we specified VERBOSE
	if [ "$OPT_V" -eq 1 -o "`grep '^--- FAIL' $tmp_file`" != "" ]; then
		cat $tmp_file
	else
		grep --color=auto "^---" $tmp_file
	fi
	[ $OPT_L ] && cat $tmp_file >> $OPT_L

	COUNT=$((COUNT + 1))
done
rm ${tmp_file}
exit $FINAL_STATUS
