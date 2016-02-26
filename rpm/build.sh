#!/bin/bash -xe

REV=$1
if [ "x$REV" == "x" ] ; then
	echo "Usage: $0 <revision>"
	exit 1
fi

LOCALREPO="/etc/yum.repos.d/localrepo.repo"
if [ ! -f $LOCALREPO ]; then
    cp localrepo.repo $LOCALREPO
fi
yum clean all
yum repolist | grep localrepo

rm -rf out
mkdir out

rm -rf px rpmtmp  tmp
yum -y install --disablerepo="*" --enablerepo="localrepo" kernel-devel-3.10.0-229.14.1.el7.x86_64
KERNELPATH="/usr/src/kernels/3.10.0-229.14.1.el7.x86_64" VERSION=3.10.0 REVISION=229.14.1.el7 ./buildrpm.sh
cp -p px/RPMS/x86_64/* out/

rm -rf px rpmtmp  tmp
yum -y install --disablerepo="*" --enablerepo="localrepo" kernel-ml-devel-3.19.3-1.el7.elrepo.x86_64
KERNELPATH="/usr/src/kernels/3.19.3-1.el7.elrepo.x86_64" VERSION=3.19.3 REVISION=1.el7.elrepo ./buildrpm.sh
cp -p px/RPMS/x86_64/* out/

rm -rf px rpmtmp  tmp
yum -y install --disablerepo="*" --enablerepo="localrepo" kernel-devel-3.10.0-327.10.1.el7.x86_64
KERNELPATH="/usr/src/kernels/3.10.0-327.10.1.el7.x86_64" VERSION=3.10.0 REVISION=327.10.1.el7 ./buildrpm.sh
cp -p px/RPMS/x86_64/* out/

ls out/
