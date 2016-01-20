#!/bin/bash

[ -z "${KERNALPATH}" ] && KERNALPATH="/usr/src/kernels/$(/bin/uname -r)"
[ -z "${VERSION}" ] && VERSION="0.0.0"
[ -z "${REVISION}" ] && REVISION="0"

NAME=px
SUMMARY="PX-FUSE module"
DESCRIPTION="Exports a control plane to create virtual block devices in the linux namespace. Piggy-backs on FUSE transport to act as a conduit between kernel and user space."

export PLATFORM=$(/bin/uname -i)
export PROCESSOR=$(/bin/uname -p)
export BUILDDIR=${PWD}

export TOPDIR=${BUILDDIR}/px
export TMPPATH=${BUILDDIR}/rpmtmp

BLD_MACROS="--define '_topdir "${TOPDIR}"' --define '_tmppath "${TMPPATH}"' --macros=FILE:/dev/null"


RPMVERSION=${VERSION}-${REVISION}
RPMVERSION_DEFINES="--define 'pxrelease "${VERSION}"' --define 'release "${REVISION}"'"

MBUILDROOT=${BUILDDIR}/tmp/buildroot

RPMBLDROOT=${TOPDIR}/BUILD
RPMSRCROOT=${TOPDIR}/SOURCES
RPMRPMSROOT=${TOPDIR}/RPMS
RPMSRPMSROOT=${TOPDIR}/SRPMS
RPMSPECSROOT=${TOPDIR}/SPECS

BLDDIRS=" \
  ${TOPDIR} \
  ${TMPPATH} \
  ${MBUILDROOT} \
  ${RPMBLDROOT} \
  ${RPMSRCROOT} \
  ${RPMRPMSROOT} \
  ${RPMSRPMSROOT} \
  ${RPMSPECSROOT}"

for dir in ${BLDDIRS}; do mkdir -p ${dir}; done

PXSPEC=px.spec
cp -a ${BUILDDIR}/${PXSPEC} ${RPMSPECSROOT}/${PXSPEC}

EXTRA_DEFINES="--define 'kernalpath "${KERNALPATH}"' --define 'rpmdescription "${DESCRIPTION}"' --define 'required kernel >= 3.17.0'"

SOURCE_ROOT=${BUILDDIR}/..
RPM_NAME="${NAME}"
RPM_SUMMARY="${SUMMARY}"
RPM_DESCRIPTION="${DESCRIPTION}"
RPM_DEFINES="--define 'name "${RPM_NAME}"' --define 'summary "${RPM_SUMMARY}"' --define 'specsrcdir "${RPM_NAME}-src"' ${EXTRA_DEFINES}"

echo "--- Building target for ${RPM_NAME} ---"
mkdir -p ${MBUILDROOT}/${RPM_NAME}-src
cd ${SOURCE_ROOT} && tar --exclude .git --exclude rpm -czf - * | (cd ${MBUILDROOT}/${RPM_NAME}-src; tar -xzf -)
cd ${MBUILDROOT} && tar -czf ${RPMSRCROOT}/${RPM_NAME}-${RPMVERSION}.tar.gz ${RPM_NAME}-src
cd ${RPMSPECSROOT} && eval rpmbuild -ba ${BLD_MACROS[@]} ${RPMVERSION_DEFINES[@]} ${RPM_DEFINES[@]} ${PXSPEC}



