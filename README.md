# PX-FUSE module
Exports a control plane to create virtual block devices in the linux namespace. Piggy-backs on FUSE transport to act as a conduit between kernel and user space. 

## Requirements
Requires kernel >= 3.10

### Building the PX-FUSE rpm/dpkg in docker
```
# export OUTPATH=/opt/pwx; docker run -v ${OUTPATH}:${OUTPATH} -v /usr/src:/usr/src -ti -e OUTPATH=$OUTPATH portworx/px-fuse:dev
```

### Building the PX-FUSE module on Ubuntu
```
# apt-get install dh-autoreconf
# git clone https://github.com/portworx/px-fuse.git
# cd px-fuse/rpm
# # check your kernel version with 
# uname -a
3.19.0-43-generic
# # Make sure you have the kernel headers... if not, get them.
# ls /usr/src/linux-headers-<kernel version>
# KERNELPATH="/usr/src/linux-headers-3.19.0-43-generic" VERSION=3.19.0 REVISION=43 ./buildrpm.sh
# # This will generate an install package in px-fuse/rpm/px/RPMS/x86_64/
# dpkg --install px_<version>.deb
```

### Building the PX-FUSE RPM on CentOS
```
# git clone https://github.com/portworx/px-fuse.git
# cd px-fuse/rpm
# uname -r
3.10.0-123.9.3.el7.x86_64
# # Make sure you have the kernel headers... if not, get them.
# ls /usr/src/kernels/
3.10.0-123.9.3.el7.x86_64
# KERNELPATH=/usr/src/kernels/3.10.0-123.el7.x86_64 VERSION=3.10.0 REVISION=123.9.3.el7 ./buildrpm.sh
# rpm -Uvh /root/px-fuse/rpm/px/RPMS/x86_64/px-3.10.0-123.9.3.el7.x86_64.rpm
```
