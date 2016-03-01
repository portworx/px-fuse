# PX-FUSE module
Exports a control plane to create virtual block devices in the linux namespace. Piggy-backs on FUSE transport to act as a conduit between kernel and user space. 

## Requirements
Requires kernel >= 3.10

## Building the PX-FUSE RPM for your kernel
```
# cd rpm
# pwd
/root/px-fuse/rpm
# uname -r
3.10.0-123.9.3.el7.x86_64
# #Make sure you have the kernel headers... if not, get them.
# ls /usr/src/kernels/
3.10.0-123.9.3.el7.x86_64
# KERNELPATH=/usr/src/kernels/3.10.0-123.el7.x86_64 VERSION=3.10.0 REVISION=123.9.3.el7 ./buildrpm.sh
# rpm -Uvh /root/px-fuse/rpm/px/RPMS/x86_64/px-3.10.0-123.9.3.el7.x86_64.rpm
```
