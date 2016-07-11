# PX-FUSE module
Exports a control plane to create virtual block devices in the linux namespace. Piggy-backs on FUSE transport to act as a conduit between kernel and user space. 

## Requirements
Requires kernel >= 3.10

### Building the PX-FUSE rpm/dpkg in docker

```
# export OUTPATH=/opt/pwx; docker run -v ${OUTPATH}:${OUTPATH} -v /usr/src:/usr/src -ti -e OUTPATH=$OUTPATH portworx/px-fuse
```

### Building the PX-FUSE module on ubuntu/debian

```

# git clone https://github.com/portworx/px-fuse.git
# cd px-fuse
# autoreconf && ./configure
# export KERNELPATH="/usr/src/linux-headers-`uname -r`"
# make 
# insmod px.ko

```

### Building the PX-FUSE package on Ubuntu
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

### Verifying PX-FUSE will build on Ubuntu

`kernel-tests.sh` is a script which can verify if headers from alternate kernels will build with PX-FUSE.  It can 

- downloads batches of kernel header files one at a time from the Ubuntu site.
- selects of what headers to test is based on a regular expression
- installs headers and attempts to build px-fuse
- reports success or failure and outputs log of failed builds
- optionally, it can output to separate log file

To find out how many headers are in a particular regex string, use the -n (noop) feature to display them.
For example,

    ./kernel-tests.sh -n 4.[012]

will scan for the headers for versions 4.0-4.2.

```
usage: kernel-tests.sh -huvn [regex-string]

 where
    -h  print this message
    -l  output to log file
    -n  perform scan for directories but DO NO actually test
    -s  specify regex to use to search for linux header directories [default: 4.[4567]]
    -u  use alternative URL to scan for linux headers [default: http://kernel.ubuntu.com/~kernel-ppa/mainline/]
    -v  verbose error messages
    [regex-string] is the optional string used to search the linux header 
    directory names to select them for testing [default: 4.[4567]]
```
