# PX-FUSE module
Exports a control plane to create virtual block devices in the linux namespace. Piggy-backs on FUSE transport to act as a conduit between kernel and user space. 

## Requirements
Requires kernel >= 3.10

### Building the PX-FUSE module on ubuntu/debian

```
# git clone https://github.com/portworx/px-fuse.git
# cd px-fuse
# autoreconf && ./configure
# export KERNELPATH="/usr/src/linux-headers-`uname -r`"
# make 
# insmod px.ko

```

### Building the PX-FUSE module on ubuntu/debian

```
git clone  https://github.com/portworx/px-fuse.git
cd px-fuse && git checkout main
apt install -y autoconf
apt-get install -y linux-headers-$(uname -r)
apt-get install -y build-essential

```

### Building the PX-FUSE module on RHEL

```
git clone  https://github.com/portworx/px-fuse.git
cd px-fuse && git checkout main
dnf groupinstall "Development Tools"
dnf install autoconf automake
sudo dnf install kernel-devel-$(uname -r)
sudo dnf install kernel-devel
autoreconf && ./configure;KERNELPATH=/usr/src/linux-headers-$(uname -r); make

```

### Running Unit Tests on the build PX-FUSE

```
# Build and run tests
cd px-fuse
autoreconf && ./configure;KERNELPATH=/usr/src/linux-headers-$(uname -r); make; make test_clean; make pxd_test
./test/pxd_test
```

### Sample output on ubuntu for building PX-FUSE module and running Unit Tests
#### Sample Compile Command with output:
```
autoreconf && ./configure;KERNELPATH=/usr/src/linux-headers-$(uname -r);make clean; make
```
```
checking for g++... g++
checking whether the C++ compiler works... yes
checking for C++ compiler default output file name... a.out
checking for suffix of executables...
checking whether we are cross compiling... no
checking for suffix of object files... o
checking whether we are using the GNU C++ compiler... yes
checking whether g++ accepts -g... yes
checking for gcc... gcc
checking whether we are using the GNU C compiler... yes
checking whether gcc accepts -g... yes
checking for gcc option to accept ISO C89... none needed
checking whether make sets $(MAKE)... yes
checking how to run the C preprocessor... gcc -E
checking for grep that handles long lines and -e... /usr/bin/grep
checking for egrep... /usr/bin/grep -E
checking for ANSI C header files... yes
checking for sys/types.h... yes
checking for sys/stat.h... yes
checking for stdlib.h... yes
checking for string.h... yes
checking for memory.h... yes
checking for strings.h... yes
checking for inttypes.h... yes
checking for stdint.h... yes
checking for unistd.h... yes
checking fcntl.h usability... yes
checking fcntl.h presence... yes
checking for fcntl.h... yes
checking for stdint.h... (cached) yes
checking for stdlib.h... (cached) yes
checking sys/ioctl.h usability... yes
checking sys/ioctl.h presence... yes
checking for sys/ioctl.h... yes
checking sys/param.h usability... yes
checking sys/param.h presence... yes
checking for sys/param.h... yes
checking for stdbool.h that conforms to C99... yes
checking for _Bool... yes
checking for inline... inline
checking for size_t... yes
checking for ssize_t... yes
checking for uint32_t... yes
checking for uint64_t... yes
checking for memset... yes
configure: creating ./config.status
config.status: creating Makefile
config.status: creating config.h
config.status: config.h is unchanged
Kernel version 5.4 supports fastpath.
Kernel version 5.4 supports blkmq driver model.
make -C /usr/src/linux-headers-5.4.0-107-generic  M=/root/git/go/src/github.com/pure-px/px-fuse clean
make[1]: Entering directory '/usr/src/linux-headers-5.4.0-107-generic'
Kernel version 5.4 supports fastpath.
Kernel version 5.4 supports blkmq driver model.
  CLEAN   /root/git/go/src/github.com/pure-px/px-fuse/Module.symvers
make[1]: Leaving directory '/usr/src/linux-headers-5.4.0-107-generic'
Kernel version 5.4 supports fastpath.
Kernel version 5.4 supports blkmq driver model.
make  -C /usr/src/linux-headers-5.4.0-107-generic  M=/root/git/go/src/github.com/pure-px/px-fuse modules
make[1]: Entering directory '/usr/src/linux-headers-5.4.0-107-generic'
Kernel version 5.4 supports fastpath.
Kernel version 5.4 supports blkmq driver model.
  CC [M]  /root/git/go/src/github.com/pure-px/px-fuse/pxd.o
  CC [M]  /root/git/go/src/github.com/pure-px/px-fuse/dev.o
  CC [M]  /root/git/go/src/github.com/pure-px/px-fuse/iov_iter.o
  CC [M]  /root/git/go/src/github.com/pure-px/px-fuse/px_version.o
  CC [M]  /root/git/go/src/github.com/pure-px/px-fuse/kiolib.o
  CC [M]  /root/git/go/src/github.com/pure-px/px-fuse/pxd_bio_blkmq.o
  CC [M]  /root/git/go/src/github.com/pure-px/px-fuse/pxd_fastpath.o
  LD [M]  /root/git/go/src/github.com/pure-px/px-fuse/px.o
Kernel version 5.4 supports fastpath.
Kernel version 5.4 supports blkmq driver model.
  Building modules, stage 2.
  MODPOST 1 modules
  CC [M]  /root/git/go/src/github.com/pure-px/px-fuse/px.mod.o
  LD [M]  /root/git/go/src/github.com/pure-px/px-fuse/px.ko
make[1]: Leaving directory '/usr/src/linux-headers-5.4.0-107-generic'
```
#### Sample UnitTest Binary Compilation with output:
```
autoreconf && ./configure;KERNELPATH=/usr/src/linux-headers-$(uname -r); make; make test_clean; make pxd_test
```
```
checking for g++... g++
checking whether the C++ compiler works... yes
checking for C++ compiler default output file name... a.out
checking for suffix of executables...
checking whether we are cross compiling... no
checking for suffix of object files... o
checking whether we are using the GNU C++ compiler... yes
checking whether g++ accepts -g... yes
checking for gcc... gcc
checking whether we are using the GNU C compiler... yes
checking whether gcc accepts -g... yes
checking for gcc option to accept ISO C89... none needed
checking whether make sets $(MAKE)... yes
checking how to run the C preprocessor... gcc -E
checking for grep that handles long lines and -e... /usr/bin/grep
checking for egrep... /usr/bin/grep -E
checking for ANSI C header files... yes
checking for sys/types.h... yes
checking for sys/stat.h... yes
checking for stdlib.h... yes
checking for string.h... yes
checking for memory.h... yes
checking for strings.h... yes
checking for inttypes.h... yes
checking for stdint.h... yes
checking for unistd.h... yes
checking fcntl.h usability... yes
checking fcntl.h presence... yes
checking for fcntl.h... yes
checking for stdint.h... (cached) yes
checking for stdlib.h... (cached) yes
checking sys/ioctl.h usability... yes
checking sys/ioctl.h presence... yes
checking for sys/ioctl.h... yes
checking sys/param.h usability... yes
checking sys/param.h presence... yes
checking for sys/param.h... yes
checking for stdbool.h that conforms to C99... yes
checking for _Bool... yes
checking for inline... inline
checking for size_t... yes
checking for ssize_t... yes
checking for uint32_t... yes
checking for uint64_t... yes
checking for memset... yes
configure: creating ./config.status
config.status: creating Makefile
config.status: creating config.h
config.status: config.h is unchanged
Kernel version 5.4 supports fastpath.
Kernel version 5.4 supports blkmq driver model.
make  -C /usr/src/linux-headers-5.4.0-107-generic  M=/root/git/go/src/github.com/pure-px/px-fuse modules
make[1]: Entering directory '/usr/src/linux-headers-5.4.0-107-generic'
Kernel version 5.4 supports fastpath.
Kernel version 5.4 supports blkmq driver model.
Kernel version 5.4 supports fastpath.
Kernel version 5.4 supports blkmq driver model.
  Building modules, stage 2.
  MODPOST 1 modules
make[1]: Leaving directory '/usr/src/linux-headers-5.4.0-107-generic'
Kernel version 5.4 supports fastpath.
Kernel version 5.4 supports blkmq driver model.
Kernel version 5.4 supports fastpath.
Kernel version 5.4 supports blkmq driver model.
Building Tests ...
g++ -I. -std=c++11 test/pxd_test.cc test/pxd_fastpath_test.cc -lgtest -lboost_iostreams -lpthread -o test/pxd_test

```
#### Sample UnitTest Execution Output:
```
./test/pxd_test 2>&1 | grep -E "^\[.*(OK|PASSED|FAILED).*\]"
```
```
[       OK ] PxdTest.simple (156 ms)
[       OK ] PxdTest.device_size (3180 ms)
[       OK ] PxdTest.write (3247 ms)
[       OK ] PxdTest.read (3184 ms)
[       OK ] PxdTest.blkdiscard_ioctl (28355 ms)
[       OK ] PxdTest.AbortContextWithInFlightIO (48172 ms)
[       OK ] PxdTest.write_zeroes_enabled_native_path (3163 ms)
[       OK ] PxdTest.write_zeroes_disabled_native_path_no_capability (3159 ms)
[       OK ] PxdTest.write_zeroes_custom_discard_granularity (3171 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.simple_test_fastpath/BackingFile (103 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.simple_test_fastpath/LoopDevice (144 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.device_create_fastpath/BackingFile (2172 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.device_create_fastpath/LoopDevice (2285 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.device_attach_export_fastpath/BackingFile (2194 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.device_attach_export_fastpath/LoopDevice (2321 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.io_operations_fastpath/BackingFile (2183 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.io_operations_fastpath/LoopDevice (2348 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.device_detach_remove_fastpath/BackingFile (2189 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.device_detach_remove_fastpath/LoopDevice (2305 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.multiple_devices_fastpath/BackingFile (6378 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.multiple_devices_fastpath/LoopDevice (6493 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.error_handling_fastpath/BackingFile (7199 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.error_handling_fastpath/LoopDevice (7304 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.write_zeroes_disabled_fastpath_with_capability/BackingFile (2214 ms)
[       OK ] BackingDeviceTypes/PxdFastpathTest.write_zeroes_disabled_fastpath_with_capability/LoopDevice (2289 ms)
[  PASSED  ] 25 tests.

```