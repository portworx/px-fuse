#px-objs = pxd.o dev.o iov_iter.o px_version.o
px-objs = pxdnew.o px_version.o
obj-m = px.o

KBUILD_CPPFLAGS := -D__KERNEL__
PXDEFINES := -D__PXKERNEL__

ccflags-y := $(ADDCCFLAGS) -Wframe-larger-than=2048 -Werror -I$(src) $(KBUILD_CPPFLAGS) $(PXDEFINES)

KVERSION=$(shell uname -r)
ifndef KERNELPATH
ifeq ($(shell test -d "/usr/src/linux-headers-$(KVERSION)"; echo $$?),0)
     KERNELPATH=/usr/src/linux-headers-$(KVERSION)
else
     KERNELPATH=/usr/src/kernels/$(KVERSION)
endif
endif

ifeq ($(shell test -d $(KERNELPATH); echo $$?),1)
$(error Kernel path: $(KERNELPATH)  directory does not exist.)
endif

ifeq ($(shell test  -f "/usr/bin/bc"; echo $$?),0)
MINKVER=3.10
KERNELVER=$(shell echo $(KVERSION) | /bin/sed 's/-.*//' | /bin/sed 's/\(.*\..*\)\..*/\1/')
ifeq ($(shell echo "$(KERNELVER)>=$(MINKVER)" | /usr/bin/bc),0)
$(error Kernel version error: Build kernel version must be >= $(MINKVER).)
endif
endif

ifdef KERNELOTHER
KERNELOTHEROPT=O=$(KERNELOTHER)
endif

MAJOR=$(shell echo $(KVERSION) | awk -F. '{print $$1}')
MINOR=$(shell echo $(KVERSION) | awk -F. '{print $$2}')
PATCH=$(shell echo $(KVERSION) | awk -F. '{print $$3}' | awk -F- '{print $$1}')
export REVISION=$(shell echo $(KVERSION) | awk -F. '{print $$3}' |  awk -F- '{print $$2}')
export VERSION=$(MAJOR).$(MINOR).$(PATCH)
export KERNELPATH
export OUTPATH

.PHONY: rpm

all: px_version.c
	make -C $(KERNELPATH) $(KERNELOTHEROPT) M=$(CURDIR) modules

insert: all
	insmod px.ko $(PXD_NUM_CONTEXT_EXPORTED)

clean:
	make -C $(KERNELPATH) $(KERNELOTHEROPT) M=$(CURDIR) clean

install:
	make V=1 -C $(KERNELPATH) $(KERNELOTHEROPT) M=$(CURDIR) modules_install

rpm:
	@cd rpm && ./buildrpm.sh

docker-build-dev:
	docker build -t portworx/px-fuse:dev -f Dockerfile .

docker-build: docker-build-dev
	docker run --privileged \
	-v /usr/src/:/usr/src  \
	-v $(shell pwd):/home/px-fuse \
	portworx/px-fuse:dev make

px_version.c:
	echo "const char *gitversion = \"$(shell git rev-parse HEAD)\";" > $@

distclean: clean
	@/bin/rm -f  config.* Makefile
