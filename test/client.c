#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <libgen.h>
#include <sys/mman.h>
#include <assert.h>

#include "pxdmm.h"
#define CONTROL_DEV_BASE "/sys/devices/pxdmm/misc/pxdmm-control/uio0/maps/map0/"
//#define DEFPATH "/var/.px/0/690901662210331304/pxdev"
//
#define MMADDR "addr"
#define MMOFFSET "offset"
#define MMSIZE "size"
#define MMNAME "name"

//#define CONTROLDEV "/dev/pxdmm-control"
#define CONTROLDEV "/dev/uio0"

/** fuse opcodes */
enum pxd_opcode {
    PXD_INIT = 8192,    /**< send on device open from kernel */
    PXD_WRITE,          /**< write to device */
    PXD_READ,           /**< read from device */
    PXD_DISCARD,        /**< discard blocks */
    PXD_ADD,            /**< add device to kernel */
    PXD_REMOVE,         /**< remove device from kernel */
    PXD_READ_DATA,      /**< read data from kernel */
    PXD_UPDATE_SIZE,    /**< update device size */
    PXD_WRITE_SAME,     /**< write_same operation */
    PXD_LAST,
};

/** flags set by driver */
#define PXD_FLAGS_FLUSH 0x1 /**< REQ_FLUSH set on bio */
#define PXD_FLAGS_FUA   0x2 /**< REQ_FUA set on bio */
#define PXD_FLAGS_META  0x4 /**< REQ_META set on bio */
#define PXD_FLAGS_SYNC (PXD_FLAGS_FLUSH | PXD_FLAGS_FUA)


#define BKPATH "/tmp/px"
#define MAXFD (5)
struct backingFds {
	int fd;
	unsigned long dev_id;
};

static struct backingFds bkFd[MAXFD];
int getBackingFileHandle(unsigned long dev_id) {
	int i;
	char filepath[128];

	sprintf(filepath, "%s/%lu", BKPATH, dev_id);
	for (i=0; i<MAXFD; i++) {
		if (bkFd[i].dev_id == 0) { /* empty slot */
			int fd = open(filepath, O_RDWR | O_CREAT);
			if (fd < 0) {
				printf("opening file %s... returned err %d\n", filepath, fd);
				perror("backing file open error");
				exit(1);
			}
			//assert (ftruncate(fd, 2 << 30) == 0); // 2 GB file
			bkFd[i].fd = fd;
			bkFd[i].dev_id = dev_id;
			return fd;
		}

		if (bkFd[i].dev_id == dev_id) {
			return bkFd[i].fd;
		}
	}

	perror("backing file slots full");
	exit(1);
	return 0;
}

void closeBackingFileHandles(void) {
	int i;
	for (i=0; i<MAXFD; i++) {
		if (bkFd[i].fd && bkFd[i].dev_id) {
			close(bkFd[i].fd);
		}
	}
}

int cdevfd;
void *maddr;
void *commonDataBuffer;

#define ull unsigned long long
uintptr_t base;
ull size;
ull offset;

struct pxdmm_mbox *mbox;

void initiate_mapping(int dbi) {
	int fd, rc, len;
	char buf[64];
	printf("Initiating mapping for dbi %d\n", dbi);

	fd = open("/sys/devices/pxdmm/misc/pxdmm-control/map", O_RDWR);
	if (fd < 0) {
		perror("debug control file open error");
		return;
	}

	// trigger to map
	sprintf(buf, "%d", 0);
	rc = write(fd, buf, len);
	if (rc != len) {
		perror("write control file error");
		return;
	}

	close(fd);
}

void clear_mapping(int dbi) {
	int fd, rc, len;
	char buf[64];
	printf("Clearing mapping for dbi %d\n", dbi);

	fd = open("/sys/devices/pxdmm/misc/pxdmm-control/unmap", O_RDWR);
	if (fd < 0) {
		perror("debug control file open error");
		return;
	}

	// trigger to map
	sprintf(buf, "%d", 0);
	rc = write(fd, buf, len);
	if (rc != len) {
		perror("write control file error");
		return;
	}

	close(fd);
}

int readfile(char *path, char *buffer, int length) {
	int fd;
	int err;

	memset(buffer, 0, length);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("file open error");
		return -1;
	}

	err = read(fd, buffer, length);
	if (err < 0) {
		perror("read error");
		return -1;
	}

	printf("from path %s\nread %d bytes\ncontent: %s\n", path, err, buffer);
	close(fd);
	return err;
}

int pxdmm_read_request (struct pxdmm_mbox *mbox, struct pxdmm_cmdresp *req) {
	struct pxdmm_cmdresp *top;
	if (cmdQEmpty(mbox)) {
		return -1;
	}

	top = getCmdQTail(mbox);
	printf("found something in cmdQ.. %p\n", top);
	memcpy(req, top, sizeof(struct pxdmm_cmdresp));

	pxdmm_cmdresp_dump("got request:", req);
	incrCmdQTail(mbox);
	return 0;
}

int pxdmm_process_request (struct pxdmm_cmdresp *req) {
#if 1
	int fd;
	
	fd = getBackingFileHandle(req->dev_id);
	void *databuff = maddr + pxdmm_dataoffset(req->io_index);
	ssize_t progress = 0;
	ssize_t pending = req->length;

	switch (req->cmd) {
	case PXD_WRITE:
		if (lseek(fd, req->offset, SEEK_SET) != req->offset) {
			perror("file offset set fail");
			exit(1);
		}

		while (progress != req->length) {
			ssize_t rc = write(fd, databuff, pending);
			if (rc < 0) {
				perror("write failed");
				exit(1);
			}

			pending -= rc;
			progress += rc;
			databuff += rc;
		}
		if (req->cmd_flags & PXD_FLAGS_FLUSH) {
			fsync(fd);
		}
		break;
	case PXD_READ:
		if (lseek(fd, req->offset, SEEK_SET) != req->offset) {
			perror("file offset set fail");
			exit(1);
		}

		while (progress != req->length) {
			ssize_t rc = read(fd, databuff, pending);
			if (rc < 0) {
				perror("read failed");
				exit(1);
			}
			if (rc == 0) {
				memset(databuff, 0, pending);
				break; // end of file
			}
			pending -= rc;
			progress += rc;
			databuff += rc;
		}
		break;
	}
#else
	switch (req->cmd) {
	case PXD_WRITE:
		{
			void *datasrc = maddr + pxdmm_dataoffset(req->io_index);
			unsigned long csum;

		if (req->cmd_flags & PXD_FLAGS_FLUSH) {
			printf("write-flush: offset %lu, length %lu, csum %lu hasdata %d\n",
					req->offset, req->length, req->checksum, req->hasdata);
		} else {
			printf("[%u] %p: write: offset %lu, length %lu, csum %lu, hasdata %d\n",
					req->io_index, datasrc, req->offset, req->length, req->checksum, req->hasdata);
		}

		memcpy(commonDataBuffer, datasrc, req->length);
		csum = compute_checksum(0, commonDataBuffer, req->length);
		assert(csum == req->checksum);

		printf("copy done\n");

		}
		break;
	case PXD_READ:
		{
			void *datasrc = maddr + pxdmm_dataoffset(req->io_index);
			unsigned long csum;

			printf("read: offset %lu, length %lu with csum %lu\n",
					req->offset, req->length, req->checksum);

			memcpy(commonDataBuffer, datasrc, req->length);
			csum = compute_checksum(0, commonDataBuffer, req->length);
			assert(csum == req->checksum);

			// fill in some dummy data... and update checksum within kernel
			__fillpage_pattern(datasrc, PATTERN1, req->length);
			csum = compute_checksum(0, datasrc, req->length);
			req->checksum = csum;
			break;
		}
	default:
		printf("default: cmd %#x\n", req->cmd);
	}
#endif
	return 0;
}

int pxdmm_complete_request (struct pxdmm_mbox* mbox, struct pxdmm_cmdresp *req) {
	struct pxdmm_cmdresp *top;

	req->status = 0;
	top = getRespQHead(mbox);
	memcpy(top, req, sizeof(struct pxdmm_cmdresp));
	pxdmm_cmdresp_dump("send response:", req);
	incrRespQHead(mbox);
}

int main(int argc, char *argv[]) {
  int rc;
  char path[128];
  char buffer[128];
  int iter;
  struct pxdmm_cmdresp req;

  printf("arg count = %d\n", argc);

  sprintf(path, "%s%s", CONTROL_DEV_BASE, MMNAME);
  rc = readfile(path, buffer, sizeof(buffer));
  if (rc < 0) exit (rc);

  sprintf(path, "%s%s", CONTROL_DEV_BASE, MMADDR);
  rc = readfile(path, buffer, sizeof(buffer));
  if (rc < 0) exit (rc);
  base = strtoull(buffer, NULL, 0);

  sprintf(path, "%s%s", CONTROL_DEV_BASE, MMOFFSET);
  rc = readfile(path, buffer, sizeof(buffer));
  if (rc < 0) exit (rc);
  offset = strtoull(buffer, NULL, 0);

  sprintf(path, "%s%s", CONTROL_DEV_BASE, MMSIZE);
  rc = readfile(path, buffer, sizeof(buffer));
  if (rc < 0) exit (rc);
  size = strtoull(buffer, NULL, 0);

  printf("Base address: %#lx\n", base);
  printf("Offset: %llu\n", offset);
  printf("Size: %llu\n", size);

  cdevfd = open(CONTROLDEV, O_RDWR);
  if (cdevfd < 0) {
	  perror("control device open failure");
	  exit(cdevfd);
  }

  maddr = mmap((void*)base, size, PROT_WRITE, MAP_SHARED, cdevfd, offset);
  if (maddr == MAP_FAILED) {
	  perror("mmap failed on control device");
	  close(cdevfd);
	  exit(-1);
  }

  mbox = (struct pxdmm_mbox*) maddr;
  pxdmm_mbox_dump(mbox);

  printf("sizeof(pxdmm_cmdresp): %ld\n", sizeof(struct pxdmm_cmdresp));

  commonDataBuffer = malloc(MAXDATASIZE);
  assert(commonDataBuffer != NULL);

  while (true) {
	  // 1. read for any new requests, if none, sleep a while
	  // 2. read request and acknowledge the mbox after picking it.
	  if (pxdmm_read_request(mbox, &req)) {
		  continue;
	  }
	  // 3. process request
	  pxdmm_process_request(&req);

	  // 4. check if response q has space available.
	  while (respQFull(mbox)) {
		/* sleep a while */
		usleep(100);
		printf("respQ full condition, sleeping..\n");
	  }
	  // 4. complete it
	  pxdmm_complete_request(mbox, &req);
  }

  free(commonDataBuffer);
  closeBackingFileHandles();
  munmap((void*)maddr, size);
  close(cdevfd);

  return 0;
}
