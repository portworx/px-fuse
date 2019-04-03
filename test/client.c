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
//#define DEFPATH "/var/.px/0/690901662210331304/pxdev"
//
#define MMADDR "addr"
#define MMOFFSET "offset"
#define MMSIZE "size"
#define MMNAME "name"

#define CTLDEV "/dev/pxdmm-control"
#define UIO_PARAMS_BASE "/sys/devices/pxdmm/misc/pxdmm-control/uio0/maps/map0/"
#define UIODEV "/dev/uio0"

//#define WAITREQ

static
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

/**
 * PXD_ADD request from user space
 */
struct pxd_add_out {
	uint64_t dev_id;	/**< device global id */
	size_t size;		/**< block device size in bytes */
	int32_t queue_depth;	/**< use queue depth 0 to bypass queueing */
	int32_t discard_size;	/**< block device discard size in bytes */
};

/**
 * PXD_REMOVE request from user space
 */
struct pxd_remove_out {
	uint64_t dev_id;	/**< device global id */
	bool force;		/**< force remove device */
	char pad[7];
};

/**
 * PXD_UPDATE_SIZE request from user space
 */
struct pxd_update_size_out {
	uint64_t dev_id;
	size_t size;
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

#define ull unsigned long long
struct pxdmm_client {
	char name[128];
	uintptr_t base;
	ull size;
	ull offset;

	int uiodevfd;
	void *maddr;
	struct pxdmm_mbox *mbox;
	void *commonDataBuffer;
};

static
int pxdmm_client_init(struct pxdmm_client *client,
		char *paramsbase, char *uiodev) {
  char path[128];
  char buffer[128];
  int rc;

  sprintf(path, "%s%s", paramsbase, MMNAME);
  rc = readfile(path, buffer, sizeof(buffer));
  if (rc < 0) exit (rc);
  strncpy(client->name, path, sizeof(client->name)-1);
  client->name[sizeof(client->name)-1] = 0;

  sprintf(path, "%s%s", paramsbase, MMADDR);
  rc = readfile(path, buffer, sizeof(buffer));
  if (rc < 0) exit (rc);
  client->base = strtoull(buffer, NULL, 0);

  sprintf(path, "%s%s", paramsbase, MMOFFSET);
  rc = readfile(path, buffer, sizeof(buffer));
  if (rc < 0) exit (rc);
  client->offset = strtoull(buffer, NULL, 0);

  sprintf(path, "%s%s", paramsbase, MMSIZE);
  rc = readfile(path, buffer, sizeof(buffer));
  if (rc < 0) exit (rc);
  client->size = strtoull(buffer, NULL, 0);

  printf("Base address: %#lx\n", client->base);
  printf("Offset: %llu\n", client->offset);
  printf("Size: %llu\n", client->size);

  client->uiodevfd = open(uiodev, O_RDWR);
  if (client->uiodevfd < 0) {
	  perror("control device open failure");
	  exit(client->uiodevfd);
  }

  client->maddr =
	  mmap((void*)client->base, client->size, PROT_WRITE, MAP_SHARED, client->uiodevfd, client->offset);
  if (client->maddr == MAP_FAILED) {
	  perror("mmap failed on control device");
	  close(client->uiodevfd);
	  exit(-1);
  }

  client->mbox = (struct pxdmm_mbox*) client->maddr;

  pxdmm_mbox_dump(client->mbox);

  client->commonDataBuffer = malloc(MAXDATASIZE);
  assert(client->commonDataBuffer != NULL);

  return 0;
}

static
void pxdmm_client_exit(struct pxdmm_client *client) {
	if (client->commonDataBuffer) free(client->commonDataBuffer);
  	munmap((void*)client->maddr, client->size);
	close(client->uiodevfd);
}

// debug interface
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

// debug interface
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

int pxdmm_read_request (struct pxdmm_mbox *mbox, struct pxdmm_cmdresp *req) {
	struct pxdmm_cmdresp *top;
	if (cmdQEmpty(mbox)) {
		return -1;
	}

	top = getCmdQTail(mbox);
	//printf("found something in cmdQ.. %p\n", top);
	memcpy(req, top, sizeof(struct pxdmm_cmdresp));

#ifdef DEBUG_IO
	pxdmm_cmdresp_dump("got request:", req);
#endif
	incrCmdQTail(mbox);
	return 0;
}

int pxdmm_process_request (struct pxdmm_client *client,
		struct pxdmm_cmdresp *req) {
	int fd = getBackingFileHandle(req->dev_id);
	void *databuff = client->maddr + pxdmm_dataoffset(req->io_index);
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
	return 0;
}

int pxdmm_complete_request (struct pxdmm_mbox* mbox, struct pxdmm_cmdresp *req, int status) {
	struct pxdmm_cmdresp *top;

	req->status = status;
	top = getRespQHead(mbox);
	memcpy(top, req, sizeof(struct pxdmm_cmdresp));
#ifdef DEBUG_IO
	pxdmm_cmdresp_dump("send response:", req);
#endif
	incrRespQHead(mbox);
}

int main(int argc, char *argv[]) {
  struct pxdmm_cmdresp req;
  int devcount;
  struct pxd_dev_id devices[10];
  struct pxdmm_client client;

  printf("arg count = %d\n", argc);
  assert(pxdmm_client_init(&client, UIO_PARAMS_BASE, UIODEV) == 0);
  printf("sizeof(pxdmm_cmdresp): %ld\n", sizeof(struct pxdmm_cmdresp));
  printf("device count: %d\n", getDeviceCount(client.mbox));

  devcount = getDevices(client.mbox, devices, sizeof(devices)/sizeof(struct pxd_dev_id));
  pxdmm_devices_dump(devices, devcount);
  printf("sanitizeChecksum: %d\n", sanitizeDeviceList(client.mbox, devices, devcount));

#if 0
  printf("***** checking ioctl *********\n");
  {
	int _fd=open(CTLDEV, O_RDWR);
	int rc;
	struct pxd_add_out add;
	struct pxd_remove_out remove;
	struct pxd_update_size_out update;

	assert(_fd>0);

	add.dev_id = 1234;
	add.size = 1<<20;
	add.discard_size = 5;
	add.queue_depth = 32;

	rc=ioctl(_fd, PXD_ADD, &add);
	printf("Received response code for ioctl %d\n", rc);

	remove.dev_id = 1234;
	remove.force = 1;

#ifdef WAITREQ
	printf("Waiting to remove device %lu, force %u\n", remove.dev_id, remove.force);
	getchar();
#endif

	rc=ioctl(_fd, PXD_REMOVE, &remove);
	printf("Received response code for ioctl %d\n", rc);

	update.dev_id = 3456;
	update.size = 1<<30;
#ifdef WAITREQ
	printf("Waiting to update size device %lu, size %lu\n",
			update.dev_id, update.size);
	getchar();
#endif

	rc=ioctl(_fd, PXD_UPDATE_SIZE, &update);
	printf("Received response code for ioctl %d\n", rc);

	close(_fd);
  }
#endif

  while (true) {
	  if (devcount != getDeviceCount(client.mbox)) {
		/* device listing changed */
		devcount = getDevices(client.mbox, devices, sizeof(devices)/sizeof(struct pxd_dev_id));
		pxdmm_devices_dump(devices, devcount);
		printf("sanitizeChecksum: %d\n",
				sanitizeDeviceList(client.mbox, devices, devcount));
	  }

	  // 1. read for any new requests, if none, sleep a while
	  // 2. read request and acknowledge the mbox after picking it.
	  if (pxdmm_read_request(client.mbox, &req)) {
		  continue;
	  }
	  // 3. process request
	  pxdmm_process_request(&client, &req);

	  // 4. check if response q has space available.
	  while (respQFull(client.mbox)) {
		/* sleep a while */
		usleep(100);
		printf("respQ full condition, sleeping..\n");
	  }
	  // 4. complete it
	  pxdmm_complete_request(client.mbox, &req, 0 /* always success */);
  }

  closeBackingFileHandles();
  pxdmm_client_exit(&client);

  return 0;
}
