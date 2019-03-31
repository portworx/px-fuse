#ifndef _PXDMM_H_
#define _PXDMM_H_

#define NREQUESTS (256)
#define NMAXDEVICES (256)
#define MAXDATASIZE (1<<20)
#define CMDR_SIZE (8<<20)

#define VOLATILE
//#define SHOULDFLUSH

static inline
unsigned long compute_checksum(unsigned long initial, void *_addr, unsigned int len) {
	unsigned long *addr = _addr;
	unsigned long csum = initial;

	len /= sizeof(*addr);
	while (len-- > 0)
		csum ^= *addr++;
	csum = ((csum>>1) & 0x55555555)  ^  (csum & 0x55555555);

	return csum;
}

// debug routine
#define PATTERN1 0xDEADBEEF
#define PATTERN2 0xBAADBABE
#define PATTERN3 0xCAFECAFE
#define PATTERN4 0xDEEDF00F
#define PATTERN5 0xA5A5A5A5

static inline
void __fillpage(void *kaddr, unsigned int length) {
	unsigned int *p = kaddr;
	uintptr_t random = ((uintptr_t) &p >> 12); // hi order on stack addr for randomness

	int nwords = length/sizeof(unsigned int);
	while (nwords) {

		switch (random % 5) {
		case 0: *p++ = PATTERN1; break;
		case 1: *p++ = PATTERN2; break;
		case 2: *p++ = PATTERN3; break;
		case 3: *p++ = PATTERN4; break;
		case 4: *p++ = PATTERN5; break;
		}
		random++;
		nwords--;
	}
}

static inline
void __fillpage_pattern(void *kaddr, unsigned int pattern, unsigned int length) {
	unsigned int *p = kaddr;

	int nwords = length/sizeof(unsigned int);
	while (nwords) {
		*p++ = pattern;
		nwords--;
	}
}

#ifdef __KERNEL__

struct pxd_device;
struct pxd_dev_id;
struct request_queue;
struct bio;
struct pxdmm_dev;

int pxdmm_init(void);
void pxdmm_exit(void);
int pxdmm_add_request(struct pxd_device *pxd_dev,
		struct request_queue *q, struct bio *bio);
int pxdmm_complete_request(struct pxdmm_dev *udev);
int pxdmm_init_dev(struct pxd_device *pxd_dev);
int pxdmm_cleanup_dev(struct pxd_device *pxd_dev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
blk_qc_t pxdmm_make_request_slowpath(struct request_queue *q, struct bio *bio);
#else
void pxdmm_make_request_slowpath(struct request_queue *q, struct bio *bio);
#endif

#else

typedef int bool;
#define true (1)
#define false (!true)

#endif /* __KERNEL__ */

// common cmd response queue struct
struct pxdmm_cmdresp {
	uint32_t minor;
	uint32_t cmd;
	uint32_t cmd_flags;
	int hasdata;
	unsigned long dev_id;

	loff_t offset;
	loff_t length;

	unsigned long checksum;
	uint32_t status;

	// below 2 fields should be passed as is.
	uint32_t io_index;
	uintptr_t dev; // the pxdmm_dev used for this xfer
} __attribute__((aligned(64)));

// ioctl
struct pxdmm_mbox {
	const uint64_t queueSize;
	const uint64_t cmdOffset;
	const uint64_t respOffset;
	const uint64_t devOffset;
	const uint64_t dataOffset;

	// device list window parameters
	unsigned long devChecksum;
#ifdef __KERNEL__
#define LOCK_DEVWINDOW(mbox)  ((mbox)->devVersion = 0)
#define UNLOCK_DEVWINDOW(mbox,v)  ((mbox)->devVersion = (v))
#endif
#define DEVWINDOW_LOCKED(mbox)  ((mbox)->devVersion == 0)
#define DEVWINDOW_VERSION(mbox)  ((mbox)->devVersion)
	unsigned long devVersion;
	unsigned long ndevices;

	uint64_t cmdHead __attribute__((aligned(64)));
	uint64_t cmdTail __attribute__((aligned(64)));
	uint64_t respHead __attribute__((aligned(64)));
	uint64_t respTail __attribute__((aligned(64)));
} __attribute__((aligned(64)));

static inline
VOLATILE struct pxdmm_cmdresp* getCmdQBase(struct pxdmm_mbox *mbox) {
	return (VOLATILE struct pxdmm_cmdresp *)((char*) mbox + mbox->cmdOffset);
}

static inline
struct pxdmm_cmdresp* getRespQBase(struct pxdmm_mbox *mbox) {
	return (struct pxdmm_cmdresp *) ((char*) mbox + mbox->respOffset);
}

#ifndef __KERNEL__
/** Device identification passed from kernel on initialization */
struct pxd_dev_id {
	uint32_t local_minor; 	/**< minor number assigned by kernel */
	uint32_t pad;
	uint64_t dev_id;	/**< global device id */
	uint64_t size;		/**< device size known by kernel in bytes */
};

static inline
void pxdmm_devices_dump(struct pxd_dev_id *base, int count) {
	int i;

	for (i=0; i<count; i++, base++) {
		printf("[%d] minor:%u, dev_id:%lu, size:%lu\n",
				i, base->local_minor, base->dev_id, base->size);
	}
}
#endif

static inline
struct pxd_dev_id* getDeviceListBase(struct pxdmm_mbox *mbox) {
	return (struct pxd_dev_id*) ((char*) mbox + mbox->devOffset);
}

static inline
int getDeviceCount(struct pxdmm_mbox *mbox) {
	return mbox->ndevices;
}

static inline
unsigned long getDeviceListVersion(struct pxdmm_mbox *mbox) {
    return mbox->devVersion;
}

static inline
bool sanitizeDeviceList(struct pxdmm_mbox *mbox, struct pxd_dev_id* buff, int count) {
	unsigned long csum = compute_checksum(0, buff, sizeof(struct pxd_dev_id) * count);
	return (csum == mbox->devChecksum);
}

static inline
int getDevices(struct pxdmm_mbox *mbox, struct pxd_dev_id* buff, int maxcount) {
	int count;

#ifndef __KERNEL__
	while (DEVWINDOW_LOCKED(mbox)) { usleep(10); }
#endif
	count = (mbox->ndevices < maxcount) ? mbox->ndevices : maxcount;
	if (count) {
		memcpy(buff, getDeviceListBase(mbox), count*sizeof(struct pxd_dev_id));
	}
	return count;
}

static inline
void* getDataBufferBase(struct pxdmm_mbox *mbox) {
	return ((char*) mbox + mbox->dataOffset);
}

#ifndef __KERNEL__
static inline
void pxdmm_mbox_dump (struct pxdmm_mbox *mbox) {
	printf("mbox @ %p, queueSize %lu, cmdOff %lu, respOff %lu, devOff: %lu, dataOff %lu devlist %lu:%lu:%lu\n"
			"\tcmdQ Head:Tail {%lu:%lu},respQ head:Tail {%lu:%lu}\n",
			mbox, mbox->queueSize, mbox->cmdOffset, mbox->respOffset,
			mbox->devOffset, mbox->dataOffset,
			mbox->devChecksum, mbox->devVersion, mbox->ndevices,
			mbox->cmdHead, mbox->cmdTail,
			mbox->respHead, mbox->respTail);
}

#define ____offsetof(t, f) (uintptr_t)(&((t*)0)->f)

static inline
void pxdmm_cmdresp_dump(const char *msg, VOLATILE struct pxdmm_cmdresp *c) {
	printf("cmdresp: %s: minor [%ld]%u, cmd: [%ld]%u, cmd_flags [%ld]%#x, hasdata: [%ld]%d, dev_id: [%ld]%ld\n"
			"\t offset [%ld]%lu:[%ld]%lu, csum[%ld]%lu, status [%ld]%u, mmdev [%ld]%p, io_index [%ld]%u\n",
			msg,
			____offsetof(struct pxdmm_cmdresp, minor), c->minor,
			____offsetof(struct pxdmm_cmdresp, cmd), c->cmd,
			____offsetof(struct pxdmm_cmdresp, cmd_flags), c->cmd_flags,
			____offsetof(struct pxdmm_cmdresp, hasdata), c->hasdata,
			____offsetof(struct pxdmm_cmdresp, dev_id), c->dev_id,
			____offsetof(struct pxdmm_cmdresp, offset), c->offset,
			____offsetof(struct pxdmm_cmdresp, length), c->length,
			____offsetof(struct pxdmm_cmdresp, checksum), c->checksum,
			____offsetof(struct pxdmm_cmdresp, status), c->status,
			____offsetof(struct pxdmm_cmdresp, dev), (void*) c->dev,
			____offsetof(struct pxdmm_cmdresp, io_index), c->io_index);
}

#else
static inline
void pxdmm_mbox_dump (struct pxdmm_mbox *mbox) {
	printk("mbox @ %p, queueSize %llu, cmdOff %llu, respOff %llu, dataOff %llu\n"
			"\tcmdQ Head:Tail %llu:%llu\n"
			"\trespQ head:Tail %llu:%llu\n",
			mbox, mbox->queueSize, mbox->cmdOffset, mbox->respOffset, mbox->dataOffset,
			mbox->cmdHead, mbox->cmdTail,
			mbox->respHead, mbox->respTail);
}

#define  ____offsetof(t, f) (uintptr_t)(&((t*)0)->f)
static inline
void pxdmm_cmdresp_dump(const char *msg, VOLATILE struct pxdmm_cmdresp *c) {
	printk("cmdresp: %s: minor [%ld]%u, cmd: [%ld]%u, cmd_flags [%ld]%#x, hasdata: [%ld]%d, dev_id: [%ld]%ld\n"
			"\t offset [%ld]%llu:[%ld]%llu, csum[%ld]%lu, status [%ld]%u, mmdev [%ld]%p, io_index [%ld]%u\n",
			msg,
			____offsetof(struct pxdmm_cmdresp, minor), c->minor,
			____offsetof(struct pxdmm_cmdresp, cmd), c->cmd,
			____offsetof(struct pxdmm_cmdresp, cmd_flags), c->cmd_flags,
			____offsetof(struct pxdmm_cmdresp, hasdata), c->hasdata,
			____offsetof(struct pxdmm_cmdresp, dev_id), c->dev_id,
			____offsetof(struct pxdmm_cmdresp, offset), c->offset,
			____offsetof(struct pxdmm_cmdresp, length), c->length,
			____offsetof(struct pxdmm_cmdresp, checksum), c->checksum,
			____offsetof(struct pxdmm_cmdresp, status), c->status,
			____offsetof(struct pxdmm_cmdresp, dev), (void*) c->dev,
			____offsetof(struct pxdmm_cmdresp, io_index), c->io_index);
}

#endif

static inline
void pxdmm_mbox_init(struct pxdmm_mbox *mbox,
		uint64_t queueSize,
		uint64_t cmdOff,
		uint64_t respOff,
		uint64_t devOff,
		uint64_t dataOff) {
	struct pxdmm_mbox tmp = {queueSize, cmdOff, respOff, devOff, CMDR_SIZE,
								0, 0, 0, /* dev checksum, version, ndevices */
								0, 0,
								0, 0};

	memcpy(mbox, &tmp, sizeof(tmp));
}

/* cmd queue interfaces */
static inline
bool cmdQFull(struct pxdmm_mbox *mbox) {
	uint64_t nextHead;
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
	flush_dcache_page(vmalloc_to_page(mbox));
#endif
	nextHead = (mbox->cmdHead + 1) % NREQUESTS;
	return (nextHead == mbox->cmdTail);
}

static inline
bool cmdQEmpty(struct pxdmm_mbox *mbox) {
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
	flush_dcache_page(vmalloc_to_page(mbox));
#endif
	return (mbox->cmdHead == mbox->cmdTail);
}

static inline
VOLATILE struct pxdmm_cmdresp* getCmdQHead(struct pxdmm_mbox *mbox) {
	VOLATILE struct pxdmm_cmdresp *cmd = getCmdQBase(mbox);
	return &cmd[mbox->cmdHead];
}

static inline
VOLATILE struct pxdmm_cmdresp* getCmdQTail(struct pxdmm_mbox *mbox) {
	VOLATILE struct pxdmm_cmdresp *cmd = getCmdQBase(mbox);
	return &cmd[mbox->cmdTail];
}

static inline
void incrCmdQHead(struct pxdmm_mbox *mbox) {
	mbox->cmdHead = (mbox->cmdHead + 1) % NREQUESTS;
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
	flush_dcache_page(vmalloc_to_page(mbox));
#endif
}

static inline
void incrCmdQTail(struct pxdmm_mbox *mbox) {
	mbox->cmdTail = (mbox->cmdTail + 1) % NREQUESTS;
}

/* response queue interfaces */
static inline
bool respQFull(struct pxdmm_mbox *mbox) {
	uint64_t nextHead;
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
	flush_dcache_page(vmalloc_to_page(mbox));
#endif
	nextHead = (mbox->respHead + 1) % NREQUESTS;
	return (nextHead == mbox->respTail);
}

static inline
bool respQEmpty(struct pxdmm_mbox *mbox) {
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
	flush_dcache_page(vmalloc_to_page(mbox));
#endif
	return (mbox->respHead == mbox->respTail);
}

static inline
VOLATILE struct pxdmm_cmdresp* getRespQHead(struct pxdmm_mbox *mbox) {
	VOLATILE struct pxdmm_cmdresp *resp = getRespQBase(mbox);
	return &resp[mbox->respHead];
}

static inline
VOLATILE struct pxdmm_cmdresp* getRespQTail(struct pxdmm_mbox *mbox) {
	VOLATILE struct pxdmm_cmdresp *resp = getRespQBase(mbox);
	return &resp[mbox->respTail];
}

static inline
void incrRespQHead(struct pxdmm_mbox *mbox) {
	mbox->respHead = (mbox->respHead + 1) % NREQUESTS;
}

static inline
void incrRespQTail(struct pxdmm_mbox *mbox) {
	mbox->respTail = (mbox->respTail + 1) % NREQUESTS;
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
	flush_dcache_page(vmalloc_to_page(mbox));
#endif
}

static inline
loff_t pxdmm_dataoffset(uint32_t io_index) {
	return CMDR_SIZE + (io_index * MAXDATASIZE);
}

#endif /* _PXDMM_H_ */
