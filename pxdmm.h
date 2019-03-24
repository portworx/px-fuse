#ifndef _PXDMM_H_
#define _PXDMM_H_

int pxdmm_init(void);
void pxdmm_exit(void);

#define NREQUESTS (256)
#define MAXDATASIZE (1<<20)
#define CMDR_SIZE (8<<20)

struct pxd_device;
struct request_queue;
struct bio;
struct pxdmm_dev;

// common cmd response queue struct
struct pxdmm_cmdresp {
	uint32_t minor;
	uint32_t cmd;
	uint32_t cmd_flags;
	int hasdata;
	unsigned long dev_id;

	loff_t offset;
	loff_t length;

	uint32_t status;

	// below 2 fields should be passed as is.
	uintptr_t dev; // the pxdmm_dev used for this xfer
	uint32_t io_index;
} __attribute__((aligned(64)));

// ioctl
struct pxdmm_mbox {
	const int queueSize; // const
	uint64_t cmdHead __attribute__((aligned(64)));
	uint64_t cmdTail __attribute__((aligned(64)));
	uint64_t respHead __attribute__((aligned(64)));
	uint64_t respTail __attribute__((aligned(64)));
} __attribute__((aligned(64)));

/* cmd queue interfaces */
static inline
bool cmdQFull(struct pxdmm_mbox *mbox) {
	uint64_t nextHead = (mbox->cmdHead + 1) % NREQUESTS;
	return (nextHead == mbox->cmdTail);
}

static inline
bool cmdQEmpty(struct pxdmm_mbox *mbox) {
	return (mbox->cmdHead == mbox->cmdTail);
}

static inline
struct pxdmm_cmdresp* getCmdQHead(struct pxdmm_mbox *mbox, uintptr_t cmdQbase) {
	struct pxdmm_cmdresp *cmd = (struct pxdmm_cmdresp*) cmdQbase;
	return &cmd[mbox->cmdHead];
}

static inline
struct pxdmm_cmdresp* getCmdQTail(struct pxdmm_mbox *mbox, uintptr_t cmdQbase) {
	struct pxdmm_cmdresp *cmd = (struct pxdmm_cmdresp*) cmdQbase;
	return &cmd[mbox->cmdTail];
}

static inline
void incrCmdQHead(struct pxdmm_mbox *mbox) {
	mbox->cmdHead = (mbox->cmdHead + 1) % NREQUESTS;
}

static inline
void incrCmdQTail(struct pxdmm_mbox *mbox) {
	mbox->cmdTail = (mbox->cmdTail + 1) % NREQUESTS;
}

/* response queue interfaces */
static inline
bool respQFull(struct pxdmm_mbox *mbox) {
	uint64_t nextHead = (mbox->respHead + 1) % NREQUESTS;
	return (nextHead == mbox->respTail);
}

static inline
bool respQEmpty(struct pxdmm_mbox *mbox) {
	return (mbox->respHead == mbox->respTail);
}

static inline
struct pxdmm_cmdresp* getRespQHead(struct pxdmm_mbox *mbox, uintptr_t respQbase) {
	struct pxdmm_cmdresp *resp = (struct pxdmm_cmdresp*) respQbase;
	return &resp[mbox->respHead];
}

static inline
struct pxdmm_cmdresp* getRespQTail(struct pxdmm_mbox *mbox, uintptr_t respQbase) {
	struct pxdmm_cmdresp *resp = (struct pxdmm_cmdresp*) respQbase;
	return &resp[mbox->respTail];
}

static inline
void incrRespQHead(struct pxdmm_mbox *mbox) {
	mbox->respHead = (mbox->respHead + 1) % NREQUESTS;
}

static inline
void incrRespQTail(struct pxdmm_mbox *mbox) {
	mbox->respTail = (mbox->respTail + 1) % NREQUESTS;
}

static inline
loff_t pxdmm_dataoffset(uint32_t io_index) {
	return CMDR_SIZE + (io_index * MAXDATASIZE);
}

int pxdmm_add_request(struct pxd_device *pxd_dev,
		struct request_queue *q, struct bio *bio);
int pxdmm_complete_request(struct pxdmm_dev *udev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
blk_qc_t pxdmm_make_request_slowpath(struct request_queue *q, struct bio *bio);
#else
void pxdmm_make_request_slowpath(struct request_queue *q, struct bio *bio);
#endif
#endif /* _PXDMM_H_ */
