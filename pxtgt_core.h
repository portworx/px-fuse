#ifndef _PXTGT_CORE_H_
#define _PXTGT_CORE_H_

#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/workqueue.h>
#ifdef __PX_BLKMQ__
#include <linux/blk-mq.h>
#endif
#include "pxtgt.h"

struct pxtgt_device;

// Added metadata for each bio
struct pxtgt_io_tracker {
#define PXTGT_IOT_MAGIC (0xbeefcafe)
	unsigned int magic;
	struct pxtgt_device *pxtgt_dev; // back pointer to pxd device
	struct list_head item;
	atomic_t active; // only HEAD has refs to all active IO
	int status;

	unsigned long start; // start time [HEAD]
	struct bio *orig;    // original request bio [HEAD]

	struct work_struct wi; // work item

	// THIS SHOULD BE LAST ITEM
	struct bio clone;    // cloned bio [ALL]
};

struct pxtgt_context {
	spinlock_t lock;
	struct list_head list;
	size_t num_devices;
	struct file_operations fops;
	char name[256];
	int id;
	struct miscdevice miscdev;
	struct delayed_work abort_work;
	uint64_t open_seq;
};

struct pxtgt_context* find_context(unsigned ctx);

struct pxtgt_device {
#define PXTGT_DEV_MAGIC (0xcafec0de)
	unsigned int magic;
	uint64_t dev_id;
	int major;
	int minor;
	struct gendisk *disk;
	struct device dev;
	size_t size;
	spinlock_t lock;
	spinlock_t qlock;
	struct list_head node;
	int open_count;
	bool removing;
	struct pxtgt_context *ctx;
	bool connected;

#define PXTGT_ACTIVE(pxtgt_dev)  (atomic_read(&pxtgt_dev->ncount))
	// congestion handling
	atomic_t ncount; // [global] total active requests, always modify with pxtgt_dev.lock
	atomic_t ncomplete;
	atomic_t nerror;
	atomic_t nio_flush;
	atomic_t nio_discard;
	atomic_t nio_write;
	atomic_t nio_preflush;
	atomic_t nio_fua;

	unsigned int qdepth;
	atomic_t congested;
	unsigned int nr_congestion_on;
	unsigned int nr_congestion_off;

	bool block_io;
	char source[MAX_PXTGT_DEVPATH_LEN+1];
	struct file *fp;

	struct workqueue_struct *wq;

	atomic_t suspend;
	wait_queue_head_t suspend_wq;
#ifdef __PX_BLKMQ__
    struct blk_mq_tag_set tag_set;
#endif
};

void pxtgt_check_q_congested(struct pxtgt_device *pxtgt_dev);
void pxtgt_check_q_decongested(struct pxtgt_device *pxtgt_dev);

#define pxtgt_printk(args...)
//#define pxtgt_printk(args, ...) printk(KERN_ERR args, ##__VA_ARGS__)

#define pxtgt_io_printk(args...)
//#define pxtgt_io_printk(args, ...) printk(KERN_ERR args, ##__VA_ARGS__)
//
#define pxtgt_mem_printk(args...)
//#define pxtgt_mem_printk(args, ...) printk(KERN_ERR args, ##__VA_ARGS__)

#ifndef SECTOR_SIZE
#define SECTOR_SIZE 512
#endif
#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT (9)
#endif

#define SEGMENT_SIZE (1024 * 1024)

// slow path make request io entry point
struct request_queue;
struct bio;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
blk_qc_t pxtgt_make_request(struct request_queue *q, struct bio *bio);
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
void pxtgt_make_request(struct request_queue *q, struct bio *bio);
#define BLK_QC_RETVAL
#endif

static inline
mode_t open_mode(mode_t mode) {
	mode_t m = O_LARGEFILE | O_NOATIME; // default
	if (mode & O_RDWR) {
		m |= O_RDWR;
	}

	if (mode & O_SYNC) m |= O_SYNC;
	if (mode & O_DIRECT) m |= O_DIRECT;

	return m;
}

static inline
void decode_mode(mode_t mode, char *out) {
	if (mode & O_LARGEFILE) *out++ = 'L';
	if (mode & O_NOATIME) *out++ = 'A';
	if (mode & O_DIRECT) *out++='D';
	if (mode & O_WRONLY) *out++ = 'W';
	if (mode & O_RDWR) {
		*out++ = 'R';
		*out++ = 'W';
	} else { // O_RDONLY is defined as zero
		*out++ = 'R';
	}
	if (mode & O_SYNC) *out++ = 'S';
	if (mode & O_TRUNC) *out++ = 'T';
	if (mode & O_APPEND) *out++ = 'P';

	*out = '\0';
}

static inline
int write_allowed(mode_t curr) {
	return ((curr & (O_RDWR | O_WRONLY)));
}

#endif /* _PXTGT_CORE_H_ */
