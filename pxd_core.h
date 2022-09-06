#ifndef _PXD_CORE_H_
#define _PXD_CORE_H_

#include <linux/types.h>
#include <linux/miscdevice.h>
#ifdef __PX_BLKMQ__
#include <linux/blk-mq.h>
#endif
#include "pxd.h"

#include "pxd_fastpath.h"
#include "fuse_i.h"

struct pxd_context {
	spinlock_t lock;
	struct list_head list;
	size_t num_devices;
	struct fuse_conn fc;
	struct file_operations fops;
	char name[256];
	int id;
	struct miscdevice miscdev;
	struct delayed_work abort_work;

	uint64_t open_seq;
};

struct pxd_context* find_context(unsigned ctx);

struct pxd_device {
#define PXD_DEV_MAGIC (0xcafec0de)
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
	struct pxd_fastpath_extension fp;
	struct pxd_context *ctx;
	bool connected;
	mode_t mode;
	bool fastpath; // this is persistent, how the block device registered with kernel
	unsigned int queue_depth; // sysfs attribute bdev io queue depth
	unsigned int discard_size;

#define PXD_ACTIVE(pxd_dev)  (atomic_read(&pxd_dev->ncount))
	// congestion handling
	atomic_t ncount; // [global] total active requests, always modify with pxd_dev.lock
	unsigned int qdepth; // congestion control
	atomic_t congested;
	bool exported; //  [pxd_dev->lock protected] whether pxd_device exported to kernel
	unsigned int nr_congestion_on;
	unsigned int nr_congestion_off;

	wait_queue_head_t suspend_wq;
#if defined(__PXD_BIO_BLKMQ__) && defined(__PX_BLKMQ__)
        struct blk_mq_tag_set tag_set;
#endif
};

// how pxd_device got registered with the kernel during device add.
static inline
bool fastpath_enabled(struct pxd_device *pxd_dev) {
	return pxd_dev->fastpath;
}

// current IO status - fastpath vs nativepath
static inline
bool fastpath_active(struct pxd_device *pxd_dev) {
	return pxd_dev->fp.fastpath;
}

void pxd_check_q_congested(struct pxd_device *pxd_dev);
void pxd_check_q_decongested(struct pxd_device *pxd_dev);

#define pxd_printk(args...)
//#define pxd_printk(args, ...) printk(KERN_ERR args, ##__VA_ARGS__)

#define pxd_io_printk(args...)
//#define pxd_io_printk(args, ...) printk(KERN_ERR args, ##__VA_ARGS__)
//
#define pxd_mem_printk(args...)
//#define pxd_mem_printk(args, ...) printk(KERN_ERR args, ##__VA_ARGS__)

#ifndef SECTOR_SIZE
#define SECTOR_SIZE 512
#endif
#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT (9)
#endif

#define SEGMENT_SIZE (1024 * 1024)

#ifdef __PXD_BIO_MAKEREQ__
void pxd_reroute_slowpath(struct request_queue *q, struct bio *bio);
#else
void pxdmq_reroute_slowpath(struct fuse_req*);
#endif
int pxd_initiate_fallback(struct pxd_device *pxd_dev);
int pxd_initiate_failover(struct pxd_device *pxd_dev);


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

#endif /* _PXD_CORE_H_ */
