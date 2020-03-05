#ifndef _PXD_CORE_H_
#define _PXD_CORE_H_

#include <linux/types.h>
#include <linux/miscdevice.h>
#ifdef __PX_BLKMQ__
#include <linux/blk-mq.h>
#endif

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
	struct list_head pending_requests;
	struct delayed_work abort_work;

	uint64_t open_seq;
};

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
	bool fastpath;
	bool strict;
#ifdef __PX_BLKMQ__
        struct blk_mq_tag_set tag_set;
#endif
};

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
#define MAX_WRITESEGS_FOR_FLUSH ((4*SEGMENT_SIZE)/PXD_LBS)

// slow path make request io entry point
struct request_queue;
struct bio;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
blk_qc_t pxd_make_request_slowpath(struct request_queue *q, struct bio *bio);
#else
void pxd_make_request_slowpath(struct request_queue *q, struct bio *bio);
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

#endif /* _PXD_CORE_H_ */
