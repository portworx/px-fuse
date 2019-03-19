#ifndef _PXD_CORE_H_
#define _PXD_CORE_H_

#include <linux/miscdevice.h>

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
	struct timer_list timer;
	bool init_sent;
	uint64_t unique;
};

struct pxd_device {
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
};

#define pxd_printk(args...)
//#define pxd_printk(args...) printk(KERN_ERR args)

#ifndef SECTOR_SIZE
#define SECTOR_SIZE 512
#endif
#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT (9)
#endif

#define SEGMENT_SIZE (1024 * 1024)
#define MAX_DISCARD_SIZE (4*SEGMENT_SIZE)
#define MAX_WRITESEGS_FOR_FLUSH ((4*SEGMENT_SIZE)/PXD_LBS)

#endif /* _PXD_CORE_H_ */
