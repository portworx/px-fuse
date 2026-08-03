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
	struct work_struct failover_work;

	/* Ctx-scoped fastpath freeze gate.
	 *
	 * When set, a pxd_io_failover work item entering the failover state
	 * machine does NOT pick branch (a)/(b)/(c). Instead it parks the
	 * fproot on that device's existing pxd_dev->fp.failQ (using
	 * fproot->wait, same linkage branch (c) uses) and returns without
	 * calling pxd_initiate_failover. It does NOT hard-fail and does NOT
	 * block the kthread worker.
	 *
	 * The ctx-teardown code (pxdctx_reset_fastpath called from
	 * pxd_failover_work / pxd_abort_context) drains each device's failQ
	 * with the appropriate mode (reissue-to-native for the soft path,
	 * abort for the hard path). pxd_fp_freeze_end also drains once more
	 * after clearing the gate to catch items that parked between the
	 * reset_fastpath drain and the gate clear.
	 *
	 * Read by pxd_io_failover with READ_ONCE, written by
	 * pxd_fp_freeze_start/end with WRITE_ONCE. Compiler barrier only; on
	 * x86 aligned int reads are atomic. Cross-CPU visibility ordering is
	 * provided by smp_wmb() in freeze_start/end and by the fastpath
	 * kthread flush that follows the gate set.
	 */
	int fp_freeze;

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
	unsigned int discard_granularity; // discard granularity in bytes
	unsigned int capabilities;  // Capability flags (PXD_CAP_*)

#define PXD_ACTIVE(pxd_dev)  (atomic_read(&pxd_dev->ncount))
	// [global] total active requests
	// usually, this is incremented on submitting IO and decremented on
	// successful IO completion. But, say the iopath is remote fastpath
	// and the IO fails => retry IO in native path. native path also
	// increments/decrements the ncount => ncount should be decremented
	// even on IO failure in fastpath.
	atomic_t ncount;
	// congestion handling
	unsigned int qdepth;
	atomic_t congested;
	bool exported;
	unsigned int nr_congestion_on;
	unsigned int nr_congestion_off;

	struct work_struct remove_work;

	wait_queue_head_t remove_wait;
	wait_queue_head_t suspend_wq;
#if defined(__PXD_BIO_BLKMQ__) && defined(__PX_BLKMQ__)
        struct blk_mq_tag_set tag_set;
#endif
};

static inline void pxd_mark_device_dead(struct pxd_device *pxd_dev)
{
	#if (((LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,25) && LINUX_VERSION_CODE <  KERNEL_VERSION(5,16,0))) || (LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,11))) || \
			(LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0) && ((defined(__EL8__) && !defined(QUEUE_FLAG_DEAD)) || defined(__SUSE_HAS_NO_PART_SCAN__)))
		// del_gendisk will try to fsync device
		// so freeze queue and then *mark queue dead* to ensure no new reqs
		// gets accepted.
		blk_mark_disk_dead(pxd_dev->disk);
	#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
		// del_gendisk will not submit any new IO.
		// so freeze queue and then queue dying, to ensure no new reqs
		// gets accepted.
		blk_set_queue_dying(pxd_dev->disk->queue);
	#endif
}

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

// Check if device has a specific capability
static inline
bool pxd_has_cap(struct pxd_device *pxd_dev, unsigned int cap) {
	return (pxd_dev->capabilities & cap) != 0;
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

// the SEGMENT_SIZE is set to 512K because of a limitation
// in __fuse_notify_read_data, which could process atmost
// 128 iovecs per bio_vec (128 * 4096 = 512K)
#define SEGMENT_SIZE (512 * 1024)

void pxdmq_reroute_slowpath(struct fuse_req*);
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
