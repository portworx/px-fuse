#ifndef _PXD_FASTPATH_H_
#define _PXD_FASTPATH_H_

#include <linux/atomic.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/kthread.h>
#include <linux/dma-mapping.h>
#include <linux/statfs.h>
#include <linux/file.h>
#include <linux/splice.h>
#include <linux/fs.h>
#include <linux/falloc.h>
#include <linux/bio.h>

#define MAX_THREADS (nr_cpu_ids)


// A one-time built, static lookup table to distribute requests to cpu within
// same numa node
struct node_cpu_map {
	int cpu[NR_CPUS];
	int ncpu;
};

// Added metadata for each bio
struct pxd_io_tracker {
	unsigned long start; // start time
	struct bio *orig;    // original request bio
	struct bio clone;    // cloned bio
};

struct pxd_device;
struct thread_context {
	struct pxd_device  *pxd_dev;
	struct task_struct *pxd_thread;
	wait_queue_head_t   pxd_event;
	spinlock_t  		lock;
	struct bio_list  bio_list;
};

struct pxd_fastpath_extension {
	// Extended information
	bool   block_device;
	loff_t offset; // offset into the backing device/file
	int bg_flush_enabled; // dynamically enable bg flush from driver
	int n_flush_wrsegs; // num of PXD_LBS write segments to force flush

	// Below information has to be set through new PXD_UPDATE_PATH ioctl
	int nfd;
	struct file *file[MAX_PXD_BACKING_DEVS];
	char device_path[MAX_PXD_BACKING_DEVS][MAX_PXD_DEVPATH_LEN];

	struct thread_context *tc;
	wait_queue_head_t   congestion_wait;
	wait_queue_head_t   sync_event;
	spinlock_t   	sync_lock;
	atomic_t nsync_active; // [global] currently active?
	atomic_t nsync; // [global] number of forced syncs completed
	atomic_t ncount; // [global] total active requests
	atomic_t nswitch; // [global] total number of requests through bio switch path
	atomic_t nslowPath; // [global] total requests through slow path
	atomic_t ncomplete; // [global] total completed requests
	atomic_t ncongested; // [global] total number of times queue congested
	atomic_t nwrite_counter; // [global] completed writes, gets cleared on a threshold
	atomic_t index[MAX_NUMNODES];
};

// global initialization during module init for fastpath
int fastpath_init(void);
void fastpath_cleanup(void);

// per device initialization for fastpath
int pxd_fastpath_init(struct pxd_device *pxd_dev, loff_t offset);
void pxd_fastpath_cleanup(struct pxd_device *pxd_dev);

#endif /* _PXD_FASTPATH_H_ */
