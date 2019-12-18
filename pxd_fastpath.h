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

// atleast 2 per cpu
// create two pool of PXD_MAX_THREAD_PER_CPU threads on each cpu, dedicated for writes and reads
// writer threads are pinned on the same cpu.
// reader threads are pinned on the same numa node
#define PXD_MAX_THREAD_PER_CPU (4)

struct pxd_device;
struct pxd_context;

// A one-time built, static lookup table to distribute requests to cpu within
// same numa node
struct node_cpu_map {
	int cpu[NR_CPUS];
	int ncpu;
};

// Added metadata for each bio
struct pxd_io_tracker {
	struct pxd_device *pxd_dev; // back pointer to pxd device
	struct pxd_io_tracker *head; // back pointer to head copy [ALL]
	struct list_head replicas; // only replica needs this
	struct list_head item; // only HEAD needs this
	atomic_t active; // only HEAD has refs to all active IO
	atomic_t fails; // should be zero, non-zero indicates atleast one path failed
	struct file* file;
	int read; // if read is from the first target only

	unsigned long start; // start time [HEAD]
	struct bio *orig;    // original request bio [HEAD]

	// THIS SHOULD BE LAST ITEM
	struct bio clone;    // cloned bio [ALL]
};

struct pxd_device;
struct thread_context {
	spinlock_t  	    read_lock;
	wait_queue_head_t   read_event;
	struct list_head iot_readers;
	struct task_struct *reader[PXD_MAX_THREAD_PER_CPU];

	spinlock_t  	    write_lock;
	wait_queue_head_t   write_event;
	struct list_head iot_writers;
	struct task_struct *writer[PXD_MAX_THREAD_PER_CPU];
};

struct pxd_fastpath_extension {
	// Extended information
	int bg_flush_enabled; // dynamically enable bg flush from driver
	int n_flush_wrsegs; // num of PXD_LBS write segments to force flush

	// Below information has to be set through new PXD_UPDATE_PATH ioctl
	int nfd;
	struct file *file[MAX_PXD_BACKING_DEVS];
	char device_path[MAX_PXD_BACKING_DEVS][MAX_PXD_DEVPATH_LEN+1];

	struct thread_context *tc;
	unsigned int qdepth;
	bool congested;
	unsigned int nr_congestion_on;
	unsigned int nr_congestion_off;

	// if set, then newer IOs shall block, until reactivated.
	int suspend;
	wait_queue_head_t  suspend_wait;
	spinlock_t suspend_lock;

	wait_queue_head_t   sync_event;
	spinlock_t   	sync_lock;
	atomic_t nsync_active; // [global] currently active?
	atomic_t nsync; // [global] number of forced syncs completed
	atomic_t nio_discard;
	atomic_t nio_preflush;
	atomic_t nio_flush;
	atomic_t nio_flush_nop;
	atomic_t nio_fua;
	atomic_t nio_write;
	atomic_t ncount; // [global] total active requests, always modify with pxd_dev.lock
	atomic_t nswitch; // [global] total number of requests through bio switch path
	atomic_t nslowPath; // [global] total requests through slow path
	atomic_t ncomplete; // [global] total completed requests
	atomic_t nwrite_counter; // [global] completed writes, gets cleared on a threshold
	atomic_t index[MAX_NUMNODES]; // [global] read path IO optimization - last cpu
};

// global initialization during module init for fastpath
int fastpath_init(void);
void fastpath_cleanup(void);

struct pxd_update_path_out;
int pxd_init_fastpath_target(struct pxd_device *pxd_dev, struct pxd_update_path_out *update_path);

// per device initialization for fastpath
int pxd_fastpath_init(struct pxd_device *pxd_dev);
void pxd_fastpath_cleanup(struct pxd_device *pxd_dev);

void pxdctx_set_connected(struct pxd_context *ctx, bool enable);

// IO entry point
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
blk_qc_t pxd_make_request_fastpath(struct request_queue *q, struct bio *bio);
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
void pxd_make_request_fastpath(struct request_queue *q, struct bio *bio);
#define BLK_QC_RETVAL
#endif

void enableFastPath(struct pxd_device *pxd_dev, bool force);
void disableFastPath(struct pxd_device *pxd_dev);

// congestion
int pxd_device_congested(void *, int);

#endif /* _PXD_FASTPATH_H_ */
