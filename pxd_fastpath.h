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

struct pxd_device;
struct pxd_context;
struct fuse_conn;

typedef enum pxd_failover_state {
        PXD_FP_FAILOVER_NONE = 0,
        PXD_FP_FAILOVER_ACTIVE = 1,
} pxd_failover_state_t;

// Added metadata for each bio
struct pxd_io_tracker {
#define PXD_IOT_MAGIC (0xbeefcafe)
	unsigned int magic;
	struct pxd_device *pxd_dev; // back pointer to pxd device
	struct pxd_io_tracker *head; // back pointer to head copy [ALL]
	struct list_head replicas; // only replica needs this
	struct list_head item; // only HEAD needs this
	atomic_t active; // only HEAD has refs to all active IO
	atomic_t fails; // should be zero, non-zero indicates atleast one path failed
	struct file* file;

	unsigned long start; // start time [HEAD]
	struct bio *orig;    // original request bio [HEAD]

	struct work_struct wi; // work item

	// THIS SHOULD BE LAST ITEM
	struct bio clone;    // cloned bio [ALL]
};

struct pxd_sync_ws {
	struct work_struct ws;
	struct pxd_device *pxd_dev;
	int index; // file index
	int rc; // result
};

struct pxd_fastpath_extension {
	// Extended information
	atomic_t ioswitch_active; // failover or fallback active
	atomic_t suspend;
	atomic_t app_suspend; // userspace suspended IO
	rwlock_t suspend_lock;
	bool fastpath;
	int nfd;
	struct file *file[MAX_PXD_BACKING_DEVS];
	struct workqueue_struct *wq;
	struct pxd_sync_ws syncwi[MAX_PXD_BACKING_DEVS];
	struct completion sync_complete;
	atomic_t sync_done;

	// failover work item
	spinlock_t  fail_lock;
	pxd_failover_state_t active_failover;
	bool force_fail; // debug
	bool can_failover; // can device failover to userspace on any error
	struct list_head failQ; // protected by fail_lock

	char device_path[MAX_PXD_BACKING_DEVS][MAX_PXD_DEVPATH_LEN+1];
	atomic_t nio_discard;
	atomic_t nio_preflush;
	atomic_t nio_flush;
	atomic_t nio_flush_nop;
	atomic_t nio_fua;
	atomic_t nio_write;

	atomic_t nswitch; // [global] total number of requests through bio switch path
	atomic_t nslowPath; // [global] total requests through slow path
	atomic_t ncomplete; // [global] total completed requests
	atomic_t nerror; // [global] total IO error
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
void disableFastPath(struct pxd_device *pxd_dev, bool skipSync);

// congestion
int pxd_device_congested(void *, int);

// return the io count processed by a thread
int get_thread_count(int id);

void pxd_fastpath_adjust_limits(struct pxd_device *pxd_dev, struct request_queue *topque);
int pxd_suspend_state(struct pxd_device *pxd_dev);
int pxd_switch_fastpath(struct pxd_device*);
int pxd_switch_nativepath(struct pxd_device*);
void pxd_suspend_io(struct pxd_device*);
void pxd_resume_io(struct pxd_device*);

// external request from userspace to control io path
int pxd_request_suspend(struct pxd_device *pxd_dev, bool skip_flush, bool coe);
int pxd_request_suspend_internal(struct pxd_device *pxd_dev, bool skip_flush, bool coe);
int pxd_request_resume(struct pxd_device *pxd_dev);
int pxd_request_resume_internal(struct pxd_device *pxd_dev);
int pxd_request_ioswitch(struct pxd_device *pxd_dev, int code);

// handle IO reroutes and switch events
int __pxd_reissuefailQ(struct pxd_device *pxd_dev, int status);
void pxd_abortfailQ(struct pxd_device *pxd_dev);
void __pxd_abortfailQ(struct pxd_device *pxd_dev);

#endif /* _PXD_FASTPATH_H_ */
