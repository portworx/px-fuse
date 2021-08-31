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

#include "pxd_bio.h"

struct pxd_device;
struct pxd_context;
struct fuse_conn;

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
#ifdef __PXD_BIO_BLKMQ__
	atomic_t blkmq_frozen; // state indicating whether actually mq frozen
#else
	rwlock_t suspend_lock;
#endif
	bool fastpath;
	int nfd;
	struct file *file[MAX_PXD_BACKING_DEVS];
	struct workqueue_struct *wq;
	struct pxd_sync_ws syncwi[MAX_PXD_BACKING_DEVS];
	struct completion sync_complete;
	atomic_t sync_done;

	// failover work item
	spinlock_t  fail_lock;
	bool active_failover; // is failover active
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

#ifndef __PX_FASTPATH__
#include "pxd_fastpath_stub.h"
#else

// global initialization during module init for fastpath
int fastpath_init(void);
void fastpath_cleanup(void);

struct pxd_update_path_out;
int pxd_init_fastpath_target(struct pxd_device *pxd_dev, struct pxd_update_path_out *update_path);

// per device initialization for fastpath
int pxd_fastpath_init(struct pxd_device *pxd_dev);
void pxd_fastpath_cleanup(struct pxd_device *pxd_dev);

void enableFastPath(struct pxd_device *pxd_dev, bool force);
void disableFastPath(struct pxd_device *pxd_dev, bool skipSync);

// congestion
int pxd_device_congested(void *, int);

// return the io count processed by a thread
int get_thread_count(int id);

void pxd_fastpath_adjust_limits(struct pxd_device *pxd_dev, struct request_queue *topque);
int pxd_suspend_state(struct pxd_device *pxd_dev);
int pxd_debug_switch_fastpath(struct pxd_device*);
int pxd_debug_switch_nativepath(struct pxd_device*);
void pxd_suspend_io(struct pxd_device*);
void pxd_resume_io(struct pxd_device*);
int pxd_fastpath_vol_cleanup(struct pxd_device *pxd_dev);

// external request from userspace to control io path
int pxd_request_suspend(struct pxd_device *pxd_dev, bool skip_flush, bool coe);
int pxd_request_suspend_internal(struct pxd_device *pxd_dev, bool skip_flush, bool coe);
int pxd_request_resume(struct pxd_device *pxd_dev);
int pxd_request_resume_internal(struct pxd_device *pxd_dev);
int pxd_request_ioswitch(struct pxd_device *pxd_dev, int code);

// handle IO reroutes and switch events
void pxd_reissuefailQ(struct pxd_device *pxd_dev, struct list_head *ios, int status);

static inline
struct block_device* get_bdev(struct file *fileh)
{
    struct address_space *mapping = fileh->f_mapping;
    struct inode *inode = mapping->host;
    struct block_device *bdev = NULL;


	if (S_ISBLK(inode->i_mode))
		bdev = I_BDEV(inode);

    return bdev;
}

static inline
unsigned get_mode(struct file *fileh)
{
    struct address_space *mapping = fileh->f_mapping;
    struct inode *inode = mapping->host;

    return inode->i_mode;
}

static inline
int remap_io_status(int status)
{
	switch (status) {
	case 0: // success
	case -EOPNOTSUPP: // op not supported - no failover
	case -ENOSPC: // no space on device - no failover
	case -ENOMEM: // no memory - no failover
		return status;
	}

	return -EIO;
}
#endif /* __PX_FASTPATH__ */

#endif /* _PXD_FASTPATH_H_ */
