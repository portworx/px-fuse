/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#ifndef _FS_FUSE_I_H
#define _FS_FUSE_I_H

#ifdef __KERNEL__
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/poll.h>
#include <linux/workqueue.h>
#include <linux/hash.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#include "iov_iter.h"

#define iov_iter_advance __iov_iter_advance
#define iov_iter __iov_iter
#define iov_iter_init __iov_iter_init
#define copy_page_to_iter __copy_page_to_iter
#define copy_page_from_iter __copy_page_from_iter

#endif

#include "pxd.h"
#include "pxd_bio.h"

struct fuse_conn;

/**
 * A request to the client
 */
struct pxd_device;
struct fuse_req {
	/** Need to fetch state of device and keep counters updated */
	struct pxd_device *pxd_dev;

	/** The request input header */
	struct fuse_in_header in;

	/** Read/write request */
	struct pxd_rdwr_in pxd_rdwr_in;

	union {
		/** Associated request structrure. */
		struct request *rq;

		/** Associated bio structrure. */
 		struct bio *bio;
	};

	/** Request completion callback */
	/** return: 'true' to free the request, 'false' otherwise */
	bool (*end)(struct fuse_conn *, struct fuse_req *, int status);

	/** Associate request queue */
	struct request_queue *queue;

	/** sequence number used for restart */
	u64 sequence;

#ifdef __PXD_BIO_BLKMQ__
	// Additional fastpath context
	struct fp_root_context fproot;
#endif
};

#ifdef __PXD_BIO_BLKMQ__
static inline
struct pxd_device* fproot_to_pxd(struct fp_root_context *fproot)
{
	struct fuse_req *f = container_of(fproot, struct fuse_req, fproot);

	return f->pxd_dev;
}

static inline
struct request* fproot_to_request(struct fp_root_context *fproot)
{
	struct fuse_req *f = container_of(fproot, struct fuse_req, fproot);

	return f->rq;
}

static inline
struct fuse_req* fproot_to_fuse_request(struct fp_root_context *fproot)
{
	return container_of(fproot, struct fuse_req, fproot);
}

#endif

#define FUSE_MAX_PER_CPU_IDS 256

struct ____cacheline_aligned fuse_per_cpu_ids {
	/** number of free ids in stack */
	u32 num_free_ids;

	/** followed by list of free ids */
	u64 free_ids[FUSE_MAX_PER_CPU_IDS];
};
#endif

#ifndef __KERNEL__
#define ____cacheline_aligned alignas(64)
#endif

/** Maximum number of outstanding background requests */
#define FUSE_DEFAULT_MAX_BACKGROUND (PXD_MAX_QDEPTH * PXD_MAX_DEVICES)

/** size of request ring buffer */
#define FUSE_REQUEST_QUEUE_SIZE (2 * FUSE_DEFAULT_MAX_BACKGROUND)

#ifdef __KERNEL__
/** writer control block */
struct ____cacheline_aligned fuse_queue_writer {
	uint32_t write;         /** cached write index */
	uint32_t read;		/** cached read index */
	spinlock_t lock;	/** writer lock */
	uint32_t need_wake_up; /** if true reader needs wake up call */
	uint64_t sequence;        /** next request sequence number */
	uint64_t pad[5];
};

/** reader control block */
struct ____cacheline_aligned fuse_queue_reader {
	uint32_t read;          /** read index updated by reader */
	uint32_t write;		/** write index updated by writer */
	uint32_t pad_0;
	atomic_t in_runq; /** a thread is processing the queue */
	uint64_t pad_2[6];
};

#else

#include <atomic>
#include <mutex>
#include "spin_lock.h"

/** writer control block */
struct alignas(64) fuse_queue_writer {
	uint32_t write;         	/** cached write index */
	uint32_t read;			/** cached read index */
	px::spinlock lock;		/** writer lock */
	uint32_t need_wake_up;
	uint64_t sequence;      /** next request sequence number */
	uint32_t committed_;    /** last write index committed to reader */
	bool in_runq;           //not used //        /** a thread is processing the queue */
	char pad_1[3];
	uint32_t pad_2[8];
};

/** reader control block */
struct alignas(64) fuse_queue_reader {
	std::atomic<uint32_t> read;	/** read index updated by reader */
	std::atomic<uint32_t> write;	/** write index updated by writer */
	px::spinlock lock;
	std::atomic<uint32_t> in_runq; /** read only, kernel exposed flag, a thread is processing the queue */
	uint64_t pad_2[6];
};

struct fuse_queue_cb;

namespace px {
namespace ioring {
/// call into the kernel to run pending entries
/// @param queue user->kernel queue
/// @param fd file descriptor associated with the queue
/// @param ioctl_cmd ioctl command
/// @param lock queue lock, unlocked around ioctl
void run_queue(fuse_queue_cb *queue, int fd, int ioctl_cmd,
	       std::unique_lock<px::spinlock> &lock);
}
}

#endif

/** opcodes for fuse_user_request */
#define FUSE_USER_OP_NOP 0		/** nop */
#define FUSE_USER_OP_REQ_DONE 1		/** request completion */

/** request from user space to kernel */
struct fuse_user_request {
	uint8_t opcode;		/** operation code */
	uint16_t len;		/** number of entries in iovec array */
	uint8_t pad;		/** padding */
	int32_t res;		/** result code */
	uint64_t unique;	/** unique id of request */
	uint64_t user_data;	/** user data returned in response */
	uint64_t iov_addr;	/** address of iovec array */
};

/** queue control block */
struct fuse_queue_cb {
	struct fuse_queue_writer w;
	struct fuse_queue_reader r;
};

/** fuse connection queues */
struct ____cacheline_aligned fuse_conn_queues {
	/** requests from kernel to user space */
	struct fuse_queue_cb requests_cb;
	struct rdwr_in requests[FUSE_REQUEST_QUEUE_SIZE];

	/** requests from user space to kernel */
	struct fuse_queue_cb user_requests_cb;
	struct fuse_user_request user_requests[FUSE_REQUEST_QUEUE_SIZE];
};

#ifdef __KERNEL__
/**
 * A Fuse connection.
 *
 * This structure is created, when the filesystem is mounted, and is
 * destroyed, when the client device is closed and the filesystem is
 * unmounted.
 */
struct fuse_conn {
	/** Lock protecting accessess to  members of this structure */
	spinlock_t lock;

	/** Readers of the connection are waiting on this */
	wait_queue_head_t waitq;

	/** request queue */
	struct fuse_conn_queues *queue;

	/** maps request ids to requests */
	struct fuse_req **request_map;

	/** stack of free ids */
	u64 *free_ids;

	/** number of free ids in stack */
	u32 num_free_ids;

	/** Connection established, cleared on umount, connection
	    abort and device release */
	bool connected;

	/* Alow operations on disconnected fuse conenction. */
	bool allow_disconnected;

	/** per cpu id allocators */
	struct fuse_per_cpu_ids __percpu *per_cpu_ids;

	/** Refcount */
	atomic_t count;

	/** O_ASYNC requests */
	struct fasync_struct *fasync;

	/** Called on final put */
	void (*release)(struct fuse_conn *);

	/** timer for periodic processing */
	struct timer_list iowork_timer;
	// struct work_struct iowork;
	wait_queue_head_t io_wait;
	struct task_struct* io_worker_thread;
};

/** Device operations */
extern const struct file_operations fuse_dev_operations;

/**
 * Initialize the client device
 */
int fuse_dev_init(void);

/**
 * Cleanup the client device
 */
void fuse_dev_cleanup(void);

/**
 * Allocate a request
 */
struct fuse_req *fuse_request_alloc(void);

/**
 * Free a request
 */
void fuse_request_free(struct fuse_req *req);

/**
 * Get a request, may fail with -ENOMEM,
 */
struct fuse_req *fuse_get_req(struct fuse_conn *fc);
struct fuse_req *fuse_get_req_for_background(struct fuse_conn *fc);

/**
 * Send a request in the background
 */
void fuse_request_send_nowait(struct fuse_conn *fc, struct fuse_req *req);

/**
 * start processing pending IOs from userspace.
 */
//void fuse_run_user_queue(struct work_struct *w);
void fuse_run_user_queue(struct fuse_conn *fc);

/* Abort all requests */
void fuse_abort_conn(struct fuse_conn *fc);

/**
 * Initialize fuse_conn
 */
int fuse_conn_init(struct fuse_conn *fc);

/**
 * Abort pending requests
 */
void fuse_end_queued_requests(struct fuse_conn *fc);

/**
 * Release reference to fuse_conn
 */
struct fuse_conn *fuse_conn_get(struct fuse_conn *fc);
void fuse_conn_put(struct fuse_conn *fc);

/**
 * Acquire reference to fuse_conn
 */
struct fuse_conn *fuse_conn_get(struct fuse_conn *fc);

int fuse_restart_requests(struct fuse_conn *fc);

ssize_t pxd_add(struct fuse_conn *fc, struct pxd_add_ext_out *add);
ssize_t pxd_remove(struct fuse_conn *fc, struct pxd_remove_out *remove);
ssize_t pxd_update_size(struct fuse_conn *fc, struct pxd_update_size *update_size);
ssize_t pxd_ioc_update_size(struct fuse_conn *fc, struct pxd_update_size *update_size);
ssize_t pxd_read_init(struct fuse_conn *fc, struct iov_iter *iter);

void fuse_request_init(struct fuse_req *req);

void fuse_convert_zero_writes(struct fuse_req *req);

void fuse_process_user_request(struct fuse_conn *fc, struct fuse_user_request *ureq);

void fuse_queue_init_cb(struct fuse_queue_cb *cb);

struct fuse_req* request_find_in_ctx(unsigned ctx, u64 unique);
#endif
#endif /* _FS_FUSE_I_H */
