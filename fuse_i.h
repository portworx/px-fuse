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

/** One input argument of a request */
struct fuse_in_arg {
	unsigned size;
	const void *value;
};

/** The request input */
struct fuse_in {
	/** The request header */
	struct fuse_in_header h;

	/** Number of arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_in_arg args[3];
};

/** One output argument of a request */
struct fuse_arg {
	unsigned size;
	void *value;
};

/** The request output */
struct fuse_out {
	/** Header returned from userspace */
	struct fuse_out_header h;
};

/**
 * A request to the client
 */
struct fuse_req {
	/** This can be on either pending processing or io lists in
	    fuse_conn */
	struct list_head list;

	/** Need to fetch state of device */
	struct pxd_device *pxd_dev;

	/** The request input */
	struct fuse_in in;

	/** The request output */
	struct fuse_out out;

	struct pxd_rdwr_in pxd_rdwr_in;

	union {
		/** Associated request structrure. */
		struct request *rq;

		/** Associated bio structrure. */
 		struct bio *bio;
	};

	/** Request completion callback */
	bool (*end)(struct fuse_conn *, struct fuse_req *, int status);

	/** Associate request queue */
	struct request_queue *queue;
#if defined __PXD_BIO_BLKMQ__ && defined __PX_FASTPATH__
	// Additional fastpath context
	struct fp_root_context fproot;
#endif
};

#if defined __PXD_BIO_BLKMQ__ && defined __PX_FASTPATH__
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

/*
 * Shared-memory queue control blocks.
 *
 * Layout is shared verbatim between kernel and userspace via the mmap'd queue.
 * Cursor and signaling slots are typed; the per-side lock is held in an
 * opaque 32-byte region (lock_storage) at offset 32 of each half. Each side
 * placement-initialises its own native lock type over that region at queue
 * init time -- spinlock_t on the kernel side (dev.c:fuse_queue_init_cb),
 * pthread_spinlock_t (or px::spinlock) on the userspace side. This keeps
 * the cross-build header free of pthread.h and free of any userspace lock
 * library, and gives LOCKDEP/DEBUG_SPINLOCK headroom on the kernel side.
 *
 * Field validity by channel (see netdoc 19 sec 11.2):
 *   - sequence:      load-bearing on fuse_conn_queues.user_requests_cb.w
 *                    (kernel-assigned monotonic ID counter consumed via
 *                    request_find_in_ctx for zero-copy READ_BIO/WRITE_BIO).
 *                    Reserved on io_ring_ctx.requests_cb.w and responses_cb.w.
 *   - need_wake_up:  load-bearing only on io_ring_ctx.requests_cb.w
 *                    (SQPOLL wake mailbox kernel -> userspace).
 *   - committed_:    load-bearing only on io_ring_ctx.requests_cb.w from
 *                    userspace (sync-mode batched-commit cursor); kernel
 *                    never touches it.
 *   - in_runq:       load-bearing only on io_ring_ctx.requests_cb.w from
 *                    userspace (sync-mode drain-dedupe flag); kernel never
 *                    touches it.
 *   - lock_storage:  always live on every channel.
 *
 * Reader-half cursors are accessed via smp_load_acquire / smp_store_release
 * on the kernel side and via std::atomic on the userspace side; both reduce
 * to the same plain uint32_t storage so the wire layout matches byte-for-byte.
 */

/** writer control block */
struct ____cacheline_aligned fuse_queue_writer {
	uint32_t write;            /** offset  0: producer cursor */
	uint32_t read;             /** offset  4: producer-cached consumer cursor */
	uint64_t sequence;         /** offset  8: kernel-assigned ID counter
				    *             (user_requests_cb channel only) */
	uint32_t need_wake_up;     /** offset 16: SQPOLL wake mailbox
				    *             (io_ring requests_cb only) */
	uint32_t committed_;       /** offset 20: userspace batched-commit cursor
				    *             (io_ring requests_cb only) */
	uint8_t  in_runq;          /** offset 24: userspace drain-dedupe flag
				    *             (io_ring requests_cb only) */
	uint8_t  __pad1[7];        /** offset 25..31 */
	uint8_t  lock_storage[32]; /** offset 32: opaque slot, each side placement-
				    *             inits its own native lock here */
};

/** reader control block */
struct ____cacheline_aligned fuse_queue_reader {
	uint32_t read;             /** offset  0: consumer cursor (shared) */
	uint32_t write;            /** offset  4: producer cursor (shared) */
	uint8_t  __pad1[24];       /** offset  8..31 */
	uint8_t  lock_storage[32]; /** offset 32: opaque slot */
};

#ifdef __KERNEL__
/*
 * Helpers: reinterpret lock_storage as the kernel's native spinlock_t. The
 * sizing and offset invariants are enforced by BUILD_BUG_ON in dev.c at
 * fuse_queue_init_cb time, so callers can assume both halves are valid.
 */
static inline spinlock_t *fuse_qw_lock(struct fuse_queue_writer *w)
{
	return (spinlock_t *)w->lock_storage;
}

static inline spinlock_t *fuse_qr_lock(struct fuse_queue_reader *r)
{
	return (spinlock_t *)r->lock_storage;
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

	/** The list of pending requests */
	struct list_head pending;

	/** The list of requests being processed */
	struct list_head processing;

	/** maps request ids to requests */
	struct fuse_req **request_map;

	/** stack of free ids */
	u64 *free_ids;

	/** number of free ids in stack */
	u32 num_free_ids;

	/** per cpu id allocators */
	struct fuse_per_cpu_ids __percpu *per_cpu_ids;

	/** The next unique request id */
	u64 reqctr;

	/** Connection established, cleared on umount, connection
	    abort and device release */
	bool connected;

	/* Alow operations on disconnected fuse conenction. */
	bool allow_disconnected;

	/** Refcount */
	atomic_t count;

	/** Entry on the fuse_conn_list */
	struct list_head entry;

	/** O_ASYNC requests */
	struct fasync_struct *fasync;

	/** Called on final put */
	void (*release)(struct fuse_conn *);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	/** Shared-memory request/response queues used by the io_uring transport.
	 *  Allocated and freed via pxd_uring_init_conn() / pxd_uring_free_conn(). */
	struct fuse_conn_queues *queue;
#endif
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

void fuse_restart_requests(struct fuse_conn *fc);
void fuse_convert_zero_writes(struct fuse_req *req);

ssize_t pxd_add(struct fuse_conn *fc, struct pxd_add_v2_out *add);
ssize_t pxd_remove(struct fuse_conn *fc, struct pxd_remove_out *remove);
ssize_t pxd_update_size(struct fuse_conn *fc, struct pxd_update_size *update_size);
ssize_t pxd_ioc_update_size(struct fuse_conn *fc, struct pxd_update_size *update_size);
ssize_t pxd_read_init(struct fuse_conn *fc, struct iov_iter *iter);
ssize_t pxd_export(struct fuse_conn *fc, uint64_t dev_id);

// fastpath extension
ssize_t pxd_update_path(struct fuse_conn *fc, struct pxd_update_path_out *update_path);
int pxd_set_fastpath(struct fuse_conn *fc, struct pxd_fastpath_out*);

void fuse_request_init(struct fuse_req *req);
void fuse_req_init_context(struct fuse_req *req);

void request_end(struct fuse_conn *fc, struct fuse_req *req, bool lock);
struct fuse_req *request_find(struct fuse_conn *fc, u64 unique);

/* Generic queue control-block init. Defined in dev.c. The body also calls
 * pxd_uring_init_cb() (declared in io.h) when uring is compiled in, so any
 * uring-specific per-CB setup lives in io.c, not here. */
void fuse_queue_init_cb(struct fuse_queue_cb *cb);

#endif
#endif /* _FS_FUSE_I_H */
