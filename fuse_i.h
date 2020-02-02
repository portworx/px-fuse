/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#ifndef _FS_FUSE_I_H
#define _FS_FUSE_I_H

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

struct fuse_conn;

/**
 * A request to the client
 */
struct fuse_req {
	/** Request to use fastpath */
	unsigned fastpath:1;

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
	void (*end)(struct fuse_conn *, struct fuse_req *, int status);

	/** Associate request queue */
	struct request_queue *queue;

	/** sequence number used for restart */
	u64 sequence;
};

#define FUSE_MAX_PER_CPU_IDS 256

struct ____cacheline_aligned fuse_per_cpu_ids {
	/** number of free ids in stack */
	u32 num_free_ids;

	/** followed by list of free ids */
	u64 free_ids[FUSE_MAX_PER_CPU_IDS];
};

/** size of request ring buffer */
#define FUSE_REQUEST_QUEUE_SIZE (2 * FUSE_DEFAULT_MAX_BACKGROUND)

/** request queue */
struct ____cacheline_aligned fuse_req_queue {
	struct ____cacheline_aligned {
		uint32_t write;         /** cached write pointer */
		uint32_t read;		/** cached read pointer */
		spinlock_t lock;	/** writer lock */
		uint32_t pad_0;
		uint64_t sequence;        /** next request sequence number */
		struct rdwr_in *requests;	/** request ring buffer */
		uint64_t pad[4];
	} w;

	struct ____cacheline_aligned {
		uint32_t read;          /** read index updated by reader */
		uint32_t write;		/** write pointer updated by receive function */
		struct rdwr_in *requests;	/** request ring buffer */
		uint64_t pad_2[14];
	} r;
};

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
	struct fuse_req_queue queue;

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

	/** The next unique request id */
	u64 reqctr;

	/** Refcount */
	atomic_t count;

	/** Entry on the fuse_conn_list */
	struct list_head entry;

	/** O_ASYNC requests */
	struct fasync_struct *fasync;

	/** Called on final put */
	void (*release)(struct fuse_conn *);
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

int fuse_restart_requests(struct fuse_conn *fc);

ssize_t pxd_add(struct fuse_conn *fc, struct pxd_add_ext_out *add);
ssize_t pxd_remove(struct fuse_conn *fc, struct pxd_remove_out *remove);
ssize_t pxd_update_size(struct fuse_conn *fc, struct pxd_update_size_out *update_size);
ssize_t pxd_read_init(struct fuse_conn *fc, struct iov_iter *iter);

// fastpath extension
ssize_t pxd_update_path(struct fuse_conn *fc, struct pxd_update_path_out *update_path);
int pxd_set_fastpath(struct fuse_conn *fc, struct pxd_fastpath_out*);

void fuse_request_init(struct fuse_req *req);

void fuse_convert_zero_writes(struct fuse_req *req);

#endif /* _FS_FUSE_I_H */
