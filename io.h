#ifndef PXFUSE_IO_H
#define PXFUSE_IO_H

// SPDX-License-Identifier: GPL-2.0
/*
 * Shared application/kernel submission and completion ring pairs, for
 * supporting fast/efficient IO.
 *
 * A note on the read/write ordering memory barriers that are matched between
 * the application and kernel side.
 *
 * After the application reads the CQ ring tail, it must use an
 * appropriate smp_rmb() to pair with the smp_wmb() the kernel uses
 * before writing the tail (using smp_load_acquire to read the tail will
 * do). It also needs a smp_mb() before updating CQ head (ordering the
 * entry load(s) with the head store), pairing with an implicit barrier
 * through a control-dependency in io_get_cqring (smp_store_release to
 * store head will do). Failure to do so could lead to reading invalid
 * CQ entries.
 *
 * Likewise, the application must use an appropriate smp_wmb() before
 * writing the SQ tail (ordering SQ entry stores with the tail store),
 * which pairs with smp_load_acquire in io_get_sqring (smp_store_release
 * to store the tail will do). And it needs a barrier ordering the SQ
 * head load before writing new SQ entries (smp_load_acquire to read
 * head will do).
 *
 * When using the SQ poll thread (IORING_SETUP_SQPOLL), the application
 * needs to check the SQ flags for IORING_SQ_NEED_WAKEUP *after*
 * updating the SQ tail; a full memory barrier smp_mb() is needed
 * between.
 *
 * Also see the examples in the liburing library:
 *
 *	git://git.kernel.dk/liburing
 *
 * io_uring also uses READ/WRITE_ONCE() for _any_ store or load that happens
 * from data shared between the kernel and application. This is done both
 * for ordering purposes, but also to ensure that once a value is loaded from
 * data that the application could potentially modify, it remains stable.
 *
 * Copyright (C) 2018-2019 Jens Axboe
 * Copyright (c) 2018-2019 Christoph Hellwig
 */

#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/percpu-refcount.h>
#include <linux/miscdevice.h>
#include "fuse_i.h"

struct async_list {
	spinlock_t		lock;
	atomic_t		cnt;
	struct list_head	list;

	struct file		*file;
	off_t			io_end;
	size_t			io_pages;
};

struct io_ring_ctx {
	struct {
		struct percpu_ref	refs;
	} ____cacheline_aligned_in_smp;

	struct {
		unsigned int		flags;
		bool			compat;
		bool			account_mem;

		unsigned		cached_sq_head;
		unsigned		sq_entries;
		unsigned		sq_mask;
		unsigned		sq_thread_idle;

		void    *queue;

		struct fuse_queue_cb *requests_cb;
		struct fuse_queue_cb *responses_cb;
		struct io_uring_cqe *responses;
		struct io_uring_sqe *requests;

		struct list_head	defer_list;
	} ____cacheline_aligned_in_smp;

	/* IO offload */
	struct workqueue_struct	*sqo_wq;
#define NSLAVES (8)
	struct task_struct	*sqo_thread[NSLAVES];	/* if using sq thread polling */
	struct mm_struct	*sqo_mm;
	wait_queue_head_t	sqo_wait;
	spinlock_t		io_lock;

	struct {
		/* CQ ring */
		unsigned		cached_cq_tail;
		unsigned		cq_entries;
		unsigned		cq_mask;
		struct eventfd_ctx	*cq_ev_fd;
		struct wait_queue_head	cq_wait;
		struct fasync_struct	*cq_fasync;
	} ____cacheline_aligned_in_smp;

	/*
	 * If used, fixed file set. Writers must ensure that ->refs is dead,
	 * readers must ensure that ->refs is alive as long as the file* is
	 * used. Only updated through io_uring_register(2).
	 */
	struct file		**user_files;
	unsigned		nr_user_files;

	/* if used, fixed mapped user buffers */
	unsigned		nr_user_bufs;
	struct io_mapped_ubuf	*user_bufs;

	struct completion	ctx_done;

	struct {
		struct mutex		uring_lock;
		wait_queue_head_t	wait;
	} ____cacheline_aligned_in_smp;

	struct {
		spinlock_t		completion_lock;
		bool			poll_multi_file;
		/*
		 * ->poll_list is protected by the ctx->uring_lock for
		 * io_uring instances that don't use IORING_SETUP_SQPOLL.
		 * For SQPOLL, only the single threaded io_sq_thread() will
		 * manipulate the list, hence no extra locking is needed there.
		 */
		struct list_head	poll_list;
		struct list_head	cancel_list;
	} ____cacheline_aligned_in_smp;

	struct async_list	pending_async[2];

	uint32_t context_id;
};

struct sqe_submit {
	const struct io_uring_sqe	*sqe;
	unsigned short			index;
	bool				has_user;
	bool				needs_lock;
	bool				needs_fixed_file;
};

/*
 * First field must be the file pointer in all the
 * iocb unions! See also 'struct kiocb' in <linux/fs.h>
 */
struct io_poll_iocb {
	struct file			*file;
	struct wait_queue_head		*head;
	unsigned			events;
	bool				done;
	bool				canceled;
	struct wait_queue_entry		wait;
};

/*
 * NOTE! Each of the iocb union members has the file pointer
 * as the first entry in their struct definition. So you can
 * access the file pointer through any of the sub-structs,
 * or directly as just 'ki_filp' in this struct.
 */
struct io_kiocb {
	union {
		struct file		*file;
		struct kiocb		rw;
		struct io_poll_iocb	poll;
	};

	struct sqe_submit	submit;

	struct io_ring_ctx	*ctx;
	struct list_head	list;
	unsigned int		flags;
	refcount_t		refs;
#define REQ_F_NOWAIT		1	/* must not punt to workers */
#define REQ_F_IOPOLL_COMPLETED	2	/* polled IO has completed */
#define REQ_F_FIXED_FILE	4	/* ctx owns file */
#define REQ_F_SEQ_PREV		8	/* sequential with previous */
#define REQ_F_IO_DRAIN		16	/* drain existing IO first */
#define REQ_F_IO_DRAINED	32	/* drain done */
	u64			user_data;
	u32			error;	/* iopoll result from callback */
	u32			sequence;

	struct work_struct	work;
};

extern struct kmem_cache *req_cachep;

struct io_uring_params;

int io_ring_register_device(void);
void io_ring_unregister_device(void);

#endif //PXFUSE_IO_H
