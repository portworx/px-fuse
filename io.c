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
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/refcount.h>
#include <linux/uio.h>

#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmu_context.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/blkdev.h>
#include <linux/bvec.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <net/scm.h>
#include <linux/anon_inodes.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/nospec.h>
#include <linux/sizes.h>
#include <linux/hugetlb.h>
#include <linux/blkdev.h>

#include "pxd_io_uring.h"
#include "io.h"
#include "fuse_i.h"
#include "pxd_core.h"
#include "pxd_compat.h"

#include <uapi/linux/eventpoll.h>

#define IORING_MAX_ENTRIES	4096
#define IORING_MAX_FIXED_FILES	1024

struct io_uring {
	u32 head ____cacheline_aligned_in_smp;
	u32 tail ____cacheline_aligned_in_smp;
};

/*
 * This data is shared with the application through the mmap at offset
 * IORING_OFF_SQ_RING.
 *
 * The offsets to the member fields are published through struct
 * io_sqring_offsets when calling io_uring_setup.
 */
struct io_sq_ring {
	/*
	 * Head and tail offsets into the ring; the offsets need to be
	 * masked to get valid indices.
	 *
	 * The kernel controls head and the application controls tail.
	 */
	struct io_uring		r;
	/*
	 * Bitmask to apply to head and tail offsets (constant, equals
	 * ring_entries - 1)
	 */
	u32			ring_mask;
	/* Ring size (constant, power of 2) */
	u32			ring_entries;
	/*
	 * Number of invalid entries dropped by the kernel due to
	 * invalid index stored in array
	 *
	 * Written by the kernel, shouldn't be modified by the
	 * application (i.e. get number of "new events" by comparing to
	 * cached value).
	 *
	 * After a new SQ head value was read by the application this
	 * counter includes all submissions that were dropped reaching
	 * the new SQ head (and possibly more).
	 */
	u32			dropped;
	/*
	 * Runtime flags
	 *
	 * Written by the kernel, shouldn't be modified by the
	 * application.
	 *
	 * The application needs a full memory barrier before checking
	 * for IORING_SQ_NEED_WAKEUP after updating the sq tail.
	 */
	u32			flags;
	/*
	 * Ring buffer of indices into array of io_uring_sqe, which is
	 * mmapped by the application using the IORING_OFF_SQES offset.
	 *
	 * This indirection could e.g. be used to assign fixed
	 * io_uring_sqe entries to operations and only submit them to
	 * the queue when needed.
	 *
	 * The kernel modifies neither the indices array nor the entries
	 * array.
	 */
	u32			array[];
};

/*
 * This data is shared with the application through the mmap at offset
 * IORING_OFF_CQ_RING.
 *
 * The offsets to the member fields are published through struct
 * io_cqring_offsets when calling io_uring_setup.
 */
struct io_cq_ring {
	/*
	 * Head and tail offsets into the ring; the offsets need to be
	 * masked to get valid indices.
	 *
	 * The application controls head and the kernel tail.
	 */
	struct io_uring		r;
	/*
	 * Bitmask to apply to head and tail offsets (constant, equals
	 * ring_entries - 1)
	 */
	u32			ring_mask;
	/* Ring size (constant, power of 2) */
	u32			ring_entries;
	/*
	 * Number of completion events lost because the queue was full;
	 * this should be avoided by the application by making sure
	 * there are not more requests pending thatn there is space in
	 * the completion queue.
	 *
	 * Written by the kernel, shouldn't be modified by the
	 * application (i.e. get number of "new events" by comparing to
	 * cached value).
	 *
	 * As completion events come in out of order this counter is not
	 * ordered with any other data.
	 */
	u32			overflow;
	/*
	 * Ring buffer of completion events.
	 *
	 * The kernel writes completion events fresh every time they are
	 * produced, so the application is allowed to modify pending
	 * entries.
	 */
	struct io_uring_cqe	cqes[];
};

struct io_mapped_ubuf {
	u64		ubuf;
	size_t		len;
	struct		bio_vec *bvec;
	unsigned int	nr_bvecs;
};

#define IO_PLUG_THRESHOLD		2
#define IO_IOPOLL_BATCH			8

struct io_submit_state {
	struct blk_plug		plug;

	/*
	 * io_kiocb alloc cache
	 */
	void			*reqs[IO_IOPOLL_BATCH];
	unsigned		int free_reqs;
	unsigned		int cur_req;

	/*
	 * File reference cache
	 */
	struct file		*file;
	unsigned int		fd;
	unsigned int		has_refs;
	unsigned int		used_refs;
	unsigned int		ios_left;
};

static void io_sq_wq_submit_work(struct work_struct *work);

struct kmem_cache *req_cachep;

static void io_ring_ctx_ref_free(struct percpu_ref *ref)
{
	struct io_ring_ctx *ctx = container_of(ref, struct io_ring_ctx, refs);

	complete(&ctx->ctx_done);
}

static size_t queue_size(struct io_ring_ctx *ctx)
{
	return sizeof(struct fuse_queue_cb) + sizeof(struct fuse_queue_cb) +
			ctx->sq_entries * sizeof(struct io_uring_sqe) +
			ctx->cq_entries * sizeof(struct io_uring_cqe);
}

static int io_ring_ctx_init(struct io_ring_ctx *ctx, struct io_uring_params *params)
{
	int i;

	memset(ctx, 0, sizeof(*ctx));

	ctx->flags = params->flags;
	ctx->sq_thread_idle = params->sq_thread_idle;

	params->sq_entries = params->sq_entries == 0 ?
							FUSE_REQUEST_QUEUE_SIZE : roundup_pow_of_two(
								params->sq_entries);
	params->cq_entries = params->cq_entries == 0 ?
							FUSE_REQUEST_QUEUE_SIZE : roundup_pow_of_two(
								params->cq_entries);

	ctx->sq_entries = params->sq_entries;
	ctx->sq_mask = ctx->sq_entries - 1;
	ctx->cq_entries = params->cq_entries;
	ctx->cq_mask = ctx->cq_entries - 1;

	ctx->queue = vmalloc((queue_size(ctx) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
	if (!ctx->queue) {
		printk(KERN_ERR "failed to allocate request queue");
		return -ENOMEM;
	}

	ctx->requests_cb = ctx->queue;
	ctx->requests = (void *)(ctx->requests_cb + 1);
	ctx->responses_cb = (void *)(ctx->requests + ctx->sq_entries);
	ctx->responses = (void *)(ctx->responses_cb + 1);

	pr_info("queue size %ld requests_cb %ld requests %ld responses_cb %ld responses %ld",
			queue_size(ctx), (void *)ctx->requests_cb - ctx->queue,
			(void *)ctx->requests - ctx->queue,
			(void *)ctx->responses_cb - ctx->queue,
			(void *)ctx->responses - ctx->queue);

	fuse_queue_init_cb(ctx->requests_cb);
	fuse_queue_init_cb(ctx->responses_cb);

	ctx->user_files = kcalloc(IORING_MAX_FIXED_FILES, sizeof(struct file *),
		GFP_KERNEL);
	if (ctx->user_files == NULL) {
		vfree(ctx->queue);
		return -ENOMEM;
	}
	ctx->nr_user_files = IORING_MAX_FIXED_FILES;

	if (percpu_ref_init(&ctx->refs, io_ring_ctx_ref_free, 0, GFP_KERNEL)) {
		vfree(ctx->queue);
		kfree(ctx->user_files);
		return -ENOMEM;
	}

	init_waitqueue_head(&ctx->wait);
	init_completion(&ctx->ctx_done);
	mutex_init(&ctx->uring_lock);
	init_waitqueue_head(&ctx->cq_wait);
	for (i = 0; i < ARRAY_SIZE(ctx->pending_async); i++) {
		spin_lock_init(&ctx->pending_async[i].lock);
		INIT_LIST_HEAD(&ctx->pending_async[i].list);
		atomic_set(&ctx->pending_async[i].cnt, 0);
	}
	spin_lock_init(&ctx->completion_lock);
	INIT_LIST_HEAD(&ctx->poll_list);
	INIT_LIST_HEAD(&ctx->cancel_list);
	INIT_LIST_HEAD(&ctx->defer_list);

	return 0;
}

static inline bool io_sequence_defer(struct io_ring_ctx *ctx,
				     struct io_kiocb *req)
{
	if ((req->flags & (REQ_F_IO_DRAIN|REQ_F_IO_DRAINED)) != REQ_F_IO_DRAIN)
		return false;

	return req->sequence > ctx->cached_cq_tail;
}

static struct io_kiocb *io_get_deferred_req(struct io_ring_ctx *ctx)
{
	struct io_kiocb *req;

	if (list_empty(&ctx->defer_list))
		return NULL;

	req = list_first_entry(&ctx->defer_list, struct io_kiocb, list);
	if (!io_sequence_defer(ctx, req)) {
		list_del_init(&req->list);
		return req;
	}

	return NULL;
}

static void __io_commit_cqring(struct io_ring_ctx *ctx)
{
	struct fuse_queue_cb *cb = ctx->responses_cb;

	if (ctx->cached_cq_tail != READ_ONCE(cb->r.write)) {
		/* order cqe stores with ring update */
		smp_store_release(&cb->r.write, ctx->cached_cq_tail);

		if (wq_has_sleeper(&ctx->cq_wait)) {
			wake_up_interruptible(&ctx->cq_wait);
			kill_fasync(&ctx->cq_fasync, SIGIO, POLL_IN);
		}
	}
}

static void io_commit_cqring(struct io_ring_ctx *ctx)
{
	struct io_kiocb *req;

	__io_commit_cqring(ctx);

	while ((req = io_get_deferred_req(ctx)) != NULL) {
		req->flags |= REQ_F_IO_DRAINED;
		queue_work(ctx->sqo_wq, &req->work);
	}
}

static struct io_uring_cqe *io_get_cqring(struct io_ring_ctx *ctx)
{
	struct fuse_queue_cb *cb = ctx->responses_cb;
	unsigned tail;

	tail = ctx->cached_cq_tail;

	/*
	 * writes to the cq entry need to come after reading head; the
	 * control dependency is enough as we're using WRITE_ONCE to
	 * fill the cq entry
	 */
	if (tail - READ_ONCE(cb->r.read) == ctx->cq_entries)
		return NULL;

	ctx->cached_cq_tail++;
	return &ctx->responses[tail & ctx->cq_mask];
}

static void io_cqring_fill_event(struct io_ring_ctx *ctx, u64 ki_user_data,
				 long res)
{
	struct io_uring_cqe *cqe;

	cqe = io_get_cqring(ctx);
	BUG_ON(!cqe);
	WRITE_ONCE(cqe->user_data, ki_user_data);
	WRITE_ONCE(cqe->res, res);
	WRITE_ONCE(cqe->flags, 0);
}

static void io_cqring_add_event(struct io_ring_ctx *ctx, u64 user_data,
				long res)
{
	struct fuse_queue_cb *cb = ctx->responses_cb;

	unsigned long flags;

	spin_lock_irqsave(&cb->w.lock, flags);
	io_cqring_fill_event(ctx, user_data, res);
	io_commit_cqring(ctx);
	spin_unlock_irqrestore(&cb->w.lock, flags);
}

static void io_ring_drop_ctx_refs(struct io_ring_ctx *ctx, unsigned refs)
{
	percpu_ref_put_many(&ctx->refs, refs);

	if (waitqueue_active(&ctx->wait))
		wake_up(&ctx->wait);
}

static struct io_kiocb *io_get_req(struct io_ring_ctx *ctx,
				   struct io_submit_state *state)
{
	gfp_t gfp = GFP_KERNEL | __GFP_NOWARN;
	struct io_kiocb *req;

	if (!percpu_ref_tryget(&ctx->refs))
		return NULL;

	if (!state) {
		req = kmem_cache_alloc(req_cachep, gfp);
		if (unlikely(!req))
			goto out;
	} else if (!state->free_reqs) {
		size_t sz;
		int ret;

		sz = min_t(size_t, state->ios_left, ARRAY_SIZE(state->reqs));
		ret = kmem_cache_alloc_bulk(req_cachep, gfp, sz, state->reqs);

		/*
		 * Bulk alloc is all-or-nothing. If we fail to get a batch,
		 * retry single alloc to be on the safe side.
		 */
		if (unlikely(ret <= 0)) {
			state->reqs[0] = kmem_cache_alloc(req_cachep, gfp);
			if (!state->reqs[0])
				goto out;
			ret = 1;
		}
		state->free_reqs = ret - 1;
		state->cur_req = 1;
		req = state->reqs[0];
	} else {
		req = state->reqs[state->cur_req];
		state->free_reqs--;
		state->cur_req++;
	}

	req->file = NULL;
	req->ctx = ctx;
	req->flags = 0;
	/* one is dropped after submission, the other at completion */
	refcount_set(&req->refs, 2);
	return req;
out:
	io_ring_drop_ctx_refs(ctx, 1);
	return NULL;
}

static void io_free_req(struct io_kiocb *req)
{
	if (req->file && !(req->flags & REQ_F_FIXED_FILE))
		fput(req->file);
	io_ring_drop_ctx_refs(req->ctx, 1);
	kmem_cache_free(req_cachep, req);
}

static void io_put_req(struct io_kiocb *req)
{
	if (refcount_dec_and_test(&req->refs))
		io_free_req(req);
}

static void kiocb_end_write(struct kiocb *kiocb)
{
	if (kiocb->ki_flags & IOCB_WRITE) {
		struct inode *inode = file_inode(kiocb->ki_filp);

		/*
		 * Tell lockdep we inherited freeze protection from submission
		 * thread.
		 */
		if (S_ISREG(inode->i_mode))
			__sb_writers_acquired(inode->i_sb, SB_FREEZE_WRITE);
		file_end_write(kiocb->ki_filp);
	}
}

static void io_complete_rw(struct kiocb *kiocb, long res, long res2)
{
	struct io_kiocb *req = container_of(kiocb, struct io_kiocb, rw);

	kiocb_end_write(kiocb);

	io_cqring_add_event(req->ctx, req->user_data, res);
	io_put_req(req);
}

/*
 * If we tracked the file through the SCM inflight mechanism, we could support
 * any file. For now, just ensure that anything potentially problematic is done
 * inline.
 */
static bool io_file_supports_async(struct file *file)
{
	umode_t mode = file_inode(file)->i_mode;

	if (S_ISBLK(mode) || S_ISCHR(mode))
		return true;
	if (S_ISREG(mode) && file->f_op != &fuse_dev_operations)
		return true;

	return false;
}

static int io_prep_rw(struct io_kiocb *req, const struct sqe_submit *s,
		      bool force_nonblock)
{
	const struct io_uring_sqe *sqe = s->sqe;
	struct kiocb *kiocb = &req->rw;
	int ret;

	if (!req->file) {
		pr_info("%s: file is null", __func__);
		return -EBADF;
	}

	if (force_nonblock && !io_file_supports_async(req->file))
		force_nonblock = false;

	kiocb->ki_pos = READ_ONCE(sqe->off);
	kiocb->ki_flags = iocb_flags(kiocb->ki_filp);
	kiocb->ki_hint = file_write_hint(kiocb->ki_filp);

	ret = kiocb_set_rw_flags(kiocb, READ_ONCE(sqe->rw_flags));
	if (unlikely(ret)) {
		pr_info("%s: kiocb_set_rw_flags %d", __func__, ret);
		return ret;
	}

	/* don't allow async punt if RWF_NOWAIT was requested */
	if (kiocb->ki_flags & IOCB_NOWAIT)
		req->flags |= REQ_F_NOWAIT;

	if (force_nonblock)
		kiocb->ki_flags |= IOCB_NOWAIT;

	if (kiocb->ki_flags & IOCB_HIPRI) {
		pr_info("%s: ki_flags has HIPRI", __func__);
		return -EINVAL;
	}
	kiocb->ki_complete = io_complete_rw;
	return 0;
}

static inline void io_rw_done(struct kiocb *kiocb, ssize_t ret)
{
	switch (ret) {
	case -EIOCBQUEUED:
		break;
	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
	case -ERESTART_RESTARTBLOCK:
		/*
		 * We can't just restart the syscall, since previously
		 * submitted sqes may already be in progress. Just fail this
		 * IO with EINTR.
		 */
		ret = -EINTR;
		/* fall through */
	default:
		kiocb->ki_complete(kiocb, ret, 0);
	}
}

static int io_import_fixed(struct io_ring_ctx *ctx, int rw,
			   const struct io_uring_sqe *sqe,
			   struct iov_iter *iter)
{
	size_t len = READ_ONCE(sqe->len);
	struct io_mapped_ubuf *imu;
	unsigned index, buf_index;
	size_t offset;
	u64 buf_addr;

	/* attempt to use fixed buffers without having provided iovecs */
	if (unlikely(!ctx->user_bufs))
		return -EFAULT;

	buf_index = READ_ONCE(sqe->buf_index);
	if (unlikely(buf_index >= ctx->nr_user_bufs))
		return -EFAULT;

	index = array_index_nospec(buf_index, ctx->nr_user_bufs);
	imu = &ctx->user_bufs[index];
	buf_addr = READ_ONCE(sqe->addr);

	/* overflow */
	if (buf_addr + len < buf_addr)
		return -EFAULT;
	/* not inside the mapped region */
	if (buf_addr < imu->ubuf || buf_addr + len > imu->ubuf + imu->len)
		return -EFAULT;

	/*
	 * May not be a start of buffer, set size appropriately
	 * and advance us to the beginning.
	 */
	offset = buf_addr - imu->ubuf;
	iov_iter_bvec(iter, rw, imu->bvec, imu->nr_bvecs, offset + len);
	if (offset)
		iov_iter_advance(iter, offset);
	return 0;
}

static int io_import_iovec(struct io_ring_ctx *ctx, int rw,
			   const struct sqe_submit *s, struct iovec **iovec,
			   struct iov_iter *iter)
{
	const struct io_uring_sqe *sqe = s->sqe;
	void __user *buf = u64_to_user_ptr(READ_ONCE(sqe->addr));
	size_t sqe_len = READ_ONCE(sqe->len);
	u8 opcode;

	/*
	 * We're reading ->opcode for the second time, but the first read
	 * doesn't care whether it's _FIXED or not, so it doesn't matter
	 * whether ->opcode changes concurrently. The first read does care
	 * about whether it is a READ or a WRITE, so we don't trust this read
	 * for that purpose and instead let the caller pass in the read/write
	 * flag.
	 */
	opcode = READ_ONCE(sqe->opcode);
	if (opcode == IORING_OP_READ_FIXED ||
	    opcode == IORING_OP_WRITE_FIXED) {
		int ret = io_import_fixed(ctx, rw, sqe, iter);
		*iovec = NULL;
		return ret;
	}

	if (!s->has_user)
		return -EFAULT;

	return import_iovec(rw, buf, sqe_len, UIO_FASTIOV, iovec, iter);
}

/*
 * Make a note of the last file/offset/direction we punted to async
 * context. We'll use this information to see if we can piggy back a
 * sequential request onto the previous one, if it's still hasn't been
 * completed by the async worker.
 */
static void io_async_list_note(int rw, struct io_kiocb *req, size_t len)
{
	struct async_list *async_list = &req->ctx->pending_async[rw];
	struct kiocb *kiocb = &req->rw;
	struct file *filp = kiocb->ki_filp;
	off_t io_end = kiocb->ki_pos + len;

	if (filp == async_list->file && kiocb->ki_pos == async_list->io_end) {
		unsigned long max_pages;

		/* Use 8x RA size as a decent limiter for both reads/writes */
		max_pages = filp->f_ra.ra_pages;
		if (!max_pages)
			max_pages = SZ_128K / PAGE_SIZE;
		max_pages *= 8;

		/* If max pages are exceeded, reset the state */
		len >>= PAGE_SHIFT;
		if (async_list->io_pages + len <= max_pages) {
			req->flags |= REQ_F_SEQ_PREV;
			async_list->io_pages += len;
		} else {
			io_end = 0;
			async_list->io_pages = 0;
		}
	}

	/* New file? Reset state. */
	if (async_list->file != filp) {
		async_list->io_pages = 0;
		async_list->file = filp;
	}
	async_list->io_end = io_end;
}

static int io_read(struct io_kiocb *req, const struct sqe_submit *s,
		   bool force_nonblock)
{
	struct iovec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	struct kiocb *kiocb = &req->rw;
	struct iov_iter iter;
	struct file *file;
	size_t iov_count;
	int ret;
	ssize_t ret2;

	ret = io_prep_rw(req, s, force_nonblock);
	if (ret)
		return ret;
	file = kiocb->ki_filp;

	if (unlikely(!(file->f_mode & FMODE_READ)))
		return -EBADF;
	if (unlikely(!file->f_op->read_iter))
		return -EINVAL;

	ret = io_import_iovec(req->ctx, READ, s, &iovec, &iter);
	if (ret < 0)
		return ret;

	iov_count = iov_iter_count(&iter);
	/* Catch -EAGAIN return for forced non-blocking submission */
	ret2 = call_read_iter(file, kiocb, &iter);
	if (!force_nonblock || ret2 != -EAGAIN) {
		io_rw_done(kiocb, ret2);
		ret = 0;
	} else {
		/*
		 * If ->needs_lock is true, we're already in async
		 * context.
		 */
		if (!s->needs_lock)
			io_async_list_note(READ, req, iov_count);
		ret = -EAGAIN;
	}
	kfree(iovec);
	return ret;
}

static int io_write(struct io_kiocb *req, const struct sqe_submit *s,
		    bool force_nonblock)
{
	struct iovec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	struct kiocb *kiocb = &req->rw;
	struct iov_iter iter;
	struct file *file;
	size_t iov_count;
	int ret;
	ssize_t ret2;

	ret = io_prep_rw(req, s, force_nonblock);
	if (ret) {
		pr_info("%s: io prep rw fail: %d", __func__, ret);
		return ret;
	}

	file = kiocb->ki_filp;
	if (unlikely(!(file->f_mode & FMODE_WRITE)))
		return -EBADF;
	if (unlikely(!file->f_op->write_iter)) {
		pr_info("%s: write iter is NULL", __func__);
		return -EINVAL;
	}

	ret = io_import_iovec(req->ctx, WRITE, s, &iovec, &iter);
	if (ret < 0)
		return ret;

	iov_count = iov_iter_count(&iter);

	ret = -EAGAIN;
	if (force_nonblock &&
	    ((s->sqe->flags & IOSQE_FORCE_ASYNC) || !(kiocb->ki_flags & IOCB_DIRECT))) {
		/* If ->needs_lock is true, we're already in async context. */
		if (!s->needs_lock)
			io_async_list_note(WRITE, req, iov_count);
		goto out_free;
	}

	/*
	 * Open-code file_start_write here to grab freeze protection,
	 * which will be released by another thread in
	 * io_complete_rw().  Fool lockdep by telling it the lock got
	 * released so that it doesn't complain about the held lock when
	 * we return to userspace.
	 */
	if (S_ISREG(file_inode(file)->i_mode)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
		__sb_start_write(file_inode(file)->i_sb,
			SB_FREEZE_WRITE);
#else
		__sb_start_write(file_inode(file)->i_sb,
			SB_FREEZE_WRITE, true);
#endif
		__sb_writers_release(file_inode(file)->i_sb,
			SB_FREEZE_WRITE);
	}
	kiocb->ki_flags |= IOCB_WRITE;

	ret2 = call_write_iter(file, kiocb, &iter);
	if (!force_nonblock || ret2 != -EAGAIN) {
		io_rw_done(kiocb, ret2);
		ret = 0;
	} else {
		/*
		 * If ->needs_lock is true, we're already in async
		 * context.
		 */
		if (!s->needs_lock)
			io_async_list_note(WRITE, req, iov_count);
		ret = -EAGAIN;
	}
out_free:
	kfree(iovec);
	return ret;
}

// return nr_bytes in iovec if successful
//   < 0 for failure
#ifndef __PXD_BIO_MAKEREQ__
static int build_bvec(struct fuse_req *req, int *rw, size_t off, size_t len,
						struct bio_vec **iovec, struct iov_iter *iter)
{
	struct request *rq = req->rq;
	int nr_bvec = 0;
	struct bio_vec *bvec = NULL;
	struct bio_vec *alloc_bvec = NULL;
	struct bio *bio = rq->bio;
	struct req_iterator rq_iter;
	struct bio_vec tmp;
	size_t offset = 0;
	size_t skip;
	bool map_end = false;
	size_t map_len = len;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
	rq_for_each_bvec(tmp, rq, rq_iter) {
#else
	rq_for_each_segment(tmp, rq, rq_iter) {
#endif
		nr_bvec++;
	}

	if (nr_bvec > UIO_FASTIOV) {
		alloc_bvec = bvec = kmalloc_array(nr_bvec, sizeof(struct bio_vec),
			     GFP_NOIO);
	} else {
		alloc_bvec = bvec = *iovec;
	}
	if (!bvec)
		return -EIO;

	skip = off - (BIO_SECTOR(bio) << SECTOR_SHIFT);
	nr_bvec = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
	rq_for_each_bvec(tmp, rq, rq_iter) {
#else
	rq_for_each_segment(tmp, rq, rq_iter) {
#endif
		if (!tmp.bv_len) continue;
		if (skip >= tmp.bv_len) {
			skip -= tmp.bv_len;
			continue;
		} else if (!map_end) {
			size_t bvlen = tmp.bv_len - skip;
			map_end = true;
			nr_bvec++;
			offset = skip;
			if (bvlen >= map_len) {
				tmp.bv_len = map_len;
				*bvec = tmp;
				break;
			}
			*bvec = tmp;
			bvec++;
			map_len -= bvlen;
			skip = 0;
		} else {
			nr_bvec++;
			if (map_len <= tmp.bv_len) {
				tmp.bv_len = map_len;
				*bvec = tmp;
				break;
			}
			*bvec = tmp;
			bvec++;
			map_len -= tmp.bv_len;
		}
	}
	bvec = alloc_bvec;
	*rw = bio_data_dir(bio);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
	iov_iter_bvec(iter, bio_data_dir(bio), bvec, nr_bvec, len);
#else
	iov_iter_bvec(iter, ITER_BVEC | bio_data_dir(bio), bvec, nr_bvec, len);
#endif
	iter->iov_offset = offset;

	return len;
}
#else
static int build_bvec(struct fuse_req *req, int *rw, size_t off, size_t len,
		struct bio_vec **iovec, struct iov_iter *iter)
{
	struct bio *bio = req->bio;
	int nr_bvec = bio->bi_vcnt;
	struct bio_vec *bvec = NULL;
	struct bio_vec *alloc_bvec = NULL;
	struct bvec_iter bv_iter;
	struct bio_vec bv;
	size_t offset = 0;
	size_t skip;
	bool map_end = false;
	size_t map_len = len;

	if (nr_bvec > UIO_FASTIOV) {
		alloc_bvec = bvec = kmalloc_array(nr_bvec, sizeof(struct bio_vec),
			     GFP_NOIO);
	} else {
		alloc_bvec = bvec = *iovec;
	}
	if (!bvec)
		return -EIO;

	nr_bvec = 0;
	skip = off - (BIO_SECTOR(bio) << SECTOR_SHIFT);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
	bio_for_each_bvec(bv, bio, bv_iter) {
#else
	bio_for_each_segment(bv, bio, bv_iter) {
#endif
		if (!bv.bv_len) continue;
		if (skip >= bv.bv_len) {
			skip -= bv.bv_len;
			continue;
		} else if (!map_end) {
			size_t bvlen = bv.bv_len - skip;
			map_end = true;
			nr_bvec++;
			offset = skip;
			if (bvlen >= map_len) {
				bv.bv_len = map_len;
				*bvec = bv;
				break;
			}
			*bvec = bv;
			bvec++;
			map_len -= bvlen;
			skip = 0;
		} else {
			nr_bvec++;
			if (map_len <= bv.bv_len) {
				bv.bv_len = map_len;
				*bvec = bv;
				break;
			}
			*bvec = bv;
			bvec++;
			map_len -= bv.bv_len;
		}
	}

	bvec = alloc_bvec;
	*rw = bio_data_dir(bio);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
	iov_iter_bvec(iter, bio_data_dir(bio), bvec, nr_bvec, len);
#else
	iov_iter_bvec(iter, ITER_BVEC | bio_data_dir(bio), bvec, nr_bvec, len);
#endif
	iter->iov_offset = offset;
	return len;
}
#endif

static int io_import_bvec(struct io_kiocb *req, int *rw,
			   const struct sqe_submit *s, struct bio_vec **iovec,
			   struct iov_iter *iter)
{
	const struct io_uring_sqe *sqe = s->sqe;
	size_t sqe_off = req->rw.ki_pos;
	size_t sqe_len = READ_ONCE(sqe->len);
	uint64_t unique_id = READ_ONCE(sqe->addr);
	uint32_t conn_id = READ_ONCE(sqe->buf_index);
	struct fuse_req *freq;

	if (!s->has_user)
		return -EFAULT;

	freq = request_find_in_ctx(conn_id, unique_id);
	if (!freq) {
		printk(KERN_ERR "%s: request %u:%lld not found\n", __func__, conn_id, unique_id);
		return -ENOENT;
	}

	return build_bvec(freq, rw, sqe_off, sqe_len, iovec, iter);
}

static int io_switch(struct io_kiocb *req, const struct sqe_submit *s,
		    int dir, bool force_nonblock)
{
	struct bio_vec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	struct kiocb *kiocb = &req->rw;
	struct iov_iter iter;
	struct file *file;
	size_t iov_count;
	int ret;
	ssize_t ret2;
	int rw;

	ret = io_prep_rw(req, s, force_nonblock);
	if (ret) {
		pr_info("%s: io prep rw fail: %d", __func__, ret);
		return ret;
	}

	file = kiocb->ki_filp;
	if (unlikely(!(file->f_mode & FMODE_WRITE)))
		return -EBADF;
	if (unlikely(!file->f_op->write_iter)) {
		pr_info("%s: write iter is NULL", __func__);
		return -EINVAL;
	}

	ret = io_import_bvec(req, &rw, s, &iovec, &iter);
	if (ret < 0)
		goto out_free;

	if (rw != dir) {
		ret = -EINVAL;
		pr_info("%s: invalid direction", __func__);
		goto out_free;
	}

	iov_count = iov_iter_count(&iter);

	ret = -EAGAIN;
	if (force_nonblock &&
	    ((s->sqe->flags & IOSQE_FORCE_ASYNC) || !(kiocb->ki_flags & IOCB_DIRECT))) {
		/* If ->needs_lock is true, we're already in async context. */
		if (!s->needs_lock)
			io_async_list_note(WRITE, req, iov_count);
		goto out_free;
	}

	if (rw == WRITE) {
		/*
		 * Open-code file_start_write here to grab freeze protection,
		 * which will be released by another thread in
		 * io_complete_rw().  Fool lockdep by telling it the lock got
		 * released so that it doesn't complain about the held lock when
		 * we return to userspace.
		 */
		if (S_ISREG(file_inode(file)->i_mode)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
			__sb_start_write(file_inode(file)->i_sb,
				SB_FREEZE_WRITE);
#else
			__sb_start_write(file_inode(file)->i_sb,
				SB_FREEZE_WRITE, true);
#endif
			__sb_writers_release(file_inode(file)->i_sb,
				SB_FREEZE_WRITE);
		}
		kiocb->ki_flags |= IOCB_WRITE;

		ret2 = call_write_iter(file, kiocb, &iter);
		if (!force_nonblock || ret2 != -EAGAIN) {
			io_rw_done(kiocb, ret2);
			ret = 0;
		} else {
			/*
			 * If ->needs_lock is true, we're already in async
			 * context.
			 */
			if (!s->needs_lock)
				io_async_list_note(WRITE, req, iov_count);
			ret = -EAGAIN;
		}
	} else {
		/* Catch -EAGAIN return for forced non-blocking submission */
		ret2 = call_read_iter(file, kiocb, &iter);
		if (!force_nonblock || ret2 != -EAGAIN) {
			io_rw_done(kiocb, ret2);
			ret = 0;
		} else {
			/*
			 * If ->needs_lock is true, we're already in async
			 * context.
			 */
			if (!s->needs_lock)
				io_async_list_note(READ, req, iov_count);
			ret = -EAGAIN;
		}
	}
out_free:
	if (iovec != inline_vecs) kfree(iovec);
	return ret;
}

static int io_discard(struct io_kiocb *req, const struct sqe_submit *s,
	bool force_nonblock)
{
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	int ret = -EINVAL;
	const struct io_uring_sqe *sqe = s->sqe;
	struct inode *inode;

	loff_t off = READ_ONCE(sqe->off);
	loff_t bytes = READ_ONCE(sqe->len);

	/* discard always requires a blocking context */
	if (force_nonblock)
		return -EAGAIN;

	if (unlikely(!(req->file->f_mode & FMODE_WRITE))) {
		ret = -EINVAL;
		goto out;
	}

	inode = req->file->f_inode;
	if (S_ISBLK(inode->i_mode)) {
		struct block_device *bdev = I_BDEV(inode);
		struct address_space *mapping = bdev->bd_inode->i_mapping;
		truncate_inode_pages_range(mapping, off, off + bytes - 1);
		ret = blkdev_issue_discard(bdev, off / SECTOR_SIZE,
			bytes / SECTOR_SIZE, GFP_KERNEL, 0);
		if (ret < 0) {
			pr_warn("%s: blkdev_issue_discard failed: ret %d", __func__, ret);
			if (ret != -EINVAL && ret != -EOPNOTSUPP)
				ret = -EIO;
		}
	} else if (unlikely(!req->file->f_op->fallocate)) {
		printk("%s: fallocate is NULL", __func__);
		ret = -EOPNOTSUPP;
	} else {
		ret = req->file->f_op->fallocate(req->file, mode, off, bytes);
		if (ret < 0) {
			pr_warn("%s: fallocate failed: ret %d", __func__, ret);
			if (ret != -EINVAL && ret != -EOPNOTSUPP)
				ret = -EIO;
		}
	}

out:
	io_cqring_add_event(req->ctx, req->user_data, ret);
	io_put_req(req);

	// always pass submission
	return 0;
}

static int io_syncfs(struct io_kiocb *req, const struct sqe_submit *s,
	bool force_nonblock)
{
	struct file *file = req->file;
	struct inode *inode = file->f_mapping->host;
	int ret = -EOPNOTSUPP;

	/* syncfs always requires a blocking context */
	if (force_nonblock)
		return -EAGAIN;

	if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) {
		struct super_block *sb = file->f_path.dentry->d_sb;
		down_read(&sb->s_umount);
		ret = sync_filesystem(sb);
		up_read(&sb->s_umount);
	} else if (S_ISBLK(inode->i_mode)) {
		struct block_device *bdev = I_BDEV(inode);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0) &&  !defined(QUEUE_FLAG_NOWAIT)
		ret = blkdev_issue_flush(bdev, GFP_KERNEL, NULL);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(5,11,0)
		ret = blkdev_issue_flush(bdev, GFP_KERNEL);
#else
		ret = blkdev_issue_flush(bdev);
#endif
	}

	io_cqring_add_event(req->ctx, req->user_data, ret);
	io_put_req(req);

	// always pass submission
	return 0;
}

/*
 * IORING_OP_NOP just posts a completion event, nothing else.
 */
static int io_nop(struct io_kiocb *req, u64 user_data)
{
	struct io_ring_ctx *ctx = req->ctx;
	long err = 0;

	io_cqring_add_event(ctx, user_data, err);
	io_put_req(req);
	return 0;
}

static int io_prep_fsync(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (!req->file)
		return -EBADF;

	if (unlikely(sqe->addr || sqe->ioprio || sqe->buf_index))
		return -EINVAL;

	return 0;
}

static int io_fsync(struct io_kiocb *req, const struct io_uring_sqe *sqe,
		    bool force_nonblock)
{
	loff_t sqe_off = READ_ONCE(sqe->off);
	loff_t sqe_len = READ_ONCE(sqe->len);
	loff_t end = sqe_off + sqe_len;
	unsigned fsync_flags;
	int ret;

	fsync_flags = READ_ONCE(sqe->fsync_flags);
	if (unlikely(fsync_flags & ~IORING_FSYNC_DATASYNC))
		return -EINVAL;

	ret = io_prep_fsync(req, sqe);
	if (ret)
		return ret;

	/* fsync always requires a blocking context */
	if (force_nonblock)
		return -EAGAIN;

	ret = vfs_fsync_range(req->rw.ki_filp, sqe_off,
				end > 0 ? end : LLONG_MAX,
				fsync_flags & IORING_FSYNC_DATASYNC);

	io_cqring_add_event(req->ctx, sqe->user_data, ret);
	io_put_req(req);
	return 0;
}

static void io_poll_remove_one(struct io_kiocb *req)
{
	struct io_poll_iocb *poll = &req->poll;

	spin_lock(&poll->head->lock);
	WRITE_ONCE(poll->canceled, true);
	if (!list_empty(&poll->wait.entry)) {
		list_del_init(&poll->wait.entry);
		queue_work(req->ctx->sqo_wq, &req->work);
	}
	spin_unlock(&poll->head->lock);

	list_del_init(&req->list);
}

static void io_poll_remove_all(struct io_ring_ctx *ctx)
{
	struct io_kiocb *req;

	spin_lock_irq(&ctx->completion_lock);
	while (!list_empty(&ctx->cancel_list)) {
		req = list_first_entry(&ctx->cancel_list, struct io_kiocb,list);
		io_poll_remove_one(req);
	}
	spin_unlock_irq(&ctx->completion_lock);
}

/*
 * Find a running poll command that matches one specified in sqe->addr,
 * and remove it if found.
 */
static int io_poll_remove(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_kiocb *poll_req, *next;
	int ret = -ENOENT;

	if (sqe->ioprio || sqe->off || sqe->len || sqe->buf_index ||
	    sqe->poll_events)
		return -EINVAL;

	spin_lock_irq(&ctx->completion_lock);
	list_for_each_entry_safe(poll_req, next, &ctx->cancel_list, list) {
		if (READ_ONCE(sqe->addr) == poll_req->user_data) {
			io_poll_remove_one(poll_req);
			ret = 0;
			break;
		}
	}
	spin_unlock_irq(&ctx->completion_lock);

	io_cqring_add_event(req->ctx, sqe->user_data, ret);
	io_put_req(req);
	return 0;
}

static void io_poll_complete(struct io_ring_ctx *ctx, struct io_kiocb *req,
			     unsigned mask)
{
	req->poll.done = true;
	io_cqring_fill_event(ctx, req->user_data, mask);
	io_commit_cqring(ctx);
}

static void io_poll_complete_work(struct work_struct *work)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);
	struct io_poll_iocb *poll = &req->poll;
	struct poll_table_struct pt = { ._key = poll->events };
	struct io_ring_ctx *ctx = req->ctx;
	unsigned mask = 0;

	if (!READ_ONCE(poll->canceled))
		mask = poll->file->f_op->poll(poll->file, &pt) & poll->events;

	/*
	 * Note that ->ki_cancel callers also delete iocb from active_reqs after
	 * calling ->ki_cancel.  We need the ctx_lock roundtrip here to
	 * synchronize with them.  In the cancellation case the list_del_init
	 * itself is not actually needed, but harmless so we keep it in to
	 * avoid further branches in the fast path.
	 */
	spin_lock_irq(&ctx->completion_lock);
	if (!mask && !READ_ONCE(poll->canceled)) {
		add_wait_queue(poll->head, &poll->wait);
		spin_unlock_irq(&ctx->completion_lock);
		return;
	}
	list_del_init(&req->list);
	io_poll_complete(ctx, req, mask);
	spin_unlock_irq(&ctx->completion_lock);

	io_put_req(req);
}

static int io_poll_wake(struct wait_queue_entry *wait, unsigned mode, int sync,
			void *key)
{
	struct io_poll_iocb *poll = container_of(wait, struct io_poll_iocb,
							wait);
	struct io_kiocb *req = container_of(poll, struct io_kiocb, poll);
	struct io_ring_ctx *ctx = req->ctx;
	unsigned mask = (unsigned int)(uintptr_t)key;
	unsigned long flags;

	/* for instances that support it check for an event match first: */
	if (mask && !(mask & poll->events))
		return 0;

	list_del_init(&poll->wait.entry);

	if (mask && spin_trylock_irqsave(&ctx->completion_lock, flags)) {
		list_del(&req->list);
		io_poll_complete(ctx, req, mask);
		spin_unlock_irqrestore(&ctx->completion_lock, flags);

		io_put_req(req);
	} else {
		queue_work(ctx->sqo_wq, &req->work);
	}

	return 1;
}

struct io_poll_table {
	struct poll_table_struct pt;
	struct io_kiocb *req;
	int error;
};

static void io_poll_queue_proc(struct file *file, struct wait_queue_head *head,
			       struct poll_table_struct *p)
{
	struct io_poll_table *pt = container_of(p, struct io_poll_table, pt);

	if (unlikely(pt->req->poll.head)) {
		pt->error = -EINVAL;
		return;
	}

	pt->error = 0;
	pt->req->poll.head = head;
	add_wait_queue(head, &pt->req->poll.wait);
}

static int io_poll_add(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_poll_iocb *poll = &req->poll;
	struct io_ring_ctx *ctx = req->ctx;
	struct io_poll_table ipt;
	bool cancel = false;
	unsigned mask;
	u16 events;

	if (sqe->addr || sqe->ioprio || sqe->off || sqe->len || sqe->buf_index)
		return -EINVAL;
	if (!poll->file)
		return -EBADF;

	INIT_WORK(&req->work, io_poll_complete_work);
	events = READ_ONCE(sqe->poll_events);
	poll->events = events | EPOLLERR | EPOLLHUP;

	poll->head = NULL;
	poll->done = false;
	poll->canceled = false;

	ipt.pt._qproc = io_poll_queue_proc;
	ipt.pt._key = poll->events;
	ipt.req = req;
	ipt.error = -EINVAL; /* same as no support for IOCB_CMD_POLL */

	/* initialized the list so that we can do list_empty checks */
	INIT_LIST_HEAD(&poll->wait.entry);
	init_waitqueue_func_entry(&poll->wait, io_poll_wake);

	mask = poll->file->f_op->poll(poll->file, &ipt.pt) & poll->events;

	spin_lock_irq(&ctx->completion_lock);
	if (likely(poll->head)) {
		spin_lock(&poll->head->lock);
		if (unlikely(list_empty(&poll->wait.entry))) {
			if (ipt.error)
				cancel = true;
			ipt.error = 0;
			mask = 0;
		}
		if (mask || ipt.error)
			list_del_init(&poll->wait.entry);
		else if (cancel)
			WRITE_ONCE(poll->canceled, true);
		else if (!poll->done) /* actually waiting for an event */
			list_add_tail(&req->list, &ctx->cancel_list);
		spin_unlock(&poll->head->lock);
	}
	if (mask) { /* no async, we'd stolen it */
		ipt.error = 0;
		io_poll_complete(ctx, req, mask);
	}
	spin_unlock_irq(&ctx->completion_lock);

	if (mask) {
		io_put_req(req);
	}
	return ipt.error;
}

static int io_req_defer(struct io_ring_ctx *ctx, struct io_kiocb *req,
			const struct io_uring_sqe *sqe)
{
	struct io_uring_sqe *sqe_copy;

	if (!io_sequence_defer(ctx, req) && list_empty(&ctx->defer_list))
		return 0;

	sqe_copy = kmalloc(sizeof(*sqe_copy), GFP_KERNEL);
	if (!sqe_copy)
		return -EAGAIN;

	spin_lock_irq(&ctx->completion_lock);
	if (!io_sequence_defer(ctx, req) && list_empty(&ctx->defer_list)) {
		spin_unlock_irq(&ctx->completion_lock);
		kfree(sqe_copy);
		return 0;
	}

	memcpy(sqe_copy, sqe, sizeof(*sqe_copy));
	req->submit.sqe = sqe_copy;

	INIT_WORK(&req->work, io_sq_wq_submit_work);
	list_add_tail(&req->list, &ctx->defer_list);
	spin_unlock_irq(&ctx->completion_lock);
	return -EIOCBQUEUED;
}

static int __io_submit_sqe(struct io_ring_ctx *ctx, struct io_kiocb *req,
			   const struct sqe_submit *s, bool force_nonblock)
{
	int ret, opcode;

	if (unlikely(s->index >= ctx->sq_entries)) {
		pr_info("%s: invalid index", __func__);
		return -EINVAL;
	}
	req->user_data = READ_ONCE(s->sqe->user_data);

	opcode = READ_ONCE(s->sqe->opcode);
	switch (opcode) {
	case IORING_OP_NOP:
		ret = io_nop(req, req->user_data);
		break;
	case IORING_OP_READV:
		if (unlikely(s->sqe->buf_index))
			return -EINVAL;
		ret = io_read(req, s, force_nonblock);
		break;
	case IORING_OP_WRITEV:
		if (unlikely(s->sqe->buf_index)) {
			pr_info("%s: invalid buf index", __func__);
			return -EINVAL;
		}
		ret = io_write(req, s, force_nonblock);
		break;
	case IORING_OP_READ_FIXED:
		ret = io_read(req, s, force_nonblock);
		break;
	case IORING_OP_WRITE_FIXED:
		ret = io_write(req, s, force_nonblock);
		break;
	case IORING_OP_FSYNC:
		ret = io_fsync(req, s->sqe, force_nonblock);
		break;
	case IORING_OP_POLL_ADD:
		ret = io_poll_add(req, s->sqe);
		break;
	case IORING_OP_POLL_REMOVE:
		ret = io_poll_remove(req, s->sqe);
		break;
	case IORING_OP_READ_BIO:
		ret = io_switch(req, s, READ, force_nonblock);
		break;
	case IORING_OP_WRITE_BIO:
		ret = io_switch(req, s, WRITE, force_nonblock);
		break;
	case IORING_OP_DISCARD_FIXED:
		ret = io_discard(req, s, force_nonblock);
		break;
	case IORING_OP_SYNCFS_FIXED:
		ret = io_syncfs(req, s, force_nonblock);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static struct async_list *io_async_list_from_sqe(struct io_ring_ctx *ctx,
						 const struct io_uring_sqe *sqe)
{
	switch (sqe->opcode) {
	case IORING_OP_READV:
	case IORING_OP_READ_FIXED:
		return &ctx->pending_async[READ];
	case IORING_OP_WRITEV:
	case IORING_OP_WRITE_FIXED:
		return &ctx->pending_async[WRITE];
	default:
		return NULL;
	}
}

static inline bool io_sqe_needs_user(const struct io_uring_sqe *sqe)
{
	u8 opcode = READ_ONCE(sqe->opcode);

	return !(opcode == IORING_OP_READ_FIXED ||
		 opcode == IORING_OP_WRITE_FIXED);
}

static void io_sq_wq_submit_work(struct work_struct *work)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);
	struct io_ring_ctx *ctx = req->ctx;
	struct mm_struct *cur_mm = NULL;
	struct async_list *async_list;
	LIST_HEAD(req_list);
	mm_segment_t old_fs;
	int ret;

	async_list = io_async_list_from_sqe(ctx, req->submit.sqe);
restart:
	do {
		struct sqe_submit *s = &req->submit;
		const struct io_uring_sqe *sqe = s->sqe;

		/* Ensure we clear previously set non-block flag */
		req->rw.ki_flags &= ~IOCB_NOWAIT;

		ret = 0;
		if (io_sqe_needs_user(sqe) && !cur_mm) {
			if (!mmget_not_zero(ctx->sqo_mm)) {
				ret = -EFAULT;
			} else {
				cur_mm = ctx->sqo_mm;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
				use_mm(cur_mm);
#else
				kthread_use_mm(cur_mm);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
				old_fs = force_uaccess_begin();
#else
				old_fs = get_fs();
				set_fs(USER_DS);
#endif
			}
		}

		if (!ret) {
			s->has_user = cur_mm != NULL;
			s->needs_lock = true;
			do {
				ret = __io_submit_sqe(ctx, req, s, false);
				/*
				 * We can get EAGAIN for polled IO even though
				 * we're forcing a sync submission from here,
				 * since we can't wait for request slots on the
				 * block side.
				 */
				if (ret != -EAGAIN)
					break;
				cond_resched();
			} while (1);
		}

		/* drop submission reference */
		io_put_req(req);

		if (ret) {
			io_cqring_add_event(ctx, sqe->user_data, ret);
			io_put_req(req);
		}

		/* async context always use a copy of the sqe */
		kfree(sqe);

		if (!async_list)
			break;
		if (!list_empty(&req_list)) {
			req = list_first_entry(&req_list, struct io_kiocb,
						list);
			list_del(&req->list);
			continue;
		}
		if (list_empty(&async_list->list))
			break;

		req = NULL;
		spin_lock(&async_list->lock);
		if (list_empty(&async_list->list)) {
			spin_unlock(&async_list->lock);
			break;
		}
		list_splice_init(&async_list->list, &req_list);
		spin_unlock(&async_list->lock);

		req = list_first_entry(&req_list, struct io_kiocb, list);
		list_del(&req->list);
	} while (req);

	/*
	 * Rare case of racing with a submitter. If we find the count has
	 * dropped to zero AND we have pending work items, then restart
	 * the processing. This is a tiny race window.
	 */
	if (async_list) {
		ret = atomic_dec_return(&async_list->cnt);
		while (!ret && !list_empty(&async_list->list)) {
			spin_lock(&async_list->lock);
			atomic_inc(&async_list->cnt);
			list_splice_init(&async_list->list, &req_list);
			spin_unlock(&async_list->lock);

			if (!list_empty(&req_list)) {
				req = list_first_entry(&req_list,
							struct io_kiocb, list);
				list_del(&req->list);
				goto restart;
			}
			ret = atomic_dec_return(&async_list->cnt);
		}
	}

	if (cur_mm) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
		force_uaccess_end(old_fs);
#else
		set_fs(old_fs);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
		unuse_mm(cur_mm);
#else
		kthread_unuse_mm(cur_mm);
#endif
		mmput(cur_mm);
	}
}

/*
 * See if we can piggy back onto previously submitted work, that is still
 * running. We currently only allow this if the new request is sequential
 * to the previous one we punted.
 */
static bool io_add_to_prev_work(struct async_list *list, struct io_kiocb *req)
{
	bool ret = false;

	if (!list)
		return false;
	if (!(req->flags & REQ_F_SEQ_PREV))
		return false;
	if (!atomic_read(&list->cnt))
		return false;

	ret = true;
	spin_lock(&list->lock);
	list_add_tail(&req->list, &list->list);
	if (!atomic_read(&list->cnt)) {
		list_del_init(&req->list);
		ret = false;
	}
	spin_unlock(&list->lock);
	return ret;
}

static bool io_op_needs_file(const struct io_uring_sqe *sqe)
{
	int op = READ_ONCE(sqe->opcode);

	switch (op) {
	case IORING_OP_NOP:
	case IORING_OP_POLL_REMOVE:
		return false;
	default:
		return true;
	}
}

static int io_req_set_file(struct io_ring_ctx *ctx, const struct sqe_submit *s,
			   struct io_submit_state *state, struct io_kiocb *req)
{
	unsigned flags;
	int fd;

	flags = READ_ONCE(s->sqe->flags);
	fd = READ_ONCE(s->sqe->fd);

	if (flags & IOSQE_IO_DRAIN) {
		req->flags |= REQ_F_IO_DRAIN;
		req->sequence = ctx->cached_sq_head - 1;
	}

	if (!io_op_needs_file(s->sqe))
		return 0;

	/* Only fixed files supported */
	BUG_ON(!(flags & IOSQE_FIXED_FILE));

	if (unlikely(!ctx->user_files ||
		     (unsigned) fd >= ctx->nr_user_files))
		return -EBADF;
	req->file = ctx->user_files[fd];
	req->flags |= REQ_F_FIXED_FILE;

	return 0;
}

static int io_submit_sqe(struct io_ring_ctx *ctx, struct sqe_submit *s,
			 struct io_submit_state *state)
{
	struct io_kiocb *req;
	int ret;

	/* enforce forwards compatibility on users */
	if (unlikely(s->sqe->flags &
		     ~(IOSQE_FIXED_FILE | IOSQE_IO_DRAIN | IOSQE_FORCE_ASYNC))) {
		pr_info("%s: invalid flags", __func__);
		return -EINVAL;
	}

	req = io_get_req(ctx, state);
	if (unlikely(!req))
		return -EAGAIN;

	ret = io_req_set_file(ctx, s, state, req);
	if (unlikely(ret))
		goto out;

	ret = io_req_defer(ctx, req, s->sqe);
	if (ret) {
		if (ret == -EIOCBQUEUED)
			ret = 0;
		return ret;
	}

	ret = __io_submit_sqe(ctx, req, s, true);
	if (ret == -EAGAIN && !(req->flags & REQ_F_NOWAIT)) {
		struct io_uring_sqe *sqe_copy;

		sqe_copy = kmalloc(sizeof(*sqe_copy), GFP_KERNEL);
		if (sqe_copy) {
			struct async_list *list;

			memcpy(sqe_copy, s->sqe, sizeof(*sqe_copy));
			s->sqe = sqe_copy;

			memcpy(&req->submit, s, sizeof(*s));
			list = io_async_list_from_sqe(ctx, s->sqe);
			if (!io_add_to_prev_work(list, req)) {
				if (list)
					atomic_inc(&list->cnt);
				INIT_WORK(&req->work, io_sq_wq_submit_work);
				queue_work(ctx->sqo_wq, &req->work);
			}

			/*
			 * Queued up for async execution, worker will release
			 * submit reference when the iocb is actually
			 * submitted.
			 */
			return 0;
		}
	}

out:
	/* drop submission reference */
	io_put_req(req);

	/* and drop final reference, if we failed */
	if (ret)
		io_put_req(req);

	return ret;
}

/*
 * Batched submission is done, ensure local IO is flushed out.
 */
static void io_submit_state_end(struct io_submit_state *state)
{
	blk_finish_plug(&state->plug);
	if (state->free_reqs)
		kmem_cache_free_bulk(req_cachep, state->free_reqs,
					&state->reqs[state->cur_req]);
}

/*
 * Start submission side cache.
 */
static void io_submit_state_start(struct io_submit_state *state,
				  struct io_ring_ctx *ctx, unsigned max_ios)
{
	blk_start_plug(&state->plug);
	state->free_reqs = 0;
	state->file = NULL;
	state->ios_left = max_ios;
}

static void io_commit_sqring(struct io_ring_ctx *ctx)
{
	struct fuse_queue_cb *cb = ctx->requests_cb;

	if (ctx->cached_sq_head != READ_ONCE(cb->r.read)) {
		/*
		 * Ensure any loads from the SQEs are done at this point,
		 * since once we write the new head, the application could
		 * write new data to them.
		 */
		smp_store_release(&cb->r.read, ctx->cached_sq_head);
	}
}

/*
 * Fetch an sqe, if one is available. Note that s->sqe will point to memory
 * that is mapped by userspace. This means that care needs to be taken to
 * ensure that reads are stable, as we cannot rely on userspace always
 * being a good citizen. If members of the sqe are validated and then later
 * used, it's important that those reads are done through READ_ONCE() to
 * prevent a re-load down the line.
 */
static bool io_get_sqring(struct io_ring_ctx *ctx, struct sqe_submit *s)
{
	unsigned head, new_head;

	/*
	 * The cached sq head (or cq tail) serves two purposes:
	 *
	 * 1) allows us to batch the cost of updating the user visible
	 *    head updates.
	 * 2) allows the kernel side to track the head on its own, even
	 *    though the application is the one updating it.
	 */
	head = ctx->cached_sq_head;
	/* make sure SQ entry isn't read before tail */
	new_head = smp_load_acquire(&ctx->requests_cb->r.write);

	if (head == new_head)
		return false;

	s->index = head & ctx->sq_mask;
	s->sqe = &ctx->requests[head & ctx->sq_mask];
	++ctx->cached_sq_head;

	return true;
}

static int io_submit_sqes(struct io_ring_ctx *ctx, struct sqe_submit *sqes,
			  unsigned int nr, bool has_user, bool mm_fault)
{
	struct io_submit_state state, *statep = NULL;
	int ret, i, submitted = 0;

	if (nr > IO_PLUG_THRESHOLD) {
		io_submit_state_start(&state, ctx, nr);
		statep = &state;
	}

	for (i = 0; i < nr; i++) {
		if (unlikely(mm_fault)) {
			ret = -EFAULT;
		} else {
			sqes[i].has_user = has_user;
			sqes[i].needs_lock = true;
			sqes[i].needs_fixed_file = true;
			ret = io_submit_sqe(ctx, &sqes[i], statep);
		}
		if (!ret) {
			submitted++;
			continue;
		}

		io_cqring_add_event(ctx, sqes[i].sqe->user_data, ret);
	}

	if (statep)
		io_submit_state_end(&state);

	return submitted;
}

static int io_sq_thread(void *data)
{
	struct sqe_submit sqes[IO_IOPOLL_BATCH];
	struct io_ring_ctx *ctx = data;
	struct mm_struct *cur_mm = NULL;
	mm_segment_t old_fs;
	DEFINE_WAIT(wait);
	unsigned inflight;
	unsigned long timeout;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	old_fs = force_uaccess_begin();
#else
	old_fs = get_fs();
	set_fs(USER_DS);
#endif

	pr_info("%s: started to %d", __func__, ctx->sq_thread_idle);

	timeout = inflight = 0;
	while (!kthread_should_park()) {
		bool all_fixed, mm_fault = false;
		int i;

		if (inflight) {
			unsigned nr_events = inflight;

			inflight -= nr_events;
			if (!inflight)
				timeout = jiffies + ctx->sq_thread_idle;
		}

		if (!io_get_sqring(ctx, &sqes[0])) {
			/*
			 * We're polling. If we're within the defined idle
			 * period, then let us spin without work before going
			 * to sleep.
			 */
			if (inflight || !time_after(jiffies, timeout)) {
				cpu_relax();
				continue;
			}

			/*
			 * Drop cur_mm before scheduling, we can't hold it for
			 * long periods (or over schedule()). Do this before
			 * adding ourselves to the waitqueue, as the unuse/drop
			 * may sleep.
			 */
			if (cur_mm) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
				unuse_mm(cur_mm);
#else
				kthread_unuse_mm(cur_mm);
#endif
				mmput(cur_mm);
				cur_mm = NULL;
			}

			prepare_to_wait(&ctx->sqo_wait, &wait,
						TASK_INTERRUPTIBLE);

			/* Tell userspace we may need a wakeup call */
			ctx->requests_cb->w.need_wake_up =
				IORING_SQ_NEED_WAKEUP;
			/* make sure to read SQ tail after writing flags */
			smp_mb();

			if (!io_get_sqring(ctx, &sqes[0])) {
				if (kthread_should_park()) {
					finish_wait(&ctx->sqo_wait, &wait);
					break;
				}
				if (signal_pending(current))
					flush_signals(current);
				schedule();
				finish_wait(&ctx->sqo_wait, &wait);

				ctx->requests_cb->w.need_wake_up = 0;
				continue;
			}
			finish_wait(&ctx->sqo_wait, &wait);

			ctx->requests_cb->w.need_wake_up = 0;
		}

		i = 0;
		all_fixed = true;
		do {
			if (all_fixed && io_sqe_needs_user(sqes[i].sqe))
				all_fixed = false;

			i++;
			if (i == ARRAY_SIZE(sqes))
				break;
		} while (io_get_sqring(ctx, &sqes[i]));

		/* Unless all new commands are FIXED regions, grab mm */
		if (!all_fixed && !cur_mm) {
			mm_fault = !mmget_not_zero(ctx->sqo_mm);
			if (!mm_fault) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
				use_mm(ctx->sqo_mm);
#else
				kthread_use_mm(ctx->sqo_mm);
#endif
				cur_mm = ctx->sqo_mm;
			}
		}

		inflight += io_submit_sqes(ctx, sqes, i, cur_mm != NULL,
						mm_fault);

		/* Commit SQ ring head once we've consumed all SQEs */
		io_commit_sqring(ctx);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	force_uaccess_end(old_fs);
#else
	set_fs(old_fs);
#endif
	if (cur_mm) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
		unuse_mm(cur_mm);
#else
		kthread_unuse_mm(cur_mm);
#endif
		mmput(cur_mm);
	}

	kthread_parkme();

	return 0;
}

static void __io_sqe_files_unregister(struct io_ring_ctx *ctx)
{
	int i;

	for (i = 0; i < ctx->nr_user_files; i++)
		if (ctx->user_files[i])
			fput(ctx->user_files[i]);
}

static int io_sqe_files_unregister(struct io_ring_ctx *ctx)
{
	if (!ctx->user_files)
		return -ENXIO;

	__io_sqe_files_unregister(ctx);
	kfree(ctx->user_files);
	ctx->user_files = NULL;
	ctx->nr_user_files = 0;
	return 0;
}

static void io_sq_thread_stop(struct io_ring_ctx *ctx)
{
	if (ctx->sqo_thread) {
		/*
		 * The park is a bit of a work-around, without it we get
		 * warning spews on shutdown with SQPOLL set and affinity
		 * set to a single CPU.
		 */
		kthread_park(ctx->sqo_thread);
		kthread_stop(ctx->sqo_thread);
		ctx->sqo_thread = NULL;
	}
}

static void io_finish_async(struct io_ring_ctx *ctx)
{
	io_sq_thread_stop(ctx);

	if (ctx->sqo_wq) {
		destroy_workqueue(ctx->sqo_wq);
		ctx->sqo_wq = NULL;
	}
}

static int io_sqe_register_file(struct io_ring_ctx *ctx, int fd)
{
	int i;
	int err;

	mutex_lock(&ctx->uring_lock);

	for (i = 0; i < ctx->nr_user_files; ++i) {
		if (!ctx->user_files[i])
			break;
	}

	err = -ENFILE;
	if (i == ctx->nr_user_files)
		goto out;

	err = -EBADF;
	ctx->user_files[i] = fget(fd);
	if (!ctx->user_files[i])
		goto out;

	if (ctx->user_files[i]->f_op == &fuse_dev_operations) {
		fput(ctx->user_files[i]);
		ctx->user_files[i] = NULL;
		goto out;
	}

	mutex_unlock(&ctx->uring_lock);
	return i;

out:
	mutex_unlock(&ctx->uring_lock);
	return err;
}

static int io_sqe_unregister_file(struct io_ring_ctx *ctx, int index)
{
	if (index >= ctx->nr_user_files)
		return -EINVAL;

	mutex_lock(&ctx->uring_lock);

	if (!ctx->user_files[index]) {
		mutex_unlock(&ctx->uring_lock);
		return -ENOENT;
	}

	fput(ctx->user_files[index]);
	ctx->user_files[index] = NULL;

	mutex_unlock(&ctx->uring_lock);

	return 0;
}

static int io_sqe_files_register(struct io_ring_ctx *ctx, void __user *arg,
				 unsigned nr_args)
{
	__s32 __user *fds = (__s32 __user *) arg;
	int fd, ret = 0;
	unsigned i;

	if (ctx->user_files)
		return -EBUSY;
	if (!nr_args)
		return -EINVAL;
	if (nr_args > IORING_MAX_FIXED_FILES)
		return -EMFILE;

	ctx->user_files = kcalloc(nr_args, sizeof(struct file *), GFP_KERNEL);
	if (!ctx->user_files)
		return -ENOMEM;

	for (i = 0; i < nr_args; i++) {
		ret = -EFAULT;
		if (copy_from_user(&fd, &fds[i], sizeof(fd)))
			break;

		ctx->user_files[i] = fget(fd);

		ret = -EBADF;
		if (!ctx->user_files[i])
			break;
		/*
		 * Don't allow io_uring instances to be registered. If UNIX
		 * isn't enabled, then this causes a reference cycle and this
		 * instance can never get freed. If UNIX is enabled we'll
		 * handle it just fine, but there's still no point in allowing
		 * a ring fd as it doesn't support regular read/write anyway.
		 */
		if (ctx->user_files[i]->f_op == &fuse_dev_operations) {
			fput(ctx->user_files[i]);
			break;
		}
		ctx->nr_user_files++;
		ret = 0;
	}

	if (ret) {
		for (i = 0; i < ctx->nr_user_files; i++)
			fput(ctx->user_files[i]);

		kfree(ctx->user_files);
		ctx->user_files = NULL;
		ctx->nr_user_files = 0;
		return ret;
	}

	return ret;
}

static int io_sq_offload_start(struct io_ring_ctx *ctx, struct io_uring_params *p)
{
	int ret;

	init_waitqueue_head(&ctx->sqo_wait);
	mmgrab(current->mm);
	ctx->sqo_mm = current->mm;

	if (ctx->flags & IORING_SETUP_SQPOLL) {
		ret = -EPERM;
		if (!capable(CAP_SYS_ADMIN))
			goto err;

		ctx->sq_thread_idle = msecs_to_jiffies(p->sq_thread_idle);
		if (!ctx->sq_thread_idle)
			ctx->sq_thread_idle = HZ;

		ctx->sqo_thread = kthread_create(io_sq_thread, ctx,
			"pxd-io");
		if (IS_ERR(ctx->sqo_thread)) {
			ret = PTR_ERR(ctx->sqo_thread);
			ctx->sqo_thread = NULL;
			goto err;
		}
		wake_up_process(ctx->sqo_thread);
	} else if (p->flags & IORING_SETUP_SQ_AFF) {
		/* Can't have SQ_AFF without SQPOLL */
		ret = -EINVAL;
		goto err;
	}

	/* Do QD, or 2 * CPUS, whatever is smallest */
	ctx->sqo_wq = alloc_workqueue("pxd-wq", WQ_UNBOUND | WQ_FREEZABLE,
			2 * num_online_cpus());
	if (!ctx->sqo_wq) {
		ret = -ENOMEM;
		goto err;
	}

	return 0;
err:
	io_sq_thread_stop(ctx);
	mmdrop(ctx->sqo_mm);
	ctx->sqo_mm = NULL;
	return ret;
}

static void io_mem_free(void *ptr)
{
	if (!ptr)
		return;
	vfree(ptr);
}

static int io_sqe_buffer_unregister(struct io_ring_ctx *ctx)
{
	int i, j;

	if (!ctx->user_bufs)
		return -ENXIO;

	for (i = 0; i < ctx->nr_user_bufs; i++) {
		struct io_mapped_ubuf *imu = &ctx->user_bufs[i];

		for (j = 0; j < imu->nr_bvecs; j++)
			put_page(imu->bvec[j].bv_page);

		kvfree(imu->bvec);
		imu->nr_bvecs = 0;
	}

	kfree(ctx->user_bufs);
	ctx->user_bufs = NULL;
	ctx->nr_user_bufs = 0;
	return 0;
}

static int io_copy_iov(struct io_ring_ctx *ctx, struct iovec *dst,
		       void __user *arg, unsigned index)
{
	struct iovec __user *src;

#ifdef CONFIG_COMPAT
	if (ctx->compat) {
		struct compat_iovec __user *ciovs;
		struct compat_iovec ciov;

		ciovs = (struct compat_iovec __user *) arg;
		if (copy_from_user(&ciov, &ciovs[index], sizeof(ciov)))
			return -EFAULT;

		dst->iov_base = (void __user *) (unsigned long) ciov.iov_base;
		dst->iov_len = ciov.iov_len;
		return 0;
	}
#endif
	src = (struct iovec __user *) arg;
	if (copy_from_user(dst, &src[index], sizeof(*dst)))
		return -EFAULT;
	return 0;
}

static int io_sqe_buffer_register(struct io_ring_ctx *ctx, void __user *arg,
				  unsigned nr_args)
{
	struct vm_area_struct **vmas = NULL;
	struct page **pages = NULL;
	int i, j, got_pages = 0;
	int ret = -EINVAL;

	if (ctx->user_bufs)
		return -EBUSY;
	if (!nr_args || nr_args > UIO_MAXIOV)
		return -EINVAL;

	ctx->user_bufs = kcalloc(nr_args, sizeof(struct io_mapped_ubuf),
					GFP_KERNEL);
	if (!ctx->user_bufs)
		return -ENOMEM;

	for (i = 0; i < nr_args; i++) {
		struct io_mapped_ubuf *imu = &ctx->user_bufs[i];
		unsigned long off, start, end, ubuf;
		int pret, nr_pages;
		struct iovec iov;
		size_t size;

		ret = io_copy_iov(ctx, &iov, arg, i);
		if (ret)
			goto err;

		/*
		 * Don't impose further limits on the size and buffer
		 * constraints here, we'll -EINVAL later when IO is
		 * submitted if they are wrong.
		 */
		ret = -EFAULT;
		if (!iov.iov_base || !iov.iov_len)
			goto err;

		/* arbitrary limit, but we need something */
		if (iov.iov_len > SZ_1G)
			goto err;

		ubuf = (unsigned long) iov.iov_base;
		end = (ubuf + iov.iov_len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		start = ubuf >> PAGE_SHIFT;
		nr_pages = end - start;

		ret = 0;
		if (!pages || nr_pages > got_pages) {
			kfree(vmas);
			kfree(pages);
			pages = kvmalloc_array(nr_pages, sizeof(struct page *),
						GFP_KERNEL);
			vmas = kvmalloc_array(nr_pages,
					sizeof(struct vm_area_struct *),
					GFP_KERNEL);
			if (!pages || !vmas) {
				ret = -ENOMEM;
				goto err;
			}
			got_pages = nr_pages;
		}

		imu->bvec = kvmalloc_array(nr_pages, sizeof(struct bio_vec),
						GFP_KERNEL);
		ret = -ENOMEM;
		if (!imu->bvec) {
			goto err;
		}

		ret = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
		down_read(&current->mm->mmap_sem);
#else
		down_read(&current->mm->mmap_lock);
#endif
		pret = get_user_pages(ubuf, nr_pages,
					FOLL_WRITE,
				      pages, vmas);
		if (pret == nr_pages) {
			/* don't support file backed memory */
			for (j = 0; j < nr_pages; j++) {
				struct vm_area_struct *vma = vmas[j];

				if (vma->vm_file) {
					ret = -EOPNOTSUPP;
					break;
				}
			}
		} else {
			ret = pret < 0 ? pret : -EFAULT;
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
		up_read(&current->mm->mmap_sem);
#else
		up_read(&current->mm->mmap_lock);
#endif
		if (ret) {
			/*
			 * if we did partial map, or found file backed vmas,
			 * release any pages we did get
			 */
			if (pret > 0) {
				for (j = 0; j < pret; j++)
					put_page(pages[j]);
			}
			kvfree(imu->bvec);
			goto err;
		}

		off = ubuf & ~PAGE_MASK;
		size = iov.iov_len;
		for (j = 0; j < nr_pages; j++) {
			size_t vec_len;

			vec_len = min_t(size_t, size, PAGE_SIZE - off);
			imu->bvec[j].bv_page = pages[j];
			imu->bvec[j].bv_len = vec_len;
			imu->bvec[j].bv_offset = off;
			off = 0;
			size -= vec_len;
		}
		/* store original address for later verification */
		imu->ubuf = ubuf;
		imu->len = iov.iov_len;
		imu->nr_bvecs = nr_pages;

		ctx->nr_user_bufs++;
	}
	kvfree(pages);
	kvfree(vmas);
	return 0;
err:
	kvfree(pages);
	kvfree(vmas);
	io_sqe_buffer_unregister(ctx);
	return ret;
}

static int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg)
{
	__s32 __user *fds = arg;
	int fd;

	if (ctx->cq_ev_fd)
		return -EBUSY;

	if (copy_from_user(&fd, fds, sizeof(*fds)))
		return -EFAULT;

	ctx->cq_ev_fd = eventfd_ctx_fdget(fd);
	if (IS_ERR(ctx->cq_ev_fd)) {
		int ret = PTR_ERR(ctx->cq_ev_fd);
		ctx->cq_ev_fd = NULL;
		return ret;
	}

	return 0;
}

static int io_eventfd_unregister(struct io_ring_ctx *ctx)
{
	if (ctx->cq_ev_fd) {
		eventfd_ctx_put(ctx->cq_ev_fd);
		ctx->cq_ev_fd = NULL;
		return 0;
	}

	return -ENXIO;
}

static void io_ring_ctx_free(struct io_ring_ctx *ctx)
{
	io_finish_async(ctx);
	if (ctx->sqo_mm)
		mmdrop(ctx->sqo_mm);

	io_sqe_buffer_unregister(ctx);
	io_sqe_files_unregister(ctx);
	io_eventfd_unregister(ctx);

	io_mem_free(ctx->queue);

	percpu_ref_exit(&ctx->refs);

	kfree(ctx);
}

static void io_ring_ctx_wait_and_kill(struct io_ring_ctx *ctx)
{
	mutex_lock(&ctx->uring_lock);
	percpu_ref_kill(&ctx->refs);
	mutex_unlock(&ctx->uring_lock);

	io_poll_remove_all(ctx);
	wait_for_completion(&ctx->ctx_done);
	io_ring_ctx_free(ctx);
}

static int __io_uring_register(struct io_ring_ctx *ctx, unsigned opcode,
			       void __user *arg, unsigned nr_args)
	__releases(ctx->uring_lock)
	__acquires(ctx->uring_lock)
{
	int ret;

	/*
	 * We're inside the ring mutex, if the ref is already dying, then
	 * someone else killed the ctx or is already going through
	 * io_uring_register().
	 */
	if (percpu_ref_is_dying(&ctx->refs))
		return -ENXIO;

	percpu_ref_kill(&ctx->refs);

	/*
	 * Drop uring mutex before waiting for references to exit. If another
	 * thread is currently inside io_uring_enter() it might need to grab
	 * the uring_lock to make progress. If we hold it here across the drain
	 * wait, then we can deadlock. It's safe to drop the mutex here, since
	 * no new references will come in after we've killed the percpu ref.
	 */
	mutex_unlock(&ctx->uring_lock);
	wait_for_completion(&ctx->ctx_done);
	mutex_lock(&ctx->uring_lock);

	switch (opcode) {
	case IORING_REGISTER_BUFFERS:
		ret = io_sqe_buffer_register(ctx, arg, nr_args);
		break;
	case IORING_UNREGISTER_BUFFERS:
		ret = -EINVAL;
		if (arg || nr_args)
			break;
		ret = io_sqe_buffer_unregister(ctx);
		break;
	case IORING_REGISTER_FILES:
		ret = io_sqe_files_register(ctx, arg, nr_args);
		break;
	case IORING_UNREGISTER_FILES:
		ret = -EINVAL;
		if (arg || nr_args)
			break;
		ret = io_sqe_files_unregister(ctx);
		break;
	case IORING_REGISTER_EVENTFD:
		ret = -EINVAL;
		if (nr_args != 1)
			break;
		ret = io_eventfd_register(ctx, arg);
		break;
	case IORING_UNREGISTER_EVENTFD:
		ret = -EINVAL;
		if (arg || nr_args)
			break;
		ret = io_eventfd_unregister(ctx);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	/* bring the ctx back to life */
	reinit_completion(&ctx->ctx_done);
	percpu_ref_reinit(&ctx->refs);
	return ret;
}

long io_uring_register(unsigned int fd, unsigned int opcode,
		void __user *arg, unsigned int nr_args)
{
	struct io_ring_ctx *ctx;
	long ret = -EBADF;
	struct fd f;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = -EOPNOTSUPP;
	if (f.file->f_op != &fuse_dev_operations)
		goto out_fput;

	ctx = f.file->private_data;

	mutex_lock(&ctx->uring_lock);
	ret = __io_uring_register(ctx, opcode, arg, nr_args);
	mutex_unlock(&ctx->uring_lock);
out_fput:
	fdput(f);
	return ret;
}

static void io_ring_submit(struct io_ring_ctx *ctx)
{
	struct io_submit_state state, *statep = NULL;
	int i;
	uint32_t read = ctx->requests_cb->r.read;
	uint32_t write = smp_load_acquire(&ctx->requests_cb->r.write);

	while (read != write) {
		int to_submit = write - read;

		if (to_submit > IO_PLUG_THRESHOLD) {
			io_submit_state_start(&state, ctx, to_submit);
			statep = &state;
		}

		for (i = 0; i < to_submit; i++) {
			struct sqe_submit s;
			int ret;

			if (!io_get_sqring(ctx, &s))
				break;

			s.has_user = true;
			s.needs_lock = false;
			s.needs_fixed_file = false;

			ret = io_submit_sqe(ctx, &s, statep);
			if (ret)
				io_cqring_add_event(ctx, s.sqe->user_data, ret);
		}
		io_commit_sqring(ctx);

		if (statep) {
			io_submit_state_end(statep);
			statep = NULL;
		}

		read = ctx->requests_cb->r.read;
		write = smp_load_acquire(&ctx->requests_cb->r.write);
	}
}

static int io_run_queue(struct io_ring_ctx *ctx)
{
	if (!percpu_ref_tryget(&ctx->refs))
		return 0;

	io_ring_submit(ctx);
	io_ring_drop_ctx_refs(ctx, 1);

	return 0;
}

static int io_uring_open(struct inode *inode, struct file *file)
{
	struct io_ring_ctx *ctx;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx == NULL)
		return -ENOMEM;

	file->private_data = ctx;

	return 0;
}

static int io_uring_release(struct inode *inode, struct file *file)
{
	struct io_ring_ctx *ctx = file->private_data;

	file->private_data = NULL;
	io_ring_ctx_wait_and_kill(ctx);

	return 0;
}

static long io_ring_ioctl_init(struct io_ring_ctx *ctx, unsigned long arg)
{
	struct io_uring_params params;
	int ret;

	if (copy_from_user(&params, (void *)arg, sizeof(params)))
		return -EFAULT;

	ret = io_ring_ctx_init(ctx, &params);
	if (ret != 0)
		return ret;

	ret = io_sq_offload_start(ctx, &params);
	if (ret != 0) {
		io_ring_ctx_wait_and_kill(ctx);
		return ret;
	}

	if (copy_to_user((void *)arg, &params, sizeof(params)))
		return -EFAULT;

	return 0;
}

static long io_uring_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct io_ring_ctx *ctx = filp->private_data;

	switch (cmd) {
	case PXD_IOC_WAKE_UP_SQO:
		wake_up(&ctx->sqo_wait);
		return 0;
	case PXD_IOC_RUN_IO_QUEUE:
		return io_run_queue(ctx);
	case PXD_IOC_REGISTER_FILE:
		return io_sqe_register_file(ctx, arg);
	case PXD_IOC_UNREGISTER_FILE:
		return io_sqe_unregister_file(ctx, arg);
	case PXD_IOC_INIT_IO:
		return io_ring_ioctl_init(ctx, arg);
	default:
		return -ENOTTY;
	}
	return 0;
}

static int io_uring_fasync(int fd, struct file *file, int on)
{
	struct io_ring_ctx *ctx = file->private_data;

	return fasync_helper(fd, file, on, &ctx->cq_fasync);
}

static unsigned io_uring_poll(struct file *file, poll_table *wait)
{
	unsigned mask = POLLOUT | POLLWRNORM;
	struct io_ring_ctx *ctx = file->private_data;
	struct fuse_queue_cb *cb = ctx->responses_cb;

	if (!ctx)
		return POLLERR;

	poll_wait(file, &ctx->cq_wait, wait);

	if (cb->r.read != cb->r.write)
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

static void io_uring_vm_close(struct vm_area_struct *vma)
{
	pr_info("io_uring_vm_close");
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
static int io_uring_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,1,0) && !defined(__EL8__)
static int io_uring_vm_fault(struct vm_fault *vmf)
#else
static vm_fault_t io_uring_vm_fault(struct vm_fault *vmf)
#endif
{
	struct page *page;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
	struct file *file = vma->vm_file;
#else
	struct file *file = vmf->vma->vm_file;
#endif
	struct io_ring_ctx *ctx = file->private_data;
	void *map_addr = (void*)ctx->queue + (vmf->pgoff << PAGE_SHIFT);
	if ((vmf->pgoff << PAGE_SHIFT) > queue_size(ctx)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,1,0)
		return -EFAULT;
#else
		return VM_FAULT_SIGSEGV;
#endif
	}
	page = vmalloc_to_page(map_addr);
	get_page(page);
	vmf->page = page;
	return 0;
}

static void io_uring_vm_open(struct vm_area_struct *vma)
{
	pr_info("pxd_vm_open off %ld start %ld end %ld",
		vma->vm_pgoff << PAGE_SHIFT, vma->vm_start, vma->vm_end);
}

static struct vm_operations_struct io_uring_vm_ops = {
	.close = io_uring_vm_close,
	.fault = io_uring_vm_fault,
	.open = io_uring_vm_open,
};

static int io_uring_mmap(struct file *filp, struct vm_area_struct *vma)
{
	vma->vm_ops = &io_uring_vm_ops;
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_private_data = filp->private_data;
	io_uring_vm_open(vma);
	return 0;
}

struct file_operations io_ring_fops = {
	.owner = THIS_MODULE,
	.open = io_uring_open,
	.release = io_uring_release,
	.unlocked_ioctl = io_uring_ioctl,
	.poll = io_uring_poll,
	.fasync = io_uring_fasync,
	.mmap = io_uring_mmap,
};

static struct miscdevice miscdev;

int io_ring_register_device()
{
	miscdev.minor = MISC_DYNAMIC_MINOR;
	miscdev.name = "pxd/pxd-io";
	miscdev.fops = &io_ring_fops;
	return misc_register(&miscdev);
}

void io_ring_unregister_device()
{
	misc_deregister(&miscdev);
}

#endif
