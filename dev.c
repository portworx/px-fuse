/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/uio.h>
#include <linux/miscdevice.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/pipe_fs_i.h>
#include <linux/swap.h>
#include <linux/splice.h>
#include <linux/aio.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include "pxd_compat.h"
#include "pxd_fastpath.h"
#include "pxd_core.h"
#include "pxd_trace.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
#define PAGE_CACHE_GET(page) get_page(page)
#define PAGE_CACHE_RELEASE(page) put_page(page)
#else
#define PAGE_CACHE_GET(page) page_cache_get(page)
#define PAGE_CACHE_RELEASE(page) page_cache_release(page)
#endif

/** Maximum number of outstanding background requests */
#define FUSE_DEFAULT_MAX_BACKGROUND (PXD_MAX_QDEPTH * PXD_MAX_DEVICES)

#define FUSE_MAX_REQUEST_IDS (2 * FUSE_DEFAULT_MAX_BACKGROUND)

static struct kmem_cache *fuse_req_cachep;

static struct fuse_conn *fuse_get_conn(struct file *file)
{
	/*
	 * Lockless access is OK, because file->private data is set
	 * once during mount and is valid until the file is released.
	 */
	return file->private_data;
}

void fuse_request_init(struct fuse_req *req)
{
	memset(req, 0, sizeof(*req));
	INIT_LIST_HEAD(&req->list);
}

static struct fuse_req *__fuse_request_alloc(gfp_t flags)
{
	struct fuse_req *req = kmem_cache_alloc(fuse_req_cachep, flags);

	if (req) {
		fuse_request_init(req);
	}

	return req;
}

struct fuse_req *fuse_request_alloc()
{
	return __fuse_request_alloc(GFP_NOIO);
}

void fuse_request_free(struct fuse_req *req)
{
	kmem_cache_free(fuse_req_cachep, req);
}

void fuse_req_init_context(struct fuse_req *req)
{
	req->in.h.uid = from_kuid_munged(&init_user_ns, current_fsuid());
	req->in.h.gid = from_kgid_munged(&init_user_ns, current_fsgid());
	req->in.h.pid = current->pid;
}

static struct fuse_req *__fuse_get_req(struct fuse_conn *fc)
{
	struct fuse_req *req;
	int err;

	if (!fc->connected && !fc->allow_disconnected) {
		 err = -ENOTCONN;
		goto out;
	}

	req = fuse_request_alloc();
	if (!req) {
		err = -ENOMEM;
		goto out;
	}

	fuse_req_init_context(req);
	return req;

 out:
	return ERR_PTR(err);
}

struct fuse_req *fuse_get_req(struct fuse_conn *fc)
{
	return __fuse_get_req(fc);
}

struct fuse_req *fuse_get_req_for_background(struct fuse_conn *fc)
{
	return __fuse_get_req(fc);
}

static unsigned len_args(unsigned numargs, struct fuse_arg *args)
{
	unsigned nbytes = 0;
	unsigned i;

	for (i = 0; i < numargs; i++)
		nbytes += args[i].size;

	return nbytes;
}

static u64 fuse_get_unique(struct fuse_conn *fc)
{
	struct fuse_per_cpu_ids *my_ids;
	u64 uid;
	int num_alloc;

	int cpu = get_cpu();

	my_ids = per_cpu_ptr(fc->per_cpu_ids, cpu);

	if (unlikely(my_ids->num_free_ids == 0)) {
		spin_lock(&fc->lock);
		BUG_ON(fc->num_free_ids == 0);
		num_alloc = min(fc->num_free_ids, (u32)FUSE_MAX_PER_CPU_IDS / 2);
		memcpy(my_ids->free_ids, &fc->free_ids[fc->num_free_ids - num_alloc],
			num_alloc * sizeof(u64));
		fc->num_free_ids -= num_alloc;
		spin_unlock(&fc->lock);

		my_ids->num_free_ids = num_alloc;
	}

	uid = my_ids->free_ids[--my_ids->num_free_ids];

	put_cpu();

	uid += FUSE_MAX_REQUEST_IDS;

	/* zero is special */
	if (uid == 0)
		uid += FUSE_MAX_REQUEST_IDS;

	return uid;
}

static void fuse_put_unique(struct fuse_conn *fc, u64 uid)
{
	struct fuse_per_cpu_ids *my_ids;
	int num_free;
	int cpu = get_cpu();

	my_ids = per_cpu_ptr(fc->per_cpu_ids, cpu);

	if (unlikely(my_ids->num_free_ids == FUSE_MAX_PER_CPU_IDS)) {
		num_free = FUSE_MAX_PER_CPU_IDS / 2;
		spin_lock(&fc->lock);
		BUG_ON(fc->num_free_ids + num_free > FUSE_MAX_REQUEST_IDS);
		memcpy(&fc->free_ids[fc->num_free_ids],
			&my_ids->free_ids[my_ids->num_free_ids - num_free],
			num_free * sizeof(u64));
		fc->num_free_ids += num_free;
		spin_unlock(&fc->lock);

		my_ids->num_free_ids -= num_free;
	}

	my_ids->free_ids[my_ids->num_free_ids++] = uid;

	fc->request_map[uid & (FUSE_MAX_REQUEST_IDS - 1)] = NULL;

	put_cpu();
}

static void queue_request(struct fuse_conn *fc, struct fuse_req *req)
{
	list_add_tail(&req->list, &fc->pending);
}

static void fuse_conn_wakeup(struct fuse_conn *fc)
{
	wake_up(&fc->waitq);
	kill_fasync(&fc->fasync, SIGIO, POLL_IN);
}

/*
 * This function is called when a request is finished.  Either a reply
 * has arrived or it was aborted (and not yet sent) or some error
 * occurred during communication with userspace, or the device file
 * was closed.  The requester thread is woken up (if still waiting),
 * the 'end' callback is called if given, else the reference to the
 * request is released
 *
 * If called with fc->lock, unlocks it
 */
void request_end(struct fuse_conn *fc, struct fuse_req *req,
                        bool lock)
__releases(fc->lock)
{
	u64 uid;
	bool shouldfree = false;

	if (likely(lock)) {
		spin_lock(&fc->lock);
	}
	list_del(&req->list);
	spin_unlock(&fc->lock);
	uid = req->in.h.unique;
	if (req->end)
		shouldfree = req->end(fc, req, req->out.h.error);
	fuse_put_unique(fc, uid);
	if (shouldfree) fuse_request_free(req);
}

static void fuse_request_send_nowait_locked(struct fuse_conn *fc,
					    struct fuse_req *req)
{
	queue_request(fc, req);
}

void fuse_request_send_nowait(struct fuse_conn *fc, struct fuse_req *req)
{
	req->in.h.len = sizeof(struct fuse_in_header) +
		len_args(req->in.numargs, (struct fuse_arg *)req->in.args);

	req->in.h.unique = fuse_get_unique(fc);
	fc->request_map[req->in.h.unique & (FUSE_MAX_REQUEST_IDS - 1)] = req;

	/*
	 * Ensures checking the value of allow_disconnected and adding request to
	 * queue is done atomically.
	 */
	rcu_read_lock();

	if (fc->connected || fc->allow_disconnected) {
		spin_lock(&fc->lock);
		fuse_request_send_nowait_locked(fc, req);
		spin_unlock(&fc->lock);

		rcu_read_unlock();

		fuse_conn_wakeup(fc);
	} else {
		rcu_read_unlock();

		req->out.h.error = -ENOTCONN;
		request_end(fc, req, true);
	}
}

static int request_pending(struct fuse_conn *fc)
{
	return !list_empty(&fc->pending);
}

/* Wait until a request is available on the pending list */
static void request_wait(struct fuse_conn *fc)
__releases(fc->lock)
__acquires(fc->lock)
{
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue_exclusive(&fc->waitq, &wait);
	while (fc->connected && !request_pending(fc)) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (signal_pending(current))
			break;

		spin_unlock(&fc->lock);
		schedule();
		spin_lock(&fc->lock);
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&fc->waitq, &wait);
}

static ssize_t fuse_copy_req_read(struct fuse_req *req, struct iov_iter *iter)
{
	size_t copied, len;

	copied = sizeof(req->in.h);
	if (copy_to_iter(&req->in.h, copied, iter) != copied) {
		printk(KERN_ERR "%s: copy header error\n", __func__);
		return -EFAULT;
	}

	len = req->in.args[0].size;
	if (copy_to_iter((void *)req->in.args[0].value, len, iter) != len) {
		printk(KERN_ERR "%s: copy arg error\n", __func__);
		return -EFAULT;
	}
	copied += len;

	return copied;
}

extern uint32_t pxd_detect_zero_writes;

static bool __check_zero_page_write(char *base, size_t len) {
	uint8_t wsize = sizeof(uint64_t);
	char *p;
	size_t i;
	uint64_t *q;

	p = base;
	q = (uint64_t *)p;
	for (i = 0; i < (len / wsize); i++) {
		if (q[i]) {
			return false;
		}
	}
	for (i = len - (len % wsize); i < len; i++) {
		if (p[i]) {
			return false;
		}
	}
	return true;
}

/* Check if the request is writing zeroes and if so, convert it as a discard
 * request.
 */
#ifndef __PXD_BIO_MAKEREQ__
static void __fuse_convert_zero_writes(struct fuse_req *req)
{
	struct req_iterator breq_iter;

#ifdef HAVE_BVEC_ITER
	struct bio_vec bvec;
#else
	struct bio_vec *bvec = NULL;
#endif
	char *kaddr, *p;
	size_t len;

	rq_for_each_segment(bvec, req->rq, breq_iter) {
		kaddr = kmap_atomic(BVEC(bvec).bv_page);
		p = kaddr + BVEC(bvec).bv_offset;
		len = BVEC(bvec).bv_len;
		if (!__check_zero_page_write(p, len)) {
			kunmap_atomic(kaddr);
			return;
		}
		kunmap_atomic(kaddr);
	}
	req->in.h.opcode = PXD_DISCARD;
}
#else
static void __fuse_convert_zero_writes(struct fuse_req *req)
{
#if defined(HAVE_BVEC_ITER)
	struct bvec_iter bvec_iter;
	struct bio_vec bvec;
#else
	int bvec_iter;
	struct bio_vec *bvec = NULL;
#endif
	char *kaddr, *p;
	size_t len;

	bio_for_each_segment(bvec, req->bio, bvec_iter) {
		kaddr = kmap_atomic(BVEC(bvec).bv_page);
		p = kaddr + BVEC(bvec).bv_offset;
		len = BVEC(bvec).bv_len;
		if (!__check_zero_page_write(p, len)) {
			kunmap_atomic(kaddr);
			return;
		}
		kunmap_atomic(kaddr);
	}
	req->in.h.opcode = PXD_DISCARD;
}
#endif

void fuse_convert_zero_writes(struct fuse_req *req)
{
	__fuse_convert_zero_writes(req);
}

/*
 * Read a single request into the userspace filesystem's buffer.  This
 * function waits until a request is available, then removes it from
 * the pending list and copies request data to userspace buffer.  If
 * no reply is needed (FORGET) or request has been aborted or there
 * was an error during the copying then it's finished by calling
 * request_end().  Otherwise add it to the processing list, and set
 * the 'sent' flag.
 */
static ssize_t fuse_dev_do_read(struct fuse_conn *fc, struct file *file,
	struct iov_iter *iter)
{
	int err;
	struct fuse_req *req;
	struct list_head *entry, *first, *last, tmp, *next;
	ssize_t copied = 0, copied_this_time;
	ssize_t remain = iter->count;

	INIT_LIST_HEAD(&tmp);

	spin_lock(&fc->lock);
	if (!request_pending(fc)) {
		err = -EAGAIN;
		if ((file->f_flags & O_NONBLOCK) && fc->connected)
			goto err_unlock;
		request_wait(fc);
		err = -ENODEV;
		if (!fc->connected)
			goto err_unlock;
		err = -ERESTARTSYS;
		if (!request_pending(fc))
			goto err_unlock;
	}

retry:
	entry = fc->pending.next;
	first = fc->pending.next;
	last = &fc->pending;
	while (entry != &fc->pending) {
		req = list_entry(entry, struct fuse_req, list);
		if (req->in.h.len <= remain) {
			last = entry;
			remain -= req->in.h.len;
			entry = entry->next;
		} else {
			remain = 0;
			break;
		}
	}

	err = copied ? copied : -EINVAL;
	if (last == &fc->pending)
		goto err_unlock;

	list_cut_position(&tmp, &fc->pending, last);
	list_splice_tail(&tmp, &fc->processing);
	spin_unlock(&fc->lock);

	entry = first;
	err = 0;
	while (1) {
		req = list_entry(entry, struct fuse_req, list);

		/* Check if a write request is writing zeroes */
		if (pxd_detect_zero_writes && (req->in.h.opcode == PXD_WRITE) &&
		    req->pxd_rdwr_in.size &&
		    !(req->pxd_rdwr_in.flags & PXD_FLAGS_SYNC)) {
			fuse_convert_zero_writes(req);
		}
		next = entry->next;
		copied_this_time = fuse_copy_req_read(req, iter);
		if (likely(copied_this_time > 0)) {
			copied += copied_this_time;
		} else {
			err = copied_this_time;
			req->out.h.error = -EIO;
			request_end(fc, req, true);
		}
		if (entry == last)
			break;
		entry = next;
	}
	if (!copied) {
		copied = err;
	}

	/* Check if more requests could be picked up */
	if (remain && request_pending(fc)) {
		INIT_LIST_HEAD(&tmp);
		spin_lock(&fc->lock);
		if (request_pending(fc)) {
			goto retry;
		}
		spin_unlock(&fc->lock);
	}
	return copied;

 err_unlock:
	spin_unlock(&fc->lock);
	return err;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static ssize_t fuse_dev_read(struct kiocb *iocb, const struct iovec *iov,
			      unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct fuse_conn *fc = fuse_get_conn(file);
	struct iov_iter iter;
	if (!fc)
		return -EPERM;
	iov_iter_init(&iter, READ, iov, nr_segs, iov_length(iov, nr_segs));

	return fuse_dev_do_read(fc, file, &iter);
}
#else
static ssize_t fuse_dev_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct fuse_conn *fc = fuse_get_conn(file);
	if (!fc)
		return -EPERM;

	return fuse_dev_do_read(fc, file, to);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
static int fuse_dev_pipe_buf_steal(struct pipe_inode_info *pipe,
                                   struct pipe_buffer *buf)
{
        return 1;
}
static const struct pipe_buf_operations fuse_dev_pipe_buf_ops = {
         .can_merge = 0,
         .map = generic_pipe_buf_map,
         .unmap = generic_pipe_buf_unmap,
         .confirm = generic_pipe_buf_confirm,
         .release = generic_pipe_buf_release,
         .steal = fuse_dev_pipe_buf_steal,
         .get = generic_pipe_buf_get,
};
#endif

static ssize_t fuse_dev_splice_read(struct file *in, loff_t *ppos,
				    struct pipe_inode_info *pipe,
				    size_t len, unsigned int flags)
{
	return -EINVAL;
}

static int fuse_notify_add(struct fuse_conn *conn, unsigned int size,
		struct iov_iter *iter)
{
	struct pxd_add_out add;
	struct pxd_add_ext_out add_ext;
	size_t len = sizeof(add);

	if (copy_from_iter(&add, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}

	memset(&add_ext, 0, sizeof(add_ext));
	memcpy(&add_ext, &add, sizeof(add));
	add_ext.open_mode = O_LARGEFILE | O_RDWR | O_NOATIME; // default flags
	return pxd_add(conn, &add_ext);
}

static int fuse_notify_add_ext(struct fuse_conn *conn, unsigned int size,
		struct iov_iter *iter)
{
	struct pxd_add_ext_out add;
	size_t len = sizeof(add);

	if (copy_from_iter(&add, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}
	trace_fuse_notify_add_ext(add.dev_id, add.size, add.queue_depth, add.discard_size, add.open_mode, add.enable_fp, add.paths.count);
	return pxd_add(conn, &add);
}


/* Look up request on processing list by unique ID */
struct fuse_req *request_find(struct fuse_conn *fc, u64 unique)
{
	u32 index = unique & (FUSE_MAX_REQUEST_IDS - 1);
	struct fuse_req *req = fc->request_map[index];
	if (req == NULL) {
		printk(KERN_ERR "no request unique %llx", unique);
		return req;
	}
	if (req->in.h.unique != unique) {
		printk(KERN_ERR "id mismatch got %llx need %llx", req->in.h.unique, unique);
		return NULL;
	}
	return req;
}

/*
static struct fuse_req* request_find_in_ctx(unsigned ctx, u64 unique)
{
	struct pxd_context *pctx = find_context(ctx);

	if (!pctx) return NULL;

	return request_find(&pctx->fc, unique);
}
*/

#define IOV_BUF_SIZE 64

static int copy_in_read_data_iovec(struct iov_iter *iter,
	struct pxd_read_data_out *read_data, struct iovec *iov,
	struct iov_iter *data_iter)
{
	int iovcnt;
	size_t len;

	trace_copy_in_read_data_iovec(read_data->unique, read_data->iovcnt, read_data->iovcnt - min(read_data->iovcnt, IOV_BUF_SIZE));
	if (!read_data->iovcnt)
		return -EFAULT;

	iovcnt = min(read_data->iovcnt, IOV_BUF_SIZE);
	len = iovcnt * sizeof(struct iovec);
	if (copy_from_iter(iov, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy iovec\n", __func__);
		return -EFAULT;
	}
	read_data->iovcnt -= iovcnt;


	iov_iter_init(data_iter, READ, iov, iovcnt, iov_length(iov, iovcnt));

	return 0;
}

#ifndef __PXD_BIO_MAKEREQ__
static int __fuse_notify_read_data(struct fuse_conn *conn,
		struct fuse_req *req,
		struct pxd_read_data_out *read_data_p, struct iov_iter *iter)
{
	struct iovec iov[IOV_BUF_SIZE];
	struct iov_iter data_iter;
#ifdef HAVE_BVEC_ITER
	struct bio_vec bvec;
#else
	struct bio_vec *bvec = NULL;
#endif
	struct req_iterator breq_iter;
	size_t copied, skipped = 0;
	int ret;

	ret = copy_in_read_data_iovec(iter, read_data_p, iov, &data_iter);
	if (ret)
		return ret;

	trace_fuse_notify_read_data_request(req->pxd_dev->dev_id, read_data_p->unique, blk_rq_pos(req->rq) * SECTOR_SIZE,
		blk_rq_bytes(req->rq), req->pxd_rdwr_in.offset, read_data_p->offset);

	/* advance the iterator if data is unaligned */
	if (unlikely(req->pxd_rdwr_in.offset & PXD_LBS_MASK)) {
		iov_iter_advance(&data_iter,
				 req->pxd_rdwr_in.offset & PXD_LBS_MASK);
	}

	rq_for_each_segment(bvec, req->rq, breq_iter) {
		ssize_t len = BVEC(bvec).bv_len;

		trace_fuse_notify_read_data_segment_info(req->pxd_dev->dev_id, read_data_p->unique,
			BVEC(bvec).bv_offset,
			BVEC(bvec).bv_len);
		copied = 0;
		if (skipped < read_data_p->offset) {
			if (read_data_p->offset - skipped >= len) {
				skipped += len;
				copied = len;
			} else {
				copied = read_data_p->offset - skipped;
				skipped = read_data_p->offset;
			}
		}
		if (copied < len) {
			size_t copy_this = copy_page_to_iter(BVEC(bvec).bv_page,
				BVEC(bvec).bv_offset + copied,
				len - copied, &data_iter);

			trace_fuse_notify_read_data_copy(req->pxd_dev->dev_id, read_data_p->unique, copied, copy_this,
				BVEC(bvec).bv_offset, BVEC(bvec).bv_offset + copied,
				BVEC(bvec).bv_len, len - copied, iter->count);
			if (copy_this != len - copied) {
				if (!iter->count)
					return 0;

				/* out of space in destination, copy more iovec */
				ret = copy_in_read_data_iovec(iter, read_data_p,
					iov, &data_iter);
				if (ret)
					return ret;
				len -= (copied + copy_this);
				copied = copy_page_to_iter(BVEC(bvec).bv_page,
					BVEC(bvec).bv_offset + copied + copy_this,
					len, &data_iter);
				trace_fuse_notify_read_data_finalcopy(req->pxd_dev->dev_id, read_data_p->unique, len, copied,
					BVEC(bvec).bv_offset, BVEC(bvec).bv_offset + copied + copy_this,
					BVEC(bvec).bv_len);
				if (copied != len) {
					printk(KERN_ERR "%s: copy failed new iovec, bio_vec : page = %p len = %d offset = %d\n",
						__func__, BVEC(bvec).bv_page, BVEC(bvec).bv_len, BVEC(bvec).bv_offset);
					return -EFAULT;
				}
			}
		}
	}

	return 0;
}

#else
static int __fuse_notify_read_data(struct fuse_conn *conn,
		struct fuse_req *req,
		struct pxd_read_data_out *read_data_p, struct iov_iter *iter)
{
	struct iovec iov[IOV_BUF_SIZE];
	struct iov_iter data_iter;
#ifdef HAVE_BVEC_ITER
	struct bio_vec bvec;
	struct bvec_iter bvec_iter;
#else
	struct bio_vec *bvec = NULL;
	int bvec_iter;
#endif
	size_t copied, skipped = 0;
	int ret;

	ret = copy_in_read_data_iovec(iter, read_data_p, iov, &data_iter);
	if (ret)
		return ret;

	/* advance the iterator if data is unaligned */
	if (unlikely(req->pxd_rdwr_in.offset & PXD_LBS_MASK))
		iov_iter_advance(&data_iter,
				 req->pxd_rdwr_in.offset & PXD_LBS_MASK);

	bio_for_each_segment(bvec, req->bio, bvec_iter) {
		ssize_t len = BVEC(bvec).bv_len;
		copied = 0;
		if (skipped < read_data_p->offset) {
			if (read_data_p->offset - skipped >= len) {
				skipped += len;
				copied = len;
			} else {
				copied = read_data_p->offset - skipped;
				skipped = read_data_p->offset;
			}
		}
		if (copied < len) {
			size_t copy_this = copy_page_to_iter(BVEC(bvec).bv_page,
				BVEC(bvec).bv_offset + copied,
				len - copied, &data_iter);
			if (copy_this != len - copied) {
				if (!iter->count)
					return 0;

				/* out of space in destination, copy more iovec */
				ret = copy_in_read_data_iovec(iter, read_data_p,
					iov, &data_iter);
				if (ret)
					return ret;
				len -= (copied + copy_this);
				copied = copy_page_to_iter(BVEC(bvec).bv_page,
					BVEC(bvec).bv_offset + copied + copy_this,
					len, &data_iter);
				if (copied != len) {
					printk(KERN_ERR "%s: copy failed new iovec, bio_vec : page = %p len = %d offset = %d\n",
						__func__, BVEC(bvec).bv_page, BVEC(bvec).bv_len, BVEC(bvec).bv_offset);
					return -EFAULT;
				}
			}
		}
	}

	return 0;
}
#endif

static int fuse_notify_read_data(struct fuse_conn *conn, unsigned int size,
				struct iov_iter *iter)
{
	struct pxd_read_data_out read_data;
	size_t len = sizeof(read_data);
	struct fuse_req *req;

	if (copy_from_iter(&read_data, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy read_data arg\n", __func__);
		return -EFAULT;
	}

	spin_lock(&conn->lock);
	req = request_find(conn, read_data.unique);
	if (!req) {
		spin_unlock(&conn->lock);
		printk(KERN_ERR "%s: request %lld not found\n", __func__,
		       read_data.unique);
		return -ENOENT;
	}
	spin_unlock(&conn->lock);

	if (req->in.h.opcode != PXD_WRITE &&
	    req->in.h.opcode != PXD_WRITE_SAME) {
		printk(KERN_ERR "%s: request is not a write\n", __func__);
		return -EINVAL;
	}

	return __fuse_notify_read_data(conn, req, &read_data, iter);
}


static int fuse_notify_remove(struct fuse_conn *conn, unsigned int size,
		struct iov_iter *iter)
{
	struct pxd_remove_out remove;
	size_t len = sizeof(remove);

	if (copy_from_iter(&remove, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}
	return pxd_remove(conn, &remove);
}

static int fuse_notify_update_size(struct fuse_conn *conn, unsigned int size,
		struct iov_iter *iter)
{
	struct pxd_update_size update_size;
	size_t len = sizeof(update_size);

	if (copy_from_iter(&update_size, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}
	return pxd_update_size(conn, &update_size);
}

static int fuse_notify_get_features(struct fuse_conn *conn, unsigned int size,
		struct iov_iter *iter)
{
	return pxd_supported_features();
}

static int fuse_notify_suspend(struct fuse_conn *conn, unsigned int size,
		struct iov_iter *iter) {
	struct pxd_context *ctx = container_of(conn, struct pxd_context, fc);
	struct pxd_suspend req;
	size_t len = sizeof(req);
	struct pxd_device *pxd_dev;

	if (copy_from_iter(&req, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}

	pxd_dev = find_pxd_device(ctx, req.dev_id);
	if (!pxd_dev) {
		printk(KERN_ERR "device %llu not found\n", req.dev_id);
		return -EINVAL;
	}
	return pxd_request_suspend(pxd_dev, req.skip_flush, req.coe);
}

static int fuse_notify_resume(struct fuse_conn *conn, unsigned int size,
		struct iov_iter *iter) {
	struct pxd_context *ctx = container_of(conn, struct pxd_context, fc);
	struct pxd_resume req;
	size_t len = sizeof(req);
	struct pxd_device *pxd_dev;

	if (copy_from_iter(&req, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}

	pxd_dev = find_pxd_device(ctx, req.dev_id);
	if (!pxd_dev) {
		printk(KERN_ERR "device %llu not found\n", req.dev_id);
		return -EINVAL;
	}

	return pxd_request_resume(pxd_dev);
}

static int fuse_notify_ioswitch_event(struct fuse_conn *conn, unsigned int size,
               struct iov_iter *iter, bool failover) {
       struct pxd_context *ctx = container_of(conn, struct pxd_context, fc);
       struct pxd_ioswitch req;
       size_t len = sizeof(req);
       struct pxd_device *pxd_dev;

       if (copy_from_iter(&req, len, iter) != len) {
               printk(KERN_ERR "%s: can't copy arg\n", __func__);
               return -EFAULT;
       }

       pxd_dev = find_pxd_device(ctx, req.dev_id);
       if (!pxd_dev) {
               printk(KERN_ERR "device %llu not found\n", req.dev_id);
               return -EINVAL;
       }

       return pxd_request_ioswitch(pxd_dev,
                failover ? PXD_FAILOVER_TO_USERSPACE : PXD_FALLBACK_TO_KERNEL);
}

static int fuse_notify_export(struct fuse_conn *conn, unsigned int size,
		struct iov_iter *iter)
{
	uint64_t dev_id;
	size_t len = sizeof(dev_id);

	if (copy_from_iter(&dev_id, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}

	return pxd_export(conn, dev_id);
}

static int fuse_notify(struct fuse_conn *fc, enum fuse_notify_code code,
		       unsigned int size, struct iov_iter *iter)
{
	switch ((int)code) {
	case PXD_READ_DATA:
		return fuse_notify_read_data(fc, size, iter);
	case PXD_ADD:
		return fuse_notify_add(fc, size, iter);
	case PXD_REMOVE:
		return fuse_notify_remove(fc, size, iter);
	case PXD_UPDATE_SIZE:
		return fuse_notify_update_size(fc, size, iter);
	case PXD_ADD_EXT:
		return fuse_notify_add_ext(fc, size, iter);
	case PXD_GET_FEATURES:
		return fuse_notify_get_features(fc, size, iter);
	case PXD_SUSPEND:
		return fuse_notify_suspend(fc, size, iter);
	case PXD_RESUME:
		return fuse_notify_resume(fc, size, iter);
	case PXD_FAILOVER_TO_USERSPACE:
		return fuse_notify_ioswitch_event(fc, size, iter, true);
	case PXD_FALLBACK_TO_KERNEL:
		return fuse_notify_ioswitch_event(fc, size, iter, false);
	case PXD_EXPORT_DEV:
		return fuse_notify_export(fc, size, iter);
	default:
		return -EINVAL;
	}
}

/*
 * Write a single reply to a request.  First the header is copied from
 * the write buffer.  The request is then searched on the processing
 * list by the unique ID found in the header.  If found, then remove
 * it from the list and copy the rest of the buffer to the request.
 * The request is finished by calling request_end()
 */
#ifndef __PXD_BIO_MAKEREQ__
static int __fuse_dev_do_write(struct fuse_conn *fc,
		struct fuse_req *req, struct iov_iter *iter)
{
	if (req->in.h.opcode == PXD_READ && iter->count > 0) {
#ifdef HAVE_BVEC_ITER
		struct bio_vec bvec;
#else
		struct bio_vec *bvec = NULL;
#endif
		struct request *breq = req->rq;
		struct req_iterator breq_iter;
		int nsegs = breq->nr_phys_segments;

		if (nsegs) {
			int i = 0;
			rq_for_each_segment(bvec, breq, breq_iter) {
				ssize_t len = BVEC(bvec).bv_len;
				if (copy_page_from_iter(BVEC(bvec).bv_page,
							BVEC(bvec).bv_offset,
							len, iter) != len) {
					printk(KERN_ERR "%s: copy page %d of %d error\n",
					       __func__, i, nsegs);
					return -EFAULT;
				}
				i++;
			}
		}
	}
	request_end(fc, req, true);
	return 0;
}
#else
static int __fuse_dev_do_write(struct fuse_conn *fc,
		struct fuse_req *req, struct iov_iter *iter)
{
#if defined(HAVE_BVEC_ITER)
	struct bio_vec bvec;
	struct bio *breq = req->bio;
	int nsegs = bio_segments(breq);
	struct bvec_iter bvec_iter;
#else
	struct bio_vec *bvec = NULL;
	struct bio *breq = req->bio;
	int nsegs = bio_segments(breq);
	int bvec_iter;
#endif

	if (req->in.h.opcode == PXD_READ && iter->count > 0) {
		if (nsegs) {
			int i = 0;
			bio_for_each_segment(bvec, breq, bvec_iter) {
				ssize_t len = BVEC(bvec).bv_len;
				if (copy_page_from_iter(BVEC(bvec).bv_page,
							BVEC(bvec).bv_offset,
							len, iter) != len) {
					printk(KERN_ERR "%s: copy page %d of %d error\n",
					       __func__, i, nsegs);
					return -EFAULT;
				}
				i++;
			}
		}
	}
	request_end(fc, req, true);
	return 0;
}
#endif

static ssize_t fuse_dev_do_write(struct fuse_conn *fc, struct iov_iter *iter)
{
	int err;
	struct fuse_req *req;
	struct fuse_out_header oh;
	size_t len;
	size_t nbytes = iter->count;

	if (iter->count < sizeof(struct fuse_out_header))
		return -EINVAL;

	len = sizeof(oh);
	if (copy_from_iter(&oh, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy header\n", __func__);
		return -EFAULT;
	}

	if (oh.len != nbytes)
		return -EINVAL;

	/*
	 * Zero oh.unique indicates unsolicited notification message
	 * and error contains notification code.
	 */
	if (!oh.unique) {
		err = fuse_notify(fc, oh.error, nbytes - sizeof(oh), iter);
		return err ? err : nbytes;
	}

	if (oh.error <= -1000 || oh.error > 0)
		return -EINVAL;

	err = -ENOENT;

	req = request_find(fc, oh.unique);
	if (!req) {
		printk(KERN_ERR "%s: request %lld not found\n", __func__, oh.unique);
		return -ENOENT;
	}

	spin_lock(&fc->lock);
	if (!fc->connected) {
		spin_unlock(&fc->lock);
		return err;
	}

	list_del_init(&req->list);
	spin_unlock(&fc->lock);

	req->out.h = oh;

	err = __fuse_dev_do_write(fc, req, iter);
	if (err) return err;

	return nbytes;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static ssize_t fuse_dev_write(struct kiocb *iocb, const struct iovec *iov,
			      unsigned long nr_segs, loff_t pos)
{
	struct fuse_conn *fc = fuse_get_conn(iocb->ki_filp);
	struct iov_iter iter;
	if (!fc)
		return -EPERM;

	iov_iter_init(&iter, WRITE, iov, nr_segs, iov_length(iov, nr_segs));

	return fuse_dev_do_write(fc, &iter);
}
#else
static ssize_t fuse_dev_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct fuse_conn *fc = fuse_get_conn(iocb->ki_filp);
	if (!fc)
		return -EPERM;

	return fuse_dev_do_write(fc, from);
}
#endif

static ssize_t fuse_dev_splice_write(struct pipe_inode_info *pipe,
				     struct file *out, loff_t *ppos,
				     size_t len, unsigned int flags)
{
	return -EINVAL;
}

static unsigned fuse_dev_poll(struct file *file, poll_table *wait)
{
	unsigned mask = POLLOUT | POLLWRNORM;
	struct fuse_conn *fc = fuse_get_conn(file);
	if (!fc)
		return POLLERR;

	poll_wait(file, &fc->waitq, wait);

	spin_lock(&fc->lock);
	if (!fc->connected)
		mask = POLLERR;
	else if (request_pending(fc))
		mask |= POLLIN | POLLRDNORM;
	spin_unlock(&fc->lock);

	return mask;
}

/*
 * Abort all requests on the given list (pending or processing)
 *
 * This function releases and reacquires fc->lock
 */
static void end_requests(struct fuse_conn *fc, struct list_head *head)
__releases(fc->lock)
__acquires(fc->lock)
{
	while (!list_empty(head)) {
		struct fuse_req *req;
		req = list_entry(head->next, struct fuse_req, list);
		req->out.h.error = -ECONNABORTED;
		request_end(fc, req, false);
		spin_lock(&fc->lock);
	}
}

void fuse_end_queued_requests(struct fuse_conn *fc)
__releases(fc->lock)
__acquires(fc->lock)
{
	end_requests(fc, &fc->pending);
	end_requests(fc, &fc->processing);
}

static void fuse_conn_free_allocs(struct fuse_conn *fc)
{
	if (fc->per_cpu_ids)
		free_percpu(fc->per_cpu_ids);
	if (fc->free_ids)
		kfree(fc->free_ids);
	if (fc->request_map)
		kfree(fc->request_map);
}

int fuse_conn_init(struct fuse_conn *fc)
{
	int i, rc;
	int cpu;

	memset(fc, 0, sizeof(*fc));
	spin_lock_init(&fc->lock);
	atomic_set(&fc->count, 1);
	init_waitqueue_head(&fc->waitq);
	INIT_LIST_HEAD(&fc->pending);
	INIT_LIST_HEAD(&fc->processing);
	INIT_LIST_HEAD(&fc->entry);
	fc->request_map = kmalloc(FUSE_MAX_REQUEST_IDS * sizeof(struct fuse_req*),
		GFP_KERNEL);

	rc = -ENOMEM;
	if (!fc->request_map) {
		printk(KERN_ERR "failed to allocate request map");
		goto err_out;
	}
	memset(fc->request_map, 0,
		FUSE_MAX_REQUEST_IDS * sizeof(struct fuse_req*));

	fc->free_ids = kmalloc(FUSE_MAX_REQUEST_IDS * sizeof(u64), GFP_KERNEL);
	if (!fc->free_ids) {
		printk(KERN_ERR "failed to allocate free requests");
		goto err_out;
	}
	for (i = 0; i < FUSE_MAX_REQUEST_IDS; ++i) {
		fc->free_ids[i] = FUSE_MAX_REQUEST_IDS - i - 1;
	}
	fc->num_free_ids = FUSE_MAX_REQUEST_IDS;

	fc->per_cpu_ids = alloc_percpu(struct fuse_per_cpu_ids);
	if (!fc->per_cpu_ids) {
		printk(KERN_ERR "failed to allocate per cpu ids");
		goto err_out;
	}

	for_each_possible_cpu(cpu) {
		struct fuse_per_cpu_ids *my_ids = per_cpu_ptr(fc->per_cpu_ids, cpu);
		memset(my_ids, 0, sizeof(*my_ids));
	}

	fc->reqctr = 0;
	return 0;
err_out:
	fuse_conn_free_allocs(fc);
	return rc;
}

void fuse_conn_put(struct fuse_conn *fc)
{
	if (atomic_dec_and_test(&fc->count)) {
		fuse_conn_free_allocs(fc);
		fc->release(fc);
	}
}

struct fuse_conn *fuse_conn_get(struct fuse_conn *fc)
{
	atomic_inc(&fc->count);
	return fc;
}

/*
 * Abort all requests.
 *
 * Emergency exit in case of a malicious or accidental deadlock, or
 * just a hung filesystem.
 *
 * The same effect is usually achievable through killing the
 * filesystem daemon and all users of the filesystem.  The exception
 * is the combination of an asynchronous request and the tricky
 * deadlock (see Documentation/filesystems/fuse.txt).
 *
 * During the aborting, progression of requests from the pending and
 * processing lists onto the io list, and progression of new requests
 * onto the pending list is prevented by req->connected being false.
 *
 * Progression of requests under I/O to the processing list is
 * prevented by the req->aborted flag being true for these requests.
 * For this reason requests on the io list must be aborted first.
 */
void fuse_abort_conn(struct fuse_conn *fc)
{
	spin_lock(&fc->lock);
	if (fc->connected) {
		fc->connected = 0;
		fuse_end_queued_requests(fc);
		wake_up_all(&fc->waitq);
		kill_fasync(&fc->fasync, SIGIO, POLL_IN);
	}
	spin_unlock(&fc->lock);
}

static int fuse_dev_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = fuse_get_conn(file);
	if (fc) {
		spin_lock(&fc->lock);
		fc->connected = 0;
		fuse_end_queued_requests(fc);
		spin_unlock(&fc->lock);
		fuse_conn_put(fc);
	}

	return 0;
}

void fuse_restart_requests(struct fuse_conn *fc)
{
	spin_lock(&fc->lock);
	list_splice_init(&fc->processing, &fc->pending);
	wake_up(&fc->waitq);
	kill_fasync(&fc->fasync, SIGIO, POLL_IN);
	spin_unlock(&fc->lock);
}

static int fuse_dev_fasync(int fd, struct file *file, int on)
{
	struct fuse_conn *fc = fuse_get_conn(file);
	if (!fc)
		return -EPERM;

	/* No locking - fasync_helper does its own locking */
	return fasync_helper(fd, file, on, &fc->fasync);
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
const struct file_operations fuse_dev_operations = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.read		= do_sync_read,
	.aio_read	= fuse_dev_read,
	.splice_read	= fuse_dev_splice_read,
	.write		= do_sync_write,
	.aio_write	= fuse_dev_write,
	.splice_write	= fuse_dev_splice_write,
	.poll		= fuse_dev_poll,
	.release	= fuse_dev_release,
	.fasync		= fuse_dev_fasync,
};
#else
const struct file_operations fuse_dev_operations = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.read_iter	= fuse_dev_read_iter,
	.splice_read	= fuse_dev_splice_read,
	.write_iter	= fuse_dev_write_iter,
	.splice_write	= fuse_dev_splice_write,
	.poll		= fuse_dev_poll,
	.release	= fuse_dev_release,
	.fasync		= fuse_dev_fasync,
};
#endif

int fuse_dev_init(void)
{
	int err = -ENOMEM;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,16,0)
	fuse_req_cachep = kmem_cache_create_usercopy("pxd_fuse_request",
					    sizeof(struct fuse_req),
					    0, 0, 0, sizeof(struct fuse_req), NULL);
#else
	fuse_req_cachep = kmem_cache_create("pxd_fuse_request",
					    sizeof(struct fuse_req),
					    0, 0, NULL);
#endif
	if (!fuse_req_cachep)
		goto out;

	return 0;

 out:
	return err;
}

void fuse_dev_cleanup(void)
{
	kmem_cache_destroy(fuse_req_cachep);
}
