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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#include "iov_iter.h"

#define iov_iter_advance __iov_iter_advance
#define iov_iter __iov_iter
#define iov_iter_init __iov_iter_init
#define copy_page_to_iter __copy_page_to_iter
#define copy_page_from_iter __copy_page_from_iter

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
#define PAGE_CACHE_GET(page) get_page(page)
#define PAGE_CACHE_RELEASE(page) put_page(page)
#else
#define PAGE_CACHE_GET(page) page_cache_get(page)
#define PAGE_CACHE_RELEASE(page) page_cache_release(page)
#endif

/** Maximum number of outstanding background requests */
#define FUSE_DEFAULT_MAX_BACKGROUND (PXD_MAX_QDEPTH * PXD_MAX_DEVICES)

/** Congestion starts at 75% of maximum */
#define FUSE_DEFAULT_CONGESTION_THRESHOLD (FUSE_DEFAULT_MAX_BACKGROUND * 3 / 4)

#define FUSE_HASH_SIZE FUSE_DEFAULT_MAX_BACKGROUND

static struct kmem_cache *fuse_req_cachep;

static struct fuse_conn *fuse_get_conn(struct file *file)
{
	/*
	 * Lockless access is OK, because file->private data is set
	 * once during mount and is valid until the file is released.
	 */
	return file->private_data;
}

static void fuse_request_init(struct fuse_req *req, struct page **pages,
			      struct fuse_page_desc *page_descs,
			      unsigned npages)
{
	memset(req, 0, sizeof(*req));
	memset(pages, 0, sizeof(*pages) * npages);
	memset(page_descs, 0, sizeof(*page_descs) * npages);
	INIT_LIST_HEAD(&req->list);
	INIT_HLIST_NODE(&req->hash_entry);
	atomic_set(&req->count, 1);
	req->pages = pages;
	req->page_descs = page_descs;
	req->max_pages = npages;
}

static struct fuse_req *__fuse_request_alloc(unsigned npages, gfp_t flags)
{
	struct fuse_req *req = kmem_cache_alloc(fuse_req_cachep, flags);

	if (req) {
		struct page **pages;
		struct fuse_page_desc *page_descs;

		if (npages <= FUSE_REQ_INLINE_PAGES) {
			pages = req->inline_pages;
			page_descs = req->inline_page_descs;
		} else {
			pages = kmalloc(sizeof(struct page *) * npages, flags);
			page_descs = kmalloc(sizeof(struct fuse_page_desc) *
					     npages, flags);

			if (!pages || !page_descs) {
				kfree(pages);
				kfree(page_descs);
				kmem_cache_free(fuse_req_cachep, req);
				return NULL;
			}
		}

		fuse_request_init(req, pages, page_descs, npages);
	}

	return req;
}

struct fuse_req *fuse_request_alloc(unsigned npages)
{
	return __fuse_request_alloc(npages, GFP_ATOMIC);
}

struct fuse_req *fuse_request_alloc_nofs(unsigned npages)
{
	return __fuse_request_alloc(npages, GFP_NOFS);
}

void fuse_request_free(struct fuse_req *req)
{
	if (req->pages != req->inline_pages) {
		kfree(req->pages);
		kfree(req->page_descs);
	}
	kmem_cache_free(fuse_req_cachep, req);
}

void __fuse_get_request(struct fuse_req *req)
{
	atomic_inc(&req->count);
}

static void fuse_req_init_context(struct fuse_req *req)
{
	req->in.h.uid = from_kuid_munged(&init_user_ns, current_fsuid());
	req->in.h.gid = from_kgid_munged(&init_user_ns, current_fsgid());
	req->in.h.pid = current->pid;
}

static struct fuse_req *__fuse_get_req(struct fuse_conn *fc, unsigned npages,
				       bool for_background)
{
	struct fuse_req *req;
	int err;

	err = -ENOTCONN;
	if (!fc->connected && !fc->allow_disconnected)
		goto out;

	req = fuse_request_alloc(npages);
	err = -ENOMEM;
	if (!req) {
		goto out;
	}

	fuse_req_init_context(req);
	req->background = for_background;
	return req;

 out:
	return ERR_PTR(err);
}

struct fuse_req *fuse_get_req(struct fuse_conn *fc, unsigned npages)
{
	return __fuse_get_req(fc, npages, false);
}

struct fuse_req *fuse_get_req_for_background(struct fuse_conn *fc,
					     unsigned npages)
{
	return __fuse_get_req(fc, npages, true);
}

void fuse_put_request(struct fuse_conn *fc, struct fuse_req *req)
{
	if (atomic_dec_and_test(&req->count))
		fuse_request_free(req);
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
	fc->reqctr++;
	/* zero is special */
	if (fc->reqctr == 0)
		fc->reqctr = 1;

	return fc->reqctr;
}

static void queue_request(struct fuse_conn *fc, struct fuse_req *req)
{
	list_add_tail(&req->list, &fc->pending);
	if (hlist_unhashed(&req->hash_entry))
		hlist_add_head(&req->hash_entry,
			       &fc->hash[req->in.h.unique % FUSE_HASH_SIZE]);
	req->state = FUSE_REQ_PENDING;
}

static void fuse_conn_wakeup(struct fuse_conn *fc)
{
	wake_up(&fc->waitq);
	kill_fasync(&fc->fasync, SIGIO, POLL_IN);
}

void fuse_request_send_oob(struct fuse_conn *fc, struct fuse_req *req)
{
	spin_lock(&fc->lock);
	req->background = 0;
	req->isreply = 1;
	req->in.h.unique = fuse_get_unique(fc);
	req->in.h.len = sizeof(struct fuse_in_header) +
		len_args(req->in.numargs, (struct fuse_arg *) req->in.args);
	list_add(&req->list, &fc->pending);
	if (hlist_unhashed(&req->hash_entry))
		hlist_add_head(&req->hash_entry,
			       &fc->hash[req->in.h.unique % FUSE_HASH_SIZE]);
	req->state = FUSE_REQ_PENDING;
	spin_unlock(&fc->lock);

	fuse_conn_wakeup(fc);
}

/*
 * This function is called when a request is finished.  Either a reply
 * has arrived or it was aborted (and not yet sent) or some error
 * occurred during communication with userspace, or the device file
 * was closed.  The requester thread is woken up (if still waiting),
 * the 'end' callback is called if given, else the reference to the
 * request is released
 *
 * Called with fc->lock, unlocks it
 */
static void request_end(struct fuse_conn *fc, struct fuse_req *req)
__releases(fc->lock)
{
	void (*end) (struct fuse_conn *, struct fuse_req *) = req->end;
	req->end = NULL;
	if (!hlist_unhashed(&req->hash_entry))
		hlist_del_init(&req->hash_entry);
	list_del(&req->list);
	req->state = FUSE_REQ_FINISHED;
	if (req->background) {
		req->background = 0;

		if (fc->num_background == fc->congestion_threshold &&
		    fc->connected && fc->bdi_initialized) {
			clear_bdi_congested(&fc->bdi, BLK_RW_SYNC);
			clear_bdi_congested(&fc->bdi, BLK_RW_ASYNC);
		}
		fc->num_background--;
		fc->active_background--;
	}
	spin_unlock(&fc->lock);
	if (end)
		end(fc, req);
	fuse_put_request(fc, req);
}

static void fuse_request_send_nowait_locked(struct fuse_conn *fc,
					    struct fuse_req *req)
{
	BUG_ON(!req->background);
	fc->num_background++;
	if (fc->num_background == fc->congestion_threshold &&
	    fc->bdi_initialized) {
		set_bdi_congested(&fc->bdi, BLK_RW_SYNC);
		set_bdi_congested(&fc->bdi, BLK_RW_ASYNC);
	}
	fc->active_background++;
	req->in.h.unique = fuse_get_unique(fc);
	queue_request(fc, req);
}

static void fuse_request_send_nowait(struct fuse_conn *fc, struct fuse_req *req)
{
	req->in.h.len = sizeof(struct fuse_in_header) +
		len_args(req->in.numargs, (struct fuse_arg *)req->in.args);

	spin_lock(&fc->lock);
	if (fc->connected || fc->allow_disconnected) {
		if (!fc->connected) {
			printk(KERN_INFO "%s: Request on disconnected FC", __func__);
		}
		fuse_request_send_nowait_locked(fc, req);
		spin_unlock(&fc->lock);

		fuse_conn_wakeup(fc);
	} else {
		req->out.h.error = -ENOTCONN;
		request_end(fc, req);
	}
}

void fuse_request_send_background(struct fuse_conn *fc, struct fuse_req *req)
{
	req->isreply = 1;
	fuse_request_send_nowait(fc, req);
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

ssize_t fuse_copy_req_read(struct fuse_req *req, struct iov_iter *iter)
{
	struct request *breq = req->rq;
	size_t copied = 0;
	size_t len;

	len = sizeof(req->in.h);
	if (copy_to_iter(&req->in.h, len, iter) != len) {
		printk(KERN_ERR "%s: copy header error\n", __func__);
		return -EFAULT;
	}
	copied += len;

	len = req->in.args[0].size;
	if (copy_to_iter((void *)req->in.args[0].value, len, iter) != len) {
		printk(KERN_ERR "%s: copy arg error\n", __func__);
		return -EFAULT;
	}
	copied += len;

	if (unlikely(req->num_pages)) {
		int i;
		for (i = 0; i < req->num_pages; ++i) {
			len = req->page_descs[i].length;
			if (copy_page_to_iter(req->pages[i],
					      req->page_descs[i].offset,
					      len, iter) != len) {
				printk(KERN_ERR "%s: copy page arg %d of %d error\n",
				       __func__, i, breq->nr_phys_segments);
				return -EFAULT;
			}
			copied += len;
		}
	}

	return copied;
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
	ssize_t copied, copied_this_time;
	ssize_t remain = iter->count;
	bool no_reply = false;

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

	entry = fc->pending.next;
	first = fc->pending.next;
	last = &fc->pending;
	while (entry != &fc->pending) {
		req = list_entry(entry, struct fuse_req, list);
		if (req->in.h.len <= remain) {
			req->state = FUSE_REQ_SENT;
			last = entry;
			remain -= req->in.h.len;
			entry = entry->next;
		} else {
			break;
		}
	}

	err = -EINVAL;
	if (last == &fc->pending)
		goto err_unlock;

	list_cut_position(&tmp, &fc->pending, last);
	list_splice_tail(&tmp, &fc->processing);

	spin_unlock(&fc->lock);

	entry = first;
	copied = 0;
	err = 0;
	while (1) {
		req = list_entry(entry, struct fuse_req, list);
		copied_this_time = fuse_copy_req_read(req, iter);
		if (copied_this_time > 0) {
			copied += copied_this_time;
		} else {
			err = copied_this_time;
			goto err_reqs;
		}

		no_reply = no_reply || !req->isreply;
		if (entry == last)
			break;
		entry = entry->next;
	}

	if (unlikely(no_reply)) {
		entry = first;
		while (1) {
			req = list_entry(entry, struct fuse_req, list);
			next = entry->next;
			if (!req->isreply) {
				spin_lock(&fc->lock);
				request_end(fc, req);
			}
			if (entry == last)
				break;
			entry = next;
		}
	}

	return copied;

 err_unlock:
	spin_unlock(&fc->lock);
	return err;

 err_reqs:
	entry = first;
	while (1) {
		req = list_entry(entry, struct fuse_req, list);
		next = entry->next;
		req->out.h.error = -EIO;
		spin_lock(&fc->lock);
		request_end(fc, req);
		if (entry == last)
			break;
		entry = next;
	}
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
	size_t len = sizeof(add);

	if (copy_from_iter(&add, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}

	return pxd_add(conn, &add);
}

/* Look up request on processing list by unique ID */
static struct fuse_req *request_find(struct fuse_conn *fc, u64 unique)
{
	struct fuse_req *req;

	hlist_for_each_entry(req, &fc->hash[unique % FUSE_HASH_SIZE],
			     hash_entry)
		if (req->in.h.unique == unique)
			return req;

	return NULL;
}

#define IOV_BUF_SIZE 64

static int copy_in_read_data_iovec(struct iov_iter *iter,
	struct pxd_read_data_out *read_data, struct iovec *iov,
	struct iov_iter *data_iter)
{
	int iovcnt;
	size_t len;

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

static int fuse_notify_read_data(struct fuse_conn *conn, unsigned int size,
				struct iov_iter *iter)
{
	struct pxd_read_data_out read_data;
	size_t len = sizeof(read_data);
	struct fuse_req *req;
	struct iovec iov[IOV_BUF_SIZE];
#ifdef HAVE_BVEC_ITER
	struct bio_vec bvec;
#else
	struct bio_vec *bvec = NULL;
#endif

#ifdef USE_REQUEST_QUEUE
	struct req_iterator breq_iter;
#elif defined(HAVE_BVEC_ITER)
	struct bvec_iter bvec_iter;
#else
	int bvec_iter;
#endif
	struct iov_iter data_iter;
	size_t copied, skipped = 0;
	int ret;

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

	ret = copy_in_read_data_iovec(iter, &read_data, iov, &data_iter);
	if (ret)
		return ret;

	/* advance the iterator if data is unaligned */
	if (unlikely(req->misc.pxd_rdwr_in.offset & PXD_LBS_MASK))
		iov_iter_advance(&data_iter,
				 req->misc.pxd_rdwr_in.offset & PXD_LBS_MASK);

#ifdef USE_REQUEST_QUEUE
	rq_for_each_segment(bvec, req->rq, breq_iter) {
#else
	bio_for_each_segment(bvec, req->bio, bvec_iter) {
#endif
		copied = 0;
		len = BVEC(bvec).bv_len;
		if (skipped < read_data.offset) {
			if (read_data.offset - skipped >= len) {
				skipped += len;
				copied = len;
			} else {
				copied = read_data.offset - skipped;
				skipped = read_data.offset;
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
				ret = copy_in_read_data_iovec(iter, &read_data,
					iov, &data_iter);
				if (ret)
					return ret;
				len -= copied;
				copied = copy_page_to_iter(BVEC(bvec).bv_page,
					BVEC(bvec).bv_offset + copied + copy_this,
					len, &data_iter);
				if (copied != len) {
					printk(KERN_ERR "%s: copy failed new iovec\n",
						__func__);
					return -EFAULT;
				}
			}
		}
	}

	return 0;
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
	struct pxd_update_size_out update_size;
	size_t len = sizeof(update_size);

	if (copy_from_iter(&update_size, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}
	return pxd_update_size(conn, &update_size);
}

static int fuse_notify_update_path(struct fuse_conn *conn, unsigned int size,
		struct iov_iter *iter)
{
	struct pxd_update_path_out update_path;
	size_t len = sizeof(update_path);

	if (copy_from_iter(&update_path, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}
	return pxd_update_path(conn, &update_path);
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
	case PXD_UPDATE_PATH:
		return fuse_notify_update_path(fc, size, iter);
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
static ssize_t fuse_dev_do_write(struct fuse_conn *fc, struct iov_iter *iter)
{
	int err;
	struct fuse_req *req;
	struct fuse_out_header oh;
	size_t copied = 0;
	size_t len;
	size_t nbytes = iter->count;

	if (iter->count < sizeof(struct fuse_out_header))
		return -EINVAL;

	len = sizeof(oh);
	if (copy_from_iter(&oh, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy header\n", __func__);
		return -EFAULT;
	}
	copied += len;

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

	spin_lock(&fc->lock);
	err = -ENOENT;
	if (!fc->connected)
		goto err_unlock;

	req = request_find(fc, oh.unique);
	if (!req)
		goto err_unlock;

	req->state = FUSE_REQ_WRITING;
	list_del_init(&req->list);
	spin_unlock(&fc->lock);

	req->out.h = oh;

	if (req->bio_pages && req->out.numargs && iter->count > 0) {
#ifdef HAVE_BVEC_ITER
		struct bio_vec bvec;
#else
		struct bio_vec *bvec = NULL;
#endif
#ifdef USE_REQUEST_QUEUE
		struct request *breq = req->rq;
		struct req_iterator breq_iter;
		if (breq->nr_phys_segments && req->in.h.opcode == PXD_READ) {
			int i = 0;
			rq_for_each_segment(bvec, breq, breq_iter) {
				len = BVEC(bvec).bv_len;
				if (copy_page_from_iter(BVEC(bvec).bv_page,
							BVEC(bvec).bv_offset,
							len, iter) != len) {
					printk(KERN_ERR "%s: copy page %d of %d error\n",
					       __func__, i, breq->nr_phys_segments);
					return -EFAULT;
				}
				copied += len;
			}
		}
#else
#ifdef HAVE_BVEC_ITER
		struct bvec_iter bvec_iter;
#else
		int bvec_iter;
#endif
		int i = 0;
		int nsegs = bio_segments(req->bio);
		if (req->in.h.opcode == PXD_READ) {
			bio_for_each_segment(bvec, req->bio, bvec_iter) {
				len = BVEC(bvec).bv_len;
				if (copy_page_from_iter(BVEC(bvec).bv_page,
							BVEC(bvec).bv_offset,
							len, iter) != len) {
					printk(KERN_ERR "%s: copy page %d of %d error\n",
							__func__, i, nsegs);
					return -EFAULT;
				}
				i++;
				copied += len;
			}
		}
#endif
	}
	err = 0;

	spin_lock(&fc->lock);
	if (err)
		req->out.h.error = -EIO;
	request_end(fc, req);

	return err ? err : nbytes ;

 err_unlock:
	spin_unlock(&fc->lock);
	return err;
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
		request_end(fc, req);
		spin_lock(&fc->lock);
	}
}

static void end_queued_requests(struct fuse_conn *fc)
__releases(fc->lock)
__acquires(fc->lock)
{
	fc->max_background = UINT_MAX;
	end_requests(fc, &fc->pending);
	end_requests(fc, &fc->processing);
}

static void end_polls(struct fuse_conn *fc)
{
	struct rb_node *p;

	p = rb_first(&fc->polled_files);

	while (p) {
		struct fuse_file *ff;
		ff = rb_entry(p, struct fuse_file, polled_node);
		wake_up_interruptible_all(&ff->poll_wait);

		p = rb_next(p);
	}
}

int fuse_conn_init(struct fuse_conn *fc)
{
	int i;

	memset(fc, 0, sizeof(*fc));
	spin_lock_init(&fc->lock);
	init_rwsem(&fc->killsb);
	atomic_set(&fc->count, 1);
	init_waitqueue_head(&fc->waitq);
	INIT_LIST_HEAD(&fc->pending);
	INIT_LIST_HEAD(&fc->processing);
	INIT_LIST_HEAD(&fc->entry);
	fc->hash = kmalloc(FUSE_HASH_SIZE * sizeof(*fc->hash), GFP_KERNEL);
	if (!fc->hash)
		return -ENOMEM;
	for (i = 0; i < FUSE_HASH_SIZE; ++i)
		INIT_HLIST_HEAD(&fc->hash[i]);
	fc->max_background = FUSE_DEFAULT_MAX_BACKGROUND;
	fc->congestion_threshold = FUSE_DEFAULT_CONGESTION_THRESHOLD;
	fc->khctr = 0;
	fc->polled_files = RB_ROOT;
	fc->reqctr = 0;
	fc->initialized = 0;
	fc->attr_version = 1;
	get_random_bytes(&fc->scramble_key, sizeof(fc->scramble_key));
	return 0;
}

void fuse_conn_put(struct fuse_conn *fc)
{
	if (atomic_dec_and_test(&fc->count)) {
		if (fc->destroy_req)
			fuse_request_free(fc->destroy_req);
		if (fc->hash)
			kfree(fc->hash);
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
		fc->initialized = 1;
		end_queued_requests(fc);
		end_polls(fc);
		wake_up_all(&fc->waitq);
		kill_fasync(&fc->fasync, SIGIO, POLL_IN);
	}
	spin_unlock(&fc->lock);
}

int fuse_dev_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = fuse_get_conn(file);
	if (fc) {
		spin_lock(&fc->lock);
		fc->connected = 0;
		fc->initialized = 1;
		end_queued_requests(fc);
		end_polls(fc);
		spin_unlock(&fc->lock);
		fuse_conn_put(fc);
	}

	return 0;
}

void fuse_restart_requests(struct fuse_conn *fc)
{
	struct fuse_req *req;

	spin_lock(&fc->lock);
	list_for_each_entry(req, &fc->processing, list)
		req->state = FUSE_REQ_PENDING;
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
	fuse_req_cachep = kmem_cache_create("pxd_fuse_request",
					    sizeof(struct fuse_req),
					    0, 0, NULL);
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
