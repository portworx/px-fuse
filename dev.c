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
#include <linux/sort.h>
#include "pxd_compat.h"

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

static struct fuse_req *__fuse_get_req(struct fuse_conn *fc)
{
	struct fuse_req *req;
	int err;

	req = fuse_request_alloc();
	if (!req) {
		err = -ENOMEM;
		goto out;
	}

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
	u32 write, next_index;

	spin_lock(&fc->queue.w.lock);
	write = fc->queue.w.write;
	next_index = (write + 1) & (FUSE_REQUEST_QUEUE_SIZE - 1);
	if (fc->queue.w.read == next_index) {
		fc->queue.w.read = fc->queue.r.read;
		BUG_ON(next_index == fc->queue.w.read);
	}

	fc->queue.w.requests[write].in = req->in;
	fc->queue.w.requests[write].rdwr = req->pxd_rdwr_in;
	req->sequence = fc->queue.w.sequence++;
	fc->queue.w.write = next_index;
	smp_store_release(&fc->queue.r.write, next_index);
	spin_unlock(&fc->queue.w.lock);
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
 */
static void request_end(struct fuse_conn *fc, struct fuse_req *req,
	int status)
{
	u64 uid = req->in.unique;
	if (req->end)
		req->end(fc, req, status);
	fuse_put_unique(fc, uid);
#ifndef __PX_BLKMQ__
	fuse_request_free(req);
#endif
}

void fuse_request_send_nowait(struct fuse_conn *fc, struct fuse_req *req)
{
	req->in.unique = fuse_get_unique(fc);
	fc->request_map[req->in.unique & (FUSE_MAX_REQUEST_IDS - 1)] = req;

	/*
	 * Ensures checking the value of allow_disconnected and adding request to
	 * queue is done atomically.
	 */
	rcu_read_lock();

	if (fc->connected || fc->allow_disconnected) {
		queue_request(fc, req);
		rcu_read_unlock();

		fuse_conn_wakeup(fc);
	} else {
		rcu_read_unlock();
		request_end(fc, req, -ENOTCONN);
	}
}

static int request_pending(struct fuse_conn *fc)
{
	return fc->queue.r.read != fc->queue.r.write;
}

/* Wait until a request is available on the pending list */
static void request_wait(struct fuse_conn *fc)
{
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue_exclusive(&fc->waitq, &wait);
	while (!request_pending(fc)) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (signal_pending(current))
			break;

		schedule();
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&fc->waitq, &wait);
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
static void __fuse_convert_zero_writes_slowpath(struct fuse_req *req)
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
	req->in.opcode = PXD_DISCARD;
}

static void __fuse_convert_zero_writes_fastpath(struct fuse_req *req)
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
	req->in.opcode = PXD_DISCARD;
}

void fuse_convert_zero_writes(struct fuse_req *req)
{
	if (req->fastpath) {
		__fuse_convert_zero_writes_fastpath(req);
	} else {
		__fuse_convert_zero_writes_slowpath(req);
	}
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
	ssize_t copied = 0, copied_this_time;
	ssize_t remain = iter->count;
	u32 read, write;

	if (!request_pending(fc)) {
		if ((file->f_flags & O_NONBLOCK))
			return -EAGAIN;
		request_wait(fc);
		if (!request_pending(fc))
			return -ERESTARTSYS;
	}

retry:
	read = fc->queue.r.read;
	write = smp_load_acquire(&fc->queue.r.write);

	while (read != write && remain >= sizeof(struct rdwr_in)) {
		/* copy as many contiguous elements as possible */
		copied_this_time = min(FUSE_REQUEST_QUEUE_SIZE - read,
			min(write - read, (u32)(remain / sizeof(struct rdwr_in)))) *
				   sizeof(struct rdwr_in);
		if (copy_to_iter(&fc->queue.r.requests[read], copied_this_time, iter)
		    != copied_this_time) {
			printk(KERN_ERR "%s: copy error\n", __func__);
			return -EFAULT;
		}
		read = (read + copied_this_time / sizeof(struct rdwr_in)) &
		       (FUSE_REQUEST_QUEUE_SIZE - 1);
		copied += copied_this_time;
		remain -= copied_this_time;
	}

	fc->queue.r.read = read;

	/* Check if more requests could be picked up */
	if (remain && request_pending(fc))
		goto retry;

	return copied;
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
	return pxd_add(conn, &add);
}


/* Look up request on processing list by unique ID */
static struct fuse_req *request_find(struct fuse_conn *fc, u64 unique)
{
	u32 index = unique & (FUSE_MAX_REQUEST_IDS - 1);
	struct fuse_req *req = fc->request_map[index];
	if (req == NULL) {
		printk(KERN_ERR "no request unique %llx", unique);
		return req;
	}
	if (req->in.unique != unique) {
		printk(KERN_ERR "id mismatch got %llx need %llx", req->in.unique, unique);
		return NULL;
	}
	return req;
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

static int __fuse_notify_read_data_slowpath(struct fuse_conn *conn,
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

	/* advance the iterator if data is unaligned */
	if (unlikely(req->pxd_rdwr_in.offset & PXD_LBS_MASK))
		iov_iter_advance(&data_iter,
				 req->pxd_rdwr_in.offset & PXD_LBS_MASK);

	rq_for_each_segment(bvec, req->rq, breq_iter) {
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

static int __fuse_notify_read_data_fastpath(struct fuse_conn *conn,
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

	if (req->in.opcode != PXD_WRITE &&
	    req->in.opcode != PXD_WRITE_SAME) {
		printk(KERN_ERR "%s: request is not a write\n", __func__);
		return -EINVAL;
	}

	if (req->fastpath) {
		return __fuse_notify_read_data_fastpath(conn, req, &read_data, iter);
	}

	return __fuse_notify_read_data_slowpath(conn, req, &read_data, iter);
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
		struct iov_iter *iter) {
	struct pxd_update_path_out update_path;
	size_t len = sizeof(update_path);

	if (copy_from_iter(&update_path, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}

	return pxd_update_path(conn, &update_path);
}

static int fuse_notify_set_fastpath(struct fuse_conn *conn, unsigned int size,
		struct iov_iter *iter) {
	struct pxd_fastpath_out fp;
	size_t len = sizeof(fp);

	if (copy_from_iter(&fp, len, iter) != len) {
		printk(KERN_ERR "%s: can't copy arg\n", __func__);
		return -EFAULT;
	}

	return pxd_set_fastpath(conn, &fp);
}

static int fuse_notify_get_features(struct fuse_conn *conn, unsigned int size,
		struct iov_iter *iter) {
	int features = 0;

#ifdef __PX_FASTPATH__
	features |= PXD_FEATURE_FASTPATH;
#endif

	return features;
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
	case PXD_UPDATE_PATH:
		return fuse_notify_update_path(fc, size, iter);
	case PXD_SET_FASTPATH:
		return fuse_notify_set_fastpath(fc, size, iter);
	case PXD_GET_FEATURES:
		return fuse_notify_get_features(fc, size, iter);
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
static int __fuse_dev_do_write_slowpath(struct fuse_conn *fc,
		struct fuse_req *req, struct iov_iter *iter)
{
	if (req->in.opcode == PXD_READ && iter->count > 0) {
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
	return 0;
}

static int __fuse_dev_do_write_fastpath(struct fuse_conn *fc,
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

	if (req->in.opcode == PXD_READ && iter->count > 0) {
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
	return 0;
}

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

	req = request_find(fc, oh.unique);
	if (!req) {
		printk(KERN_ERR "%s: request %lld not found\n", __func__, oh.unique);
		return -ENOENT;
	}

	if (req->fastpath) {
		err = __fuse_dev_do_write_fastpath(fc, req, iter);
	} else {
		err = __fuse_dev_do_write_slowpath(fc, req, iter);
	}

	if (err)
		return err;

	request_end(fc, req, oh.error);

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

	if (request_pending(fc))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

void fuse_end_queued_requests(struct fuse_conn *fc)
__releases(fc->lock)
__acquires(fc->lock)
{
	int i;
	for (i = 0; i < FUSE_REQUEST_QUEUE_SIZE; ++i) {
		struct fuse_req *req = fc->request_map[i];
		if (req != NULL) {
			request_end(fc, req, -ECONNABORTED);
		}
	}
}

static void fuse_conn_free_allocs(struct fuse_conn *fc)
{
	if (fc->per_cpu_ids)
		free_percpu(fc->per_cpu_ids);
	if (fc->free_ids)
		kfree(fc->free_ids);
	if (fc->request_map)
		kfree(fc->request_map);
	if (fc->queue.w.requests)
		vfree(fc->queue.w.requests);
}

static int fuse_req_queue_init(struct fuse_req_queue *queue)
{
	size_t alloc_size = FUSE_REQUEST_QUEUE_SIZE * sizeof(queue->w.requests[0]);
	queue->w.requests = vmalloc(alloc_size);
	if (queue->w.requests == NULL)
		return -ENOMEM;
	memset(queue->w.requests, 0, alloc_size);

	queue->w.sequence = 1;
	queue->w.read = 0;
	queue->w.write = 0;
	spin_lock_init(&queue->w.lock);

	queue->r.requests = queue->w.requests;
	queue->r.write = 0;
	queue->r.read = 0;

	return 0;
}

int fuse_conn_init(struct fuse_conn *fc)
{
	int i, rc;
	int cpu;

	memset(fc, 0, sizeof(*fc));
	spin_lock_init(&fc->lock);
	atomic_set(&fc->count, 1);
	init_waitqueue_head(&fc->waitq);
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

	/* start with nothing allocated to cpus */
	for_each_possible_cpu(cpu) {
		struct fuse_per_cpu_ids *my_ids = per_cpu_ptr(fc->per_cpu_ids, cpu);
		memset(my_ids, 0, sizeof(*my_ids));
	}

	fc->reqctr = 0;

	rc = fuse_req_queue_init(&fc->queue);
	if (rc != 0)
		goto err_out;

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

int fuse_dev_release(struct inode *inode, struct file *file)
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

static int compare_reqs(const void *lhs, const void *rhs)
{
	struct fuse_req *lhs_req = *(struct fuse_req**)lhs;
	struct fuse_req *rhs_req = *(struct fuse_req**)rhs;



	if (lhs_req->sequence < rhs_req->sequence)
		return -1;
	if (lhs_req->sequence > rhs_req->sequence)
		return 1;
	return 0;
}

/* Request map contains all pending requests. Add them back to the queue sorted by
 * original request order. This function is called when the reader is inactive
 * and reader part can be safely modified.
 */
int fuse_restart_requests(struct fuse_conn *fc)
{
	int i;
	struct fuse_req **resend_reqs;
	u32 read = fc->queue.r.read;	/* ok to access read part since user space is
 					* inactive */
	u32 write;
	u64 sequence;
	int resend_count = 0;

	/*
	 * Receive function may be adding new requests while scan is in progress.
	 * Find the sequence of the first request unread by user space. If there are no
	 * pending requests, use the next request sequence.
	 */
	spin_lock(&fc->queue.w.lock);
	sequence = fc->queue.w.sequence;
	write = fc->queue.w.write;
	if (read != write) {
		int index = fc->queue.w.requests[read].in.unique &
			(FUSE_MAX_REQUEST_IDS - 1);
		sequence = fc->request_map[index]->sequence;
	}
	spin_unlock(&fc->queue.w.lock);

	printk(KERN_INFO "read %d write %d sequence %lld", read, write, sequence);

	resend_reqs = vmalloc(sizeof(struct fuse_req *) * FUSE_REQUEST_QUEUE_SIZE);
	if (resend_reqs == NULL)
		return -ENOMEM;

	/* Add all pending requests with lower sequence to resend list */
	for (i = 0; i < FUSE_REQUEST_QUEUE_SIZE; ++i) {
		struct fuse_req *req = fc->request_map[i];
		if (req == NULL)
			continue;
		if (req->sequence < sequence)
			resend_reqs[resend_count++] = req;
	}

	sort(resend_reqs, resend_count, sizeof(struct fuse_req*), &compare_reqs, NULL);

	/* Put requests back into the queue*/
	for (i = resend_count; i != 0; --i) {
		read = (read - 1) & (FUSE_REQUEST_QUEUE_SIZE - 1);
		fc->queue.w.requests[read].in = resend_reqs[i - 1]->in;
		fc->queue.w.requests[read].rdwr = resend_reqs[i - 1]->pxd_rdwr_in;
	}

	spin_lock(&fc->queue.w.lock);
	fc->queue.w.read = read;
	/* update the reader part */
	fc->queue.r.read = read;
	fc->queue.r.write = fc->queue.w.write;
	spin_unlock(&fc->queue.w.lock);

	spin_lock(&fc->lock);
	fuse_conn_wakeup(fc);
	spin_unlock(&fc->lock);

	vfree(resend_reqs);

	return 0;
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
