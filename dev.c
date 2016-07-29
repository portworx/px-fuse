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
	return __fuse_request_alloc(npages, GFP_NOIO);
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

static void block_sigs(sigset_t *oldset)
{
	sigset_t mask;

	siginitsetinv(&mask, sigmask(SIGKILL));
	sigprocmask(SIG_BLOCK, &mask, oldset);
}

static void restore_sigs(sigset_t *oldset)
{
	sigprocmask(SIG_SETMASK, oldset, NULL);
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

static bool fuse_block_alloc(struct fuse_conn *fc, bool for_background)
{
	return !fc->initialized || (for_background && fc->blocked);
}

static struct fuse_req *__fuse_get_req(struct fuse_conn *fc, unsigned npages,
				       bool for_background)
{
	struct fuse_req *req;
	int err;

	if (fuse_block_alloc(fc, for_background)) {
		sigset_t oldset;
		int intr;

		block_sigs(&oldset);
		intr = wait_event_interruptible_exclusive(fc->blocked_waitq,
				!fuse_block_alloc(fc, for_background));
		restore_sigs(&oldset);
		err = -EINTR;
		if (intr)
			goto out;
	}

	err = -ENOTCONN;
	if (!fc->connected && !fc->allow_disconnected)
		goto out;

	req = fuse_request_alloc(npages);
	err = -ENOMEM;
	if (!req) {
		if (for_background)
			wake_up(&fc->blocked_waitq);
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
	if (atomic_dec_and_test(&req->count)) {
		if (unlikely(req->background)) {
			/*
			 * We get here in the unlikely case that a background
			 * request was allocated but not sent
			 */
			spin_lock(&fc->lock);
			if (!fc->blocked)
				wake_up(&fc->blocked_waitq);
			spin_unlock(&fc->lock);
		}

		fuse_request_free(req);
	}
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
	req->in.h.len = sizeof(struct fuse_in_header) +
		len_args(req->in.numargs, (struct fuse_arg *) req->in.args);
	list_add_tail(&req->list, &fc->pending);
	if (hlist_unhashed(&req->hash_entry))
		hlist_add_head(&req->hash_entry,
			       &fc->hash[req->in.h.unique % FUSE_HASH_SIZE]);
	req->state = FUSE_REQ_PENDING;
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
	wake_up(&fc->waitq);
	kill_fasync(&fc->fasync, SIGIO, POLL_IN);
	spin_unlock(&fc->lock);
}

static void flush_bg_queue(struct fuse_conn *fc)
{
	while (fc->active_background < fc->max_background &&
	       !list_empty(&fc->bg_queue)) {
		struct fuse_req *req;

		req = list_entry(fc->bg_queue.next, struct fuse_req, list);
		list_del(&req->list);
		fc->active_background++;
		req->in.h.unique = fuse_get_unique(fc);
		queue_request(fc, req);
	}
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

		if (fc->num_background == fc->max_background)
			fc->blocked = 0;

		/* Wake up next waiter, if any */
		if (!fc->blocked && waitqueue_active(&fc->blocked_waitq))
			wake_up(&fc->blocked_waitq);

		if (fc->num_background == fc->congestion_threshold &&
		    fc->connected && fc->bdi_initialized) {
			clear_bdi_congested(&fc->bdi, BLK_RW_SYNC);
			clear_bdi_congested(&fc->bdi, BLK_RW_ASYNC);
		}
		fc->num_background--;
		fc->active_background--;
		flush_bg_queue(fc);
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
	if (fc->num_background == fc->max_background)
		fc->blocked = 1;
	if (fc->num_background == fc->congestion_threshold &&
	    fc->bdi_initialized) {
		set_bdi_congested(&fc->bdi, BLK_RW_SYNC);
		set_bdi_congested(&fc->bdi, BLK_RW_ASYNC);
	}
	list_add_tail(&req->list, &fc->bg_queue);
	flush_bg_queue(fc);
}

static void fuse_request_send_nowait(struct fuse_conn *fc, struct fuse_req *req)
{
	spin_lock(&fc->lock);
	if (fc->connected || fc->allow_disconnected) {
		if (!fc->connected) {
			printk(KERN_INFO "%s: Request on disconnected FC", __func__);
		}
		fuse_request_send_nowait_locked(fc, req);
		spin_unlock(&fc->lock);
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

struct fuse_copy_state {
	struct fuse_conn *fc;
	int write;
	struct fuse_req *req;
	const struct iovec *iov;
	struct pipe_buffer *pipebufs;
	struct pipe_buffer *currbuf;
	struct pipe_inode_info *pipe;
	unsigned long nr_segs;
	unsigned long seglen;
	unsigned long addr;
	struct page *pg;
	unsigned len;
	unsigned offset;
	unsigned move_pages:1;
};

static void fuse_copy_init(struct fuse_copy_state *cs, struct fuse_conn *fc,
			   int write,
			   const struct iovec *iov, unsigned long nr_segs)
{
	memset(cs, 0, sizeof(*cs));
	cs->fc = fc;
	cs->write = write;
	cs->iov = iov;
	cs->nr_segs = nr_segs;
}

/* Unmap and put previous page of userspace buffer */
static void fuse_copy_finish(struct fuse_copy_state *cs)
{
	if (cs->currbuf) {
		struct pipe_buffer *buf = cs->currbuf;

		if (cs->write)
			buf->len = PAGE_SIZE - cs->len;
		cs->currbuf = NULL;
	} else if (cs->pg) {
		if (cs->write) {
			flush_dcache_page(cs->pg);
			set_page_dirty_lock(cs->pg);
		}
		put_page(cs->pg);
	}
	cs->pg = NULL;
}

/*
 * Get another pagefull of userspace buffer, and map it to kernel
 * address space, and lock request
 */
static int fuse_copy_fill(struct fuse_copy_state *cs)
{
	struct page *page;
	int err;

	fuse_copy_finish(cs);
	if (cs->pipebufs) {
		struct pipe_buffer *buf = cs->pipebufs;

		if (!cs->write) {
			err = buf->ops->confirm(cs->pipe, buf);
			if (err)
				return err;

			BUG_ON(!cs->nr_segs);
			cs->currbuf = buf;
			cs->pg = buf->page;
			cs->offset = buf->offset;
			cs->len = buf->len;
			cs->pipebufs++;
			cs->nr_segs--;
		} else {
			if (cs->nr_segs == cs->pipe->buffers)
				return -EIO;

			page = alloc_page(GFP_HIGHUSER);
			if (!page)
				return -ENOMEM;

			buf->page = page;
			buf->offset = 0;
			buf->len = 0;

			cs->currbuf = buf;
			cs->pg = page;
			cs->offset = 0;
			cs->len = PAGE_SIZE;
			cs->pipebufs++;
			cs->nr_segs++;
		}
	} else {
		if (!cs->seglen) {
			BUG_ON(!cs->nr_segs);
			cs->seglen = cs->iov[0].iov_len;
			cs->addr = (unsigned long) cs->iov[0].iov_base;
			cs->iov++;
			cs->nr_segs--;
		}
		err = get_user_pages_fast(cs->addr, 1, cs->write, &page);
		if (err < 0)
			return err;
		BUG_ON(err != 1);
		cs->pg = page;
		cs->offset = cs->addr % PAGE_SIZE;
		cs->len = min(PAGE_SIZE - cs->offset, cs->seglen);
		cs->seglen -= cs->len;
		cs->addr += cs->len;
	}

	return 0;
}

/* Do as much copy to/from userspace buffer as we can */
static int fuse_copy_do(struct fuse_copy_state *cs, void **val, unsigned *size)
{
	unsigned ncpy = min(*size, cs->len);
	if (val) {
		void *pgaddr = kmap_atomic(cs->pg);
		void *buf = pgaddr + cs->offset;

		if (cs->write)
			memcpy(buf, *val, ncpy);
		else
			memcpy(*val, buf, ncpy);

		kunmap_atomic(pgaddr);
		*val += ncpy;
	}
	*size -= ncpy;
	cs->len -= ncpy;
	cs->offset += ncpy;
	return ncpy;
}

static int fuse_check_page(struct page *page)
{
	if (page_mapcount(page) ||
	    page->mapping != NULL ||
	    page_count(page) != 1 ||
	    (page->flags & PAGE_FLAGS_CHECK_AT_PREP &
	     ~(1 << PG_locked |
	       1 << PG_referenced |
	       1 << PG_uptodate |
	       1 << PG_lru |
	       1 << PG_active |
	       1 << PG_reclaim))) {
		printk(KERN_WARNING "fuse: trying to steal weird page\n");
		printk(KERN_WARNING "  page=%p index=%li flags=%08lx, count=%i, mapcount=%i, mapping=%p\n", page, page->index, page->flags, page_count(page), page_mapcount(page), page->mapping);
		return 1;
	}
	return 0;
}

static int fuse_try_move_page(struct fuse_copy_state *cs, struct page **pagep)
{
	int err;
	struct page *oldpage = *pagep;
	struct page *newpage;
	struct pipe_buffer *buf = cs->pipebufs;

	fuse_copy_finish(cs);

	err = buf->ops->confirm(cs->pipe, buf);
	if (err)
		return err;

	BUG_ON(!cs->nr_segs);
	cs->currbuf = buf;
	cs->len = buf->len;
	cs->pipebufs++;
	cs->nr_segs--;

	if (cs->len != PAGE_SIZE)
		goto out_fallback;

	if (buf->ops->steal(cs->pipe, buf) != 0)
		goto out_fallback;

	newpage = buf->page;

	if (WARN_ON(!PageUptodate(newpage)))
		return -EIO;

	ClearPageMappedToDisk(newpage);

	if (fuse_check_page(newpage) != 0)
		goto out_fallback_unlock;

	/*
	 * This is a new and locked page, it shouldn't be mapped or
	 * have any special flags on it
	 */
	if (WARN_ON(page_mapped(oldpage)))
		goto out_fallback_unlock;
	if (WARN_ON(page_has_private(oldpage)))
		goto out_fallback_unlock;
	if (WARN_ON(PageDirty(oldpage) || PageWriteback(oldpage)))
		goto out_fallback_unlock;
	if (WARN_ON(PageMlocked(oldpage)))
		goto out_fallback_unlock;

	err = replace_page_cache_page(oldpage, newpage, GFP_KERNEL);
	if (err) {
		unlock_page(newpage);
		return err;
	}

	PAGE_CACHE_GET(newpage);

	if (!(buf->flags & PIPE_BUF_FLAG_LRU))
		lru_cache_add_file(newpage);

	err = 0;

	spin_lock(&cs->fc->lock);
	*pagep = newpage;
	spin_unlock(&cs->fc->lock);

	if (err) {
		unlock_page(newpage);
		PAGE_CACHE_RELEASE(newpage);
		return err;
	}

	unlock_page(oldpage);
	PAGE_CACHE_RELEASE(oldpage);
	cs->len = 0;

	return 0;

out_fallback_unlock:
	unlock_page(newpage);
out_fallback:
	cs->pg = buf->page;
	cs->offset = buf->offset;

	return 1;
}

static int fuse_ref_page(struct fuse_copy_state *cs, struct page *page,
			 unsigned offset, unsigned count)
{
	struct pipe_buffer *buf;

	if (cs->nr_segs == cs->pipe->buffers)
		return -EIO;

	fuse_copy_finish(cs);

	buf = cs->pipebufs;
	PAGE_CACHE_GET(page);
	buf->page = page;
	buf->offset = offset;
	buf->len = count;

	cs->pipebufs++;
	cs->nr_segs++;
	cs->len = 0;

	return 0;
}

/*
 * Copy a page in the request to/from the userspace buffer.  Must be
 * done atomically
 */
static int fuse_copy_page(struct fuse_copy_state *cs, struct page **pagep,
			  unsigned offset, unsigned count, int zeroing)
{
	int err;
	struct page *page = *pagep;

	if (page && zeroing && count < PAGE_SIZE)
		clear_highpage(page);

	while (count) {
		if (cs->write && cs->pipebufs && page) {
			return fuse_ref_page(cs, page, offset, count);
		} else if (!cs->len) {
			if (cs->move_pages && page &&
			    offset == 0 && count == PAGE_SIZE) {
				err = fuse_try_move_page(cs, pagep);
				if (err <= 0)
					return err;
			} else {
				err = fuse_copy_fill(cs);
				if (err)
					return err;
			}
		}
		if (page) {
			void *mapaddr = kmap_atomic(page);
			void *buf = mapaddr + offset;
			offset += fuse_copy_do(cs, &buf, &count);
			kunmap_atomic(mapaddr);
		} else
			offset += fuse_copy_do(cs, NULL, &count);
	}
	if (page && !cs->write)
		flush_dcache_page(page);
	return 0;
}

/* Copy pages in the request to/from userspace buffer */
static int fuse_copy_pages(struct fuse_copy_state *cs, unsigned nbytes,
			   int zeroing)
{
	unsigned i;
	struct fuse_req *req = cs->req;

	for (i = 0; i < req->num_pages && (nbytes || zeroing); i++) {
		int err;
		unsigned offset = req->page_descs[i].offset;
		unsigned count = min(nbytes, req->page_descs[i].length);

		err = fuse_copy_page(cs, &req->pages[i], offset, count,
				     zeroing);
		if (err)
			return err;

		nbytes -= count;
	}
	return 0;
}

/* Copy a single argument in the request to/from userspace buffer */
static int fuse_copy_one(struct fuse_copy_state *cs, void *val, unsigned size)
{
	while (size) {
		if (!cs->len) {
			int err = fuse_copy_fill(cs);
			if (err)
				return err;
		}
		fuse_copy_do(cs, &val, &size);
	}
	return 0;
}

/* Copy request arguments to/from userspace buffer */
static int fuse_copy_args(struct fuse_copy_state *cs, unsigned numargs,
			  unsigned argpages, struct fuse_arg *args,
			  int zeroing)
{
	int err = 0;
	unsigned i;

	for (i = 0; !err && i < numargs; i++)  {
		struct fuse_arg *arg = &args[i];
		if (i == numargs - 1 && argpages)
			err = fuse_copy_pages(cs, arg->size, zeroing);
		else
			err = fuse_copy_one(cs, arg->value, arg->size);
	}
	return err;
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
				struct fuse_copy_state *cs, size_t nbytes)
{
	int err;
	struct fuse_req *req;
	struct fuse_in *in;
	unsigned reqsize;

 restart:
	spin_lock(&fc->lock);
	err = -EAGAIN;
	if ((file->f_flags & O_NONBLOCK) && fc->connected &&
	    !request_pending(fc))
		goto err_unlock;

	request_wait(fc);
	err = -ENODEV;
	if (!fc->connected)
		goto err_unlock;
	err = -ERESTARTSYS;
	if (!request_pending(fc))
		goto err_unlock;

	req = list_entry(fc->pending.next, struct fuse_req, list);
	req->state = FUSE_REQ_READING;
	list_move(&req->list, &fc->io);

	in = &req->in;
	reqsize = in->h.len;
	/* If request is too large, reply with an error and restart the read */
	if (nbytes < reqsize) {
		printk("%s request is too large (%u), buffer size (%lu)",
			__func__, reqsize, nbytes);
		req->out.h.error = -EIO;
		/* SETXATTR is special, since it may contain too large data */
		if (in->h.opcode == FUSE_SETXATTR)
			req->out.h.error = -E2BIG;
		request_end(fc, req);
		goto restart;
	}
	spin_unlock(&fc->lock);
	cs->req = req;
	err = fuse_copy_one(cs, &in->h, sizeof(in->h));
	if (!err)
		err = fuse_copy_args(cs, in->numargs, in->argpages,
				     (struct fuse_arg *) in->args, 0);
	fuse_copy_finish(cs);
	spin_lock(&fc->lock);
	if (err) {
		req->out.h.error = -EIO;
		request_end(fc, req);
		return err;
	}
	if (!req->isreply)
		request_end(fc, req);
	else {
		req->state = FUSE_REQ_SENT;
		list_move_tail(&req->list, &fc->processing);
		spin_unlock(&fc->lock);
	}
	return reqsize;

 err_unlock:
	spin_unlock(&fc->lock);
	return err;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static ssize_t fuse_dev_read(struct kiocb *iocb, const struct iovec *iov,
			      unsigned long nr_segs, loff_t pos)
{
	struct fuse_copy_state cs;
	struct file *file = iocb->ki_filp;
	struct fuse_conn *fc = fuse_get_conn(file);
	if (!fc)
		return -EPERM;

	fuse_copy_init(&cs, fc, 1, iov, nr_segs);

	return fuse_dev_do_read(fc, file, &cs, iov_length(iov, nr_segs));
}
#else
static ssize_t fuse_dev_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct fuse_copy_state cs;
	struct file *file = iocb->ki_filp;
	struct fuse_conn *fc = fuse_get_conn(file);
	if (!fc)
		return -EPERM;

	fuse_copy_init(&cs, fc, 1, to->iov, to->nr_segs);

	return fuse_dev_do_read(fc, file, &cs, iov_length(to->iov, to->nr_segs));
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
	int ret;
	int page_nr = 0;
	int do_wakeup = 0;
	struct pipe_buffer *bufs;
	struct fuse_copy_state cs;
	struct fuse_conn *fc = fuse_get_conn(in);
	if (!fc)
		return -EPERM;

	bufs = kmalloc(pipe->buffers * sizeof(struct pipe_buffer), GFP_KERNEL);
	if (!bufs)
		return -ENOMEM;

	fuse_copy_init(&cs, fc, 1, NULL, 0);
	cs.pipebufs = bufs;
	cs.pipe = pipe;
	ret = fuse_dev_do_read(fc, in, &cs, len);
	if (ret < 0)
		goto out;

	ret = 0;
	pipe_lock(pipe);

	if (!pipe->readers) {
		send_sig(SIGPIPE, current, 0);
		if (!ret)
			ret = -EPIPE;
		goto out_unlock;
	}

	if (pipe->nrbufs + cs.nr_segs > pipe->buffers) {
		ret = -EIO;
		goto out_unlock;
	}

	while (page_nr < cs.nr_segs) {
		int newbuf = (pipe->curbuf + pipe->nrbufs) & (pipe->buffers - 1);
		struct pipe_buffer *buf = pipe->bufs + newbuf;

		buf->page = bufs[page_nr].page;
		buf->offset = bufs[page_nr].offset;
		buf->len = bufs[page_nr].len;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
		buf->ops = &fuse_dev_pipe_buf_ops;
#else
		/*
		 * Need to be careful about this.  Having buf->ops in module
		 * code can Oops if the buffer persists after module unload.
		 */
		buf->ops = &nosteal_pipe_buf_ops;
#endif

		pipe->nrbufs++;
		page_nr++;
		ret += buf->len;

		if (pipe->files)
			do_wakeup = 1;
	}

out_unlock:
	pipe_unlock(pipe);

	if (do_wakeup) {
		smp_mb();
		if (waitqueue_active(&pipe->wait))
			wake_up_interruptible(&pipe->wait);
		kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
	}

out:
	for (; page_nr < cs.nr_segs; page_nr++)
		PAGE_CACHE_RELEASE(bufs[page_nr].page);

	kfree(bufs);
	return ret;
}

static int fuse_notify_add(struct fuse_conn *conn, unsigned int size,
		struct fuse_copy_state *cs)
{
	int ret;
	struct pxd_add_out add;

	ret = fuse_copy_one(cs, &add, sizeof(add));
	if (ret < 0) {
		fuse_copy_finish(cs);
		return ret;
	}

	ret = pxd_add(conn, &add);

	return ret;
}

static int fuse_notify_remove(struct fuse_conn *conn, unsigned int size,
		struct fuse_copy_state *cs)
{
	int ret;
	struct pxd_remove_out remove;

	ret = fuse_copy_one(cs, &remove, sizeof(remove));
	if (ret < 0) {
		fuse_copy_finish(cs);
		return ret;
	}

	ret = pxd_remove(conn, &remove);

	return ret;
}

static int fuse_notify(struct fuse_conn *fc, enum fuse_notify_code code,
		       unsigned int size, struct fuse_copy_state *cs)
{
	switch ((int)code) {
	case PXD_ADD:
		return fuse_notify_add(fc, size, cs);
	case PXD_REMOVE:
		return fuse_notify_remove(fc, size, cs);
	default:
		fuse_copy_finish(cs);
		return -EINVAL;
	}
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

static int copy_out_args(struct fuse_copy_state *cs, struct fuse_out *out,
			 unsigned nbytes)
{
	unsigned reqsize = sizeof(struct fuse_out_header);

	if (out->h.error)
		return nbytes != reqsize ? -EINVAL : 0;

	reqsize += len_args(out->numargs, out->args);

	if (reqsize < nbytes || (reqsize > nbytes && !out->argvar))
		return -EINVAL;
	else if (reqsize > nbytes) {
		struct fuse_arg *lastarg = &out->args[out->numargs-1];
		unsigned diffsize = reqsize - nbytes;
		if (diffsize > lastarg->size)
			return -EINVAL;
		lastarg->size -= diffsize;
	}
	return fuse_copy_args(cs, out->numargs, out->argpages, out->args,
			      out->page_zeroing);
}

/*
 * Write a single reply to a request.  First the header is copied from
 * the write buffer.  The request is then searched on the processing
 * list by the unique ID found in the header.  If found, then remove
 * it from the list and copy the rest of the buffer to the request.
 * The request is finished by calling request_end()
 */
static ssize_t fuse_dev_do_write(struct fuse_conn *fc,
				 struct fuse_copy_state *cs, size_t nbytes)
{
	int err;
	struct fuse_req *req;
	struct fuse_out_header oh;

	if (nbytes < sizeof(struct fuse_out_header))
		return -EINVAL;

	err = fuse_copy_one(cs, &oh, sizeof(oh));

	if (err)
		goto err_finish;

	err = -EINVAL;

	if (oh.len != nbytes)
		goto err_finish;

	/*
	 * Zero oh.unique indicates unsolicited notification message
	 * and error contains notification code.
	 */
	if (!oh.unique) {
		err = fuse_notify(fc, oh.error, nbytes - sizeof(oh), cs);
		return err ? err : nbytes;
	}

	err = -EINVAL;
	if (oh.error <= -1000 || oh.error > 0)
		goto err_finish;

	spin_lock(&fc->lock);
	err = -ENOENT;
	if (!fc->connected)
		goto err_unlock;

	req = request_find(fc, oh.unique);
	if (!req)
		goto err_unlock;

	req->state = FUSE_REQ_WRITING;
	list_move(&req->list, &fc->io);
	req->out.h = oh;
	cs->req = req;
	if (!req->out.page_replace)
		cs->move_pages = 0;
	spin_unlock(&fc->lock);

	err = copy_out_args(cs, &req->out, nbytes);
	fuse_copy_finish(cs);

	spin_lock(&fc->lock);
	if (err)
		req->out.h.error = -EIO;
	request_end(fc, req);

	return err ? err : nbytes;

 err_unlock:
	spin_unlock(&fc->lock);
 err_finish:
	fuse_copy_finish(cs);
	return err;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static ssize_t fuse_dev_write(struct kiocb *iocb, const struct iovec *iov,
			      unsigned long nr_segs, loff_t pos)
{
	struct fuse_copy_state cs;
	struct fuse_conn *fc = fuse_get_conn(iocb->ki_filp);
	if (!fc)
		return -EPERM;

	fuse_copy_init(&cs, fc, 0, iov, nr_segs);

	return fuse_dev_do_write(fc, &cs, iov_length(iov, nr_segs));
}
#else
static ssize_t fuse_dev_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct fuse_copy_state cs;
	struct fuse_conn *fc = fuse_get_conn(iocb->ki_filp);
	if (!fc)
		return -EPERM;

	fuse_copy_init(&cs, fc, 0, from->iov, from->nr_segs);

	return fuse_dev_do_write(fc, &cs, iov_length(from->iov, from->nr_segs));
}
#endif

static ssize_t fuse_dev_splice_write(struct pipe_inode_info *pipe,
				     struct file *out, loff_t *ppos,
				     size_t len, unsigned int flags)
{
	unsigned nbuf;
	unsigned idx;
	struct pipe_buffer *bufs;
	struct fuse_copy_state cs;
	struct fuse_conn *fc;
	size_t rem;
	ssize_t ret;

	fc = fuse_get_conn(out);
	if (!fc)
		return -EPERM;

	bufs = kmalloc(pipe->buffers * sizeof(struct pipe_buffer), GFP_KERNEL);
	if (!bufs)
		return -ENOMEM;

	pipe_lock(pipe);
	nbuf = 0;
	rem = 0;
	for (idx = 0; idx < pipe->nrbufs && rem < len; idx++)
		rem += pipe->bufs[(pipe->curbuf + idx) & (pipe->buffers - 1)].len;

	ret = -EINVAL;
	if (rem < len) {
		pipe_unlock(pipe);
		goto out;
	}

	rem = len;
	while (rem) {
		struct pipe_buffer *ibuf;
		struct pipe_buffer *obuf;

		BUG_ON(nbuf >= pipe->buffers);
		BUG_ON(!pipe->nrbufs);
		ibuf = &pipe->bufs[pipe->curbuf];
		obuf = &bufs[nbuf];

		if (rem >= ibuf->len) {
			*obuf = *ibuf;
			ibuf->ops = NULL;
			pipe->curbuf = (pipe->curbuf + 1) & (pipe->buffers - 1);
			pipe->nrbufs--;
		} else {
			ibuf->ops->get(pipe, ibuf);
			*obuf = *ibuf;
			obuf->flags &= ~PIPE_BUF_FLAG_GIFT;
			obuf->len = rem;
			ibuf->offset += obuf->len;
			ibuf->len -= obuf->len;
		}
		nbuf++;
		rem -= obuf->len;
	}
	pipe_unlock(pipe);

	fuse_copy_init(&cs, fc, 0, NULL, nbuf);
	cs.pipebufs = bufs;
	cs.pipe = pipe;

	if (flags & SPLICE_F_MOVE)
		cs.move_pages = 1;

	ret = fuse_dev_do_write(fc, &cs, len);

	for (idx = 0; idx < nbuf; idx++) {
		struct pipe_buffer *buf = &bufs[idx];
		buf->ops->release(pipe, buf);
	}
out:
	kfree(bufs);
	return ret;
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

/*
 * Abort requests under I/O
 *
 * The requests are set to aborted and finished, and the request
 * waiter is woken up.  This will make request_wait_answer() wait
 * until the request is unlocked and then return.
 *
 * If the request is asynchronous, then the end function needs to be
 * called after waiting for the request to be unlocked (if it was
 * locked).
 */
static void end_io_requests(struct fuse_conn *fc)
__releases(fc->lock)
__acquires(fc->lock)
{
	while (!list_empty(&fc->io)) {
		struct fuse_req *req =
			list_entry(fc->io.next, struct fuse_req, list);
		void (*end) (struct fuse_conn *, struct fuse_req *) = req->end;

		req->out.h.error = -ECONNABORTED;
		req->state = FUSE_REQ_FINISHED;
		list_del_init(&req->list);
		if (end) {
			req->end = NULL;
			__fuse_get_request(req);
			spin_unlock(&fc->lock);
			end(fc, req);
			fuse_put_request(fc, req);
			spin_lock(&fc->lock);
		}
	}
}

static void end_queued_requests(struct fuse_conn *fc)
__releases(fc->lock)
__acquires(fc->lock)
{
	fc->max_background = UINT_MAX;
	flush_bg_queue(fc);
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
	init_waitqueue_head(&fc->blocked_waitq);
	INIT_LIST_HEAD(&fc->pending);
	INIT_LIST_HEAD(&fc->processing);
	INIT_LIST_HEAD(&fc->io);
	INIT_LIST_HEAD(&fc->bg_queue);
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
	fc->blocked = 0;
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
		fc->blocked = 0;
		fc->initialized = 1;
		end_io_requests(fc);
		end_queued_requests(fc);
		end_polls(fc);
		wake_up_all(&fc->waitq);
		wake_up_all(&fc->blocked_waitq);
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
		fc->blocked = 0;
		fc->initialized = 1;
		end_queued_requests(fc);
		end_polls(fc);
		wake_up_all(&fc->blocked_waitq);
		spin_unlock(&fc->lock);
		fuse_conn_put(fc);
	}

	return 0;
}

static void move_matching(struct fuse_conn *fc,
		struct list_head *from, struct list_head *to,
		int (*filter)(struct fuse_conn *fc, struct fuse_req *req,
				void *arg),
		void *arg)
{
	struct fuse_req *req, *tmp;

	list_for_each_entry_safe(req, tmp, from, list) {
		if (filter(fc, req, arg)) {
			list_del(&req->list);
			list_add_tail(&req->list, to);
		}
	}
}

void fuse_end_matching_requests(struct fuse_conn *fc,
		int (*filter)(struct fuse_conn *fc, struct fuse_req *req,
				void *arg),
		void *arg)
{
	struct list_head del_list;

	INIT_LIST_HEAD(&del_list);

	spin_lock(&fc->lock);
	move_matching(fc, &fc->bg_queue, &del_list, filter, arg);
	move_matching(fc, &fc->pending, &del_list, filter, arg);
	move_matching(fc, &fc->processing, &del_list, filter, arg);
	end_requests(fc, &del_list);
	spin_unlock(&fc->lock);
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
