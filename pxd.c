#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/sysfs.h>
#include <linux/crc32.h>
#include <linux/miscdevice.h>
#include <linux/atomic.h>
#include <linux/dma-mapping.h>

#include "fuse_i.h"
#include "pxd.h"

// Configuration parameters
// Summary of test results:
// Multiple threads are needed to saturate random reads
// Single threaded write path with sync writes offer better performance, or have
// negligible loss when compared to async writes. Sync writes are good for data
// integrity as well. If available exported sync interface, use it.
// So the above will be the default configuration.
//
// Also generally block request handling has two interfaces, one fetching
// directly each BIO, the other does collect requests in a queue and does
// batch push them through elevator merging... we are directly using the
// original block io interface, did not find much performance help using
// the request Queue interface... So USE_REQUEST_QUEUE shall remain disabled
// as default.
//

#define MAX_THREADS (32)
#define SYNCWRITES
#define WRITEMULTITHREAD  (false)
//#define DMTHINPOOL /* This configures HACK code path to identify backing volume for dmthin pool only */

#define CREATE_TRACE_POINTS
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE pxd_trace
#include <pxd_trace.h>
#undef CREATE_TRACE_POINTS

#include "pxd_compat.h"

/** enables time tracing */
//#define GD_TIME_LOG
#ifdef GD_TIME_LOG
#define KTIME_GET_TS(t) ktime_get_ts((t))
#else
#define KTIME_GET_TS(t)
#endif

#define pxd_printk(args...)
//#define pxd_printk(args...) printk(KERN_ERR args)

#ifndef SECTOR_SIZE
#define SECTOR_SIZE 512
#endif
#define SEGMENT_SIZE (1024 * 1024)

#define MAX_WRITESEGS_FOR_FLUSH ((16*SEGMENT_SIZE)/PXD_LBS)

#define PXD_TIMER_SECS_MIN 30
#define PXD_TIMER_SECS_MAX 600

#define TOSTRING_(x) #x
#define VERTOSTR(x) TOSTRING_(x)

extern const char *gitversion;
static dev_t pxd_major;
static DEFINE_IDA(pxd_minor_ida);

struct pxd_context {
	spinlock_t lock;
	struct list_head list;
	size_t num_devices;
	struct fuse_conn fc;
	struct file_operations fops;
	char name[256];
	int id;
	struct miscdevice miscdev;
	struct list_head pending_requests;
	struct timer_list timer;
	bool init_sent;
	uint64_t unique;
};

struct pxd_context *pxd_contexts;
uint32_t pxd_num_contexts = PXD_NUM_CONTEXTS;
uint32_t pxd_num_contexts_exported = PXD_NUM_CONTEXT_EXPORTED;
uint32_t pxd_timeout_secs = PXD_TIMER_SECS_MAX;

module_param(pxd_num_contexts_exported, uint, 0644);
module_param(pxd_num_contexts, uint, 0644);

struct pxd_device;
struct thread_context {
	struct pxd_device  *pxd_dev;
	struct task_struct *pxd_thread;
	wait_queue_head_t   pxd_event;
	spinlock_t  		lock;
//#define USE_REQUEST_QUEUE
#ifdef USE_REQUEST_QUEUE
	unsigned int     rq_count;
	struct list_head waiting_queue;
#else
	struct bio_list  bio_list;
#endif
};

struct pxd_device {
	uint64_t dev_id;
	int major;
	int minor;
	struct gendisk *disk;
	struct device dev;
	size_t size;
	spinlock_t dlock;
	spinlock_t qlock;
	struct list_head node;
	int open_count;
	bool removing;
	wait_queue_head_t   congestion_wait;

	// Extended information
	uint32_t pool_id;
	char     device_path[64];
	bool     block_device;
	struct file * file;
	struct thread_context tc[MAX_THREADS];
	atomic_t index;
	atomic_t connected;
	atomic_t bio_count;
	atomic_t write_counter;
	struct pxd_context *ctx;
};

// Forward decl
static int refreshFsPath(struct pxd_device *pxd_dev, bool);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
static void pxd_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t op, uint32_t flags, bool qfn,
			uint64_t reqctr);
#else
static void pxd_request(struct fuse_req *req, uint32_t size, uint64_t off,
	uint32_t minor, uint32_t flags, bool qfn, uint64_t reqctr);
#endif
static struct fuse_req *pxd_fuse_req(struct pxd_device *pxd_dev, int nr_pages);
static void pxd_request_complete(struct fuse_conn *fc, struct fuse_req *req);

#define	REQCTR(fc) (fc)->reqctr
/***********************/

#include <linux/splice.h>
#include <linux/fs.h>
#include <linux/falloc.h>
#include <linux/kthread.h>
#include <linux/bio.h>

#define SECTOR_SHIFT (9)

/* Common functions */
static int _pxd_write(struct file *file, struct bio_vec *bvec, loff_t *pos)
{
	ssize_t bw;
	void *kaddr = kmap(bvec->bv_page) + bvec->bv_offset;

	pxd_printk("_pxd_write entry buf %p offset %lld, length %d entered\n",
                kaddr, *pos, bvec->bv_len);

	if (bvec->bv_len != PXD_LBS) {
		printk(KERN_ERR"Unaligned block writes %d bytes\n", bvec->bv_len);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	bw = __kernel_write(pxd_dev->file, kaddr, bvec->bv_len, pos);
#else
	{
		mm_segment_t old_fs = get_fs();
		set_fs(get_ds());
		bw = vfs_write(file, kaddr, bvec->bv_len, pos);
		set_fs(old_fs);
	}
#endif
	kunmap(bvec->bv_page);

	if (likely(bw == bvec->bv_len)) {
		pxd_printk("myloop: Write successful at byte offset %llu, length %i.\n",
                        (unsigned long long)*pos, bvec->bv_len);
		return 0;
	}
	printk(KERN_ERR "myloop: Write error at byte offset %llu, length %i.\n",
                        (unsigned long long)*pos, bvec->bv_len);
	if (bw >= 0) bw = -EIO;
	return bw;
}

static
ssize_t _pxd_read(struct pxd_device *pxd_dev, struct bio_vec *bvec, loff_t *pos) {
	int result;
	void *kaddr = kmap(bvec->bv_page) + bvec->bv_offset;

        /* read from file at offset pos into the buffer */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	result = kernel_read(pxd_dev->file, kaddr, bvec->bv_len, pos);
#else
	mm_segment_t old_fs = get_fs();
	set_fs(get_ds());
	result = vfs_read(pxd_dev->file, kaddr, bvec->bv_len, pos);
	set_fs(old_fs);
#endif

	kunmap(bvec->bv_page);
	if (result < 0) printk(KERN_ERR "__vfs_read return %d\n", result);
	return result;
}

static void _pxd_setup(struct pxd_device *pxd_dev, bool enable) {
	if (!enable) {
		printk(KERN_ERR "_pxd_setup called to disable IO\n");
		atomic_set(&pxd_dev->connected, false /* false==>io-disabled */);
	} else {
		printk(KERN_ERR "_pxd_setup called to enable IO\n");
	}

#ifndef USE_REQUEST_QUEUE
	spin_lock_irq(&pxd_dev->dlock);
	if (enable) {
		refreshFsPath(pxd_dev, true);
	} else {
		if (pxd_dev->file) filp_close(pxd_dev->file, NULL);
		pxd_dev->file = NULL;
	}
	spin_unlock_irq(&pxd_dev->dlock);
#else
	spin_lock_irq(&pxd_dev->qlock);
	if (enable) {
		refreshFsPath(pxd_dev, true);
	} else {
		if (pxd_dev->file) filp_close(pxd_dev->file, NULL);
		pxd_dev->file = NULL;
	}
	spin_unlock_irq(&pxd_dev->qlock);
#endif

	if (enable) atomic_set(&pxd_dev->connected, true /* false==>io-disabled */);
}

static void pxdctx_set_connected(struct pxd_context *ctx, bool enable) {
	struct list_head *cur;
	spin_lock(&ctx->lock);
	list_for_each(cur, &ctx->list) {
		struct pxd_device *pxd_dev = container_of(cur, struct pxd_device, node);

		_pxd_setup(pxd_dev, enable);
	}
	spin_unlock(&ctx->lock);
}


#ifndef USE_REQUEST_QUEUE
static ssize_t
do_pxd_receive(struct pxd_device *pxd_dev, struct bio_vec *bvec, loff_t pos)
{
        return _pxd_read(pxd_dev, bvec, &pos);
}

static int
pxd_receive(struct pxd_device *pxd_dev, struct bio *bio, loff_t pos)
{
	ssize_t s;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif

	pxd_printk("pxd_receive[%llu] with bio=%p, pos=%llu\n",
				pxd_dev->dev_id, bio, pos);
	bio_for_each_segment(bvec, bio, i) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
		s = do_pxd_receive(pxd_dev, &bvec, pos);
		if (s < 0) return s;

		if (s != bvec.bv_len) {
			zero_fill_bio(bio);
			break;
		}
		pos += bvec.bv_len;
#else
		s = do_pxd_receive(pxd_dev, bvec, pos);
		if (s < 0) return s;

		if (s != bvec->bv_len) {
			zero_fill_bio(bio);
			break;
		}
		pos += bvec->bv_len;
#endif
	}
	return 0;
}

static int do_pxd_send(struct pxd_device *pxd_dev, struct bio *bio, loff_t pos) {
	int ret = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif

	pxd_printk("do_pxd_send bio%p, off%lld bio_segments %d\n", bio, pos, bio_segments(bio));

	atomic_add(bio_segments(bio), &pxd_dev->write_counter);
	//bio_request_contiguous(bio);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	bio_for_each_segment(bvec, bio, i) {
		ret = _pxd_write(pxd_dev->file, &bvec, &pos);
		if (ret < 0) {
			pxd_printk("do_pxd_write pos %lld page %p, off %u for len %d FAILED %d\n",
				pos, bvec.bv_page, bvec.bv_offset, bvec.bv_len, ret);
			return ret;
		}

		cond_resched();
	}
#else
	bio_for_each_segment(bvec, bio, i) {
		ret = _pxd_write(pxd_dev->file, bvec, &pos);
		if (ret < 0) {
			pxd_printk("do_pxd_write pos %lld page %p, off %u for len %d FAILED %d\n",
				pos, bvec->bv_page, bvec->bv_offset, bvec->bv_len, ret);
			return ret;
		}

		cond_resched();
	}
#endif
	return 0;
}

static int _pxd_flush(struct pxd_device *pxd_dev) {
	int ret;
	struct file *file = pxd_dev->file;
	pxd_printk("vfs_fsync[%s] (REQ_FLUSH) call...\n", pxd_dev->device_path);
	ret = vfs_fsync(file, 0);
	pxd_printk("vfs_fsync[%s] (REQ_FLUSH) done...\n", pxd_dev->device_path);
	if (unlikely(ret && ret != -EINVAL)) {
		ret = -EIO;
	}

	atomic_set(&pxd_dev->write_counter, 0);
	return ret;
}

static int _pxd_discard(struct pxd_device *pxd_dev, struct bio *bio, loff_t pos) {
	struct file *file = pxd_dev->file;
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	int ret;

	pxd_printk("calling discard [%s] (REQ_DISCARD)...\n", pxd_dev->device_path);
	if ((!file->f_op->fallocate)) {
		return -EOPNOTSUPP;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	ret = file->f_op->fallocate(file, mode, pos, bio->bi_iter.bi_size);
#else
	ret = file->f_op->fallocate(file, mode, pos, bio->bi_size);
#endif
	pxd_printk("discard [%s] (REQ_DISCARD) done...\n", pxd_dev->device_path);
	if (unlikely(ret && ret != -EINVAL && ret != -EOPNOTSUPP))
		ret = -EIO;

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
static int do_bio_filebacked(struct thread_context *tc, struct bio *bio)
{
	struct pxd_device *pxd_dev = tc->pxd_dev;
	loff_t pos;
	unsigned int op = bio_op(bio);
	int ret;

	pxd_printk("do_bio_filebacked for new bio (pending %u)\n",
				tc->bio_count);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	pos = ((loff_t) bio->bi_iter.bi_sector << 9);
#else
	pos = ((loff_t) bio->bi_sector << 9);
#endif

	switch (op) {
	case REQ_OP_READ:
		return pxd_receive(pxd_dev, bio, pos);
	case REQ_OP_WRITE:

		if (bio->bi_opf & REQ_PREFLUSH) {
			ret = _pxd_flush(pxd_dev);
			if (ret < 0) return ret;
		}

		ret = do_pxd_send(pxd_dev, bio, pos);
		if (ret < 0) return ret;

		if (bio->bi_opf & REQ_FUA) {
			ret = _pxd_flush(pxd_dev);
			if (ret < 0) return ret;
		}

		return 0;

	case REQ_OP_FLUSH:
		return _pxd_flush(pxd_dev);
	case REQ_OP_DISCARD:
	case REQ_OP_WRITE_ZEROES:
		return _pxd_discard(pxd_dev, bio, pos);
	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
}

#else
static int do_bio_filebacked(struct thread_context *tc, struct bio *bio)
{
	struct pxd_device *pxd_dev = tc->pxd_dev;
	loff_t pos;
	int ret;
	bool shouldFlush = false;

	pxd_printk("do_bio_filebacked for new bio (pending %u)\n",
				tc->bio_count);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	pos = ((loff_t) bio->bi_iter.bi_sector << 9);
#else
	pos = ((loff_t) bio->bi_sector << 9);
#endif

	if (bio_rw(bio) == WRITE) {
		if (bio->bi_rw & REQ_FLUSH) {
			ret = _pxd_flush(pxd_dev);
			if (ret < 0) goto out;
		}

		/*
		 * We use punch hole to reclaim the free space used by the
		 * image a.k.a. discard. However we do not support discard if
		 * encryption is enabled, because it may give an attacker
		 * useful information.
		 */
		if (bio->bi_rw & REQ_DISCARD) {
			ret = _pxd_discard(pxd_dev, bio, pos);
			goto out;
		}
		ret = do_pxd_send(pxd_dev, bio, pos);

		shouldFlush = ((atomic_read(&pxd_dev->write_counter) > MAX_WRITESEGS_FOR_FLUSH));
		if (((bio->bi_rw & REQ_FUA) && !ret) || shouldFlush) {
			ret = _pxd_flush(pxd_dev);
		}
	} else {
		ret = pxd_receive(pxd_dev, bio, pos);
	}

out:
        return ret;
}
#endif

static inline void pxd_handle_bio(struct thread_context *tc, struct bio *bio, bool shouldClose)
{
	int ret;

	if (shouldClose) {
		printk(KERN_ERR"px is disconnected, failing IO.\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
		bio_io_error(bio);
#else
		bio_endio(bio, -ENXIO);
#endif
		return;
	}

	ret = do_bio_filebacked(tc, bio);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
	if (ret < 0) {
		bio_io_error(bio);
		return;
	}
	bio_endio(bio);
#else
	bio_endio(bio, ret);
#endif
}

static void pxd_add_bio(struct thread_context *tc, struct bio *bio) {
	atomic_inc(&tc->pxd_dev->bio_count);

	spin_lock_irq(&tc->lock);
	bio_list_add(&tc->bio_list, bio);
	spin_unlock_irq(&tc->lock);
}

static struct bio* pxd_get_bio(struct thread_context *tc, bool *shouldClose) {
	struct bio* bio;
	atomic_dec(&tc->pxd_dev->bio_count);

	*shouldClose = (atomic_read(&tc->pxd_dev->connected) == 0);
	spin_lock_irq(&tc->lock);
	bio=bio_list_pop(&tc->bio_list);
	spin_unlock_irq(&tc->lock);

	return bio;
}

static int pxd_io_thread(void *data) {
	struct thread_context *tc = data;
	struct bio *bio;
	bool shouldClose;
	while (!kthread_should_stop() || !bio_list_empty(&tc->bio_list)) {
		wait_event_interruptible(tc->pxd_event,
                             !bio_list_empty(&tc->bio_list) ||
                             kthread_should_stop());

		if (bio_list_empty(&tc->bio_list))
			continue;

		pxd_printk("pxd_io_thread new bio for device %llu, pending %u\n",
				tc->pxd_dev->dev_id, tc->bio_count);
		bio = pxd_get_bio(tc, &shouldClose);

		if (atomic_read(&tc->pxd_dev->bio_count) < tc->pxd_dev->disk->queue->nr_congestion_off) {
			//printk(KERN_ERR"congestion cleared\n");
			wake_up(&tc->pxd_dev->congestion_wait);
		}

		BUG_ON(!bio);
		pxd_handle_bio(tc, bio, shouldClose);
	}
	return 0;
}

static int initBIO(struct pxd_device *pxd_dev) {
	int i;

	// congestion init
	init_waitqueue_head(&pxd_dev->congestion_wait);
	atomic_set(&pxd_dev->bio_count,0);

	for (i=0; i<MAX_THREADS; i++) {
		struct thread_context *tc = &pxd_dev->tc[i];
		tc->pxd_dev = pxd_dev;
		spin_lock_init(&tc->lock);
		init_waitqueue_head(&tc->pxd_event);
		tc->pxd_thread = kthread_create(pxd_io_thread, tc, "pxd%d:%llu",
			i, pxd_dev->dev_id);
		if (IS_ERR(tc->pxd_thread)) {
			pxd_printk("Init kthread for device %llu failed %lu\n",
				pxd_dev->dev_id, PTR_ERR(tc->pxd_thread));
			return -EINVAL;
		}

		wake_up_process(tc->pxd_thread);
	}
	return 0;
}

static void cleanupBIO(struct pxd_device *pxd_dev) {
	int i;
	for (i=0; i<MAX_THREADS; i++) {
		struct thread_context *tc = &pxd_dev->tc[i];
		kthread_stop(tc->pxd_thread);
	}
}


#else /* USE_REQUEST_QUEUE */

static
int do_pxd_flush(struct pxd_device *pxd_dev, struct request *rq) {
	struct file *file = pxd_dev->file;
	int ret = 0;

	pxd_printk("do_pxd_flush %llu on file %p\n", pxd_dev->dev_id, file);

	ret = vfs_fsync(file, 0);
	if (unlikely(ret && ret != -EINVAL))
		ret = -EIO;

	pxd_printk("do_pxd_flush %llu skipped returns %d\n", pxd_dev->dev_id, ret);
	return ret;
}

static
int do_pxd_discard(struct pxd_device *pxd_dev, struct request *rq) {
	struct file *file = pxd_dev->file;
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	int ret;
	loff_t pos = blk_rq_pos(rq);

	pxd_printk("do_pxd_discard %llu pos %lld, bytes %u\n",
			pxd_dev->dev_id, pos, blk_rq_bytes(rq));
	if (!file->f_op->fallocate) {
		return -EOPNOTSUPP;
	}
	ret = file->f_op->fallocate(file, mode, pos, blk_rq_bytes(rq));
	if (unlikely(ret && ret != -EINVAL && ret != -EOPNOTSUPP)) {
		ret = -EIO;
	}
	return ret;
}

static void pxd_end_request(struct request *rq, int err)
{
	blk_end_request_all(rq, err);
}

static
int do_pxd_read(struct pxd_device *pxd_dev, struct request *rq) {
	struct req_iterator iter;
	ssize_t len = 0;
	loff_t pos = blk_rq_pos(rq) << SECTOR_SHIFT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	pxd_printk("do_pxd_read entry pos %lld length %d entered\n", pos, blk_rq_bytes(rq));

	rq_for_each_segment(bvec, rq, iter) {
		/*iov_iter_bvec(&i, READ, &bvec, 1, bvec.bv_len);
		len = vfs_iter_read(pxd->file, &i, &pos, 0);
		if (len < 0)
			return len;

		*/
		len = _pxd_read(pxd_dev, &bvec, &pos);

		flush_dcache_page(bvec.bv_page);
		if (len != bvec.bv_len) {
			struct bio *bio;

			__rq_for_each_bio(bio, rq)
				zero_fill_bio(bio);

			break;
		}

		cond_resched();
	}
#else
	struct bio_vec *bvec;
	pxd_printk("do_pxd_read entry pos %lld length %d entered\n", pos, blk_rq_bytes(rq));


	rq_for_each_segment(bvec, rq, iter) {
		/*iov_iter_bvec(&i, READ, &bvec, 1, bvec.bv_len);
		len = vfs_iter_read(pxd->file, &i, &pos, 0);
		if (len < 0)
			return len;

		*/
		len = _pxd_read(pxd_dev, bvec, &pos);

		flush_dcache_page(bvec->bv_page);
		if (len != bvec->bv_len) {
			struct bio *bio;

			__rq_for_each_bio(bio, rq)
				zero_fill_bio(bio);

			break;
		}

		cond_resched();
	}
#endif

	pxd_printk("do_pxd_read pos %lld for len %d PASSED\n", pos, blk_rq_bytes(rq));
	if (len < 0) return len;
	return 0;

}

static int do_pxd_write(struct pxd_device *pxd_dev, struct request *rq) {
	struct req_iterator iter;
	loff_t pos = blk_rq_pos(rq) << SECTOR_SHIFT;
	int ret = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;

	pxd_printk("do_pxd_write entry pos %lld length %d entered\n", pos, blk_rq_bytes(rq));
	rq_for_each_segment(bvec, rq, iter) {
		/*iov_iter_bvec(&i, READ, &bvec, 1, bvec.bv_len);
		len = vfs_iter_read(pxd->lo_backing_file, &i, &pos, 0);
		if (len < 0)
			return len;
		*/
		ret = _pxd_write(pxd_dev->file, &bvec, &pos);
		if (ret < 0) {
			pxd_printk("do_pxd_write pos %lld page %p, off %u for len %d FAILED %d\n",
				pos, bvec.bv_page, bvec.bv_offset, bvec.bv_len, ret);
			return ret;
		}

		cond_resched();
	}
#else
	struct bio_vec *bvec;

	pxd_printk("do_pxd_write entry pos %lld length %d entered\n", pos, blk_rq_bytes(rq));
	rq_for_each_segment(bvec, rq, iter) {
		/*iov_iter_bvec(&i, READ, &bvec, 1, bvec.bv_len);
		len = vfs_iter_read(pxd->lo_backing_file, &i, &pos, 0);
		if (len < 0)
			return len;
		*/
		ret = _pxd_write(pxd_dev->file, bvec, &pos);
		if (ret < 0) {
			pxd_printk("do_pxd_write pos %lld page %p, off %u for len %d FAILED %d\n",
				pos, bvec->bv_page, bvec->bv_offset, bvec->bv_len, ret);
			return ret;
		}

		cond_resched();
	}
#endif
	pxd_printk("do_pxd_write pos %lld for len %d PASSED\n", pos, blk_rq_bytes(rq));
	return 0;
}

static inline void pxd_handle_req(struct thread_context *tc, struct request *req, bool shouldClose)
{
        int ret = 0;
	if (shouldClose) {
		printk(KERN_ERR"px is disconnected, failing IO.\n");
		goto error_out;
	}

        if (req->cmd_type != REQ_TYPE_FS)
                goto error_out;

        if (req->cmd_flags & REQ_FLUSH) {
                /* do flush */
                pxd_printk("do flush... sector %lu, bytes %d\n", blk_rq_pos(req), blk_rq_bytes(req));
                ret = do_pxd_flush(tc->pxd_dev, req);
        } else if (rq_data_dir(req) == WRITE) {
                if ((req->cmd_flags & REQ_DISCARD)) {
                        /* handle discard */
                        pxd_printk("do discard... sector %lu, bytes %d\n", blk_rq_pos(req), blk_rq_bytes(req));
                        ret=do_pxd_discard(tc->pxd_dev,req);
                } else {
                        /* handle write */
                        pxd_printk("do write... sector %lu, bytes %d\n", blk_rq_pos(req), blk_rq_bytes(req));
                        ret=do_pxd_write(tc->pxd_dev,req);
                }
        } else {
                /* handle read */
                pxd_printk("do read... sector %lu, bytes %d\n", blk_rq_pos(req), blk_rq_bytes(req));
                ret=do_pxd_read(tc->pxd_dev, req);
        }

        pxd_end_request(req, ret);
        return;
error_out:
        pxd_end_request(req, -EIO);
}

static void pxd_add_rq(struct thread_context *tc, struct request *rq) {
	tc->rq_count++;
	list_add_tail(&rq->queuelist, &tc->waiting_queue);
}

static struct request* pxd_get_rq(struct thread_context *tc, bool *shouldClose) {
	struct request* req;
	tc->rq_count--;
	*shouldClose = (atomic_read(&tc->pxd_dev->connected) == 0);
	req = list_entry(tc->waiting_queue.next, struct request, queuelist);
	list_del_init(&req->queuelist);
	return req;
}

static int pxd_io_thread(void *data) {
	struct thread_context *tc = data;
	struct request *req;
	bool shouldClose;

	//set_user_nice(current, -20);
	while (!kthread_should_stop() || !list_empty(&tc->waiting_queue)) {
		wait_event_interruptible(tc->pxd_event,
								!list_empty(&tc->waiting_queue) ||
                                kthread_should_stop());

		if (list_empty(&tc->waiting_queue))
			continue;

		pxd_printk("pxd_io_thread new req for device %llu, pending %u\n",
			tc->pxd_dev->dev_id, tc->rq_count);

		spin_lock_irq(&tc->lock);
		req = pxd_get_rq(tc, &shouldClose);
		spin_unlock_irq(&tc->lock);

		BUG_ON(!req);
		pxd_handle_req(tc, req, shouldClose);
	}
	return 0;
}

static int initReqQ(struct pxd_device *pxd_dev) {
	int i;
	struct thread_context *tc;
	for (i=0; i<MAX_THREADS; i++) {
		tc = &pxd_dev->tc[i];
		tc->pxd_dev = pxd_dev;
		spin_lock_init(&tc->lock);
		init_waitqueue_head(&tc->pxd_event);
		INIT_LIST_HEAD(&tc->waiting_queue);
		tc->pxd_thread = kthread_create(pxd_io_thread, tc, "pxd%d:%llu",
			i, pxd_dev->dev_id);
		if (IS_ERR(tc->pxd_thread)) {
			pxd_printk("Init kthread for device %llu failed %lu\n",
				pxd_dev->dev_id, PTR_ERR(tc->pxd_thread));
			return -EINVAL;
		}

		wake_up_process(tc->pxd_thread);
	}
	return 0;
}

static void cleanupReqQ(struct pxd_device *pxd_dev) {
	int i;
	for (i=0; i<MAX_THREADS; i++) {
		struct thread_context *tc = &pxd_dev->tc[i];
		kthread_stop(tc->pxd_thread);
	}
}

#endif

static inline unsigned int get_op_flags(struct bio *bio)
{
	unsigned int op_flags;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)
	op_flags = 0; // Not present in older kernels
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
	op_flags = (bio->bi_opf & ((1 << BIO_OP_SHIFT) - 1));
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
	op_flags = bio_flags(bio);
#else
	op_flags = ((bio->bi_opf & ~REQ_OP_MASK) >> REQ_OP_BITS);
#endif
	return op_flags;
}

#ifndef USE_REQUEST_QUEUE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static blk_qc_t pxd_make_request_orig(struct request_queue *q, struct bio *bio) __deprecated
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
static void pxd_make_request_orig(struct request_queue *q, struct bio *bio) __deprecated
#define BLK_QC_RETVAL
#endif
{
        struct pxd_device *pxd_dev = q->queuedata;
        struct fuse_req *req;
        unsigned int flags;

        flags = bio->bi_flags;

        pxd_printk("%s: dev m %d g %lld %s at %ld len %d bytes %d pages "
                        "flags 0x%x op_flags 0x%x\n", __func__,
                        pxd_dev->minor, pxd_dev->dev_id,
                        bio_data_dir(bio) == WRITE ? "wr" : "rd",
                        BIO_SECTOR(bio) * SECTOR_SIZE, BIO_SIZE(bio),
                        bio->bi_vcnt, flags, get_op_flags(bio));

        req = pxd_fuse_req(pxd_dev, bio->bi_vcnt);
        if (IS_ERR(req)) {
                bio_io_error(bio);
                return BLK_QC_RETVAL;
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
        pxd_request(req, BIO_SIZE(bio), BIO_SECTOR(bio) * SECTOR_SIZE,
                pxd_dev->minor, bio_op(bio), bio->bi_opf, false, REQCTR(&pxd_dev->ctx->fc));
#else
        pxd_request(req, BIO_SIZE(bio), BIO_SECTOR(bio) * SECTOR_SIZE,
                    pxd_dev->minor, bio->bi_rw, false,
                    REQCTR(&pxd_dev->ctx->fc));
#endif

        req->misc.pxd_rdwr_in.chksum = 0;
        req->bio = bio;
        req->queue = q;

        fuse_request_send_background(&pxd_dev->ctx->fc, req);
        return BLK_QC_RETVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static blk_qc_t pxd_make_request(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
static void pxd_make_request(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL
#endif
{
	struct pxd_device *pxd_dev = q->queuedata;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	unsigned int rw = bio_op(bio);
#else
	unsigned int rw = bio_rw(bio);
#endif
	int thread;
	struct thread_context *tc;

	/* single threaded write performance is better */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	if (!WRITEMULTITHREAD && op_is_write(rw)) {
#else
	if (!WRITEMULTITHREAD && bio_rw(bio) == WRITE) {
#endif
		thread = 0;
	} else {
		thread = atomic_inc_return(&pxd_dev->index) % MAX_THREADS;
	}
	tc = &pxd_dev->tc[thread];

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	if (!pxd_dev) {
#else
	if (rw == READA) rw = READ;
	if (!pxd_dev || (rw!=READ && rw != WRITE)) {
#endif
		printk(KERN_ERR"pxd basic sanity fail, pxd_device %p (%llu), rw %#x\n",
				pxd_dev, (pxd_dev? pxd_dev->dev_id: (uint64_t)0), rw);
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	if (!atomic_read(&pxd_dev->connected)) {
		printk(KERN_ERR"px is disconnected, failing IO.\n");
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	if (!pxd_dev->file) {
		if (refreshFsPath(pxd_dev, false)) {
			printk(KERN_ERR"pxd (%llu) does not have backing file failing hard\n", pxd_dev->dev_id);
			//bio_io_error(bio);
			pxd_make_request_orig(q, bio);
			return BLK_QC_RETVAL;
		}
	}

	pxd_printk("pxd_make_request for device %llu queueing with thread %d\n", pxd_dev->dev_id, thread);

	{ /* add congestion handling */
		if (atomic_read(&pxd_dev->bio_count) >= q->nr_congestion_on) {
			//printk(KERN_ERR"Hit congestion... wait until clear\n");
			wait_event_interruptible(pxd_dev->congestion_wait,
					atomic_read(&pxd_dev->bio_count) < q->nr_congestion_off);
		}

	}

	pxd_add_bio(tc, bio);
	wake_up(&tc->pxd_event);
	pxd_printk("pxd_make_request for device %llu done\n", pxd_dev->dev_id);
	return BLK_QC_RETVAL;
}
#else

/***********************/
/***********************/
// called wth qlock released
static
void pxd_rq_fn_kernel(struct pxd_device *pxd_dev, struct request_queue *q, struct request *rq) {
	u64 sect_num, sect_cnt;
	int thread;
	struct thread_context *tc;

	/* single threaded write performance is better */
	if (!WRITEMULTITHREAD && rq_data_dir(req) == WRITE) {
		thread = 0;
	} else {
		thread = atomic_inc_return(&pxd_dev->index) % MAX_THREADS;
	}
	tc = &pxd_dev->tc[thread];


	sect_num = blk_rq_pos(rq);
	/* deal whole segments */
	sect_cnt = blk_rq_sectors(rq);

	pxd_printk("pxd_rq_fn_kernel device %llu, sector %llu, count %llu, cmd_type %d, dir %d\n",
			pxd_dev->dev_id, sect_num, sect_cnt, rq->cmd_type, rq_data_dir(rq));

	if (unlikely(rq->cmd_type != REQ_TYPE_FS)) {
		printk(KERN_ERR"%s: bad access: cmd_type %x not fs\n",
			rq->rq_disk->disk_name, rq->cmd_type);
		__blk_end_request_all(rq, -EIO);
		return;
	}

	spin_lock_irq(&tc->lock);
	pxd_add_rq(tc, rq);
	spin_unlock_irq(&tc->lock);

	wake_up(&tc->pxd_event);
}

// calls with qlock released
static
void pxd_rq_fn_process(struct pxd_device *pxd_dev, struct request_queue *q, struct request *rq) {
	struct fuse_req *req;

	pxd_printk("%s: dev m %d g %lld %s at %ld len %d bytes %d pages "
			"flags  %llx\n", __func__,
			pxd_dev->minor, pxd_dev->dev_id,
			rq_data_dir(rq) == WRITE ? "wr" : "rd",
			blk_rq_pos(rq) * SECTOR_SIZE, blk_rq_bytes(rq),
			rq->nr_phys_segments, rq->cmd_flags);

	req = pxd_fuse_req(pxd_dev, 0);
	if (IS_ERR(req)) {
		__blk_end_request(rq, -EIO, blk_rq_bytes(rq));
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
	pxd_request(req, blk_rq_bytes(rq), blk_rq_pos(rq) * SECTOR_SIZE,
			    pxd_dev->minor, req_op(rq), rq->cmd_flags, true,
			    REQCTR(&pxd_dev->ctx->fc));
#else
	pxd_request(req, blk_rq_bytes(rq), blk_rq_pos(rq) * SECTOR_SIZE,
			    pxd_dev->minor, rq->cmd_flags, true,
			    REQCTR(&pxd_dev->ctx->fc));
#endif

	req->num_pages = 0;
	req->misc.pxd_rdwr_in.chksum = 0;
	req->rq = rq;
	req->queue = q;
	fuse_request_send_background(&pxd_dev->ctx->fc, req);
}
#endif
/***********************/
/***********************/

#define BASEDIR "/var/.px"
#define BTRFSVOLFMT  "%s/%d/%llu/pxdev"
#define DMTHINVOLFMT "/dev/mapper/pxvg%d-%llu"
#define MAXPOOL (5)
/* 
 * NOTE
 * Below is a hack to find the backing file/device.. proper ioctl interface
 * extension and argument submission should happen from px-storage!!
 */
static int refreshFsPath(struct pxd_device *pxd_dev, bool force) {
	int pool;
	char newPath[64];
	struct file *f;

	if (pxd_dev->file) {
		if (!force) {
			printk(KERN_INFO"Success device %llu backing file %s\n",
					pxd_dev->dev_id, pxd_dev->device_path);
			return 0;
		}

		filp_close(pxd_dev->file, NULL);
		pxd_dev->file = NULL;
	}

	for (pool=0; pool<MAXPOOL; pool++) {
#ifdef DMTHINPOOL
		sprintf(newPath, DMTHINVOLFMT, pool, pxd_dev->dev_id);
#else
		sprintf(newPath, BTRFSVOLFMT, BASEDIR, pool, pxd_dev->dev_id);
#endif

		f = filp_open(newPath, O_LARGEFILE | O_RDWR, 0600);
		if (IS_ERR_OR_NULL(f)) {
			printk(KERN_ERR"Failed device %llu at path %s err %ld\n",
				pxd_dev->dev_id, newPath, PTR_ERR(f));
			continue;
		}

		printk(KERN_INFO"Success device %llu backing file %s\n",
					pxd_dev->dev_id, newPath);
		pxd_dev->block_device = false;
		pxd_dev->pool_id = (uint32_t) pool;
		strcpy(pxd_dev->device_path, newPath);
		pxd_dev->file = f;

		return 0;
	}

	printk(KERN_ERR"Failed for device %llu no backing file found\n", pxd_dev->dev_id);
	return -ENODEV;
}

static int initBackingFsPath(struct pxd_device *pxd_dev) {
	int err;

	atomic_set(&pxd_dev->index, 0);
	atomic_set(&pxd_dev->connected, 1);

#ifndef USE_REQUEST_QUEUE
	err = initBIO(pxd_dev);
	if (err < 0) {
		return err;
	}

#else
	err = initReqQ(pxd_dev);
	if (err < 0) {
		return err;
	}
#endif

	return refreshFsPath(pxd_dev, true);
}

static void cleanupBackingFsPath(struct pxd_device *pxd_dev) {
#ifndef USE_REQUEST_QUEUE
	cleanupBIO(pxd_dev);
#else
	cleanupReqQ(pxd_dev);
#endif

	if (pxd_dev->file) {
		filp_close(pxd_dev->file, NULL);
	}
	pxd_dev->file = NULL;
}


static int pxd_bus_add_dev(struct pxd_device *pxd_dev);

static int pxd_open(struct block_device *bdev, fmode_t mode)
{
	struct pxd_device *pxd_dev = bdev->bd_disk->private_data;
	struct fuse_conn *fc = &pxd_dev->ctx->fc;
	int err = 0;

	spin_lock(&fc->lock);
	if (!fc->connected) {
		err = -ENXIO;
	} else {
		spin_lock(&pxd_dev->dlock);
		if (pxd_dev->removing)
			err = -EBUSY;
		else
			pxd_dev->open_count++;
		spin_unlock(&pxd_dev->dlock);

		if (!err)
			(void)get_device(&pxd_dev->dev);
	}
	spin_unlock(&fc->lock);
	trace_pxd_open(pxd_dev->dev_id, pxd_dev->major, pxd_dev->minor, mode, err);
	return err;
}

static void pxd_release(struct gendisk *disk, fmode_t mode)
{
	struct pxd_device *pxd_dev = disk->private_data;

	spin_lock(&pxd_dev->dlock);
	pxd_dev->open_count--;
	spin_unlock(&pxd_dev->dlock);

	trace_pxd_release(pxd_dev->dev_id, pxd_dev->major, pxd_dev->minor, mode);
	put_device(&pxd_dev->dev);
}

static long pxd_control_ioctl(
	struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct pxd_context *ctx = NULL;
	int i, status = -ENOTTY;
	char ver_data[64];
	int ver_len = 0;

	switch (cmd) {
	case PXD_IOC_DUMP_FC_INFO:
		for (i = 0; i < pxd_num_contexts; ++i) {
			ctx = &pxd_contexts[i];
			if (ctx->num_devices == 0) {
				continue;
			}
			printk(KERN_INFO "%s: pxd_ctx: %s ndevices: %lu",
				__func__, ctx->name, ctx->num_devices);
			printk(KERN_INFO "\tFC: connected: %d "
				 "max: %d threshold: %d nb: %d ab: %d",
			       ctx->fc.connected, ctx->fc.max_background,
			       ctx->fc.congestion_threshold,
			       ctx->fc.num_background,
			       ctx->fc.active_background);
		}
		status = 0;
		break;

	case PXD_IOC_GET_VERSION:
		if (argp) {
			ver_len = strlen(gitversion) < 64 ? strlen(gitversion) : 64;
			strncpy(ver_data, gitversion, ver_len);
			if (copy_to_user(argp +
				offsetof(struct pxd_ioctl_version_args, piv_len),
				&ver_len, sizeof(ver_len))) {
				return -EFAULT;
			}
			if (copy_to_user(argp +
				offsetof(struct pxd_ioctl_version_args, piv_data),
				ver_data, ver_len)) {
				return -EFAULT;
			}
		}
		printk(KERN_INFO "pxd driver at version: %s\n", gitversion);
		status = 0;
		break;
	default:
		break;
	}
	return status;
}

static const struct block_device_operations pxd_bd_ops = {
	.owner			= THIS_MODULE,
	.open			= pxd_open,
	.release		= pxd_release,
};

static void pxd_update_stats(struct fuse_req *req, int rw, unsigned int count)
{
	struct pxd_device *pxd_dev = req->queue->queuedata;
	int cpu = part_stat_lock();
	part_stat_inc(cpu, &pxd_dev->disk->part0, ios[rw]);
	part_stat_add(cpu, &pxd_dev->disk->part0, sectors[rw], count);
	part_stat_unlock();
}

/*
 * This is macroized because reqctr moves into a substructure
 * in Linux versions 4.2 and later.  However, we have a private
 * copy of fuse_i.h that uses the older layout.
 */
#define	REQCTR(fc) (fc)->reqctr
#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
#define	REQCTR(fc) (fc)->iq.reqctr
#else
#define	REQCTR(fc) (fc)->reqctr
#endif
#endif

static void pxd_request_complete(struct fuse_conn *fc, struct fuse_req *req)
{
	pxd_printk("%s: receive reply to %p(%lld) at %lld err %d\n",
			__func__, req, req->in.h.unique,
			req->misc.pxd_rdwr_in.offset, req->out.h.error);
}

static void pxd_process_read_reply(struct fuse_conn *fc, struct fuse_req *req)
{
	trace_pxd_reply(REQCTR(fc), req->in.h.unique, 0u);
	pxd_update_stats(req, 0, BIO_SIZE(req->bio) / SECTOR_SIZE);
	BIO_ENDIO(req->bio, req->out.h.error);
	pxd_request_complete(fc, req);
}

static void pxd_process_write_reply(struct fuse_conn *fc, struct fuse_req *req)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
	trace_pxd_reply(REQCTR(fc), req->in.h.unique, REQ_OP_WRITE);
#else
	trace_pxd_reply(REQCTR(fc), req->in.h.unique, REQ_WRITE);
#endif
	pxd_update_stats(req, 1, BIO_SIZE(req->bio) / SECTOR_SIZE);
	BIO_ENDIO(req->bio, req->out.h.error);
	pxd_request_complete(fc, req);
}

static void pxd_process_read_reply_q(struct fuse_conn *fc, struct fuse_req *req)
{
	blk_end_request(req->rq, req->out.h.error, blk_rq_bytes(req->rq));
	pxd_request_complete(fc, req);
}

static void pxd_process_write_reply_q(struct fuse_conn *fc, struct fuse_req *req)
{
	blk_end_request(req->rq, req->out.h.error, blk_rq_bytes(req->rq));
	pxd_request_complete(fc, req);
}

static struct fuse_req *pxd_fuse_req(struct pxd_device *pxd_dev, int nr_pages)
{
	int eintr = 0;
	struct fuse_req *req = NULL;
	struct fuse_conn *fc = &pxd_dev->ctx->fc;
	int status;

	while (req == NULL) {
		req = fuse_get_req_for_background(fc, nr_pages);
		if (IS_ERR(req) && PTR_ERR(req) == -EINTR) {
			req = NULL;
			++eintr;
		}
	}
	if (eintr > 0) {
		printk_ratelimited(KERN_INFO "%s: alloc (%d pages) EINTR retries %d",
			 __func__, nr_pages, eintr);
	}
	status = IS_ERR(req) ? PTR_ERR(req) : 0;
	if (status != 0) {
		printk_ratelimited(KERN_ERR "%s: request alloc (%d pages) failed: %d",
			 __func__, nr_pages, status);
	}
	return req;
}

static void pxd_req_misc(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags)
{
	req->bio_pages = true;
	req->in.h.pid = current->pid;
	req->misc.pxd_rdwr_in.minor = minor;
	req->misc.pxd_rdwr_in.offset = off;
	req->misc.pxd_rdwr_in.size = size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
	req->misc.pxd_rdwr_in.flags =
		((flags & REQ_FUA) ? PXD_FLAGS_FLUSH : 0) |
		((flags & REQ_META) ? PXD_FLAGS_META : 0);
#else
	req->misc.pxd_rdwr_in.flags = ((flags & REQ_FLUSH) ? PXD_FLAGS_FLUSH : 0) |
				      ((flags & REQ_FUA) ? PXD_FLAGS_FUA : 0) |
				      ((flags & REQ_META) ? PXD_FLAGS_META : 0);
#endif
}

static void pxd_read_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags, bool qfn)
{
	req->in.h.opcode = PXD_READ;
	req->in.numargs = 1;
	req->in.argpages = 0;
	req->in.args[0].size = sizeof(struct pxd_rdwr_in);
	req->in.args[0].value = &req->misc.pxd_rdwr_in;
	req->out.numargs = 1;
	req->out.argpages = 1;
	req->out.args[0].size = size;
	req->out.args[0].value = NULL;
	req->end = qfn ? pxd_process_read_reply_q : pxd_process_read_reply;

	pxd_req_misc(req, size, off, minor, flags);
}

static void pxd_write_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags, bool qfn)
{
	req->in.h.opcode = PXD_WRITE;
	req->in.numargs = 1;
	req->in.argpages = 0;
	req->in.args[0].size = sizeof(struct pxd_rdwr_in);
	req->in.args[0].value = &req->misc.pxd_rdwr_in;
	req->out.numargs = 0;
	req->end = qfn ? pxd_process_write_reply_q : pxd_process_write_reply;

	pxd_req_misc(req, size, off, minor, flags);
}

static void pxd_discard_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags, bool qfn)
{
	req->in.h.opcode = PXD_DISCARD;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct pxd_rdwr_in);
	req->in.args[0].value = &req->misc.pxd_rdwr_in;
	req->in.argpages = 0;
	req->out.numargs = 0;
	req->end = qfn ? pxd_process_write_reply_q : pxd_process_write_reply;

	pxd_req_misc(req, size, off, minor, flags);
}

static void pxd_write_same_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags, bool qfn)
{
	req->in.h.opcode = PXD_WRITE_SAME;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct pxd_rdwr_in);
	req->in.args[0].value = &req->misc.pxd_rdwr_in;
	req->in.argpages = 0;
	req->out.numargs = 0;
	req->end = qfn ? pxd_process_write_reply_q : pxd_process_write_reply;

	pxd_req_misc(req, size, off, minor, flags);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
static void pxd_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t op, uint32_t flags, bool qfn,
			uint64_t reqctr)
{
	trace_pxd_request(reqctr, req->in.h.unique, size, off, minor, flags);

	switch (op) {
	case REQ_OP_WRITE_SAME:
		pxd_write_same_request(req, size, off, minor, flags, qfn);
		break;
	case REQ_OP_WRITE:
		pxd_write_request(req, size, off, minor, flags, qfn);
		break;
	case REQ_OP_READ:
		pxd_read_request(req, size, off, minor, flags, qfn);
		break;
	case REQ_OP_DISCARD:
		pxd_discard_request(req, size, off, minor, flags, qfn);
		break;
	case REQ_OP_FLUSH:
		pxd_write_request(req, 0, 0, minor, REQ_FUA, qfn);
		break;
	}
}

#else

static void pxd_request(struct fuse_req *req, uint32_t size, uint64_t off,
	uint32_t minor, uint32_t flags, bool qfn, uint64_t reqctr)
{
	trace_pxd_request(reqctr, req->in.h.unique, size, off, minor, flags);

	switch (flags & (REQ_WRITE | REQ_DISCARD | REQ_WRITE_SAME)) {
	case REQ_WRITE:
		/* FALLTHROUGH */
	case (REQ_WRITE | REQ_WRITE_SAME):
		if (flags & REQ_WRITE_SAME)
			pxd_write_same_request(req, size, off, minor, flags, qfn);
		else
			pxd_write_request(req, size, off, minor, flags, qfn);
		break;
	case 0:
		pxd_read_request(req, size, off, minor, flags, qfn);
		break;
	case REQ_DISCARD:
		/* FALLTHROUGH */
	case REQ_WRITE | REQ_DISCARD:
		pxd_discard_request(req, size, off, minor, flags, qfn);
		break;
	}
}
#endif

#ifdef USE_REQUEST_QUEUE
static void pxd_rq_fn(struct request_queue *q)
{
	struct pxd_device *pxd_dev = q->queuedata;

	for (;;) {
		struct request *rq;

		/* Fetch request from block layer. */
		rq = blk_fetch_request(q);
		if (!rq)
			break;

		/* Filter out block requests we don't understand. */
		if (BLK_RQ_IS_PASSTHROUGH(rq)) {
			__blk_end_request_all(rq, 0);
			continue;
		}

		if (!atomic_read(&pxd_dev->connected)) {
			printk(KERN_ERR"px is disconnected, failing IO.\n");
			__blk_end_request_all(rq, -ENXIO);
			return BLK_QC_RETVAL;
		}

		spin_unlock_irq(&pxd_dev->qlock);
		pxd_printk("%s: dev m %d g %lld %s at %ld len %d bytes %d pages "
			"flags  %llx\n", __func__,
			pxd_dev->minor, pxd_dev->dev_id,
			rq_data_dir(rq) == WRITE ? "wr" : "rd",
			blk_rq_pos(rq) * SECTOR_SIZE, blk_rq_bytes(rq),
			rq->nr_phys_segments, rq->cmd_flags);

		if (!pxd_dev->file) {
			/* see whether it can be initialized now */
			if (refreshFsPath(pxd_dev, false)) {
				printk(KERN_ERR "pxd (%llu) does not have backing file taking fuse path\n", pxd_dev->dev_id);
				//blk_end_request_all(rq, -EIO);
				pxd_rq_fn_process(pxd_dev, q, rq);

				// take the queue lock and fetch the next request
				spin_lock_irq(&pxd_dev->qlock);
				continue;
			}
		}

		if (pxd_dev->file) { /* ah we have backing file path */
			pxd_printk("For device %llu have valid backing file (path: %s)\n",
					pxd_dev->dev_id, pxd_dev->device_path);
			pxd_rq_fn_kernel(pxd_dev, q, rq);
		} else {
			//blk_end_request_all(rq, -EIO);
			pxd_rq_fn_process(pxd_dev, q, rq);
		}
		// take the queue lock and fetch the next request
		spin_lock_irq(&pxd_dev->qlock);
	}
}
#endif

static int pxd_init_disk(struct pxd_device *pxd_dev, struct pxd_add_out *add)
{
	struct gendisk *disk;
	struct request_queue *q;

	if (add->queue_depth < 0 || add->queue_depth > PXD_MAX_QDEPTH)
		return -EINVAL;

	/* Bypass queue if queue_depth is zero. */
	printk(KERN_INFO "Adding device %llu with queue_depth %u\n",
			pxd_dev->dev_id, add->queue_depth);
#ifndef USE_REQUEST_QUEUE
	//if (true || add->queue_depth == 0) {
		q = blk_alloc_queue(GFP_KERNEL);
		if (!q)
			goto out_disk;
		blk_queue_make_request(q, pxd_make_request);
	//} else {
#else
		q = blk_init_queue(pxd_rq_fn, &pxd_dev->qlock);
		if (!q)
			goto out_disk;
	//}
#endif

	/* Create gendisk info. */
	disk = alloc_disk(1);
	if (!disk)
		goto freeq;

	snprintf(disk->disk_name, sizeof(disk->disk_name),
			PXD_DEV"%llu", pxd_dev->dev_id);
	disk->major = pxd_dev->major;
	disk->first_minor = pxd_dev->minor;
	disk->flags |= GENHD_FL_EXT_DEVT | GENHD_FL_NO_PART_SCAN;
	disk->fops = &pxd_bd_ops;
	disk->private_data = pxd_dev;

	blk_queue_max_hw_sectors(q, SEGMENT_SIZE / SECTOR_SIZE);
	blk_queue_max_segment_size(q, SEGMENT_SIZE);
	blk_queue_io_min(q, PXD_LBS);
	blk_queue_io_opt(q, PXD_LBS);
	blk_queue_logical_block_size(q, PXD_LBS);
	blk_queue_bounce_limit(q, BLK_BOUNCE_ANY);

	set_capacity(disk, add->size / SECTOR_SIZE);
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, q);

	/* Enable discard support. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, q);
#else
	blk_queue_flag_set(QUEUE_FLAG_DISCARD, q);
#endif
	q->limits.discard_granularity = PXD_LBS;
	q->limits.discard_alignment = PXD_LBS;
	if (add->discard_size < SECTOR_SIZE)
		q->limits.max_discard_sectors = SEGMENT_SIZE / SECTOR_SIZE;
	else
		q->limits.max_discard_sectors = add->discard_size / SECTOR_SIZE;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	q->limits.discard_zeroes_data = 1;
#endif

	/* Enable flush support. */
	BLK_QUEUE_FLUSH(q);

	disk->queue = q;
	q->queuedata = pxd_dev;
	pxd_dev->disk = disk;

	printk(KERN_ERR"pxd_add_disk with congestion on %d, off %d\n",
			q->nr_congestion_on, q->nr_congestion_off);

	return 0;
freeq:
	blk_cleanup_queue(q);

out_disk:
	return -ENOMEM;
}

static void pxd_free_disk(struct pxd_device *pxd_dev)
{
	struct gendisk *disk = pxd_dev->disk;

	if (!disk)
		return;

	pxd_dev->disk = NULL;
	if (disk->flags & GENHD_FL_UP) {
		del_gendisk(disk);
		if (disk->queue)
			blk_cleanup_queue(disk->queue);
	}
	put_disk(disk);

	if (pxd_dev->file) {
		printk(KERN_INFO "Closing backing file on device %llu\n", pxd_dev->dev_id);
		filp_close(pxd_dev->file, NULL);
		pxd_dev->file = NULL;
	}
}

ssize_t pxd_add(struct fuse_conn *fc, struct pxd_add_out *arg)
{
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	struct pxd_device *pxd_dev = NULL;
	struct pxd_device *pxd_dev_itr;
	int new_minor;
	int err;

	struct pxd_add_vol_out *add = (struct pxd_add_vol_out *) arg;

	err = -ENODEV;
	if (!try_module_get(THIS_MODULE))
		goto out;

	err = -ENOMEM;
	if (ctx->num_devices >= PXD_MAX_DEVICES) {
		printk(KERN_ERR "Too many devices attached..\n");
		goto out_module;
	}

	if (!add->extended) {
		err = -EINVAL;
		goto out;
	}

	pxd_dev = kzalloc(sizeof(*pxd_dev), GFP_KERNEL);
	if (!pxd_dev)
		goto out_module;

	spin_lock_init(&pxd_dev->dlock);
	spin_lock_init(&pxd_dev->qlock);

	new_minor = ida_simple_get(&pxd_minor_ida,
				    1, 1 << MINORBITS,
				    GFP_KERNEL);
	if (new_minor < 0) {
		err = new_minor;
		goto out_module;
	}

	pxd_dev->dev_id = add->dev_id;
	pxd_dev->major = pxd_major;
	pxd_dev->minor = new_minor;
	pxd_dev->ctx = ctx;

	// init extended information
	// Ignore these settings as they are hardcoded.
	pxd_dev->block_device = add->block_device;
	pxd_dev->pool_id = add->pool_id;
	pxd_dev->size = add->size;
	memcpy(pxd_dev->device_path, add->device_path, strlen(add->device_path)+1);

	initBackingFsPath(pxd_dev);

	err = pxd_init_disk(pxd_dev, arg);
	if (err)
		goto out_id;

	spin_lock(&ctx->lock);
	list_for_each_entry(pxd_dev_itr, &ctx->list, node) {
		if (pxd_dev_itr->dev_id == add->dev_id) {
			err = -EEXIST;
			spin_unlock(&ctx->lock);
			goto out_disk;
		}
	}

	err = pxd_bus_add_dev(pxd_dev);
	if (err) {
		spin_unlock(&ctx->lock);
		goto out_disk;
	}

	list_add(&pxd_dev->node, &ctx->list);
	++ctx->num_devices;
	spin_unlock(&ctx->lock);

	add_disk(pxd_dev->disk);

	return pxd_dev->minor;

out_disk:
	pxd_free_disk(pxd_dev);
out_id:
	ida_simple_remove(&pxd_minor_ida, new_minor);
out_module:
	if (pxd_dev)
		kfree(pxd_dev);
	module_put(THIS_MODULE);
out:
	return err;
}

ssize_t pxd_remove(struct fuse_conn *fc, struct pxd_remove_out *remove)
{
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	int found = false;
	int err;
	struct pxd_device *pxd_dev;

	spin_lock(&ctx->lock);
	list_for_each_entry(pxd_dev, &ctx->list, node) {
		if (pxd_dev->dev_id == remove->dev_id) {
			spin_lock(&pxd_dev->dlock);
			if (!pxd_dev->open_count || remove->force) {
				list_del(&pxd_dev->node);
				--ctx->num_devices;
			}
			found = true;
			break;
		}
	}
	spin_unlock(&ctx->lock);

	if (!found) {
		err = -ENOENT;
		goto out;
	}

	if (pxd_dev->open_count && !remove->force) {
		err = -EBUSY;
		spin_unlock(&pxd_dev->dlock);
		goto out;
	}

	cleanupBackingFsPath(pxd_dev);
	pxd_dev->removing = true;

	/* Make sure the req_fn isn't called anymore even if the device hangs around */
	if (pxd_dev->disk && pxd_dev->disk->queue){
		mutex_lock(&pxd_dev->disk->queue->sysfs_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
		queue_flag_set_unlocked(QUEUE_FLAG_DYING, pxd_dev->disk->queue);
#else
		blk_queue_flag_set(QUEUE_FLAG_DYING, pxd_dev->disk->queue);
#endif
		mutex_unlock(&pxd_dev->disk->queue->sysfs_lock);
	}

	spin_unlock(&pxd_dev->dlock);

	device_unregister(&pxd_dev->dev);

	module_put(THIS_MODULE);

	return 0;
out:
	return err;
}

ssize_t pxd_update_size(struct fuse_conn *fc, struct pxd_update_size_out *update_size)
{
	bool found = false;
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	int err;
	struct pxd_device *pxd_dev;

	spin_lock(&ctx->lock);
	list_for_each_entry(pxd_dev, &ctx->list, node) {
		if ((pxd_dev->dev_id == update_size->dev_id) && !pxd_dev->removing) {
			spin_lock(&pxd_dev->dlock);
			found = true;
			break;
		}
	}
	spin_unlock(&ctx->lock);

	if (!found) {
		err = -ENOENT;
		goto out;
	}

	(void)get_device(&pxd_dev->dev);

	set_capacity(pxd_dev->disk, update_size->size / SECTOR_SIZE);
	spin_unlock(&pxd_dev->dlock);

	err = revalidate_disk(pxd_dev->disk);
	BUG_ON(err);
	put_device(&pxd_dev->dev);

	return 0;
out:
	return err;
}

static struct bus_type pxd_bus_type = {
	.name		= "pxd",
};

static void pxd_root_dev_release(struct device *dev)
{
}

static struct device pxd_root_dev = {
	.init_name =    "pxd",
	.release =      pxd_root_dev_release,
};

static struct pxd_device *dev_to_pxd_dev(struct device *dev)
{
	return container_of(dev, struct pxd_device, dev);
}

static ssize_t pxd_size_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);

	return sprintf(buf, "%llu\n",
		(unsigned long long)pxd_dev->size);
}

static ssize_t pxd_major_show(struct device *dev,
		     struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);

	return sprintf(buf, "%llu\n",
			(unsigned long long)pxd_dev->major);
}

static ssize_t pxd_minor_show(struct device *dev,
		     struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);

	return sprintf(buf, "%llu\n",
			(unsigned long long)pxd_dev->minor);
}

static ssize_t pxd_timeout_show(struct device *dev,
		     struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", pxd_timeout_secs);
}

ssize_t pxd_timeout_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	uint32_t new_timeout_secs = 0;
	struct pxd_context *ctx = pxd_dev->ctx;

	if (ctx == NULL)
		return -ENXIO;

	sscanf(buf, "%d", &new_timeout_secs);
	if (new_timeout_secs < PXD_TIMER_SECS_MIN ||
			new_timeout_secs > PXD_TIMER_SECS_MAX) {
		return -EINVAL;
	}

	spin_lock(&ctx->lock);
	pxd_timeout_secs = new_timeout_secs;
	if (!ctx->fc.connected) {
		mod_timer(&ctx->timer, jiffies + (pxd_timeout_secs * HZ));
	}
	spin_unlock(&ctx->lock);
	return count;
}

static DEVICE_ATTR(size, S_IRUGO, pxd_size_show, NULL);
static DEVICE_ATTR(major, S_IRUGO, pxd_major_show, NULL);
static DEVICE_ATTR(minor, S_IRUGO, pxd_minor_show, NULL);
static DEVICE_ATTR(timeout, S_IRUGO|S_IWUSR, pxd_timeout_show, pxd_timeout_store);

static struct attribute *pxd_attrs[] = {
	&dev_attr_size.attr,
	&dev_attr_major.attr,
	&dev_attr_minor.attr,
	&dev_attr_timeout.attr,
	NULL
};

static struct attribute_group pxd_attr_group = {
	.attrs = pxd_attrs,
};

static const struct attribute_group *pxd_attr_groups[] = {
	&pxd_attr_group,
	NULL
};

static void pxd_sysfs_dev_release(struct device *dev)
{
	printk (KERN_INFO "pxd_sysfs_dev_release empty call\n");
}

static struct device_type pxd_device_type = {
	.name		= "pxd",
	.groups		= pxd_attr_groups,
	.release	= pxd_sysfs_dev_release,
};

static void pxd_dev_device_release(struct device *dev)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);

	pxd_free_disk(pxd_dev);
	ida_simple_remove(&pxd_minor_ida, pxd_dev->minor);
	kfree(pxd_dev);
}

static int pxd_bus_add_dev(struct pxd_device *pxd_dev)
{
	struct device *dev;
	int ret;

	dev = &pxd_dev->dev;
	dev->bus = &pxd_bus_type;
	dev->type = &pxd_device_type;
	dev->parent = &pxd_root_dev;
	dev->release = pxd_dev_device_release;
	dev_set_name(dev, "%d", pxd_dev->minor);
	ret = device_register(dev);

	return ret;
}

static int pxd_sysfs_init(void)
{
	int err;

	err = device_register(&pxd_root_dev);
	if (err < 0)
		return err;

	err = bus_register(&pxd_bus_type);
	if (err < 0)
		device_unregister(&pxd_root_dev);

	return err;
}

static void pxd_sysfs_exit(void)
{
	bus_unregister(&pxd_bus_type);
	device_unregister(&pxd_root_dev);
}

static void pxd_fill_init_desc(struct fuse_page_desc *desc, int num_ids)
{
	desc->length = num_ids * sizeof(struct pxd_dev_id);
	desc->offset = 0;
}

static void pxd_fill_init(struct fuse_conn *fc, struct fuse_req *req,
	struct pxd_init_in *in)
{
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	int i = 0, j = 0;
	int num_per_page = PAGE_SIZE / sizeof(struct pxd_dev_id);
	struct pxd_device *pxd_dev;
	struct pxd_dev_id *ids = NULL;

	in->version = PXD_VERSION;

	if (!req->num_pages)
		return;

	spin_lock(&ctx->lock);
	list_for_each_entry(pxd_dev, &ctx->list, node) {
		if (i == 0)
			ids = kmap_atomic(req->pages[j]);
		ids[i].dev_id = pxd_dev->dev_id;
		ids[i].local_minor = pxd_dev->minor;
		++i;
		if (i == num_per_page) {
			pxd_fill_init_desc(&req->page_descs[j], i);
			kunmap_atomic(ids);
			++j;
			i = 0;
		}
	}
	in->num_devices = ctx->num_devices;
	spin_unlock(&ctx->lock);

	if (i < num_per_page) {
		pxd_fill_init_desc(&req->page_descs[j], i);
		kunmap_atomic(ids);
	}
}

static void pxd_process_init_reply(struct fuse_conn *fc,
		struct fuse_req *req)
{
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);

	printk(KERN_INFO "%s: pxd-control-%d:%llu init OK\n",
		__func__, ctx->id, req->out.h.unique);
	pxd_printk("%s: req %p err %d len %d un %lld\n",
		__func__, req, req->out.h.error,
		req->out.h.len, req->out.h.unique);

	ctx->unique = req->out.h.unique;
	if (req->out.h.error != 0)
		fc->connected = 0;
	fc->pend_open = 0;
	fuse_put_request(fc, req);
}

static int pxd_send_init(struct fuse_conn *fc)
{
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	int rc;
	struct fuse_req *req;
	struct pxd_init_in *arg;
	void *outarg;
	int i;
	int num_per_page = PAGE_SIZE / sizeof(struct pxd_dev_id);
	int num_pages = (sizeof(struct pxd_dev_id) * ctx->num_devices +
				num_per_page - 1) / num_per_page;

	req = fuse_get_req(fc, num_pages);
	if (IS_ERR(req)) {
		rc = PTR_ERR(req);
		printk(KERN_ERR "%s: get req error %d\n", __func__, rc);
		goto err;
	}

	req->num_pages = num_pages;

	rc = -ENOMEM;
	for (i = 0; i < req->num_pages; ++i) {
		req->pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!req->pages[i])
			goto err_free_pages;
	}

	arg = &req->misc.pxd_init_in;
	pxd_fill_init(fc, req, arg);

	outarg = kzalloc(sizeof(struct pxd_init_out), GFP_KERNEL);
	if (!outarg)
		goto err_free_pages;

	req->in.h.opcode = PXD_INIT;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(struct pxd_init_in);
	req->in.args[0].value = arg;
	req->in.args[1].size = sizeof(struct pxd_dev_id) * ctx->num_devices;
	req->in.args[1].value = NULL;
	req->in.argpages = 1;
	req->out.numargs = 0;
	req->end = pxd_process_init_reply;

	fuse_request_send_oob(fc, req);

	pxd_printk("%s: version %d num devices %ld(%d)\n", __func__, arg->version,
		ctx->num_devices, arg->num_devices);
	return 0;

err_free_pages:
	printk(KERN_ERR "%s: mem alloc\n", __func__);
	for (i = 0; i < req->num_pages; ++i) {
		if (req->pages[i])
			put_page(req->pages[i]);
	}
	fuse_put_request(fc, req);
err:
	return rc;
}

static int pxd_control_open(struct inode *inode, struct file *file)
{
	int rc;
	struct pxd_context *ctx;
	struct fuse_conn *fc;

	if (!((uintptr_t)pxd_contexts <= (uintptr_t)file->f_op &&
		(uintptr_t)file->f_op < (uintptr_t)(pxd_contexts + pxd_num_contexts))) {
		printk(KERN_ERR "%s: invalid fops struct\n", __func__);
		return -EINVAL;
	}

	ctx = container_of(file->f_op, struct pxd_context, fops);
	if (ctx->id >= pxd_num_contexts_exported) {
		return 0;
	}

	fc = &ctx->fc;
	if (fc->pend_open == 1) {
		printk(KERN_ERR "%s: too many outstanding opened\n", __func__);
		return -EINVAL;
	}

	if (fc->connected == 1) {
		printk(KERN_ERR "%s: pxd-control-%d already open\n", __func__, ctx->id);
		return -EINVAL;
	}

	del_timer_sync(&ctx->timer);
	spin_lock(&ctx->lock);
	pxd_timeout_secs = PXD_TIMER_SECS_MAX;
	fc->connected = 1;
	spin_unlock(&ctx->lock);

	fc->pend_open = 1;
	fc->initialized = 1;
	fc->allow_disconnected = 1;
	file->private_data = fc;

	pxdctx_set_connected(ctx, true);
	fuse_restart_requests(fc);

	rc = pxd_send_init(fc);
	if (rc)
		return rc;

	printk(KERN_INFO "%s: pxd-control-%d open OK\n", __func__, ctx->id);
	return 0;
}

/** Note that this will not be called if userspace doesn't cleanup. */
static int pxd_control_release(struct inode *inode, struct file *file)
{
	struct pxd_context *ctx;
	ctx = container_of(file->f_op, struct pxd_context, fops);
	if (ctx->id >= pxd_num_contexts_exported) {
		return 0;
	}

	spin_lock(&ctx->lock);
	if (ctx->fc.connected == 0)
		pxd_printk("%s: not opened\n", __func__);
	else
		ctx->fc.connected = 0;
	ctx->fc.pend_open = 0;
	mod_timer(&ctx->timer, jiffies + (pxd_timeout_secs * HZ));
	spin_unlock(&ctx->lock);

	printk(KERN_INFO "%s: pxd-control-%d:%llu close OK\n", __func__,
		ctx->id, ctx->unique);
	return 0;
}

static struct miscdevice pxd_miscdev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "pxd/pxd-control",
};

MODULE_ALIAS("devname:pxd-control");

static void pxd_fuse_conn_release(struct fuse_conn *conn)
{
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void pxd_timeout(struct timer_list *args)
#else
static void pxd_timeout(unsigned long args)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	struct pxd_context *ctx = from_timer(ctx, args, timer);
#else
	struct pxd_context *ctx = (struct pxd_context *)args;
#endif
	struct fuse_conn *fc = &ctx->fc;

	BUG_ON(fc->connected);

	fc->connected = true; /* XXX: should this be false */
	fc->allow_disconnected = 0;
	pxdctx_set_connected(ctx, false);
	fuse_abort_conn(fc);
	printk(KERN_INFO "PXD_TIMEOUT (%s:%llu): Aborting all requests...",
		ctx->name, ctx->unique);
}

int pxd_context_init(struct pxd_context *ctx, int i)
{
	int err;
	spin_lock_init(&ctx->lock);
	ctx->id = i;
	ctx->fops = fuse_dev_operations;
	ctx->fops.owner = THIS_MODULE;
	ctx->fops.open = pxd_control_open;
	ctx->fops.release = pxd_control_release;

	if (ctx->id < pxd_num_contexts_exported) {
		err = fuse_conn_init(&ctx->fc);
		if (err)
			return err;
	} else {
		ctx->fops.unlocked_ioctl = pxd_control_ioctl;
	}
	ctx->fc.release = pxd_fuse_conn_release;
	ctx->fc.allow_disconnected = 1;
	INIT_LIST_HEAD(&ctx->list);
	sprintf(ctx->name, "pxd/pxd-control-%d", i);
	ctx->miscdev.minor = MISC_DYNAMIC_MINOR;
	ctx->miscdev.name = ctx->name;
	ctx->miscdev.fops = &ctx->fops;
	INIT_LIST_HEAD(&ctx->pending_requests);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	timer_setup(&ctx->timer, pxd_timeout, 0);
#else
	setup_timer(&ctx->timer, pxd_timeout, (unsigned long) ctx);
#endif
	return 0;
}

static void pxd_context_destroy(struct pxd_context *ctx)
{
	misc_deregister(&ctx->miscdev);
	del_timer_sync(&ctx->timer);
	if (ctx->id < pxd_num_contexts_exported) {
		fuse_abort_conn(&ctx->fc);
		fuse_conn_put(&ctx->fc);
	}
}

int pxd_init(void)
{
	int err, i, j;

	printk(KERN_WARNING "pxd: development driver installed\n");
	err = fuse_dev_init();
	if (err) {
		printk(KERN_ERR "pxd: failed to initialize fuse: %d\n", err);
		goto out;
	}

	pxd_contexts = kzalloc(sizeof(pxd_contexts[0]) * pxd_num_contexts,
		GFP_KERNEL);
	err = -ENOMEM;
	if (!pxd_contexts) {
		printk(KERN_ERR "pxd: failed to allocate memory\n");
		goto out_fuse_dev;
	}

	for (i = 0; i < pxd_num_contexts; ++i) {
		struct pxd_context *ctx = &pxd_contexts[i];
		err = pxd_context_init(ctx, i);
		if (err) {
			printk(KERN_ERR "pxd: failed to initialize connection\n");
			goto out_fuse;
		}
		err = misc_register(&ctx->miscdev);
		if (err) {
			printk(KERN_ERR "pxd: failed to register dev %s %d: %d\n",
				ctx->miscdev.name, i, err);
			goto out_fuse;
		}
	}

	pxd_miscdev.fops = &pxd_contexts[0].fops;
	err = misc_register(&pxd_miscdev);
	if (err) {
		printk(KERN_ERR "pxd: failed to register dev %s: %d\n",
			pxd_miscdev.name, err);
		goto out_fuse;
	}

	pxd_major = register_blkdev(0, "pxd");
	if (pxd_major < 0) {
		err = pxd_major;
		printk(KERN_ERR "pxd: failed to register dev pxd: %d\n", err);
		goto out_misc;
	}

	err = pxd_sysfs_init();
	if (err) {
		printk(KERN_ERR "pxd: failed to initialize sysfs: %d\n", err);
		goto out_blkdev;
	}

	printk(KERN_INFO "pxd: driver loaded version %s\n", gitversion);

	return 0;

out_blkdev:
	unregister_blkdev(0, "pxd");
out_misc:
	misc_deregister(&pxd_miscdev);
out_fuse:
	for (j = 0; j < i; ++j) {
		pxd_context_destroy(&pxd_contexts[j]);
	}
	kfree(pxd_contexts);
out_fuse_dev:
	fuse_dev_cleanup();
out:
	return err;
}

void pxd_exit(void)
{
	int i;

	pxd_sysfs_exit();
	unregister_blkdev(pxd_major, "pxd");
	misc_deregister(&pxd_miscdev);

	for (i = 0; i < pxd_num_contexts; ++i) {
		/* force cleanup @@@ */
		pxd_contexts[i].fc.connected = true;
		pxd_context_destroy(&pxd_contexts[i]);
	}

	fuse_dev_cleanup();

	kfree(pxd_contexts);

	printk(KERN_WARNING "pxd: development driver unloaded\n");
}

module_init(pxd_init);
module_exit(pxd_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION(VERTOSTR(PXD_VERSION));
