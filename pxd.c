#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/sysfs.h>
#include <linux/crc32.h>
#include <linux/miscdevice.h>
#include <linux/atomic.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/kthread.h>
#include <linux/dma-mapping.h>
#include <linux/statfs.h>
#include <linux/file.h>

#include "pxd_config.h"

#include "fuse_i.h"
#include "pxd.h"

#define CREATE_TRACE_POINTS
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE pxd_trace
#include <pxd_trace.h>
#undef CREATE_TRACE_POINTS

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
#include <linux/blk-mq.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
#include <linux/blk-mq.h>
#define blk_status_t int
#define BLK_STS_OK		(0)
#define BLK_STS_IOERR		(10)
#endif

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
#define MAX_DISCARD_SIZE (4*SEGMENT_SIZE)
#define MAX_WRITESEGS_FOR_FLUSH ((4*SEGMENT_SIZE)/PXD_LBS)

#define PXD_TIMER_SECS_MIN 30
#define PXD_TIMER_SECS_MAX 600

#define TOSTRING_(x) #x
#define VERTOSTR(x) TOSTRING_(x)

extern const char *gitversion;
static dev_t pxd_major;
static DEFINE_IDA(pxd_minor_ida);

struct node_cpu_map {
	int cpu[NR_CPUS];
	int ncpu;
};

// A one-time built, static lookup table to distribute requests to cpu within same numa node
static struct node_cpu_map *node_cpu_map;

static inline int getnextcpu(int node, int pos) {
	const struct node_cpu_map *map = &node_cpu_map[node];
	if (map->ncpu == 0) { return 0; }
	return map->cpu[(pos) % map->ncpu];
}

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
static const char *mode = "blk-bio";
struct thread_context {
	struct pxd_device  *pxd_dev;
	struct task_struct *pxd_thread;
	wait_queue_head_t   pxd_event;
	spinlock_t  		lock;
	struct bio_list  bio_list;
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

	// Extended information
	bool   block_device;
	loff_t offset; // offset into the backing device/file
	int bg_flush_enabled; // dynamically enable bg flush from driver
	int n_flush_wrsegs; // num of PXD_LBS write segments to force flush

	// Below information has to be set through new PXD_UPDATE_PATH ioctl
	int nfd;
	struct file *file[MAX_PXD_BACKING_DEVS];
	char device_path[MAX_PXD_BACKING_DEVS][MAX_PXD_DEVPATH_LEN];

	struct thread_context *tc;
	wait_queue_head_t   congestion_wait;
	wait_queue_head_t   sync_event;
	spinlock_t   	sync_lock;
	atomic_t sync_active; // currently active?
	atomic_t nsync; // number of forced syncs completed
	atomic_t ncount; // total active requests
	atomic_t nslowPath; // total requests through slow path
	atomic_t ncomplete; // total completed requests
	atomic_t ncongested; // total number of times queue congested
	atomic_t write_counter; // completed writes, gets cleared on a threshold
	atomic_t index[MAX_NUMNODES];
	volatile bool connected; // fc connected status
	struct pxd_context *ctx;
};

static inline
struct file* getFile(struct pxd_device *pxd_dev, int index) {
	if (index < pxd_dev->nfd) {
		return pxd_dev->file[index];
	}

	return NULL;
}

// Forward decl
static void initFile(struct pxd_device *pxd_dev, bool);
static void cleanupFile(struct pxd_device *pxd_dev);

/* when request queeuing model is used on version 4.12+, block mq model
 * is used to process IO and requests are never punted over fuse.
 */
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
#include <linux/bio.h>

#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT (9)
#endif

/* Common functions */
static int _pxd_flush(struct pxd_device *pxd_dev) {
	int ret = 0;
	int index;
	struct file *file;

	for (index=0; index<pxd_dev->nfd; index++) {
		file = getFile(pxd_dev, index);
		ret = vfs_fsync(file, 0);
		if (unlikely(ret && ret != -EINVAL && ret != -EIO)) {
			ret = -EIO;
		}
	}
	atomic_set(&pxd_dev->write_counter, 0);
	return ret;
}

static int pxd_should_flush(struct pxd_device *pxd_dev, int *active) {
	*active = atomic_read(&pxd_dev->sync_active);
	if (pxd_dev->bg_flush_enabled &&
		(atomic_read(&pxd_dev->write_counter) > pxd_dev->n_flush_wrsegs) &&
		!*active) {
		atomic_set(&pxd_dev->sync_active, 1);
		return 1;
	}
	return 0;
}

static void pxd_issue_sync(struct pxd_device *pxd_dev) {
	int i;
	struct block_device *bdev = bdget_disk(pxd_dev->disk, 0);
	if (!bdev) return;

	for (i=0; i<pxd_dev->nfd; i++) {
		vfs_fsync(getFile(pxd_dev, i), 0);
	}

	spin_lock_irq(&pxd_dev->sync_lock);
	atomic_set(&pxd_dev->write_counter, 0);
	atomic_set(&pxd_dev->sync_active, 0);
	atomic_inc(&pxd_dev->nsync);
	spin_unlock_irq(&pxd_dev->sync_lock);

	wake_up(&pxd_dev->sync_event);
}

static void pxd_check_write_cache_flush(struct pxd_device *pxd_dev) {
	int sync_wait, sync_now;
	spin_lock_irq(&pxd_dev->sync_lock);
	sync_now = pxd_should_flush(pxd_dev, &sync_wait);

	if (sync_wait) {
		wait_event_lock_irq(pxd_dev->sync_event,
				!atomic_read(&pxd_dev->sync_active),
				pxd_dev->sync_lock);
	}
	spin_unlock_irq(&pxd_dev->sync_lock);

	if (sync_now) pxd_issue_sync(pxd_dev);
}


static int _pxd_bio_discard(struct pxd_device *pxd_dev, struct bio *bio, loff_t pos) {
	struct file *file;
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	int ret;
	int i;


	pxd_printk("calling discard [%s] (REQ_DISCARD)...\n", pxd_dev->device_path);

	for (i=0; i<pxd_dev->nfd; i++) {
		file = getFile(pxd_dev, i);
		if ((!file->f_op->fallocate)) {
			return -EOPNOTSUPP;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
		ret = file->f_op->fallocate(file, mode, pos, bio->bi_iter.bi_size);
#else
		ret = file->f_op->fallocate(file, mode, pos, bio->bi_size);
#endif
		if (unlikely(ret && ret != -EINVAL && ret != -EOPNOTSUPP))
			return -EIO;
	}

	return 0;
}

static int _pxd_write(struct file *file, struct bio_vec *bvec, loff_t *pos)
{
	ssize_t bw;
	mm_segment_t old_fs = get_fs();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct iov_iter i;
#else
	void *kaddr = kmap(bvec->bv_page) + bvec->bv_offset;
#endif

	pxd_printk("_pxd_write entry offset %lld, length %d entered\n", *pos, bvec->bv_len);

	if (bvec->bv_len != PXD_LBS) {
		printk(KERN_ERR"Unaligned block writes %d bytes\n", bvec->bv_len);
	}
	set_fs(get_ds());
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
	iov_iter_bvec(&i, WRITE, bvec, 1, bvec->bv_len);
	file_start_write(file);
	bw = vfs_iter_write(file, &i, pos, 0);
	file_end_write(file);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	iov_iter_bvec(&i, ITER_BVEC | WRITE, bvec, 1, bvec->bv_len);
	file_start_write(file);
	bw = vfs_iter_write(file, &i, pos, 0);
	file_end_write(file);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	iov_iter_bvec(&i, ITER_BVEC | WRITE, bvec, 1, bvec->bv_len);
	file_start_write(file);
	bw = vfs_iter_write(file, &i, pos);
	file_end_write(file);
#else
	bw = vfs_write(file, kaddr, bvec->bv_len, pos);
#endif
	set_fs(old_fs);
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

static inline unsigned getsectors(struct bio *bio) {
	unsigned nbytes = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif

	switch (bio_op(bio)) {
	case REQ_OP_DISCARD:
	case REQ_OP_SECURE_ERASE:
	case REQ_OP_WRITE_ZEROES:
		return 0;
	case REQ_OP_WRITE_SAME:
		return 1;
	default:
		break;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	bio_for_each_segment(bvec, bio, i) {
		nbytes += bvec.bv_len;
	}
#else
	bio_for_each_segment(bvec, bio, i) {
		nbytes += bvec->bv_len;
	}
#endif

	return nbytes/SECTOR_SIZE;
}

static int do_pxd_send(struct pxd_device *pxd_dev, struct bio *bio, loff_t pos) {
	int ret = 0;
	int nsegs = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif
	int fileindex;

	pxd_printk("do_pxd_send bio%p, off%lld bio_segments %d\n", bio, pos, bio_segments(bio));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	bio_for_each_segment(bvec, bio, i) {
		nsegs++;

		for (fileindex=0; fileindex < pxd_dev->nfd; fileindex++) {
			struct file *file = getFile(pxd_dev, fileindex);
			loff_t tpos = pos;
			ret = _pxd_write(file, &bvec, &tpos);
			if (ret < 0) {
				printk(KERN_ERR"do_pxd_write[%d] pos %lld page %p, off %u for len %d FAILED %d\n",
					fileindex, pos, bvec.bv_page, bvec.bv_offset, bvec.bv_len, ret);
				return ret;
			}
		}

		pos += bvec.bv_len;
		cond_resched();
	}
#else
	bio_for_each_segment(bvec, bio, i) {
		nsegs++;
		for (fileindex=0; fileindex < pxd_dev->nfd; fileindex++) {
			struct file *file = getFile(pxd_dev, fileindex);
			loff_t tpos = pos;
			ret = _pxd_write(file, bvec, &tpos);
			if (ret < 0) {
				pxd_printk("do_pxd_write pos %lld page %p, off %u for len %d FAILED %d\n",
					pos, bvec->bv_page, bvec->bv_offset, bvec->bv_len, ret);
				return ret;
			}
		}

		pos += bvec->bv_len;
		cond_resched();
	}
#endif
	atomic_add(nsegs, &pxd_dev->write_counter);
	return 0;
}

static
ssize_t _pxd_read(struct file *file, struct bio_vec *bvec, loff_t *pos) {
	int result = 0;

    /* read from file at offset pos into the buffer */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
	struct iov_iter i;

	iov_iter_bvec(&i, READ, bvec, 1, bvec->bv_len);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	struct iov_iter i;

	iov_iter_bvec(&i, ITER_BVEC|READ, bvec, 1, bvec->bv_len);
	result = vfs_iter_read(file, &i, pos, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct iov_iter i;

	iov_iter_bvec(&i, ITER_BVEC|READ, bvec, 1, bvec->bv_len);
	result = vfs_iter_read(file, &i, pos);
#else
	mm_segment_t old_fs = get_fs();
	void *kaddr = kmap(bvec->bv_page) + bvec->bv_offset;

	set_fs(get_ds());
	result = vfs_read(file, kaddr, bvec->bv_len, pos);
	set_fs(old_fs);
	kunmap(bvec->bv_page);
#endif
	if (result < 0) printk(KERN_ERR "__vfs_read return %d\n", result);
	return result;
}

static ssize_t do_pxd_receive(struct pxd_device *pxd_dev, struct bio_vec *bvec, loff_t pos)
{
        return _pxd_read(getFile(pxd_dev, 0), bvec, &pos);
}

static ssize_t pxd_receive(struct pxd_device *pxd_dev, struct bio *bio, loff_t pos)
{
	ssize_t s;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif

	pxd_printk("pxd_receive[%llu] with bio=%p, pos=%llu, nsects=%d\n",
				pxd_dev->dev_id, bio, pos, getsectors(bio));
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

static void _pxd_setup(struct pxd_device *pxd_dev, bool enable) {
	if (!enable) {
		printk(KERN_ERR "_pxd_setup called to disable IO\n");
		pxd_dev->connected = false;
	} else {
		printk(KERN_ERR "_pxd_setup called to enable IO\n");
	}

	if (enable) {
		spin_lock_irq(&pxd_dev->dlock);
		initFile(pxd_dev, true);
		spin_unlock_irq(&pxd_dev->dlock);
	}

	if (enable) pxd_dev->connected = true;
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


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
static int do_bio_filebacked(struct thread_context *tc, struct bio *bio)
{
	struct pxd_device *pxd_dev = tc->pxd_dev;
	loff_t pos;
	unsigned int op = bio_op(bio);
	int ret;

	pxd_printk("do_bio_filebacked for new bio (pending %u)\n",
				atomic_read(&pxd_dev->ncount));
	pos = ((loff_t) bio->bi_iter.bi_sector << 9) + pxd_dev->offset;

	switch (op) {
	case REQ_OP_READ:
		return pxd_receive(pxd_dev, bio, pos);
	case REQ_OP_WRITE:

		if (bio->bi_opf & REQ_PREFLUSH) {
			ret = _pxd_flush(pxd_dev);
			if (ret < 0) return ret;
		}

		/* Before any newer writes happen, make sure previous write/sync complete */
		pxd_check_write_cache_flush(pxd_dev);

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
		return _pxd_bio_discard(pxd_dev, bio, pos);
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

	pxd_printk("do_bio_filebacked for new bio (pending %u)\n",
				atomic_read(&pxd_dev->ncount));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	pos = ((loff_t) bio->bi_iter.bi_sector << 9) + pxd_dev->offset;
#else
	pos = ((loff_t) bio->bi_sector << 9) + pxd_dev->offset;
#endif

	if (bio_data_dir(bio) == WRITE) {
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
			ret = _pxd_bio_discard(pxd_dev, bio, pos);
			goto out;
		}
		/* Before any newer writes happen, make sure previous write/sync complete */
		pxd_check_write_cache_flush(pxd_dev);
		ret = do_pxd_send(pxd_dev, bio, pos);

		if ((bio->bi_rw & REQ_FUA) && !ret) {
			ret = _pxd_flush(pxd_dev);
			if (ret < 0) goto out;
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
	//unsigned long startTime = jiffies;

	if (shouldClose) {
		printk(KERN_ERR"px is disconnected, failing IO.\n");
		bio_io_error(bio);
		return;
	}
#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	generic_start_io_acct(tc->pxd_dev->disk->queue, bio_op(bio), getsectors(bio), &tc->pxd_dev->disk->part0);
#else
	generic_start_io_acct(bio_data_dir(bio), getsectors(bio), &tc->pxd_dev->disk->part0);
#endif
#endif

	ret = do_bio_filebacked(tc, bio);

#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	generic_end_io_acct(tc->pxd_dev->disk->queue, bio_op(bio), &tc->pxd_dev->disk->part0, startTime);
#else
	generic_end_io_acct(bio_data_dir(bio), &tc->pxd_dev->disk->part0, startTime);
#endif
#endif
	atomic_inc(&tc->pxd_dev->ncomplete);
	pxd_printk("Completed a request direction %p/%d\n", bio, bio_data_dir(bio));

	if (ret < 0) {
		bio_io_error(bio);
		return;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
	bio_endio(bio);
#else
	bio_endio(bio, ret);
#endif
}

static void pxd_add_bio(struct thread_context *tc, struct bio *bio) {
	atomic_inc(&tc->pxd_dev->ncount);

	spin_lock_irq(&tc->lock);
	bio_list_add(&tc->bio_list, bio);
	spin_unlock_irq(&tc->lock);
}

static struct bio* pxd_get_bio(struct thread_context *tc, bool *shouldClose) {
	struct bio* bio;
	atomic_dec(&tc->pxd_dev->ncount);

	spin_lock_irq(&tc->lock);
	*shouldClose = !tc->pxd_dev->connected;
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
				tc->pxd_dev->dev_id, atomic_read(&tc->pxd_dev->ncount));

		bio = pxd_get_bio(tc, &shouldClose);
		BUG_ON(!bio);

		spin_lock_irq(&tc->pxd_dev->dlock);
		if (atomic_read(&tc->pxd_dev->ncount) < tc->pxd_dev->disk->queue->nr_congestion_off) {
			wake_up(&tc->pxd_dev->congestion_wait);
		}
		spin_unlock_irq(&tc->pxd_dev->dlock);

		pxd_handle_bio(tc, bio, shouldClose);
	}
	return 0;
}

static int initBIO(struct pxd_device *pxd_dev) {
	int i;

	for (i=0; i<nr_node_ids; i++) {
		atomic_set(&pxd_dev->index[i], 0);
	}

	for (i=0; i<MAX_THREADS; i++) {
		struct thread_context *tc = &pxd_dev->tc[i];
		tc->pxd_dev = pxd_dev;
		spin_lock_init(&tc->lock);
		init_waitqueue_head(&tc->pxd_event);
		tc->pxd_thread = kthread_create_on_node(pxd_io_thread, tc, cpu_to_node(i),
				"pxd%d:%llu", i, pxd_dev->dev_id);
		if (IS_ERR(tc->pxd_thread)) {
			pxd_printk("Init kthread for device %llu failed %lu\n",
				pxd_dev->dev_id, PTR_ERR(tc->pxd_thread));
			return -EINVAL;
		}

		kthread_bind(tc->pxd_thread, i);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
STATIC blk_qc_t pxd_make_request_orig(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
STATIC void pxd_make_request_orig(struct request_queue *q, struct bio *bio)
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
blk_qc_t pxd_make_request(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
void pxd_make_request(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL
#endif
{
	struct pxd_device *pxd_dev = q->queuedata;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	unsigned int rw = bio_op(bio);
#else
	unsigned int rw = bio_rw(bio);
#endif
	int cpu = smp_processor_id();
	int thread = cpu % MAX_THREADS;

	struct thread_context *tc;

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

	if (!pxd_dev->connected) {
		printk(KERN_ERR"px is disconnected, failing IO.\n");
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	if (!pxd_dev->nfd) {
		pxd_printk("px has no backing path yet, should take slow path IO.\n");
		atomic_inc(&pxd_dev->nslowPath);
		return pxd_make_request_orig(q, bio);
	}

	pxd_printk("pxd_make_request for device %llu queueing with thread %d\n", pxd_dev->dev_id, thread);

	{ /* add congestion handling */
		spin_lock_irq(&pxd_dev->dlock);
		if (atomic_read(&pxd_dev->ncount) >= q->nr_congestion_on) {
			pxd_printk("Hit congestion... wait until clear\n");
			atomic_inc(&pxd_dev->ncongested);
			wait_event_lock_irq(pxd_dev->congestion_wait,
				atomic_read(&pxd_dev->ncount) < q->nr_congestion_off,
				pxd_dev->dlock);
			pxd_printk("congestion cleared\n");
		}

		spin_unlock_irq(&pxd_dev->dlock);

	}

	/* keep writes on same cpu, but allow reads to spread but within same numa node */
	if (rw == READ) {
		int node = cpu_to_node(cpu);
		thread = getnextcpu(node, atomic_add_return(1, &pxd_dev->index[node]));
	}
	tc = &pxd_dev->tc[thread];

	pxd_add_bio(tc, bio);
	wake_up(&tc->pxd_event);
	pxd_printk("pxd_make_request for device %llu done\n", pxd_dev->dev_id);
	return BLK_QC_RETVAL;
}
/***********************/
/***********************/

/* 
 * shall get called last when new device is added/updated or when fuse connection is lost 
 * and re-estabilished.
 */
static void initFile(struct pxd_device *pxd_dev, bool force) {
	struct file *f;
	struct inode *inode;
	int i;
	int nfd = pxd_dev->nfd;

	for (i=0; i<nfd; i++) {
		if (pxd_dev->file[i] > 0) { /* valid fd exists already */
			if (force) {
				filp_close(pxd_dev->file[i], NULL);
				f = filp_open(pxd_dev->device_path[i], O_DIRECT | O_LARGEFILE | O_RDWR, 0600);
				if (IS_ERR_OR_NULL(f)) {
					printk(KERN_ERR"Failed attaching path: device %llu, path %s err %ld\n",
						pxd_dev->dev_id, pxd_dev->device_path[i], PTR_ERR(f));
					goto out_file_failed;
				}
			} else {
				f = pxd_dev->file[i];
			}
		} else {
			f = filp_open(pxd_dev->device_path[i], O_DIRECT | O_LARGEFILE | O_RDWR, 0600);
			if (IS_ERR_OR_NULL(f)) {
				printk(KERN_ERR"Failed attaching path: device %llu, path %s err %ld\n",
					pxd_dev->dev_id, pxd_dev->device_path[i], PTR_ERR(f));
				goto out_file_failed;
			}
		}

		pxd_dev->file[i] = f;

		inode = f->f_inode;
		printk(KERN_INFO"device %lld:%d, inode %lu\n", pxd_dev->dev_id, i, inode->i_ino);
		if (S_ISREG(inode->i_mode)) {
			pxd_dev->block_device = false; /* override config to use file io */
			printk(KERN_INFO"device[%lld:%d] is a regular file - inode %lu\n",
					pxd_dev->dev_id, i, inode->i_ino);
		} else if (S_ISBLK(inode->i_mode)) {
			printk(KERN_INFO"device[%lld:%d] is a block device - inode %lu\n",
				pxd_dev->dev_id, i, inode->i_ino);
		} else {
			pxd_dev->block_device = false; /* override config to use file io */
			printk(KERN_INFO"device[%lld:%d] inode %lu unknown device %#x\n",
				pxd_dev->dev_id, i, inode->i_ino, inode->i_mode);
		}
	}

	printk(KERN_INFO"pxd_dev %llu setting up with %d backing volumes, [%p,%p,%p]\n",
		pxd_dev->dev_id, pxd_dev->nfd,
		pxd_dev->file[0], pxd_dev->file[1], pxd_dev->file[2]);

	return;

out_file_failed:
	pxd_dev->nfd = 0;
	for (i=0; i<nfd; i++) {
		if (pxd_dev->file[i] > 0) filp_close(pxd_dev->file[i], NULL);
	}
	memset(pxd_dev->file, 0, sizeof(pxd_dev->file));
	memset(pxd_dev->device_path, 0, sizeof(pxd_dev->device_path));
	printk(KERN_INFO"Device %llu no backing volume setup, will take slow path\n",
		pxd_dev->dev_id);
}

static void cleanupFile(struct pxd_device *pxd_dev) {
	int i;
	for (i=0; i<pxd_dev->nfd; i++) {
		filp_close(pxd_dev->file[i], NULL);
	}
	pxd_dev->nfd=0;
}

static int initBackingFsPath(struct pxd_device *pxd_dev) {
	int err=-EINVAL;

	printk(KERN_INFO"Number of cpu ids %d\n", MAX_THREADS);
	pxd_dev->bg_flush_enabled = false; // introduces high latency
	pxd_dev->n_flush_wrsegs = MAX_WRITESEGS_FOR_FLUSH;

	// congestion init
	init_waitqueue_head(&pxd_dev->congestion_wait);
	init_waitqueue_head(&pxd_dev->sync_event);
	spin_lock_init(&pxd_dev->sync_lock);
	atomic_set(&pxd_dev->sync_active, 0);
	atomic_set(&pxd_dev->nsync, 0);

	atomic_set(&pxd_dev->ncount,0);
	atomic_set(&pxd_dev->nslowPath,0);
	atomic_set(&pxd_dev->ncomplete,0);
	atomic_set(&pxd_dev->write_counter,0);
	pxd_dev->connected = 1;
	pxd_dev->offset = 0;

	pxd_dev->tc = kzalloc(MAX_THREADS * sizeof(struct thread_context), GFP_NOIO);
	if (!pxd_dev->tc) return -ENOMEM;

	err = initBIO(pxd_dev);
	if (err < 0) {
		return err;
	}

	initFile(pxd_dev, true);
	return 0;
}

static void cleanupBackingFsPath(struct pxd_device *pxd_dev) {
	cleanupFile(pxd_dev);
	cleanupBIO(pxd_dev);
	if (pxd_dev->tc) kfree(pxd_dev->tc);
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

		{
			struct file *file = getFile(pxd_dev, 0);
			struct inode    *inode;
			struct address_space *mapping;

			if (file) {
				mapping = file->f_mapping;
				inode = mapping->host;
				set_blocksize(bdev, S_ISBLK(inode->i_mode) ?  block_size(inode->i_bdev) : PAGE_SIZE);
			}
		}
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

static void pxd_update_stats(struct fuse_req *req, int rw, unsigned int count)
{
	struct pxd_device *pxd_dev = req->queue->queuedata;
	int cpu = part_stat_lock();
	part_stat_inc(cpu, &pxd_dev->disk->part0, ios[rw]);
	part_stat_add(cpu, &pxd_dev->disk->part0, sectors[rw], count);
	part_stat_unlock();
}

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

	printk(KERN_ERR"pxd_discard: off %llu, size %d\n", off, size);
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

static int pxd_init_disk(struct pxd_device *pxd_dev, struct pxd_add_out *add)
{
	struct gendisk *disk;
	struct request_queue *q;

	if (add->queue_depth < 0 || add->queue_depth > PXD_MAX_QDEPTH)
		return -EINVAL;

	/* Bypass queue if queue_depth is zero. */
	printk(KERN_INFO "Adding device %llu with queue_depth %u\n",
			pxd_dev->dev_id, add->queue_depth);
	q = blk_alloc_queue(GFP_KERNEL);
	if (!q)
		goto out_disk;
	blk_queue_make_request(q, pxd_make_request);

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

	if (pxd_dev->nfd) {
		struct file* file = getFile(pxd_dev, 0);
		struct address_space *mapping;
		gfp_t mapmask;
		struct inode *inode;

		mapping = file->f_mapping;
		inode = mapping->host;
		mapmask = mapping_gfp_mask(mapping);
		mapping_set_gfp_mask(mapping, mapmask & ~(__GFP_IO|__GFP_FS));

		if (mapping->a_ops->direct_IO)
			printk(KERN_INFO"direct IO supported\n");

		if (inode && inode->i_sb && inode->i_sb->s_bdev)
			printk(KERN_INFO"Backing logical block size %d\n", 
				bdev_logical_block_size(inode->i_sb->s_bdev));

		if (file->f_op->fsync)
			printk(KERN_INFO "backing device supports fsync\n");
	}

	set_capacity(disk, add->size / SECTOR_SIZE);

	/* Enable discard support. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, q);
	queue_flag_clear_unlocked(QUEUE_FLAG_NOMERGES, q);
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, q);
#else
	blk_queue_flag_set(QUEUE_FLAG_NONROT, q);
	blk_queue_flag_clear(QUEUE_FLAG_NOMERGES, q);
	blk_queue_flag_set(QUEUE_FLAG_DISCARD, q);
#endif

	q->limits.discard_granularity = PXD_LBS;
	q->limits.discard_alignment = PXD_LBS;
	if (add->discard_size) {
		printk(KERN_INFO"pxd_add with discard_size set to %d, max limited at %d\n",
			add->discard_size, MAX_DISCARD_SIZE);
		if (add->discard_size > MAX_DISCARD_SIZE)
			add->discard_size = MAX_DISCARD_SIZE;
	}
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

	cleanupFile(pxd_dev);
	pxd_dev->disk = NULL;
	if (disk->flags & GENHD_FL_UP) {
		del_gendisk(disk);
		if (disk->queue)
			blk_cleanup_queue(disk->queue);
	}
	put_disk(disk);

}

ssize_t pxd_add(struct fuse_conn *fc, struct pxd_add_out *add)
{
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	struct pxd_device *pxd_dev = NULL;
	struct pxd_device *pxd_dev_itr;
	int new_minor;
	int err;

	err = -ENODEV;
	if (!try_module_get(THIS_MODULE))
		goto out;

	err = -ENOMEM;
	if (ctx->num_devices >= PXD_MAX_DEVICES) {
		printk(KERN_ERR "Too many devices attached..\n");
		goto out_module;
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
	pxd_dev->size = add->size;
	pxd_dev->offset = add->offset;
	pxd_dev->block_device = add->block_device;
	pxd_dev->nfd = 0; // will take slow path, if additional info not provided.

	err = initBackingFsPath(pxd_dev);
	if (err) {
		printk(KERN_ERR"Initializing backing volumes for pxd failed %d\n", err);
		goto out_disk;
	}

	err = pxd_init_disk(pxd_dev, add);
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

ssize_t pxd_update_path(struct fuse_conn *fc, struct pxd_update_path_out *update_path)
{
	bool found = false;
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	int err;
	struct pxd_device *pxd_dev;
	int i;
	struct file* f;

	spin_lock(&ctx->lock);
	list_for_each_entry(pxd_dev, &ctx->list, node) {
		if ((pxd_dev->dev_id == update_path->dev_id) && !pxd_dev->removing) {
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

	for (i=0; i<update_path->size; i++) {
		if (!strcmp(pxd_dev->device_path[i], update_path->devpath[i])) {
			// If previous paths are same.. then skip anymore config.
			printk(KERN_INFO"pxd%llu already configured for path %s\n",
				pxd_dev->dev_id, pxd_dev->device_path[i]);
			continue;
		}

		if (pxd_dev->file[i] > 0) filp_close(pxd_dev->file[i], NULL);

		f = filp_open(update_path->devpath[i], O_DIRECT | O_LARGEFILE | O_RDWR, 0600);
		if (IS_ERR_OR_NULL(f)) {
			printk(KERN_ERR"Failed attaching path: device %llu, path %s err %ld\n",
				pxd_dev->dev_id, update_path->devpath[i], PTR_ERR(f));
			goto out_file_failed;
		}

		pxd_dev->file[i] = f;
		strcpy(pxd_dev->device_path[i], update_path->devpath[i]);
	}
	pxd_dev->nfd = update_path->size;

	/* setup whether the access is block access or file access */
	initFile(pxd_dev, false);

	spin_unlock(&pxd_dev->dlock);

	printk(KERN_INFO"Success attaching path to device %llu [nfd:%d]\n",
		pxd_dev->dev_id, pxd_dev->nfd);
	return 0;

out_file_failed:
	for (i=0; i<pxd_dev->nfd; i++) {
		if (pxd_dev->file[i] > 0) filp_close(pxd_dev->file[i], NULL);
	}
	pxd_dev->nfd = 0;
	memset(pxd_dev->file, 0, sizeof(pxd_dev->file));
	memset(pxd_dev->device_path, 0, sizeof(pxd_dev->device_path));
out:
	if (found) spin_unlock(&pxd_dev->dlock);
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

static ssize_t pxd_mode_show(struct device *dev,
		     struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "mode:%s\n", mode);
}

static ssize_t pxd_active_show(struct device *dev,
                     struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	char *cp = buf;
	int ncount;
	int available=PAGE_SIZE-1;

	ncount=snprintf(cp, available, "nactive: %u/%u, slowpath: %u\n",
                atomic_read(&pxd_dev->ncount), atomic_read(&pxd_dev->ncomplete), atomic_read(&pxd_dev->nslowPath));

	return ncount;
}

static ssize_t pxd_sync_show(struct device *dev,
                     struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	return sprintf(buf, "sync: %u/%u %s\n",
			atomic_read(&pxd_dev->sync_active),
			atomic_read(&pxd_dev->nsync),
			(pxd_dev->bg_flush_enabled ? "(enabled)" : "(disabled)"));
}

static ssize_t pxd_sync_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	int enable = 0;

	sscanf(buf, "%d", &enable);

	if (enable) {
		pxd_dev->bg_flush_enabled = 1;
	} else {
		pxd_dev->bg_flush_enabled = 0;
	}

	return count;
}

static ssize_t pxd_wrsegment_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	return sprintf(buf, "write segment size(bytes): %d\n", pxd_dev->n_flush_wrsegs * PXD_LBS);
}

static ssize_t pxd_wrsegment_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	int nbytes, nsegs;

	sscanf(buf, "%d", &nbytes);

	nsegs = nbytes/PXD_LBS; // num of write segments
	if (nsegs < MAX_WRITESEGS_FOR_FLUSH) {
		nsegs = MAX_WRITESEGS_FOR_FLUSH;
	}

	pxd_dev->n_flush_wrsegs = nsegs;
	return count;
}

static ssize_t pxd_congestion_show(struct device *dev,
                     struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	struct request_queue *q = pxd_dev->disk->queue;

	bool congested = atomic_read(&pxd_dev->ncount) >= q->nr_congestion_on;
	return sprintf(buf, "congested: %d/%d\n", congested, atomic_read(&pxd_dev->ncongested));
}

static ssize_t pxd_congestion_clear(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);

	// debug interface to force wakeup of congestion wait threads 
	wake_up(&pxd_dev->congestion_wait);
	return count;
}

static ssize_t pxd_replicate_show(struct device *dev,
                     struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	int i;
	char *cp = buf;
	int cnt=0;

	for (i=0; i<pxd_dev->nfd; i++) {
		int c=sprintf(cp, "device[%d]: %p\n", i, pxd_dev->file[i]);
		cp+=c;
		cnt+=c;
	}

	return cnt;
}

// debug interface to configure replicate device to a pxd_device
static ssize_t pxd_replicate_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	char replicate[MAX_PXD_DEVPATH_LEN];
	struct file *f;

	if (pxd_dev->nfd >= MAX_PXD_BACKING_DEVS) {
		printk(KERN_ERR"Maximum replicate volumes configured for device %lld\n", pxd_dev->dev_id);
		goto hack_out;
	}

	sscanf(buf, "%s", replicate);
	printk(KERN_ERR"Parent device %lld, device path %s\n", pxd_dev->dev_id, replicate);

	/* look for configuring an device given as path as a replicate volume */
	f = filp_open(replicate, O_DIRECT | O_LARGEFILE | O_RDWR, 0600);
	if (IS_ERR_OR_NULL(f)) {
		printk(KERN_ERR"Failed opening replicate device at path %s err %ld\n",
				replicate, PTR_ERR(f));
		goto hack_out;
	}

	spin_lock_irq(&pxd_dev->dlock);
	pxd_dev->file[pxd_dev->nfd] = f;
	strcpy(pxd_dev->device_path[pxd_dev->nfd], replicate);
	pxd_dev->nfd++;
	initFile(pxd_dev, false);
	spin_unlock_irq(&pxd_dev->dlock);
	printk(KERN_INFO"Success attaching replicate device %s to device %lld [nfd:%d]\n",
		replicate, pxd_dev->dev_id, pxd_dev->nfd);
hack_out:
	return count;
}


static DEVICE_ATTR(size, S_IRUGO, pxd_size_show, NULL);
static DEVICE_ATTR(major, S_IRUGO, pxd_major_show, NULL);
static DEVICE_ATTR(minor, S_IRUGO, pxd_minor_show, NULL);
static DEVICE_ATTR(timeout, S_IRUGO|S_IWUSR, pxd_timeout_show, pxd_timeout_store);
static DEVICE_ATTR(mode, S_IRUGO, pxd_mode_show, NULL);
static DEVICE_ATTR(active, S_IRUGO, pxd_active_show, NULL);
static DEVICE_ATTR(sync, S_IRUGO|S_IWUSR, pxd_sync_show, pxd_sync_store);
static DEVICE_ATTR(congested, S_IRUGO|S_IWUSR, pxd_congestion_show, pxd_congestion_clear);
static DEVICE_ATTR(replicate, S_IRUGO|S_IWUSR, pxd_replicate_show, pxd_replicate_store);
static DEVICE_ATTR(writesegment, S_IRUGO|S_IWUSR, pxd_wrsegment_show, pxd_wrsegment_store);

static struct attribute *pxd_attrs[] = {
	&dev_attr_size.attr,
	&dev_attr_major.attr,
	&dev_attr_minor.attr,
	&dev_attr_timeout.attr,
	&dev_attr_mode.attr,
	&dev_attr_active.attr,
	&dev_attr_sync.attr,
	&dev_attr_congested.attr,
	&dev_attr_replicate.attr,
	&dev_attr_writesegment.attr,
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

	printk(KERN_INFO"CPU %d/%d, NUMA nodes %d/%d\n", nr_cpu_ids, NR_CPUS, nr_node_ids, MAX_NUMNODES);
	node_cpu_map = kzalloc(sizeof(struct node_cpu_map) * nr_node_ids, GFP_NOIO|GFP_KERNEL);
	if (!node_cpu_map) {
		printk(KERN_ERR "pxd: failed to initialize node_cpu_map: -ENOMEM\n");
		goto out_sysfs;
	}

	for (i=0; i<nr_cpu_ids; i++) {
		struct node_cpu_map *map=&node_cpu_map[cpu_to_node(i)];
		map->cpu[map->ncpu++] = i;
	}

	return 0;

out_sysfs:
	pxd_sysfs_exit();

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

	if (node_cpu_map) kfree(node_cpu_map);

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
