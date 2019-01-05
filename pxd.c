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

#define MAX_WRITESEGS_FOR_FLUSH ((16*SEGMENT_SIZE)/PXD_LBS)

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && defined(USE_REQUEST_QUEUE)
static char *mode = "blk-mq";
#define DRIVER_MODE_BLKMQ
struct pxd_mq_rqcmd {
    struct kthread_work work;
    struct request *rq;
    bool use_aio; /* use AIO interface to handle I/O */
    atomic_t ref; /* only for aio */
    long ret;
    struct kiocb iocb;
    struct bio_vec *bvec;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0) 
    struct cgroup_subsys_state *css;
#endif
};
#elif defined(USE_REQUEST_QUEUE)
static char *mode = "blk-rq";
struct thread_context {
	struct pxd_device  *pxd_dev;
	struct task_struct *pxd_thread;
	wait_queue_head_t   pxd_event;
	spinlock_t  		lock;
	struct list_head waiting_queue;
};
#else
static char *mode = "blk-bio";
struct thread_context {
	struct pxd_device  *pxd_dev;
	struct task_struct *pxd_thread;
	wait_queue_head_t   pxd_event;
	spinlock_t  		lock;
	struct bio_list  bio_list;
};
#endif

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
	bool aio; // async io path - experimental

	int nfd;
	struct file *file[MAX_FD_PER_PXD];

	// HACK code not needed eventually
	char device_path[64];
	int pool_id;
	uint64_t mirror; // mirror device id

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && defined(USE_REQUEST_QUEUE)
	struct blk_mq_tag_set   tag_set;
	struct kthread_worker   worker;
	struct task_struct  *worker_task;
#else
	struct thread_context *tc;
#endif
	wait_queue_head_t   congestion_wait;
	wait_queue_head_t   sync_event;
	spinlock_t   	sync_lock;
	atomic_t sync_active; // currently active?
	atomic_t nsync; // number of forced syncs completed
	atomic_t ncount; // total active requests
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
static int initFile(struct pxd_device *pxd_dev, bool);
static void cleanupFile(struct pxd_device *pxd_dev);

/* when request queeuing model is used on version 4.12+, block mq model
 * is used to process IO and requests are never punted over fuse.
 */
#if !defined(USE_REQUEST_QUEUE) || LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
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
#endif

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


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && defined(USE_REQUEST_QUEUE)
	/* Shall use block mq request mechanism */
static
void pxd_rw_aio_do_completion(struct pxd_mq_rqcmd *cmd) {
	if (!atomic_dec_and_test(&cmd->ref))
		return;

	kfree(cmd->bvec);
	cmd->bvec = NULL;
	blk_mq_complete_request(cmd->rq);
}

static
void pxd_rw_aio_complete(struct kiocb *iocb, long ret, long ret2)
{
	struct pxd_mq_rqcmd *cmd = container_of(iocb, struct pxd_mq_rqcmd, iocb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	if (cmd->css) css_put(cmd->css);
#endif

	cmd->ret = ret;
	pxd_rw_aio_do_completion(cmd);
}

static int pxd_rw_aio(struct pxd_device *pxd_dev,
		struct pxd_mq_rqcmd *cmd, loff_t pos, bool rw) {
	struct iov_iter iter;
	struct bio_vec *bvec;
	struct request *rq = cmd->rq;
	struct bio *bio = rq->bio;
	struct file *file = pxd_dev->file;
	unsigned int offset;
	int segments = 0;
	int ret;

	if (rq->bio != rq->biotail) {
		struct req_iterator iter;
		struct bio_vec tmp;

		__rq_for_each_bio(bio, rq)
			segments += bio_segments(bio);

		bvec = kmalloc(sizeof(struct bio_vec) * segments, GFP_NOIO);
		if (!bvec)
			return -EIO;
		cmd->bvec = bvec;

        /*
         * The bios of the request may be started from the middle of
         * the 'bvec' because of bio splitting, so we can't directly
         * copy bio->bi_iov_vec to new bvec. The rq_for_each_segment
         * API will take care of all details for us.
         */
		rq_for_each_segment(tmp, rq, iter) {
			*bvec = tmp;
			bvec++;
		}
		bvec = cmd->bvec;
		offset = 0;
	} else {
        /*
         * Same here, this bio may be started from the middle of the
         * 'bvec' because of bio splitting, so offset from the bvec
         * must be passed to iov iterator
         */
		offset = bio->bi_iter.bi_bvec_done;
		bvec = __bvec_iter_bvec(bio->bi_io_vec, bio->bi_iter);
		segments = bio_segments(bio);
    }

    atomic_set(&cmd->ref, 2);

	iov_iter_bvec(&iter, ITER_BVEC | rw, bvec,
              segments, blk_rq_bytes(rq));
    iter.iov_offset = offset;

	cmd->iocb.ki_pos = pos;
	cmd->iocb.ki_filp = file;
    cmd->iocb.ki_complete = pxd_rw_aio_complete;
    cmd->iocb.ki_flags = iocb_flags(file);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
    if (cmd->css)
        kthread_associate_blkcg(cmd->css);
#endif

	if (rw == WRITE) {
		atomic_add(segments, &pxd_dev->write_counter);
		ret = call_write_iter(file, &cmd->iocb, &iter);
	} else {
		ret = call_read_iter(file, &cmd->iocb, &iter);
	}

	pxd_rw_aio_do_completion(cmd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
    kthread_associate_blkcg(NULL);
#endif

    if (ret != -EIOCBQUEUED)
        cmd->iocb.ki_complete(&cmd->iocb, ret, 0);
    return 0;
}
#endif

#ifndef USE_REQUEST_QUEUE
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
#else
static int _pxd_req_discard(struct pxd_device *pxd_dev, struct request *rq, loff_t pos) {
	struct file *file;
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	int ret;
	int i;

	for (i=0; i<pxd_dev->nfd; i++) {
		file = getFile(pxd_dev, i);
		if (!file->f_op->fallocate) {
			return -EOPNOTSUPP;
		}
		ret = file->f_op->fallocate(file, mode, pos, blk_rq_bytes(rq));
		if (unlikely(ret && ret != -EINVAL && ret != -EOPNOTSUPP)) {
			return -EIO;
		}
	}
	return 0;
}
#endif

#ifdef DIO
/* Shall use block mq request mechanism */
struct aio_cmd {
	atomic_t ref; /* only for aio */
	struct kiocb iocb;
	struct bio *bio;  /* original bio */
	struct bio_vec *bvec;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	struct cgroup_subsys_state *css;
#endif
};

static
void pxd_rw_aio_do_completion(struct aio_cmd *cmd, int ret) {
	struct bio *bio;
	if (!atomic_dec_and_test(&cmd->ref))
		return;

	//TODO
	//if (cmd is ReAD, and ret is num of bytes, then advance bio and zero fill)
	bio = cmd->bio;
	kfree(cmd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
	if (ret) {
		bio_io_error(bio);
	} else {
		bio_endio(bio);
	}
#else
	bio_endio(bio, ret);
#endif
}

static
void pxd_rw_aio_complete(struct kiocb *iocb, long ret, long ret2)
{
	struct aio_cmd *cmd = container_of(iocb, struct aio_cmd, iocb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	if (cmd->css) css_put(cmd->css);
#endif

	pxd_rw_aio_do_completion(cmd, ret);
}

static int pxd_rw_aio(struct pxd_device *pxd_dev,
		struct bio *bio, loff_t pos, bool rw) {
	struct iov_iter iter;
	struct file *file = pxd_dev->file;
	unsigned int offset;
	int segments = 0;
	int ret;
	unsigned nbytes = 0;

	struct bio_vec *bvec;
	struct bvec_iter bvec_iter;

	struct aio_cmd *cmd = kmalloc(sizeof(aio_cmd), GFP_NOIO|GFP_KERNEL);
	if (!cmd) {
		bio_io_error(bio);
		return;
	}
	cmd->bio = bio;

        /*
         * Same here, this bio may be started from the middle of the
         * 'bvec' because of bio splitting, so offset from the bvec
         * must be passed to iov iterator
         */
	offset = bio->bi_iter.bi_bvec_done;
	bio_for_each_segment(bvec, bio, bvec_iter) {
		segments++;
		nbytes += bvec_iter_len(bvec);
	}
	bvec = __bvec_iter_bvec(bio->bi_io_vec, bio->bi_iter);

	atomic_set(&cmd->ref, 2);
	iov_iter_bvec(&iter, ITER_BVEC | rw, bvec, segments, nbytes);
	iter.iov_offset = offset;

	cmd->iocb.ki_pos = pos;
	cmd->iocb.ki_filp = file;
	cmd->iocb.ki_complete = pxd_rw_aio_complete;
	cmd->iocb.ki_flags = iocb_flags(file);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	if (cmd->css)
		kthread_associate_blkcg(cmd->css);
#endif

	if (rw == WRITE) {
		atomic_add(segments, &pxd_dev->write_counter);
		ret = call_write_iter(file, &cmd->iocb, &iter);
	} else {
		ret = call_read_iter(file, &cmd->iocb, &iter);
	}

	pxd_rw_aio_do_completion(cmd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	kthread_associate_blkcg(NULL);
#endif

	if (ret != -EIOCBQUEUED)
		cmd->iocb.ki_complete(&cmd->iocb, ret, 0);
	return 0;
}
#endif

static int _pxd_write(struct file *file, struct bio_vec *bvec, loff_t *pos)
{
	ssize_t bw;
	mm_segment_t old_fs = get_fs();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct iov_iter i;
#else
	void *kaddr = kmap(bvec->bv_page) + bvec->bv_offset;
#endif

	pxd_printk("_pxd_write entry buf %p offset %lld, length %d entered\n",
                kaddr, *pos, bvec->bv_len);

	if (bvec->bv_len != PXD_LBS) {
		printk(KERN_ERR"Unaligned block writes %d bytes\n", bvec->bv_len);
	}
	set_fs(get_ds());
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
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

#ifdef USE_REQUEST_QUEUE
static int do_pxd_write(struct pxd_device *pxd_dev, struct request *rq, loff_t pos) {
	struct req_iterator iter;
	int ret = 0;
	int nsegs = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;

	pxd_printk("do_pxd_write entry pos %lld length %d entered\n", pos, blk_rq_bytes(rq));
	rq_for_each_segment(bvec, rq, iter) {
		nsegs++;
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
		nsegs++;
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
	atomic_add(nsegs, &pxd_dev->write_counter);
	return 0;
}

#else
static unsigned getsectors(struct bio *bio) {
	unsigned nbytes = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif

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
#endif

static
ssize_t _pxd_read(struct file *file, struct bio_vec *bvec, loff_t *pos) {
	int result;

    /* read from file at offset pos into the buffer */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	struct iov_iter i;

	iov_iter_bvec(&i, ITER_BVEC, bvec, 1, bvec->bv_len);
	result = vfs_iter_read(file, &i, pos, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct iov_iter i;

	iov_iter_bvec(&i, ITER_BVEC, bvec, 1, bvec->bv_len);
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

#ifdef USE_REQUEST_QUEUE
static ssize_t do_pxd_read(struct pxd_device *pxd_dev, struct request *rq, loff_t pos) {
	struct req_iterator iter;
	ssize_t len = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	pxd_printk("do_pxd_read entry pos %lld length %d entered\n", pos, blk_rq_bytes(rq));

	rq_for_each_segment(bvec, rq, iter) {
		len = _pxd_read(getFile(pxd_dev, 0), &bvec, &pos);
		if (len < 0) return len;

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
		len = _pxd_read(getFile(pxd_dev,0), bvec, &pos);

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
#else
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

#endif

static void _pxd_setup(struct pxd_device *pxd_dev, bool enable) {
	if (!enable) {
		printk(KERN_ERR "_pxd_setup called to disable IO\n");
		pxd_dev->connected = false;
	} else {
		printk(KERN_ERR "_pxd_setup called to enable IO\n");
	}

#ifndef USE_REQUEST_QUEUE
	if (enable) {
		spin_lock_irq(&pxd_dev->dlock);
		initFile(pxd_dev, true);
		spin_unlock_irq(&pxd_dev->dlock);
	}
#else
	if (enable) {
		spin_lock_irq(&pxd_dev->qlock);
		initFile(pxd_dev, true);
		spin_unlock_irq(&pxd_dev->qlock);
	}
#endif

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


#ifndef USE_REQUEST_QUEUE
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
	unsigned long startTime = jiffies;

	if (shouldClose) {
		printk(KERN_ERR"px is disconnected, failing IO.\n");
		bio_io_error(bio);
		return;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	generic_start_io_acct(tc->pxd_dev->disk->queue, bio_op(bio), getsectors(bio), &tc->pxd_dev->disk->part0);
#else
	generic_start_io_acct(bio_data_dir(bio), getsectors(bio), &tc->pxd_dev->disk->part0);
#endif

	ret = do_bio_filebacked(tc, bio);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	generic_end_io_acct(tc->pxd_dev->disk->queue, bio_op(bio), &tc->pxd_dev->disk->part0, startTime);
#else
	generic_end_io_acct(bio_data_dir(bio), &tc->pxd_dev->disk->part0, startTime);
#endif
	atomic_inc(&tc->pxd_dev->ncomplete);

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
				tc->pxd_dev->dev_id, atomic_read(&pxd_dev->ncount));

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


#else /* USE_REQUEST_QUEUE */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	/* Shall use block mq request mechanism */

static int pxd_kthread_worker_fn(void *worker_ptr) 
{
    current->flags |= PF_LESS_THROTTLE;
    return kthread_worker_fn(worker_ptr);
}

static int initReqQ(struct pxd_device *pxd_dev) {
	kthread_init_worker(&pxd_dev->worker);
	pxd_dev->worker_task = kthread_run(pxd_kthread_worker_fn,
			&pxd_dev->worker, "pxd:%lld", pxd_dev->dev_id);
	if (IS_ERR(pxd_dev->worker_task))
		return -ENOMEM;
	set_user_nice(pxd_dev->worker_task, MIN_NICE);
	return 0;
}

static void cleanupReqQ(struct pxd_device *pxd_dev) {
	kthread_flush_worker(&pxd_dev->worker);
	kthread_stop(pxd_dev->worker_task);
}

#else 
static void pxd_end_request(struct thread_context *tc, struct request *rq, int err)
{
	atomic_inc(&tc->pxd_dev->ncomplete);
	blk_end_request_all(rq, err);
}

static inline void pxd_handle_req(struct thread_context *tc, struct request *req, bool shouldClose)
{
	struct pxd_device *pxd_dev = tc->pxd_dev;
	loff_t pos = ((loff_t) blk_rq_pos(req) << 9) + pxd_dev->offset;
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
		ret = _pxd_flush(tc->pxd_dev);
	} else if (rq_data_dir(req) == WRITE) {
		if ((req->cmd_flags & REQ_DISCARD)) {
			/* handle discard */
			pxd_printk("do discard... sector %lu, bytes %d\n", blk_rq_pos(req), blk_rq_bytes(req));
			ret=_pxd_req_discard(tc->pxd_dev,req,pos);
		} else {
			/* handle write */
			pxd_printk("do write... sector %lu, bytes %d\n", blk_rq_pos(req), blk_rq_bytes(req));
			/* Before any newer writes happen, make sure previous write/sync complete */
			pxd_check_write_cache_flush(pxd_dev);

			ret=do_pxd_write(tc->pxd_dev,req,pos);
			if ((req->cmd_flags & REQ_FUA) && !ret) {
				ret = _pxd_flush(tc->pxd_dev);
			}
		}
	} else {
		/* handle read */
		pxd_printk("do read... sector %lu, bytes %d\n", blk_rq_pos(req), blk_rq_bytes(req));
		ret=do_pxd_read(tc->pxd_dev, req,pos);
	}

	pxd_end_request(tc, req, ret);
	return;
error_out:
	pxd_end_request(tc, req, -EIO);
}

static void pxd_add_rq(struct thread_context *tc, struct request *rq) {
	atomic_inc(&tc->pxd_dev->ncount);

	spin_lock_irq(&tc->lock);
	list_add_tail(&rq->queuelist, &tc->waiting_queue);
	spin_unlock_irq(&tc->lock);
}

static struct request* pxd_get_rq(struct thread_context *tc, bool *shouldClose) {
	struct request* req;

	atomic_dec(&tc->pxd_dev->ncount);

	spin_lock_irq(&tc->lock);
	*shouldClose = !tc->pxd_dev->connected;
	req = list_entry(tc->waiting_queue.next, struct request, queuelist);
	list_del_init(&req->queuelist);
	spin_unlock_irq(&tc->lock);

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
			tc->pxd_dev->dev_id, atomic_read(&tc->pxd_dev->ncount));

		req = pxd_get_rq(tc, &shouldClose);
		BUG_ON(!req);

		spin_lock_irq(&tc->pxd_dev->dlock);
		if (atomic_read(&tc->pxd_dev->ncount) < tc->pxd_dev->disk->queue->nr_congestion_off) {
			wake_up(&tc->pxd_dev->congestion_wait);
		}
		spin_unlock_irq(&tc->pxd_dev->dlock);

		pxd_handle_req(tc, req, shouldClose);
	}
	return 0;
}

static int initReqQ(struct pxd_device *pxd_dev) {
	int i;

	for (i=0; i<MAX_THREADS; i++) {
		struct thread_context *tc = &pxd_dev->tc[i];
		tc->pxd_dev = pxd_dev;
		spin_lock_init(&tc->lock);
		init_waitqueue_head(&tc->pxd_event);
		INIT_LIST_HEAD(&tc->waiting_queue);
		tc->pxd_thread = kthread_create_on_node(pxd_io_thread, tc,
				cpu_to_node(i),
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

static void cleanupReqQ(struct pxd_device *pxd_dev) {
	int i;
	for (i=0; i<MAX_THREADS; i++) {
		struct thread_context *tc = &pxd_dev->tc[i];
		kthread_stop(tc->pxd_thread);
	}
}

#endif
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
STATIC blk_qc_t pxd_make_request_orig(struct request_queue *q, struct bio *bio) __deprecated
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
STATIC void pxd_make_request_orig(struct request_queue *q, struct bio *bio) __deprecated
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
#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	/* shall use block multiqueue mechanism */
#else 
/***********************/
/***********************/
// called wth qlock released
static
void pxd_rq_fn_kernel(struct pxd_device *pxd_dev, struct request_queue *q, struct request *req) {
	u64 sect_num, sect_cnt;
	int thread = smp_processor_id() % MAX_THREADS;
	struct thread_context *tc;

	tc = &pxd_dev->tc[thread];
	sect_num = blk_rq_pos(req);
	/* deal whole segments */
	sect_cnt = blk_rq_sectors(req);

	pxd_printk("pxd_rq_fn_kernel device %llu, sector %llu, count %llu, cmd_type %d, dir %d\n",
			pxd_dev->dev_id, sect_num, sect_cnt, req->cmd_type, req_data_dir(req));

	if (unlikely(req->cmd_type != REQ_TYPE_FS)) {
		printk(KERN_ERR"%s: bad access: cmd_type %x not fs\n",
			req->rq_disk->disk_name, req->cmd_type);
		__blk_end_request_all(req, -EIO);
		return;
	}

	pxd_add_rq(tc, req);
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
#endif
/***********************/
/***********************/

/* 
 * NOTE
 * Below is a hack to find the backing file/device.. proper ioctl interface
 * extension and argument submission should happen from px-storage!!
 */
static int initFile(struct pxd_device *pxd_dev, bool force) {
	struct inode *inode;
	int i;

	/* no hack needed if fds are passed */
	if (pxd_dev->nfd) {
		for (i=0; i<pxd_dev->nfd; i++) {
			struct file *f = pxd_dev->file[i];
			if (!f) {
				printk(KERN_ERR"fd file[fd=%d] invalid", i);
				return -EINVAL;
			}
			inode = f->f_inode;
			printk(KERN_WARNING"device %lld:%d, inode %lu\n",
				pxd_dev->dev_id, i, inode->i_ino);

			if (S_ISREG(inode->i_mode)) {
				pxd_dev->block_device = false;
				printk(KERN_INFO"device[%lld:%d] is a regular file - inode %lu\n",
					pxd_dev->dev_id, i, inode->i_ino);
			} else if (S_ISBLK(inode->i_mode)) {
				pxd_dev->block_device = true;
				printk(KERN_INFO"device[%lld:%d] is a block device - inode %lu\n",
					pxd_dev->dev_id, i, inode->i_ino);
			} else {
				printk(KERN_INFO"device[%lld:%d] inode %lu unknown device %#x\n",
					pxd_dev->dev_id, i, inode->i_ino, inode->i_mode);
			}
		}
		return 0;
	}

	printk(KERN_ERR"Failed for device %llu no backing file found\n", pxd_dev->dev_id);
	return -ENODEV;
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

	if (!pxd_dev->nfd) { /* hack code begins */
#define BASEDIR "/var/.px"
#define BTRFSVOLFMT  "%s/%d/%llu/pxdev"
#define DMTHINVOLFMT "/dev/mapper/pxvg%d-%llu"
#define MAXPOOL (5)
	int pool;
	char newPath[64];
	struct file* f;

	printk(KERN_INFO"pxd_dev device Id %lld hack code entered..\n",
			pxd_dev->dev_id);

	for (pool=0; pool<MAXPOOL; pool++) {
#ifdef DMTHINPOOL
		sprintf(newPath, DMTHINVOLFMT, pool, pxd_dev->dev_id);
#else
		sprintf(newPath, BTRFSVOLFMT, BASEDIR, pool, pxd_dev->dev_id);
#endif

#ifdef USE_DIO
		f = filp_open(newPath, O_DIRECT | O_LARGEFILE | O_RDWR, 0600);
#else
		f = filp_open(newPath, O_LARGEFILE | O_RDWR, 0600);
#endif
		if (IS_ERR_OR_NULL(f)) {
			printk(KERN_ERR"Failed device %llu at path %s err %ld\n",
				pxd_dev->dev_id, newPath, PTR_ERR(f));
			continue;
		}

		printk(KERN_INFO"Success device %llu backing file %s\n",
					pxd_dev->dev_id, newPath);

		strcpy(pxd_dev->device_path, newPath);
		pxd_dev->nfd = 1;
		pxd_dev->file[0] = f;
		err = 0;
		break;
	}

	if (err) {
		printk(KERN_ERR"Setting up fd for backing file (hack) failed\n");
		return -EINVAL;
	}
	printk(KERN_INFO"pxd_dev device Id %lld hack code success exit..\n", pxd_dev->dev_id);
	} /* hack code for configuring pxd volume from path search */

	{ /* hack code for configuring mirror volumes */
	struct pxd_device *mirror_dev;
	struct pxd_context *ctx = pxd_dev->ctx;
	struct list_head *cur;
	char newPath[64];
	struct file *f;
	int pool;

	if (pxd_dev->nfd >= MAX_FD_PER_PXD) {
		printk(KERN_ERR"Maximum mirrors configured for device %lld\n", pxd_dev->dev_id);
		goto hack_out;
	}

	mirror_dev = NULL;
	spin_lock(&ctx->lock);
	list_for_each(cur, &ctx->list) {
		struct pxd_device *pxd = container_of(cur, struct pxd_device, node);

		if (pxd->mirror == pxd_dev->dev_id) {
			/* configure this pxd as a mirror */
			mirror_dev = pxd;
			break;
		}
	}
	spin_unlock(&ctx->lock);

	if (!mirror_dev) {
		printk(KERN_ERR"No mirror device for id %lld, probably need attaching\n", pxd_dev->dev_id);
		goto hack_out;
	}

	for (pool=0; pool<MAXPOOL; pool++) {
		sprintf(newPath, BTRFSVOLFMT, BASEDIR, pool, mirror_dev->dev_id);
		f = filp_open(newPath, O_LARGEFILE | O_RDWR, 0600);
		if (IS_ERR_OR_NULL(f)) {
			printk(KERN_ERR"Failed mirror device %llu at path %s err %ld\n",
				mirror_dev->dev_id, newPath, PTR_ERR(f));
			continue;
		}

		spin_lock_irq(&pxd_dev->dlock);
		pxd_dev->file[pxd_dev->nfd] = f;
		pxd_dev->nfd++;
		spin_unlock_irq(&pxd_dev->dlock);
		printk(KERN_INFO"Success attaching mirror device %llu to device %lld [nfd:%d]\n",
			mirror_dev->dev_id, pxd_dev->dev_id, pxd_dev->nfd);
		goto hack_out;
	}

	printk(KERN_INFO"Unexpected failed finding mirror device %llu from file path\n",
			pxd_dev->dev_id);
	} /* hack code ends */
hack_out:

	printk(KERN_INFO"pxd_dev add setting up with %d backing devices, [%p,%p,%p]\n",
		pxd_dev->nfd, pxd_dev->file[0], pxd_dev->file[1], pxd_dev->file[2]);

	// congestion init
	init_waitqueue_head(&pxd_dev->congestion_wait);
	init_waitqueue_head(&pxd_dev->sync_event);
	spin_lock_init(&pxd_dev->sync_lock);
	atomic_set(&pxd_dev->sync_active, 0);
	atomic_set(&pxd_dev->nsync, 0);

	atomic_set(&pxd_dev->ncount,0);
	atomic_set(&pxd_dev->ncomplete,0);
	atomic_set(&pxd_dev->write_counter,0);
	pxd_dev->connected = 1;
	pxd_dev->offset = 0;

#ifndef DRIVER_MODE_BLKMQ
	pxd_dev->tc = kzalloc(MAX_THREADS * sizeof(struct thread_context), GFP_NOIO);
	if (!pxd_dev->tc) return -ENOMEM;
#endif

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

	return initFile(pxd_dev, true);
}

static void cleanupBackingFsPath(struct pxd_device *pxd_dev) {
	cleanupFile(pxd_dev);

#ifndef USE_REQUEST_QUEUE
	cleanupBIO(pxd_dev);
#else
	cleanupReqQ(pxd_dev);
#endif

#ifndef DRIVER_MODE_BLKMQ
	if (pxd_dev->tc) kfree(pxd_dev->tc);
#endif
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

#if !defined(USE_REQUEST_QUEUE) || LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
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
#endif

#ifdef USE_REQUEST_QUEUE

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	/* shall use block multiqueue mechanism */
static int do_req_filebacked(struct pxd_device *pxd_dev, struct request *rq)
{
	struct pxd_mq_rqcmd *cmd = blk_mq_rq_to_pdu(rq);
	loff_t pos = ((loff_t) blk_rq_pos(rq) << 9) + pxd_dev->offset;
	bool shouldClose = !pxd_dev->connected;

	if (shouldClose) {
		printk(KERN_ERR"px is disconnected, failing IO.\n");
		return -ENXIO;
	}

	switch (req_op(rq)) {
	case REQ_OP_FLUSH:
		return _pxd_flush(pxd_dev);
	case REQ_OP_DISCARD:
	case REQ_OP_WRITE_ZEROES:
		return _pxd_req_discard(pxd_dev,rq,pos);
	case REQ_OP_WRITE:
		/* Before any newer writes happen, make sure previous write/sync complete */
		pxd_check_write_cache_flush(pxd_dev);
		if (cmd->use_aio) {
			return pxd_rw_aio(pxd_dev, cmd, pos, WRITE);
		}
		return do_pxd_write(pxd_dev, rq, pos);
	case REQ_OP_READ:
		if (cmd->use_aio)
			return pxd_rw_aio(pxd_dev, cmd, pos, READ);
		return do_pxd_read(pxd_dev, rq, pos);
	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
}

static void pxd_handle_cmd(struct pxd_mq_rqcmd *cmd)
{
	struct pxd_device *pxd_dev = cmd->rq->q->queuedata;
	int ret = 0;

	ret = do_req_filebacked(pxd_dev, cmd->rq);
	/* complete non-aio request */
	if (!cmd->use_aio || ret) {
		atomic_inc(&pxd_dev->ncomplete);
		cmd->ret = ret ? -EIO : 0;
		blk_mq_complete_request(cmd->rq);
	}
}

static void pxd_queue_work(struct kthread_work *work)
{
    struct pxd_mq_rqcmd *cmd =
        container_of(work, struct pxd_mq_rqcmd, work);

    pxd_handle_cmd(cmd);
}

static blk_status_t pxd_queue_rq(struct blk_mq_hw_ctx *hctx,
        const struct blk_mq_queue_data *bd)
{
	struct pxd_mq_rqcmd *cmd = blk_mq_rq_to_pdu(bd->rq);
	struct pxd_device *pxd_dev = cmd->rq->q->queuedata;

	blk_mq_start_request(bd->rq);

	switch (req_op(cmd->rq)) {
	case REQ_OP_FLUSH:
	case REQ_OP_DISCARD:
	case REQ_OP_WRITE_ZEROES:
		cmd->use_aio = false;
		break;
	default:
#ifdef USE_DIO
		cmd->use_aio = true;
#else
		cmd->use_aio = false;
#endif
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	cmd->css = NULL;
#ifdef CONFIG_BLK_CGROUP
	if (cmd->use_aio && cmd->rq->bio && cmd->rq->bio->bi_css) {
		cmd->css = cmd->rq->bio->bi_css;
		css_get(cmd->css);
	}
#endif
#endif

	kthread_queue_work(&pxd_dev->worker, &cmd->work);
	return BLK_STS_OK;
}

static int pxd_init_request(struct blk_mq_tag_set *set, struct request *rq,
	unsigned int hctx_idx, unsigned int numa_node)
{
	struct pxd_mq_rqcmd *cmd = blk_mq_rq_to_pdu(rq);

	cmd->rq = rq;
	kthread_init_work(&cmd->work, pxd_queue_work);

	return 0;
}

static void pxd_complete_rq(struct request *rq)
{
    struct pxd_mq_rqcmd *cmd = blk_mq_rq_to_pdu(rq);

    if (unlikely(req_op(cmd->rq) == REQ_OP_READ && cmd->use_aio &&
             cmd->ret >= 0 && cmd->ret < blk_rq_bytes(cmd->rq))) {
        struct bio *bio = cmd->rq->bio;

        bio_advance(bio, cmd->ret);
        zero_fill_bio(bio);
    }

    blk_mq_end_request(rq, cmd->ret < 0 ? BLK_STS_IOERR : BLK_STS_OK);
}

static const struct blk_mq_ops pxd_mq_ops = {
	.queue_rq = pxd_queue_rq,
	.init_request = pxd_init_request,
	.complete = pxd_complete_rq,
};

#else
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

		if (!pxd_dev->connected) {
			printk(KERN_ERR"px is disconnected, failing IO.\n");
			__blk_end_request_all(rq, -ENXIO);
			return;
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
			if (initFile(pxd_dev, false)) {
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
#endif

static int pxd_init_disk(struct pxd_device *pxd_dev, struct pxd_add_vol_out *add)
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
		//blk_queue_make_request(q, pxd_make_request_orig);
	//} else {
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	/* shall use block multiqueue mechanism */
	{
		int err;
		pxd_dev->tag_set.ops = &pxd_mq_ops;
		pxd_dev->tag_set.nr_hw_queues = 1;
		pxd_dev->tag_set.queue_depth = 128;
		pxd_dev->tag_set.numa_node = NUMA_NO_NODE;
		pxd_dev->tag_set.cmd_size = sizeof(struct pxd_mq_rqcmd);
		pxd_dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_SG_MERGE;
		pxd_dev->tag_set.driver_data = pxd_dev;

		err = blk_mq_alloc_tag_set(&pxd_dev->tag_set);
		if (err)
			goto out_disk;

		q = blk_mq_init_queue(&pxd_dev->tag_set);
		if (IS_ERR_OR_NULL(q)) {
			err = PTR_ERR(q);
			blk_mq_free_tag_set(&pxd_dev->tag_set);
			goto out_disk;
		}
	}
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

	{
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && defined(USE_REQUEST_QUEUE)
	blk_mq_free_tag_set(&pxd_dev->tag_set);
#endif

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

ssize_t pxd_add(struct fuse_conn *fc, struct pxd_add_vol_out *add)
{
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	struct pxd_device *pxd_dev = NULL;
	struct pxd_device *pxd_dev_itr;
	int new_minor;
	int err;
	int i;

	err = -ENODEV;
	if (!try_module_get(THIS_MODULE))
		goto out;

	err = -ENOMEM;
	if (ctx->num_devices >= PXD_MAX_DEVICES) {
		printk(KERN_ERR "Too many devices attached..\n");
		goto out_module;
	}

	if (add->nfd > MAX_FD_PER_PXD) {
		err = -EINVAL;
		printk(KERN_ERR "Too many backing devices for a virtual device %d(max %d)\n",
				add->nfd, MAX_FD_PER_PXD);
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
	pxd_dev->aio = false;
	pxd_dev->bg_flush_enabled = true;
	pxd_dev->n_flush_wrsegs = MAX_WRITESEGS_FOR_FLUSH;

	for (i=0; i<add->nfd; i++) {
		pxd_dev->file[i] = fget(add->fds[i]);
		if (!pxd_dev->file[i]) {
			err = -EINVAL;
			goto out_disk;
		}
	}
	pxd_dev->nfd = add->nfd;


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

#if 1
	ncount=snprintf(cp, available, "nactive: %u/%u\n",
                atomic_read(&pxd_dev->ncount), atomic_read(&pxd_dev->ncomplete));

#else
	ncount = snprintf(cp, available, "nactive: %u/%u\n",
		atomic_read(&pxd_dev->ncount), atomic_read(&pxd_dev->ncomplete));
	available -= ncount;
	cp += ncount;
	{
	int i;
	for (i=0; i<MAX_THREADS; i++) {
		int c=snprintf(cp, available, "[%d]:%u\n",
				i, atomic_read(&pxd_dev->tc[i].tcount));
		cp+=c;
		ncount+=c;
		available -= c;
	}
	}
#endif
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

static ssize_t pxd_mirror_show(struct device *dev,
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

// debug interface to configure mirror to a pxd_device
static ssize_t pxd_mirror_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
        struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	uint64_t mirror;
	struct pxd_device *mirror_dev;
	struct pxd_context *ctx = pxd_dev->ctx;
        struct list_head *cur;

	sscanf(buf, "%lld", &mirror);

	/* ensure the mirror device is not attached, if so throw a failure message */
	mirror_dev = NULL;
	spin_lock(&ctx->lock);
	list_for_each(cur, &ctx->list) {
		struct pxd_device *pxd = container_of(cur, struct pxd_device, node);

		if (pxd->dev_id == mirror) {
			/* configure this pxd as a mirror */
			mirror_dev = pxd;
			break;
		}
	}
	spin_unlock(&ctx->lock);

	if (mirror_dev) {
		printk(KERN_ERR"Mirror device %lld already attached... mirror should be setup before target device is attached\n",
				mirror);
		return count;
	}

	pxd_dev->mirror = mirror;

	printk(KERN_INFO"Configuring device %lld as mirror for %lld\n", pxd_dev->dev_id, mirror);
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
	char replicate[64];
	struct file *f;
	struct inode *inode;

	if (pxd_dev->nfd >= MAX_FD_PER_PXD) {
		printk(KERN_ERR"Maximum replicate volumes configured for device %lld\n", pxd_dev->dev_id);
		goto hack_out;
	}

	sscanf(buf, "%s", replicate);
	printk(KERN_ERR"Parent device %lld, device path %s\n", pxd_dev->dev_id, replicate);

	/* look for configuring an device given as path as a replicate volume */
	f = filp_open(replicate, O_LARGEFILE | O_RDWR, 0600);
	if (IS_ERR_OR_NULL(f)) {
		printk(KERN_ERR"Failed opening replicate device at path %s err %ld\n",
				replicate, PTR_ERR(f));
		goto hack_out;
	}

	inode = f->f_inode;
	printk(KERN_WARNING"replicate device %s, inode %lu\n", replicate, inode->i_ino);

	if (S_ISREG(inode->i_mode)) {
		printk(KERN_INFO"replicate device[%s] is a regular file - inode %lu\n",
			replicate, inode->i_ino);
	} else if (S_ISBLK(inode->i_mode)) {
		printk(KERN_INFO"replicate device[%s] is a block device - inode %lu\n",
			replicate, inode->i_ino);
	} else {
		printk(KERN_INFO"replicate device[%s] inode %lu unknown device %#x\n",
			replicate, inode->i_ino, inode->i_mode);
	}
	spin_lock_irq(&pxd_dev->dlock);
	pxd_dev->file[pxd_dev->nfd] = f;
	pxd_dev->nfd++;
	spin_unlock_irq(&pxd_dev->dlock);
	printk(KERN_INFO"Success attaching replicate device %s to device %lld [nfd:%d]\n",
		replicate, pxd_dev->dev_id, pxd_dev->nfd);
	goto hack_out;

	printk(KERN_INFO"Unexpected failed finding replicate device %s from file path\n",
			replicate);
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
static DEVICE_ATTR(mirror, S_IRUGO|S_IWUSR, pxd_mirror_show, pxd_mirror_store);
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
	&dev_attr_mirror.attr,
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

#if 0
	/* debug dump for verification */
	for (i=0; i<nr_node_ids; i++) {
		struct node_cpu_map *map=&node_cpu_map[i];
		int j;
		printk(KERN_INFO"Numa Node %d: ncpu %d\n", i, map->ncpu);

		for (j=0; j<map->ncpu; j++) {
			printk(KERN_INFO"\tCPU[%d]=%d\n", map->cpu[j], i);
		}
	}
#endif

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
