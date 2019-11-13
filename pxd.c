#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/sysfs.h>
#include <linux/crc32.h>
#include <linux/miscdevice.h>
#include "fuse_i.h"
#include "pxd.h"
#include <linux/uio.h>

#define CREATE_TRACE_POINTS
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE pxd_trace
#include <pxd_trace.h>
#undef CREATE_TRACE_POINTS

#include "pxd_compat.h"

#ifdef __PX_BLKMQ__
#include <linux/blk-mq.h>

#define SECTOR_SHIFT    9

#endif

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
	uint64_t open_seq;
};

struct pxd_context *pxd_contexts;
uint32_t pxd_num_contexts = PXD_NUM_CONTEXTS;
uint32_t pxd_num_contexts_exported = PXD_NUM_CONTEXT_EXPORTED;
uint32_t pxd_timeout_secs = PXD_TIMER_SECS_MAX;
uint32_t pxd_detect_zero_writes = 0;

module_param(pxd_num_contexts_exported, uint, 0644);
module_param(pxd_num_contexts, uint, 0644);
module_param(pxd_detect_zero_writes, uint, 0644);

struct pxd_device {
	uint64_t dev_id;
	int major;
	int minor;
	struct gendisk *disk;
	struct device dev;
	size_t size;
	spinlock_t lock;
	spinlock_t qlock;
	struct list_head node;
	int open_count;
	bool removing;
	struct pxd_context *ctx;

#ifdef __PX_BLKMQ__
        struct blk_mq_tag_set tag_set;
#endif
};

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
		spin_lock(&pxd_dev->lock);
		if (pxd_dev->removing)
			err = -EBUSY;
		else
			pxd_dev->open_count++;
		spin_unlock(&pxd_dev->lock);

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

	spin_lock(&pxd_dev->lock);
	pxd_dev->open_count--;
	spin_unlock(&pxd_dev->lock);

	trace_pxd_release(pxd_dev->dev_id, pxd_dev->major, pxd_dev->minor, mode);
	put_device(&pxd_dev->dev);
}

static long pxd_ioctl_init(struct file *file, void __user *argp)
{
	struct pxd_context *ctx = container_of(file->f_op, struct pxd_context, fops);
	struct iov_iter iter;
	struct iovec iov = {argp, sizeof(struct pxd_ioctl_init_args)};

	iov_iter_init(&iter, WRITE, &iov, 1, sizeof(struct pxd_ioctl_init_args));

	return pxd_read_init(&ctx->fc, &iter);
}

static long pxd_control_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
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
			printk(KERN_INFO "\tFC: connected: %d", ctx->fc.connected);
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
	case PXD_IOC_INIT:
		status = pxd_ioctl_init(file, argp);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
        part_stat_lock();
        part_stat_inc(&pxd_dev->disk->part0, ios[rw]);
        part_stat_add(&pxd_dev->disk->part0, sectors[rw], count);
#else
        int cpu = part_stat_lock();
        part_stat_inc(cpu, &pxd_dev->disk->part0, ios[rw]);
        part_stat_add(cpu, &pxd_dev->disk->part0, sectors[rw], count);
#endif

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

#ifndef __PX_BLKMQ__
	blk_end_request(req->rq, req->out.h.error, blk_rq_bytes(req->rq));
#else
	blk_mq_end_request(req->rq, errno_to_blk_status(req->out.h.error));
#endif
	pxd_request_complete(fc, req);
}

static void pxd_process_write_reply_q(struct fuse_conn *fc, struct fuse_req *req)
{

#ifndef __PX_BLKMQ__
	blk_end_request(req->rq, req->out.h.error, blk_rq_bytes(req->rq));
#else
	blk_mq_end_request(req->rq, errno_to_blk_status(req->out.h.error));
#endif
	pxd_request_complete(fc, req);
}

static struct fuse_req *pxd_fuse_req(struct pxd_device *pxd_dev)
{
	int eintr = 0;
	struct fuse_req *req = NULL;
	struct fuse_conn *fc = &pxd_dev->ctx->fc;
	int status;

	while (req == NULL) {
		req = fuse_get_req_for_background(fc);
		if (IS_ERR(req) && PTR_ERR(req) == -EINTR) {
			req = NULL;
			++eintr;
		}
	}
	if (eintr > 0) {
		printk_ratelimited(KERN_INFO "%s: alloc EINTR retries %d",
			 __func__, eintr);
	}
	status = IS_ERR(req) ? PTR_ERR(req) : 0;
	if (status != 0) {
		printk_ratelimited(KERN_ERR "%s: request alloc failed: %d",
			 __func__, status);
	}
	return req;
}

static void pxd_req_misc(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags)
{
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct pxd_rdwr_in);
	req->in.args[0].value = &req->misc.pxd_rdwr_in;
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
	req->out.numargs = 1;
	req->end = qfn ? pxd_process_read_reply_q : pxd_process_read_reply;

	pxd_req_misc(req, size, off, minor, flags);
}

static void pxd_write_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags, bool qfn)
{
	req->in.h.opcode = PXD_WRITE;
	req->end = qfn ? pxd_process_write_reply_q : pxd_process_write_reply;

	pxd_req_misc(req, size, off, minor, flags);
}

static void pxd_discard_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags, bool qfn)
{
	req->in.h.opcode = PXD_DISCARD;
	req->end = qfn ? pxd_process_write_reply_q : pxd_process_write_reply;

	pxd_req_misc(req, size, off, minor, flags);
}

static void pxd_write_same_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags, bool qfn)
{
	req->in.h.opcode = PXD_WRITE_SAME;
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
static blk_qc_t pxd_make_request(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
static void pxd_make_request(struct request_queue *q, struct bio *bio)
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

	req = pxd_fuse_req(pxd_dev);
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

	req->bio = bio;
	req->queue = q;

	fuse_request_send_nowait(&pxd_dev->ctx->fc, req);
	return BLK_QC_RETVAL;
}

#ifndef __PX_BLKMQ__
static void pxd_rq_fn(struct request_queue *q)
{
	struct pxd_device *pxd_dev = q->queuedata;
	struct fuse_req *req;

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
		spin_unlock_irq(&pxd_dev->qlock);
		pxd_printk("%s: dev m %d g %lld %s at %ld len %d bytes %d pages "
			"flags  %llx\n", __func__,
			pxd_dev->minor, pxd_dev->dev_id,
			rq_data_dir(rq) == WRITE ? "wr" : "rd",
			blk_rq_pos(rq) * SECTOR_SIZE, blk_rq_bytes(rq),
			rq->nr_phys_segments, rq->cmd_flags);

		req = pxd_fuse_req(pxd_dev);
		if (IS_ERR(req)) {
  			spin_lock_irq(&pxd_dev->qlock);
			__blk_end_request(rq, -EIO, blk_rq_bytes(rq));
			continue;
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

		req->rq = rq;
		req->queue = q;
		fuse_request_send_nowait(&pxd_dev->ctx->fc, req);
		spin_lock_irq(&pxd_dev->qlock);
	}
}
#else

static blk_status_t pxd_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct pxd_device *pxd_dev = rq->q->queuedata;
	struct fuse_req *req = blk_mq_rq_to_pdu(rq);
	struct fuse_conn *fc = &pxd_dev->ctx->fc;

	if (BLK_RQ_IS_PASSTHROUGH(rq))
		return BLK_STS_IOERR;

	if (!fc->connected && !fc->allow_disconnected)
		return BLK_STS_IOERR;

	pxd_printk("%s: dev m %d g %lld %s at %ld len %d bytes %d pages "
		   "flags  %llx\n", __func__,
		pxd_dev->minor, pxd_dev->dev_id,
		rq_data_dir(rq) == WRITE ? "wr" : "rd",
		blk_rq_pos(rq) * SECTOR_SIZE, blk_rq_bytes(rq),
		rq->nr_phys_segments, rq->cmd_flags);

	fuse_request_init(req);
	fuse_req_init_context(req);

	blk_mq_start_request(rq);

	pxd_request(req, blk_rq_bytes(rq), blk_rq_pos(rq) * SECTOR_SIZE,
		pxd_dev->minor, req_op(rq), rq->cmd_flags, true,
		REQCTR(&pxd_dev->ctx->fc));

	req->misc.pxd_rdwr_in.chksum = 0;
	req->misc.pxd_rdwr_in.pad = 0;
	req->rq = rq;
	fuse_request_send_nowait(&pxd_dev->ctx->fc, req);

	return BLK_STS_OK;
}

static const struct blk_mq_ops pxd_mq_ops = {
	.queue_rq       = pxd_queue_rq,
};
#endif

static int pxd_init_disk(struct pxd_device *pxd_dev, struct pxd_add_out *add)
{
	struct gendisk *disk;
	struct request_queue *q;
	int err = 0;

	if (add->queue_depth < 0 || add->queue_depth > PXD_MAX_QDEPTH)
		return -EINVAL;

	/* Create gendisk info. */
	disk = alloc_disk(1);
	if (!disk)
		return -ENOMEM;

	snprintf(disk->disk_name, sizeof(disk->disk_name),
			PXD_DEV"%llu", pxd_dev->dev_id);
	disk->major = pxd_dev->major;
	disk->first_minor = pxd_dev->minor;
	disk->flags |= GENHD_FL_EXT_DEVT | GENHD_FL_NO_PART_SCAN;
	disk->fops = &pxd_bd_ops;
	disk->private_data = pxd_dev;

	/* Bypass queue if queue_depth is zero. */
	if (add->queue_depth == 0) {
		q = blk_alloc_queue(GFP_KERNEL);
		if (!q) {
			err = -ENOMEM;
			goto out_disk;
		}
		blk_queue_make_request(q, pxd_make_request);
	} else {
#ifdef __PX_BLKMQ__
	  memset(&pxd_dev->tag_set, 0, sizeof(pxd_dev->tag_set));
	  pxd_dev->tag_set.ops = &pxd_mq_ops;
	  pxd_dev->tag_set.queue_depth = PXD_MAX_QDEPTH;
	  pxd_dev->tag_set.numa_node = NUMA_NO_NODE;
	  pxd_dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	  pxd_dev->tag_set.nr_hw_queues = 8;
	  pxd_dev->tag_set.queue_depth = 128;
	  pxd_dev->tag_set.cmd_size = sizeof(struct fuse_req);

	  err = blk_mq_alloc_tag_set(&pxd_dev->tag_set);
	  if (err)
	    goto out_disk;

	  q = blk_mq_init_queue(&pxd_dev->tag_set);
	  if (IS_ERR(q)) {
		err = PTR_ERR(q);
		blk_mq_free_tag_set(&pxd_dev->tag_set);
		goto out_disk;
	  }
#else
	  q = blk_init_queue(pxd_rq_fn, &pxd_dev->qlock);
	  if (!q) {
		err = -ENOMEM;
	  	goto out_disk;
	  }
#endif
       }
	blk_queue_max_hw_sectors(q, SEGMENT_SIZE / SECTOR_SIZE);
	blk_queue_max_segment_size(q, SEGMENT_SIZE);
	blk_queue_io_min(q, PXD_LBS);
	blk_queue_io_opt(q, PXD_LBS);
	blk_queue_logical_block_size(q, PXD_LBS);

	set_capacity(disk, add->size / SECTOR_SIZE);

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

	return 0;
out_disk:
	put_disk(disk);
	return err;
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
#ifdef __PX_BLKMQ__
		blk_mq_free_tag_set(&pxd_dev->tag_set);
#endif
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

	spin_lock_init(&pxd_dev->lock);
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
			spin_lock(&pxd_dev->lock);
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
		spin_unlock(&pxd_dev->lock);
		goto out;
	}

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

	spin_unlock(&pxd_dev->lock);

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
			spin_lock(&pxd_dev->lock);
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
	spin_unlock(&pxd_dev->lock);

	err = revalidate_disk(pxd_dev->disk);
	BUG_ON(err);
	put_device(&pxd_dev->dev);

	return 0;
out:
	return err;
}

ssize_t pxd_read_init(struct fuse_conn *fc, struct iov_iter *iter)
{
	size_t copied = 0;
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	struct pxd_device *pxd_dev;
	struct pxd_init_in pxd_init;

	spin_lock(&fc->lock);

	pxd_init.num_devices = ctx->num_devices;
	pxd_init.version = PXD_VERSION;

	if (copy_to_iter(&pxd_init, sizeof(pxd_init), iter) != sizeof(pxd_init)) {
		printk(KERN_ERR "%s: copy pxd_init error\n", __func__);
		goto copy_error;
	}
	copied += sizeof(pxd_init);

	list_for_each_entry(pxd_dev, &ctx->list, node) {
		struct pxd_dev_id id;
		id.dev_id = pxd_dev->dev_id;
		id.local_minor = pxd_dev->minor;
		if (copy_to_iter(&id, sizeof(id), iter) != sizeof(id)) {
			printk(KERN_ERR "%s: copy dev id error copied %ld\n", __func__,
				copied);
			goto copy_error;
		}
		copied += sizeof(id);
	}

	spin_unlock(&fc->lock);

	printk(KERN_INFO "%s: pxd-control-%d init OK %d devs version %d\n", __func__,
		ctx->id, pxd_init.num_devices, pxd_init.version);

	fc->pend_open = 0;

	return copied;

copy_error:
	spin_unlock(&fc->lock);
	return -EFAULT;
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

static int pxd_control_open(struct inode *inode, struct file *file)
{
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
		printk(KERN_ERR "%s: pxd-control-%d(%lld) already open\n", __func__,
			ctx->id, ctx->open_seq);
		return -EINVAL;
	}

	del_timer_sync(&ctx->timer);
	spin_lock(&ctx->lock);
	pxd_timeout_secs = PXD_TIMER_SECS_MAX;
	fc->connected = 1;
	spin_unlock(&ctx->lock);

	fc->pend_open = 1;
	fc->allow_disconnected = 1;
	file->private_data = fc;

	fuse_restart_requests(fc);

	++ctx->open_seq;

	printk(KERN_INFO "%s: pxd-control-%d(%lld) open OK\n", __func__, ctx->id,
		ctx->open_seq);

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

	printk(KERN_INFO "%s: pxd-control-%d(%lld) close OK\n", __func__, ctx->id,
		ctx->open_seq);
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

	fc->connected = true;
	fc->allow_disconnected = 0;
	fuse_abort_conn(fc);
	printk(KERN_INFO "PXD_TIMEOUT (%s:%u): Aborting all requests...",
		ctx->name, ctx->id);
}

int pxd_context_init(struct pxd_context *ctx, int i)
{
	int err;

	spin_lock_init(&ctx->lock);
	ctx->id = i;
	ctx->open_seq = 0;
	ctx->fops = fuse_dev_operations;
	ctx->fops.owner = THIS_MODULE;
	ctx->fops.open = pxd_control_open;
	ctx->fops.release = pxd_control_release;
	ctx->fops.unlocked_ioctl = pxd_control_ioctl;

	if (ctx->id < pxd_num_contexts_exported) {
		err = fuse_conn_init(&ctx->fc);
		if (err)
			return err;
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

#ifdef __PX_BLKMQ__
	printk(KERN_INFO "pxd: blk-mq driver loaded version %s\n", gitversion);
#else
	printk(KERN_INFO "pxd: driver loaded version %s\n", gitversion);
#endif

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

	printk(KERN_INFO "pxd: driver unloaded\n");
}

module_init(pxd_init);
module_exit(pxd_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION(VERTOSTR(PXD_VERSION));
