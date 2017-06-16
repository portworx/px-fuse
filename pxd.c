#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/sysfs.h>
#include <linux/crc32.h>
#include <linux/miscdevice.h>
#include "fuse_i.h"
#include "pxd.h"

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

#define SECTOR_SIZE 512
#define SEGMENT_SIZE (1024 * 1024)

#define PXD_TIMER_SECS 600

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

module_param(pxd_num_contexts_exported, uint, 0644);
module_param(pxd_num_contexts, uint, 0644);

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
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
		printk(KERN_INFO "%s: alloc (%d pages) EINTR retries %d",
			 __func__, nr_pages, eintr);
	}
	status = IS_ERR(req) ? PTR_ERR(req) : 0;
	if (status != 0) {
		printk(KERN_ERR "%s: request alloc (%d pages) failed: %d",
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
static void pxd_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t op, uint32_t flags, bool qfn,
			uint64_t reqctr)
{
	trace_pxd_request(reqctr, req->in.h.unique, size, off, minor, flags);

	switch (op) {
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

	switch (flags & (REQ_WRITE | REQ_DISCARD)) {
	case REQ_WRITE:
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

	req = pxd_fuse_req(pxd_dev, bio->bi_vcnt);
	if (IS_ERR(req)) {
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
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

		req = pxd_fuse_req(pxd_dev, 0);
		if (IS_ERR(req)) {
  			spin_lock_irq(&pxd_dev->qlock);
			__blk_end_request(rq, -EIO, blk_rq_bytes(rq));
			continue;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
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
		spin_lock_irq(&pxd_dev->qlock);
	}
}

static int pxd_init_disk(struct pxd_device *pxd_dev, struct pxd_add_out *add)
{
	struct gendisk *disk;
	struct request_queue *q;

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
		if (!q)
			goto out_disk;
		blk_queue_make_request(q, pxd_make_request);
	} else {
		q = blk_init_queue(pxd_rq_fn, &pxd_dev->qlock);
		if (!q)
			goto out_disk;
	}

	blk_queue_max_hw_sectors(q, SEGMENT_SIZE / SECTOR_SIZE);
	blk_queue_max_segment_size(q, SEGMENT_SIZE);
	blk_queue_io_min(q, PXD_LBS);
	blk_queue_io_opt(q, PXD_LBS);
	blk_queue_logical_block_size(q, PXD_LBS);

	set_capacity(disk, add->size / SECTOR_SIZE);

	/* Enable discard support. */
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, q);
	q->limits.discard_granularity = PXD_LBS;
	q->limits.discard_alignment = PXD_LBS;
	q->limits.max_discard_sectors = SEGMENT_SIZE / SECTOR_SIZE;
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
	return -ENOMEM;
}

static void pxd_free_disk(struct pxd_device *pxd_dev)
{
	struct gendisk *disk = pxd_dev->disk;

	if (!disk)
		return;

	pxd_dev->disk = NULL;
	if (disk->flags & GENHD_FL_UP) {
		if (disk->queue)
			blk_cleanup_queue(disk->queue);
		del_gendisk(disk);
	}
	put_disk(disk);
}

ssize_t pxd_add(struct fuse_conn *fc, struct pxd_add_out *add)
{
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	struct pxd_device *pxd_dev;
	struct pxd_device *pxd_dev_itr;
	int new_minor;
	int err;

	err = -ENODEV;
	if (!try_module_get(THIS_MODULE))
		goto out;

	err = -ENOMEM;
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
	kfree(pxd_dev);
	module_put(THIS_MODULE);
out:
	return err;
}

static int match_minor(struct fuse_conn *conn, struct fuse_req *req, void *arg)
{
	/* device id is always first field in the argument */
	return req->in.h.opcode != PXD_INIT &&
		*(uint32_t *)req->in.args[0].value == (uint32_t)(uintptr_t)arg;
}

ssize_t pxd_remove(struct fuse_conn *fc, struct pxd_remove_out *remove)
{
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	int found = false;
	int err;
	struct pxd_device *pxd_dev;
	int minor;

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

	minor = pxd_dev->minor;

	spin_unlock(&pxd_dev->lock);

	device_unregister(&pxd_dev->dev);
	if (pxd_dev->disk) {
		pxd_free_disk(pxd_dev);
	}
	kfree(pxd_dev);

	fuse_end_matching_requests(fc, match_minor, (void *)(uintptr_t)minor);

	ida_simple_remove(&pxd_minor_ida, minor);

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

static DEVICE_ATTR(size, S_IRUGO, pxd_size_show, NULL);
static DEVICE_ATTR(major, S_IRUGO, pxd_major_show, NULL);
static DEVICE_ATTR(minor, S_IRUGO, pxd_minor_show, NULL);

static struct attribute *pxd_attrs[] = {
	&dev_attr_size.attr,
	&dev_attr_major.attr,
	&dev_attr_minor.attr,
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
	int num_pages = (sizeof(struct pxd_dev_id) * ctx->num_devices +
				PAGE_SIZE - 1) / PAGE_SIZE;

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

	fc->pend_open = 1;
	fc->connected = 1;
	fc->initialized = 1;
	fc->allow_disconnected = 1;
	file->private_data = fc;

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
	if (ctx->fc.connected == 0)
		pxd_printk("%s: not opened\n", __func__);
	else
		ctx->fc.connected = 0;
	ctx->fc.pend_open = 0;
	mod_timer(&ctx->timer, jiffies + (PXD_TIMER_SECS * HZ));
	printk(KERN_INFO "%s: pxd-control-%d:%llu close OK\n", __func__,
		ctx->id, ctx->unique);
	return 0;
}

static struct miscdevice pxd_miscdev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "/pxd/pxd-control",
};

MODULE_ALIAS("devname:pxd-control");

static void pxd_fuse_conn_release(struct fuse_conn *conn)
{
}

static void pxd_timeout(unsigned long args)
{
	struct pxd_context *ctx = (struct pxd_context *)args;
	struct fuse_conn *fc = &ctx->fc;

	BUG_ON(fc->connected);

	fc->connected = true;
	fc->allow_disconnected = 0;
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
	sprintf(ctx->name, "/pxd/pxd-control-%d", i);
	ctx->miscdev.minor = MISC_DYNAMIC_MINOR;
	ctx->miscdev.name = ctx->name;
	ctx->miscdev.fops = &ctx->fops;
	INIT_LIST_HEAD(&ctx->pending_requests);
	setup_timer(&ctx->timer, pxd_timeout, (unsigned long) ctx);
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

	printk(KERN_INFO "pxd: driver unloaded\n");
}

module_init(pxd_init);
module_exit(pxd_exit);

MODULE_LICENSE("GPL");
