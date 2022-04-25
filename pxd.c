#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/sysfs.h>
#include <linux/crc32.h>
#include <linux/ctype.h>
#include <linux/sched.h>
#include "fuse_i.h"
#include "pxd.h"
#include <linux/uio.h>
#include <linux/pid_namespace.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0) && !defined(part_stat_lock)
#include <linux/part_stat.h>
#endif

#define CREATE_TRACE_POINTS
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE pxd_trace
#include <pxd_trace.h>
#undef CREATE_TRACE_POINTS

#include "pxd_compat.h"
#include "pxd_core.h"

#ifdef __PX_BLKMQ__
#include <linux/blk-mq.h>
#endif

/** enables time tracing */
//#define GD_TIME_LOG
#ifdef GD_TIME_LOG
#define KTIME_GET_TS(t) ktime_get_ts((t))
#else
#define KTIME_GET_TS(t)
#endif

#define PXD_TIMER_SECS_MIN 30
#define PXD_TIMER_SECS_DEFAULT 600
#define PXD_TIMER_SECS_MAX (U32_MAX)

#if defined(PF_LESS_THROTTLE)
#define PF_IO_FLUSHER (PF_MEMALLOC_NOIO | PF_LESS_THROTTLE)
#elif defined(PF_LOCAL_THROTTLE)
#define PF_IO_FLUSHER (PF_MEMALLOC_NOIO | PF_LOCAL_THROTTLE)
#endif
#define IS_SET_IO_FLUSHER_FLAG(flg) ((flg & PF_IO_FLUSHER) == PF_IO_FLUSHER)
#define IS_SET_IO_FLUSHER(task) (IS_SET_IO_FLUSHER_FLAG((task->flags)))
#define SET_IO_FLUSHER(task) (task->flags |= PF_IO_FLUSHER)
#define CLEAR_IO_FLUSHER(task) (task->flags &= ~(PF_IO_FLUSHER))

#define TOSTRING_(x) #x
#define VERTOSTR(x) TOSTRING_(x)

extern const char *gitversion;
static dev_t pxd_major;
static DEFINE_IDA(pxd_minor_ida);

struct pxd_context *pxd_contexts;
uint32_t pxd_num_contexts = PXD_NUM_CONTEXTS;
uint32_t pxd_num_contexts_exported = PXD_NUM_CONTEXT_EXPORTED;
uint32_t pxd_timeout_secs = PXD_TIMER_SECS_DEFAULT;
uint32_t pxd_detect_zero_writes = 0;

module_param(pxd_num_contexts_exported, uint, 0644);
module_param(pxd_num_contexts, uint, 0644);
module_param(pxd_detect_zero_writes, uint, 0644);

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

static long pxd_ioctl_resize(struct file *file, void __user *argp)
{
	struct pxd_context *ctx = NULL;
	struct pxd_update_size update_args;
	long ret = 0;

	if (copy_from_user(&update_args, argp, sizeof(update_args))) {
		return -EFAULT;
	}

	if (update_args.context_id >= pxd_num_contexts_exported) {
		printk("%s : invalid context: %d\n", __func__, update_args.context_id);
		return -EFAULT;
	}

	ctx =  &pxd_contexts[update_args.context_id];
	if (!ctx || ctx->id >= pxd_num_contexts_exported) {
		return -EFAULT;
	}

	ret = pxd_ioc_update_size(&ctx->fc, &update_args);
	return ret;
}

static void print_io_flusher_state(unsigned int new_flags,
				   pid_t pid, pid_t ppid, char *comm)
{
	if (IS_SET_IO_FLUSHER_FLAG(new_flags)) {
		printk("Process %s pid %d parent pid %d IO_FLUSHER is set\n",
			       comm, pid, ppid);
	} else {
		printk("Process %s pid %d parent pid %d IO_FLUSHER not set\n", comm, pid,
				ppid);
	}
}

static int is_io_flusher_supported(void)
{
  	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0) && defined(PF_MEMALLOC_NOIO)
                #if defined(PF_LESS_THROTTLE) || defined(PF_LOCAL_THROTTLE)
			return 1;
		#else
			return 0;
		#endif
	#else
		return 0;
	#endif
}

static long pxd_ioflusher_state(void __user *argp)
{
	struct pxd_ioctl_io_flusher_args io_flusher_args;
	struct task_struct *task = NULL;
	struct pid_namespace *ns = NULL;
	pid_t ppid = -1;
	pid_t pid = -1;
	char *comm = NULL;
	unsigned int old_flags = 0;
	unsigned int new_flags = 0;
	char command[TASK_COMM_LEN] = {0};
	int is_io_flusher_set = 0;

	if (!is_io_flusher_supported()) {
		return -EOPNOTSUPP;
	}

	if (argp == NULL) {
		return -EINVAL;
	}

	if (copy_from_user(&io_flusher_args, argp, sizeof(io_flusher_args))) {
		return -EFAULT;
	}
	rcu_read_lock();
	task = current;
	ns = task_active_pid_ns(task);
	if (io_flusher_args.pid == 0) {
		get_task_struct(task);
	} else {
		struct task_struct *temp_task;
		struct pid *pid = NULL;
		pid = find_pid_ns(io_flusher_args.pid, ns);
		if (pid == NULL) {
			rcu_read_unlock();
			printk("Input pid %d does not exist", io_flusher_args.pid);
			return -ENOENT;
		}
		temp_task = pid_task(pid, PIDTYPE_PID);
		if (temp_task == NULL) {
			rcu_read_unlock();
			printk("Input pid %d does not exist", io_flusher_args.pid);
			return -ENOENT;
		}
		task = temp_task;
		get_task_struct(task);
	}
	rcu_read_unlock();
	ppid = task_pgrp_nr(task);
	pid = task_pid_nr(task);
	comm = get_task_comm(command, task);
	old_flags = task->flags;
	switch (io_flusher_args.io_flusher_action) {
	case PXD_IO_FLUSHER_GET:
		break;
	case PXD_IO_FLUSHER_SET:
		SET_IO_FLUSHER(task);
		break;
	case PXD_IO_FLUSHER_CLEAR:
		CLEAR_IO_FLUSHER(task);
		break;
	}
	new_flags = task->flags;
	put_task_struct(task);

	is_io_flusher_set = IS_SET_IO_FLUSHER_FLAG(new_flags);

	print_io_flusher_state(new_flags, pid, ppid, comm);

	if (copy_to_user(argp + offsetof(struct pxd_ioctl_io_flusher_args, is_io_flusher_set),
			&is_io_flusher_set, sizeof(is_io_flusher_set))) {
		return -EFAULT;
	}

	return 0;
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
	case PXD_IOC_RESIZE:
		return pxd_ioctl_resize(file, (void __user *)arg);
	case PXD_IOC_IO_FLUSHER:
		return pxd_ioflusher_state((void __user *)arg);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
static void pxd_update_stats(struct fuse_req *req, int sgrp, unsigned int count)
#else
static void pxd_update_stats(struct fuse_req *req, int rw, unsigned int count)
#endif
{
		struct pxd_device *pxd_dev = req->queue->queuedata;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
{
		struct block_device *p = pxd_dev->disk->part0;
		if (!p) return;


		part_stat_lock();
		part_stat_add(p, sectors[sgrp], count);
		part_stat_inc(p, ios[sgrp]);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0) || defined(__EL8__)
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

static void pxd_request_complete(struct fuse_conn *fc, struct fuse_req *req)
{
	pxd_printk("%s: receive reply to %p(%lld) at %lld err %d\n",
			__func__, req, req->in.h.unique,
			req->pxd_rdwr_in.offset, req->out.h.error);
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
	{
	  const struct bio* bio = req->bio;
	  int statgrp = STAT_WRITE;
	  size_t sz = BIO_SIZE(bio) / SECTOR_SIZE;

	  if (!bio) statgrp = STAT_FLUSH;
	  else if (!op_is_write(bio->bi_opf)) statgrp = STAT_READ;
	  else if (op_is_flush(bio->bi_opf) && (sz == 0)) statgrp = STAT_FLUSH;
	  else statgrp = STAT_WRITE;

	  pxd_update_stats(req, statgrp, sz);
	}
#else
	pxd_update_stats(req, 1, BIO_SIZE(req->bio) / SECTOR_SIZE);
#endif
	BIO_ENDIO(req->bio, req->out.h.error);
	pxd_request_complete(fc, req);
}

/* only used by the USE_REQUESTQ_MODEL definition */
static void pxd_process_read_reply_q(struct fuse_conn *fc, struct fuse_req *req)
{
#ifndef __PX_BLKMQ__
	blk_end_request(req->rq, req->out.h.error, blk_rq_bytes(req->rq));
#else
	blk_mq_end_request(req->rq, errno_to_blk_status(req->out.h.error));
#endif
	pxd_request_complete(fc, req);
}

/* only used by the USE_REQUESTQ_MODEL definition */
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
	req->in.args[0].value = &req->pxd_rdwr_in;
	req->in.h.pid = current->pid;
	req->pxd_rdwr_in.dev_minor = minor;
	req->pxd_rdwr_in.offset = off;
	req->pxd_rdwr_in.size = size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
	req->pxd_rdwr_in.flags =
		((flags & REQ_FUA) ? PXD_FLAGS_FLUSH : 0) |
		((flags & REQ_PREFLUSH) ? PXD_FLAGS_FLUSH : 0) |
		((flags & REQ_META) ? PXD_FLAGS_META : 0);
#else
	req->pxd_rdwr_in.flags = ((flags & REQ_FLUSH) ? PXD_FLAGS_FLUSH : 0) |
					  ((flags & REQ_FUA) ? PXD_FLAGS_FUA : 0) |
					  ((flags & REQ_META) ? PXD_FLAGS_META : 0);
#endif
}

static void pxd_read_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags, bool qfn)
{
	req->in.h.opcode = PXD_READ;
	if (req->fastpath) {
		req->end = pxd_process_read_reply;
	} else {
		req->end = qfn ? pxd_process_read_reply_q : pxd_process_read_reply;
	}

	pxd_req_misc(req, size, off, minor, flags);
}

static void pxd_write_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags, bool qfn)
{
	req->in.h.opcode = PXD_WRITE;
	if (req->fastpath) {
		req->end = pxd_process_write_reply;
	} else {
		req->end = qfn ? pxd_process_write_reply_q : pxd_process_write_reply;
	}

	pxd_req_misc(req, size, off, minor, flags);
}

static void pxd_discard_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags, bool qfn)
{
	req->in.h.opcode = PXD_DISCARD;
	if (req->fastpath) {
		req->end = pxd_process_write_reply;
	} else {
		req->end = qfn ? pxd_process_write_reply_q : pxd_process_write_reply;
	}

	pxd_req_misc(req, size, off, minor, flags);
}

static void pxd_write_same_request(struct fuse_req *req, uint32_t size, uint64_t off,
			uint32_t minor, uint32_t flags, bool qfn)
{
	req->in.h.opcode = PXD_WRITE_SAME;
	if (req->fastpath) {
		req->end = pxd_process_write_reply;
	} else {
		req->end = qfn ? pxd_process_write_reply_q : pxd_process_write_reply;
	}

	pxd_req_misc(req, size, off, minor, flags);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
static int pxd_request(struct fuse_req *req, uint32_t size, uint64_t off,
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
	default:
		printk(KERN_ERR"[%llu] REQ_OP_UNKNOWN(%#x): size=%d, off=%lld, minor=%d, flags=%#x\n",
			req->in.h.unique, op, size, off, minor, flags);
		return -1;
	}

	return 0;
}

#else

static int pxd_request(struct fuse_req *req, uint32_t size, uint64_t off,
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
	default:
		printk(KERN_ERR"[%llu] REQ_OP_UNKNOWN(%#x): size=%d, off=%lld, minor=%d, flags=%#x\n",
			req->in.h.unique, flags, size, off, minor, flags);
		return -1;
	}

	return 0;
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

// fastpath uses this path to punt requests to slowpath
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
blk_qc_t pxd_make_request_slowpath(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
void pxd_make_request_slowpath(struct request_queue *q, struct bio *bio)
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
	if (IS_ERR_OR_NULL(req)) {
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	req->fastpath = pxd_dev->fastpath;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
	if (pxd_request(req, BIO_SIZE(bio), BIO_SECTOR(bio) * SECTOR_SIZE,
		pxd_dev->minor, bio_op(bio), bio->bi_opf, false, REQCTR(&pxd_dev->ctx->fc))) {
#else
	if (pxd_request(req, BIO_SIZE(bio), BIO_SECTOR(bio) * SECTOR_SIZE,
		    pxd_dev->minor, bio->bi_rw, false,
		    REQCTR(&pxd_dev->ctx->fc))) {
#endif
		fuse_request_free(req);
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	req->bio = bio;
	req->queue = q;

	fuse_request_send_nowait(&pxd_dev->ctx->fc, req);
	return BLK_QC_RETVAL;
}

#if !defined(__PX_BLKMQ__)
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
		if (IS_ERR_OR_NULL(req)) {
			spin_lock_irq(&pxd_dev->qlock);
			__blk_end_request(rq, -EIO, blk_rq_bytes(rq));
			continue;
		}

		req->fastpath = pxd_dev->fastpath;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
		if (pxd_request(req, blk_rq_bytes(rq), blk_rq_pos(rq) * SECTOR_SIZE,
			    pxd_dev->minor, req_op(rq), rq->cmd_flags, true,
			    REQCTR(&pxd_dev->ctx->fc))) {
#else
		if (pxd_request(req, blk_rq_bytes(rq), blk_rq_pos(rq) * SECTOR_SIZE,
			    pxd_dev->minor, rq->cmd_flags, true,
			    REQCTR(&pxd_dev->ctx->fc))) {
#endif
			fuse_request_free(req);
			spin_lock_irq(&pxd_dev->qlock);
			__blk_end_request(rq, -EIO, blk_rq_bytes(rq));
			continue;
		}

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

	if (pxd_request(req, blk_rq_bytes(rq), blk_rq_pos(rq) * SECTOR_SIZE,
		pxd_dev->minor, req_op(rq), rq->cmd_flags, true,
		REQCTR(&pxd_dev->ctx->fc))) {
		return BLK_STS_IOERR;
	}

	req->pxd_rdwr_in.chksum = 0;
	req->pxd_rdwr_in.pad = 0;
	req->rq = rq;
	fuse_request_send_nowait(&pxd_dev->ctx->fc, req);

	return BLK_STS_OK;
}

static const struct blk_mq_ops pxd_mq_ops = {
	.queue_rq       = pxd_queue_rq,
};
#endif

static int pxd_init_disk(struct pxd_device *pxd_dev, struct pxd_add_ext_out *add)
{
	struct gendisk *disk = NULL;
	struct request_queue *q = NULL;
#ifdef __PX_BLKMQ__
	int err = 0;
#endif

	if (add->queue_depth < 0 || add->queue_depth > PXD_MAX_QDEPTH)
		return -EINVAL;

#ifndef __PX_FASTPATH__
	if (pxd_dev->fastpath) {
		printk(KERN_NOTICE"PX driver does not support fastpath, disabling it.");
		pxd_dev->fastpath = false;
	}
#else
	if (pxd_dev->fastpath) {
		pxd_printk("adding disk for fastpath device %llu", pxd_dev->dev_id);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
	  q = blk_alloc_queue(NUMA_NO_NODE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
		q = blk_alloc_queue(pxd_make_request_fastpath, NUMA_NO_NODE);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(4,18,0) && defined(__EL8__) && defined(QUEUE_FLAG_NOWAIT)
        q = blk_alloc_queue_rh(pxd_make_request_fastpath, NUMA_NO_NODE);
#else
		q = blk_alloc_queue(GFP_KERNEL);
#endif
		if (!q) {
			return -ENOMEM;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0) && !defined(QUEUE_FLAG_NOWAIT)
		blk_queue_make_request(q, pxd_make_request_fastpath);
#endif
	} else {
#endif

#ifdef __PX_BLKMQ__
	  memset(&pxd_dev->tag_set, 0, sizeof(pxd_dev->tag_set));
	  pxd_dev->tag_set.ops = &pxd_mq_ops;
	  pxd_dev->tag_set.queue_depth = add->queue_depth;
	  pxd_dev->tag_set.numa_node = NUMA_NO_NODE;
	  pxd_dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	  pxd_dev->tag_set.nr_hw_queues = 8;
	  pxd_dev->tag_set.cmd_size = sizeof(struct fuse_req);

	  err = blk_mq_alloc_tag_set(&pxd_dev->tag_set);
	  if (err) {
		return err;
	  }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
	  disk = blk_mq_alloc_disk(&pxd_dev->tag_set, pxd_dev);
	  if (IS_ERR(disk)) {
		blk_mq_free_tag_set(&pxd_dev->tag_set);
		return PTR_ERR(disk);
	  }
	  q = disk->queue;
#else
	  /* Create gendisk info. */
	  disk = alloc_disk(1);
	  if (!disk) {
		return -ENOMEM;
	  }
	  q = blk_mq_init_queue(&pxd_dev->tag_set);
	  if (IS_ERR(q)) {
		blk_mq_free_tag_set(&pxd_dev->tag_set);
		put_disk(disk);
		return PTR_ERR(q);
	  }
#endif
#else
	  /* Create gendisk info. */
	  disk = alloc_disk(1);
	  if (!disk) {
		return -ENOMEM;
	  }
	  q = blk_init_queue(pxd_rq_fn, &pxd_dev->qlock);
	  if (!q) {
		put_disk(disk);
		return -ENOMEM;
	  }
#endif

#ifdef __PX_FASTPATH__
	}
#endif
	snprintf(disk->disk_name, sizeof(disk->disk_name),
		 PXD_DEV"%llu", pxd_dev->dev_id);
	disk->major = pxd_dev->major;
	disk->minors = 256;
	disk->first_minor = pxd_dev->minor;
	disk->flags |= GENHD_FL_EXT_DEVT | GENHD_FL_NO_PART_SCAN;
	disk->fops = &pxd_bd_ops;
	disk->private_data = pxd_dev;
	set_capacity(disk, add->size / SECTOR_SIZE);

	blk_queue_max_hw_sectors(q, SEGMENT_SIZE / SECTOR_SIZE);
	blk_queue_max_segment_size(q, SEGMENT_SIZE);
	blk_queue_max_segments(q, (SEGMENT_SIZE / PXD_LBS));
	blk_queue_io_min(q, PXD_LBS);
	blk_queue_io_opt(q, PXD_LBS);
	blk_queue_logical_block_size(q, PXD_LBS);
	blk_queue_physical_block_size(q, PXD_LBS);

	/* Enable discard support. */

	QUEUE_FLAG_SET(QUEUE_FLAG_DISCARD,q);

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
}

static void pxd_free_disk(struct pxd_device *pxd_dev)
{
	struct gendisk *disk = pxd_dev->disk;

	if (!disk) {
		return;
	}

	pxd_fastpath_cleanup(pxd_dev);
	pxd_dev->disk = NULL;

	if (disk) {
		del_gendisk(disk);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
		blk_cleanup_disk(disk);
#else
		blk_cleanup_queue(disk->queue);
		put_disk(disk);
#endif

#ifdef __PX_BLKMQ__
		blk_mq_free_tag_set(&pxd_dev->tag_set);
#endif
	}
}

ssize_t pxd_add(struct fuse_conn *fc, struct pxd_add_ext_out *add)
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
	pxd_dev->connected = true; // fuse slow path connection
	pxd_dev->size = add->size;
	pxd_dev->mode = add->open_mode;
	pxd_dev->fastpath = add->enable_fp;

	printk(KERN_INFO"Device %llu added with mode %#x fastpath %d npath %lu\n",
			add->dev_id, add->open_mode, add->enable_fp, add->paths.count);

	// initializes fastpath context part of pxd_dev, enables it only
	// if pxd_dev->fastpath is true, and backing dev paths are available.
	err = pxd_fastpath_init(pxd_dev);
	if (err)
		goto out_id;

	err = pxd_init_disk(pxd_dev, add);
	if (err) {
		if (pxd_dev->fastpath) pxd_fastpath_cleanup(pxd_dev);
		goto out_id;
	}

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
	device_add_disk(&pxd_dev->dev, pxd_dev->disk, NULL);
#else
	add_disk(pxd_dev->disk);
#endif

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

	pxd_printk(KERN_INFO"pxd_remove for device %llu\n",
			remove->dev_id);

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
	pxd_fastpath_cleanup(pxd_dev);

	/* Make sure the req_fn isn't called anymore even if the device hangs around */
	if (pxd_dev->disk && pxd_dev->disk->queue){
		mutex_lock(&pxd_dev->disk->queue->sysfs_lock);

		QUEUE_FLAG_SET(QUEUE_FLAG_DYING, pxd_dev->disk->queue);

		mutex_unlock(&pxd_dev->disk->queue->sysfs_lock);
	}

	spin_unlock(&pxd_dev->lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
	// Not required
	pxd_free_disk(pxd_dev);
#else
	device_unregister(&pxd_dev->dev);
#endif

	module_put(THIS_MODULE);

	return 0;
out:
	return err;
}

ssize_t pxd_update_size(struct fuse_conn *fc, struct pxd_update_size *update_size)
{
	return -EOPNOTSUPP;
}

ssize_t pxd_ioc_update_size(struct fuse_conn *fc, struct pxd_update_size *update_size)
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

	if (update_size->size < pxd_dev->size) {
		spin_unlock(&pxd_dev->lock);
		err = -EINVAL;
		goto out;
	}
	(void)get_device(&pxd_dev->dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
	set_capacity(pxd_dev->disk, update_size->size / SECTOR_SIZE);
#else
	// set_capacity is sufficient for modifying disk size from 5.11 onwards
	set_capacity_and_notify(pxd_dev->disk, update_size->size / SECTOR_SIZE);
#endif
	spin_unlock(&pxd_dev->lock);

	// set_capacity is sufficient for modifying disk size from 5.11 onwards
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0) || (defined(__EL8__) && defined(GD_READ_ONLY))
	revalidate_disk_size(pxd_dev->disk, true);
#else
	err = revalidate_disk(pxd_dev->disk);
	BUG_ON(err);
#endif
#endif
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
		struct pxd_dev_id id = {0}; // initialize all fields to zero
		id.dev_id = pxd_dev->dev_id;
		id.local_minor = pxd_dev->minor;
		id.blkmq_device = 1; // all devices are blkmq registered devices
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

	return copied;

copy_error:
	spin_unlock(&fc->lock);
	return -EFAULT;
}


static int __pxd_update_path(struct pxd_device *pxd_dev, struct pxd_update_path_out *update_path)
{
	/// This seems risky to update paths on the fly while the px device is active
	/// Need to confirm behavior while IOs are active and handle it right!!!!
	pxd_init_fastpath_target(pxd_dev, update_path);
	return 0;

}

ssize_t pxd_update_path(struct fuse_conn *fc, struct pxd_update_path_out *update_path)
{
	bool found = false;
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	int err;
	struct pxd_device *pxd_dev;

	spin_lock(&ctx->lock);
	list_for_each_entry(pxd_dev, &ctx->list, node) {
		if ((pxd_dev->dev_id == update_path->dev_id) && !pxd_dev->removing) {
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

	err=__pxd_update_path(pxd_dev, update_path);
out:
	if (found) spin_unlock(&pxd_dev->lock);
	return err;
}


int pxd_set_fastpath(struct fuse_conn *fc, struct pxd_fastpath_out *fp)
{
	bool found = false;
	struct pxd_context *ctx = container_of(fc, struct pxd_context, fc);
	struct pxd_device *pxd_dev;
	int err;

	printk(KERN_WARNING"device %llu, set fastpath enable %d, cleanup %d\n",
			fp->dev_id, fp->enable, fp->cleanup);
	spin_lock(&ctx->lock);
	list_for_each_entry(pxd_dev, &ctx->list, node) {
		if ((pxd_dev->dev_id == fp->dev_id) && !pxd_dev->removing) {
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

	/* setup whether access is block or file access */
	if (fp->enable) {
		enableFastPath(pxd_dev, false);
	} else {
		if (fp->cleanup) disableFastPath(pxd_dev);
	}

	spin_unlock(&pxd_dev->lock);

	return 0;
out:
	if (found) spin_unlock(&pxd_dev->lock);
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
	return sprintf(buf, "%u\n", pxd_timeout_secs);
}

ssize_t pxd_timeout_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	uint32_t new_timeout_secs = 0;
	struct pxd_context *ctx = pxd_dev->ctx;

	if (ctx == NULL)
		return -ENXIO;

	sscanf(buf, "%u", &new_timeout_secs);
	if (new_timeout_secs < PXD_TIMER_SECS_MIN ||
			new_timeout_secs > PXD_TIMER_SECS_MAX) {
		return -EINVAL;
	}

	if (!ctx->fc.connected) {
		cancel_delayed_work_sync(&ctx->abort_work);
	}
	spin_lock(&ctx->lock);
	pxd_timeout_secs = new_timeout_secs;
	if (!ctx->fc.connected) {
		schedule_delayed_work(&ctx->abort_work, pxd_timeout_secs * HZ);
	}
	spin_unlock(&ctx->lock);

	return count;
}

static ssize_t pxd_active_show(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	char *cp = buf;
	int ncount;
	int available = PAGE_SIZE - 1;
	int i;

	ncount = snprintf(cp, available, "nactive: %u/%u, [write: %u, flush: %u(nop: %u), fua: %u, discard: %u, preflush: %u], switched: %u, slowpath: %u\n",
                atomic_read(&pxd_dev->fp.ncount), atomic_read(&pxd_dev->fp.ncomplete),
		atomic_read(&pxd_dev->fp.nio_write),
		atomic_read(&pxd_dev->fp.nio_flush), atomic_read(&pxd_dev->fp.nio_flush_nop),
		atomic_read(&pxd_dev->fp.nio_fua), atomic_read(&pxd_dev->fp.nio_discard),
		atomic_read(&pxd_dev->fp.nio_preflush),
		atomic_read(&pxd_dev->fp.nswitch), atomic_read(&pxd_dev->fp.nslowPath));

	cp += ncount;
	available -= ncount;
	for (i = 0; i < pxd_dev->fp.nfd; i++) {
		size_t tmp = snprintf(cp, available, "%s\n", pxd_dev->fp.device_path[i]);
		cp += tmp;
		available -= tmp;
		ncount += tmp;
	}

	return ncount;
}

static ssize_t pxd_sync_show(struct device *dev,
                     struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	return sprintf(buf, "sync: %u/%u %s\n",
			atomic_read(&pxd_dev->fp.nsync_active),
			atomic_read(&pxd_dev->fp.nsync),
			(pxd_dev->fp.bg_flush_enabled ? "(enabled)" : "(disabled)"));
}

static ssize_t pxd_sync_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	int enable = 0;

	sscanf(buf, "%d", &enable);

	if (enable) {
		pxd_dev->fp.bg_flush_enabled = 1;
	} else {
		pxd_dev->fp.bg_flush_enabled = 0;
	}

	return count;
}

static ssize_t pxd_mode_show(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	char modestr[32];
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);

	decode_mode(pxd_dev->mode, modestr);
	return sprintf(buf, "mode: %#x/%s\n", pxd_dev->mode, modestr);
}

static ssize_t pxd_wrsegment_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	return sprintf(buf, "write segment size(bytes): %d\n", pxd_dev->fp.n_flush_wrsegs * PXD_LBS);
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

	pxd_dev->fp.n_flush_wrsegs = nsegs;
	return count;
}

static ssize_t pxd_congestion_show(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);

	return sprintf(buf, "congested: %s (%d/%d)\n",
			pxd_dev->fp.congested ? "yes" : "no",
			pxd_dev->fp.nr_congestion_on,
			pxd_dev->fp.nr_congestion_off);
}

static ssize_t pxd_congestion_set(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	int thresh;

	sscanf(buf, "%d", &thresh);

	if (thresh < 0) {
		thresh = pxd_dev->fp.qdepth;
	}

	if (thresh > MAX_CONGESTION_THRESHOLD) {
		thresh = MAX_CONGESTION_THRESHOLD;
	}

	spin_lock_irq(&pxd_dev->lock);
	pxd_dev->fp.qdepth = thresh;
	spin_unlock_irq(&pxd_dev->lock);

	return count;
}

static ssize_t pxd_fastpath_state(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	return sprintf(buf, "%d\n", pxd_dev->fp.nfd);
}

static char* __strtok_r(char *src, const char delim, char **saveptr) {
	char *curr;
	char *start;

	if (src) {
		start = src;
		*saveptr = NULL;
	} else {
		start = *saveptr;
	}
	curr = start;
	while (curr && *curr) {
		if (*curr == delim) {
			*saveptr = curr+1;
			*curr = '\0';

			return start;
		}
		curr++;
	}

	return start;
}

static void __strip_nl(const char *src, char *dst, int maxlen) {
	char *tmp;
	int len=strlen(src);


	if (!src || !dst) {
		return;
	}

	dst[0] = '\0';
	if (!len) {
		return;
	}

	if (len >= maxlen) {
		// to accomodate null
		printk(KERN_WARNING"stripping newline output buffer overflow.. src %d(%s), dst %d\n",
				len, src, maxlen);
		len = maxlen - 1;
	}

	// leading space
	while (src && *src) {
		if (!isspace(*src) && !iscntrl(*src)) {
			memcpy(dst,src,len);
			dst[len]='\0';
			break;
		}
		src++;
		len--;
	}

	// trailing space
	tmp = dst + len - 1;
	while (len && *tmp) {
		if (isspace(*tmp) || iscntrl(*tmp)) {
			*tmp='\0';
			tmp--;
			len--;
			continue;
		}
		break;
	}

	printk(KERN_INFO"stripping newline src=(%s), dst=(%s), len=%d\n",
			src, dst, len);
}

static ssize_t pxd_fastpath_update(struct device *dev, struct device_attribute *attr,
					   const char *buf, size_t count)
{
	// format: path,path,path
	struct pxd_device *pxd_dev = dev_to_pxd_dev(dev);
	struct pxd_update_path_out update_out;
	const char delim = ',';
	char *token;
	char *saveptr = NULL;
	int i;
	char trimtoken[256];

	char *tmp = kzalloc(count, GFP_KERNEL);
	if (!tmp) {
		printk("No memory to process %lu bytes", count);
		return count;
	}
	memcpy(tmp, buf, count);

	i=0;
	token = __strtok_r(tmp, delim, &saveptr);
	for (i=0; i<MAX_PXD_BACKING_DEVS && token; i++) {
		// strip the token of any newline/whitespace
		__strip_nl(token, trimtoken, sizeof(trimtoken));
		strncpy(update_out.devpath[i], trimtoken, MAX_PXD_DEVPATH_LEN);
		update_out.devpath[i][MAX_PXD_DEVPATH_LEN] = '\0';

		token = __strtok_r(0, delim, &saveptr);
	}
	update_out.count = i;
	update_out.dev_id = pxd_dev->dev_id;

	__pxd_update_path(pxd_dev, &update_out);
	kfree(tmp);

	return count;
}

static DEVICE_ATTR(size, S_IRUGO, pxd_size_show, NULL);
static DEVICE_ATTR(major, S_IRUGO, pxd_major_show, NULL);
static DEVICE_ATTR(minor, S_IRUGO, pxd_minor_show, NULL);
static DEVICE_ATTR(timeout, S_IRUGO|S_IWUSR, pxd_timeout_show, pxd_timeout_store);
static DEVICE_ATTR(active, S_IRUGO, pxd_active_show, NULL);
static DEVICE_ATTR(sync, S_IRUGO|S_IWUSR, pxd_sync_show, pxd_sync_store);
static DEVICE_ATTR(congested, S_IRUGO|S_IWUSR, pxd_congestion_show, pxd_congestion_set);
static DEVICE_ATTR(writesegment, S_IRUGO|S_IWUSR, pxd_wrsegment_show, pxd_wrsegment_store);
static DEVICE_ATTR(fastpath, S_IRUGO|S_IWUSR, pxd_fastpath_state, pxd_fastpath_update);
static DEVICE_ATTR(mode, S_IRUGO, pxd_mode_show, NULL);

static struct attribute *pxd_attrs[] = {
	&dev_attr_size.attr,
	&dev_attr_major.attr,
	&dev_attr_minor.attr,
	&dev_attr_timeout.attr,
	&dev_attr_active.attr,
	&dev_attr_sync.attr,
	&dev_attr_congested.attr,
	&dev_attr_writesegment.attr,
	&dev_attr_fastpath.attr,
	&dev_attr_mode.attr,
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
	if (fc->connected == 1) {
		printk(KERN_ERR "%s: pxd-control-%d(%lld) already open\n", __func__,
			ctx->id, ctx->open_seq);
		return -EINVAL;
	}

	cancel_delayed_work_sync(&ctx->abort_work);
	spin_lock(&ctx->lock);
	pxd_timeout_secs = PXD_TIMER_SECS_DEFAULT;
	fc->connected = 1;
	spin_unlock(&ctx->lock);

	fc->allow_disconnected = 1;
	file->private_data = fc;

	pxdctx_set_connected(ctx, true);
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
	if (ctx->fc.connected == 0) {
		pxd_printk("%s: not opened\n", __func__);
	} else {
		ctx->fc.connected = 0;
	}

	schedule_delayed_work(&ctx->abort_work, pxd_timeout_secs * HZ);
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

static void pxd_abort_context(struct work_struct *work)
{
	struct pxd_context *ctx = container_of(to_delayed_work(work), struct pxd_context,
		abort_work);
	struct fuse_conn *fc = &ctx->fc;

	BUG_ON(fc->connected);

	printk(KERN_ERR "PXD_TIMEOUT (%s:%u): Aborting all requests...",
		ctx->name, ctx->id);

	fc->allow_disconnected = 0;

	/* Let other threads see the value of allow_disconnected. */
	synchronize_rcu();

	spin_lock(&fc->lock);
	fuse_end_queued_requests(fc);
	spin_unlock(&fc->lock);
	pxdctx_set_connected(ctx, false);
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
	INIT_DELAYED_WORK(&ctx->abort_work, pxd_abort_context);
	return 0;
}

static void pxd_context_destroy(struct pxd_context *ctx)
{
	misc_deregister(&ctx->miscdev);
	cancel_delayed_work_sync(&ctx->abort_work);
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

	err = fastpath_init();
	if (err) {
		printk(KERN_ERR "pxd: fastpath initialization failed: %d\n", err);
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

	fastpath_cleanup();
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
