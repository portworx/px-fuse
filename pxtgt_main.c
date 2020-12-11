#include <linux/module.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/sysfs.h>
#include <linux/crc32.h>
#include <linux/ctype.h>
#include <linux/uio.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/random.h>
#include "pxtgt.h"
#include "pxtgt_io.h"

#include "pxmgr.h"

#define STATIC

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)

#ifdef RHEL_RELEASE_CODE

#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,6)
static
void _generic_end_io_acct(struct request_queue *q, int rw,
		struct hd_struct *part, unsigned long start_time)
{
	unsigned long duration = jiffies - start_time;
	int cpu = part_stat_lock();

	part_stat_add(cpu, part, ticks[rw], duration);
	part_round_stats(q, cpu, part);
	part_dec_in_flight(q, part, rw);

	part_stat_unlock();
}

static
void _generic_start_io_acct(struct request_queue *q, int rw,
		unsigned long sectors, struct hd_struct *part)
{
	int cpu = part_stat_lock();

	part_round_stats(q, cpu, part);
	part_stat_inc(cpu, part, ios[rw]);
	part_stat_add(cpu, part, sectors[rw], sectors);
	part_inc_in_flight(q, part, rw);

	part_stat_unlock();
}
#else
static
void _generic_end_io_acct(struct request_queue *q, int rw,
		struct hd_struct *part, unsigned long start_time)
{
	unsigned long duration = jiffies - start_time;
	int cpu = part_stat_lock();

	part_stat_add(cpu, part, ticks[rw], duration);
	part_round_stats(cpu, part);
	part_dec_in_flight(part, rw);

	part_stat_unlock();
}

static
void _generic_start_io_acct(struct request_queue *q, int rw,
		unsigned long sectors, struct hd_struct *part)
{
	int cpu = part_stat_lock();

	part_round_stats(cpu, part);
	part_stat_inc(cpu, part, ios[rw]);
	part_stat_add(cpu, part, sectors[rw], sectors);
	part_inc_in_flight(part, rw);

	part_stat_unlock();
}
#endif

#else
// non RHEL distro
// based on unpatched pristine kernel release
static
void _generic_end_io_acct(struct request_queue *q, int rw,
		struct hd_struct *part, unsigned long start_time)
{
	unsigned long duration = jiffies - start_time;
	int cpu = part_stat_lock();

	part_stat_add(cpu, part, ticks[rw], duration);
	part_round_stats(cpu, part);
	part_dec_in_flight(part, rw);

	part_stat_unlock();
}

static
void _generic_start_io_acct(struct request_queue *q, int rw,
		unsigned long sectors, struct hd_struct *part)
{
	int cpu = part_stat_lock();

	part_round_stats(cpu, part);
	part_stat_inc(cpu, part, ios[rw]);
	part_stat_add(cpu, part, sectors[rw], sectors);
	part_inc_in_flight(part, rw);

	part_stat_unlock();
}

#endif
#endif

// A private global bio mempool for punting requests bypassing vfs
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
static struct bio_set pxtgt_bio_set;
#endif
#define PXTGT_MIN_POOL_PAGES (128)
static struct bio_set* ppxtgt_bio_set;

#define CREATE_TRACE_POINTS
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE pxtgt_trace
#include "pxtgt_trace.h"
#undef CREATE_TRACE_POINTS

#include "pxtgt_compat.h"
#include "pxtgt_core.h"

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

#define PXTGT_TIMER_SECS_MIN 30
#define PXTGT_TIMER_SECS_DEFAULT 600
#define PXTGT_TIMER_SECS_MAX (U32_MAX)

#define TOSTRING_(x) #x
#define VERTOSTR(x) TOSTRING_(x)

extern const char *gitversion;
static dev_t pxtgt_major;
static DEFINE_IDA(pxtgt_minor_ida);

struct pxtgt_context *pxtgt_contexts;
uint32_t pxtgt_num_contexts = PXTGT_NUM_CONTEXTS;
uint32_t pxtgt_num_contexts_exported = PXTGT_NUM_CONTEXT_EXPORTED;
uint32_t pxtgt_timeout_secs = PXTGT_TIMER_SECS_DEFAULT;

module_param(pxtgt_num_contexts_exported, uint, 0644);
module_param(pxtgt_num_contexts, uint, 0644);

static void pxtgtctx_set_connected(struct pxtgt_context *ctx, bool enable);
static int pxtgt_bus_add_dev(struct pxtgt_device *pxtgt_dev);

struct pxtgt_context* find_context(unsigned ctx)
{
	if (ctx >= pxtgt_num_contexts) {
		return NULL;
	}

	return &pxtgt_contexts[ctx];
}

static int pxtgt_open(struct block_device *bdev, fmode_t mode)
{
	struct pxtgt_device *pxtgt_dev = bdev->bd_disk->private_data;
	int err = 0;

	spin_lock(&pxtgt_dev->lock);
	if (pxtgt_dev->removing)
		err = -EBUSY;
	else
		pxtgt_dev->open_count++;
	spin_unlock(&pxtgt_dev->lock);

	if (!err)
		(void)get_device(&pxtgt_dev->dev);
	trace_pxtgt_open(pxtgt_dev->dev_id, pxtgt_dev->major, pxtgt_dev->minor, mode, err);
	return err;
}

static void pxtgt_release(struct gendisk *disk, fmode_t mode)
{
	struct pxtgt_device *pxtgt_dev = disk->private_data;

	spin_lock(&pxtgt_dev->lock);
	BUG_ON(pxtgt_dev->magic != PXTGT_DEV_MAGIC);
	pxtgt_dev->open_count--;
	spin_unlock(&pxtgt_dev->lock);

	trace_pxtgt_release(pxtgt_dev->dev_id, pxtgt_dev->major, pxtgt_dev->minor, mode);
	put_device(&pxtgt_dev->dev);
}

STATIC
long pxtgt_ioctl_dump_fc_info(void)
{
	int i;
	struct pxtgt_context *ctx;

	for (i = 0; i < pxtgt_num_contexts; ++i) {
		ctx = &pxtgt_contexts[i];
		if (ctx->num_devices == 0) {
			continue;
		}
		printk(KERN_INFO "%s: pxtgt_ctx: %s ndevices: %lu",
			__func__, ctx->name, ctx->num_devices);
	}
	return 0;
}

static long pxtgt_ioctl_get_version(void __user *argp)
{
	char ver_data[64];
	int ver_len = 0;

	if (argp) {
		ver_len = strlen(gitversion) < 64 ? strlen(gitversion) : 64;
		strncpy(ver_data, gitversion, ver_len);
		if (copy_to_user(argp +
				 offsetof(struct pxtgt_ioctl_version_args, piv_len),
			&ver_len, sizeof(ver_len))) {
			return -EFAULT;
		}
		if (copy_to_user(argp +
				 offsetof(struct pxtgt_ioctl_version_args, piv_data),
			ver_data, ver_len)) {
			return -EFAULT;
		}
	}

	return 0;
}

static long pxtgt_ioctl_init(struct file *file, void __user *argp)
{
	struct pxtgt_context *ctx = container_of(file->f_op, struct pxtgt_context, fops);
	struct iov_iter iter;
	struct iovec iov = {argp, sizeof(struct pxtgt_ioctl_init_args)};

	iov_iter_init(&iter, WRITE, &iov, 1, sizeof(struct pxtgt_ioctl_init_args));

	return pxtgt_read_init(ctx, &iter);
}

static long pxtgt_ioctl_resize(struct file *file, void __user *argp)
{
	struct pxtgt_context *ctx = NULL;
	struct pxtgt_update_size update_args;
	long ret = 0;

	if (copy_from_user(&update_args, argp, sizeof(update_args))) {
		return -EFAULT;
	}

	if (update_args.context_id >= pxtgt_num_contexts_exported) {
		printk("%s : invalid context: %d\n", __func__, update_args.context_id);
		return -EFAULT;
	}

	ctx =  &pxtgt_contexts[update_args.context_id];
	if (!ctx || ctx->id >= pxtgt_num_contexts_exported) {
		return -EFAULT;
	}

	ret = pxtgt_ioc_update_size(ctx, &update_args);
	return ret;
}

static long pxtgt_control_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case PXTGT_IOC_GET_VERSION:
		return pxtgt_ioctl_get_version((void __user *)arg);
	case PXTGT_IOC_INIT:
		return pxtgt_ioctl_init(file, (void __user *)arg);
	case PXTGT_IOC_RESIZE:
		return pxtgt_ioctl_resize(file, (void __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct block_device_operations pxtgt_bd_ops = {
	.owner			= THIS_MODULE,
	.open			= pxtgt_open,
	.release		= pxtgt_release,
};

STATIC
void pxtgt_update_stats(struct fuse_req *req, int rw, unsigned int count)
{
        struct pxtgt_device *pxtgt_dev = req->queue->queuedata;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0) || defined(__EL8__)
        part_stat_lock();
        part_stat_inc(&pxtgt_dev->disk->part0, ios[rw]);
        part_stat_add(&pxtgt_dev->disk->part0, sectors[rw], count);
#else
        int cpu = part_stat_lock();
        part_stat_inc(cpu, &pxtgt_dev->disk->part0, ios[rw]);
        part_stat_add(cpu, &pxtgt_dev->disk->part0, sectors[rw], count);
#endif
        part_stat_unlock();
}

static bool __pxtgt_device_qfull(struct pxtgt_device *pxtgt_dev)
{
	int ncount = PXTGT_ACTIVE(pxtgt_dev);

	// does not care about async or sync request.
	if (ncount > pxtgt_dev->qdepth) {
		if (atomic_cmpxchg(&pxtgt_dev->congested, 0, 1) == 0) {
			pxtgt_dev->nr_congestion_on++;
		}
		return 1;
	}
	if (atomic_cmpxchg(&pxtgt_dev->congested, 1, 0) == 1) {
		pxtgt_dev->nr_congestion_off++;
	}
	return 0;
}

// congestion callback from kernel writeback module
int pxtgt_device_congested(void *data, int bits)
{
	struct pxtgt_device *pxtgt_dev = data;

	// notify congested if device is suspended as well.
	// modified under lock, read outside lock.
	if (atomic_read(&pxtgt_dev->suspend)) {
		return 1;
	}

	return __pxtgt_device_qfull(pxtgt_dev);
}

void pxtgt_check_q_congested(struct pxtgt_device *pxtgt_dev)
{
	if (pxtgt_device_congested(pxtgt_dev, 0)) {
		wait_event_interruptible(pxtgt_dev->suspend_wq,
			!pxtgt_device_congested(pxtgt_dev, 0));
	}
}

void pxtgt_check_q_decongested(struct pxtgt_device *pxtgt_dev)
{
	if (!pxtgt_device_congested(pxtgt_dev, 0)) {
		wake_up(&pxtgt_dev->suspend_wq);
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

// All fileio reads will use this work entry.
// blockio reads will directly switch clone BIO
static void pxtgt_process_fileio(struct work_struct *wi)
{
	struct pxtgt_io_tracker *head = container_of(wi, struct pxtgt_io_tracker, wi);
	struct pxtgt_device *pxtgt_dev = head->pxtgt_dev;

	BUG_ON(head->magic != PXTGT_IOT_MAGIC);
	BUG_ON(pxtgt_dev->magic != PXTGT_DEV_MAGIC);
	do_bio_filebacked(pxtgt_dev, head);
}

static void pxtgt_compute_checksum(struct pxtgt_device *pxtgt_dev,
		struct pxtgt_io_tracker *head)
{
	// compute checksum for each 4K block and write a journal entry with checksum
}

// All writes (fileio/blockio) will use this work entry.
static void pxtgt_preprocess_write(struct work_struct *wi)
{
	struct pxtgt_io_tracker *head = container_of(wi, struct pxtgt_io_tracker, wi);
	struct pxtgt_device *pxtgt_dev = head->pxtgt_dev;

	BUG_ON(head->magic != PXTGT_IOT_MAGIC);
	BUG_ON(pxtgt_dev->magic != PXTGT_DEV_MAGIC);
	// XXX need to first write a journal checksum, data write, journal (commit)
	// step 1: compute checksum 
	pxtgt_compute_checksum(pxtgt_dev, head);

	// step 2: data write
	if (pxtgt_dev->block_io) {
		SUBMIT_BIO(&head->clone);
	} else {
		do_bio_filebacked(pxtgt_dev, head);
	}
	// step 3: after write complete from backing device
}

// step 3: journal data write complete
static void pxtgt_postprocess_write(struct pxtgt_device *pxtgt_dev,
		struct pxtgt_io_tracker *head)
{
	// check for sync write or plain data write.
	// if sync write, a journal commit entry needs to be written too.
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
static void pxtgt_complete_io_dummy(struct bio* bio)
#else
static void pxtgt_complete_io_dummy(struct bio* bio, int error)
#endif
{
	printk("%s: bio %px should never be called\n", __func__, bio);
	BUG();
}

STATIC
void __pxtgt_cleanup_block_io(struct pxtgt_io_tracker *head);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
void pxtgt_complete_io(struct bio* bio)
#else
void pxtgt_complete_io(struct bio* bio, int error)
#endif
{
	struct pxtgt_io_tracker *head = container_of(bio, struct pxtgt_io_tracker, clone);
	struct pxtgt_device *pxtgt_dev = bio->bi_private;
	int blkrc;

	BUG_ON(head->magic != PXTGT_IOT_MAGIC);
	BUG_ON(pxtgt_dev->magic != PXTGT_DEV_MAGIC);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
	blkrc = blk_status_to_errno(bio->bi_status);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
	blkrc = bio->bi_error;
#else
	blkrc = error;
#endif

	head->status = blkrc;
	if (!atomic_dec_and_test(&head->active)) {
		// not all responses have come back
		// but update head status if this is a failure
		return;
	}

	pxtgt_io_printk("%s: dev m %d g %lld %s at %ld len %d bytes %d pages "
			"flags 0x%lx\n", __func__,
			pxtgt_dev->minor, pxtgt_dev->dev_id,
			bio_data_dir(bio) == WRITE ? "wr" : "rd",
			BIO_SECTOR(bio) * SECTOR_SIZE, BIO_SIZE(bio),
			bio->bi_vcnt, bio->bi_flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,1)
	bio_end_io_acct(bio, iot->start);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) &&  \
     defined(bvec_iter_sectors))
	generic_end_io_acct(pxtgt_dev->disk->queue, bio_op(bio), &pxtgt_dev->disk->part0, head->start);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	generic_end_io_acct(bio_data_dir(bio), &pxtgt_dev->disk->part0, head->start);
#else
	_generic_end_io_acct(pxtgt_dev->disk->queue, bio_data_dir(bio), &pxtgt_dev->disk->part0, head->start);
#endif

	BUG_ON(pxtgt_dev->magic != PXTGT_DEV_MAGIC);
	atomic_inc(&pxtgt_dev->ncomplete);
	atomic_dec(&pxtgt_dev->ncount);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
{
		head->orig->bi_status = errno_to_blk_status(blkrc);
		bio_endio(head->orig);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
{
		head->orig->bi_error = blkrc;
		bio_endio(head->orig);
}
#else
{
		bio_endio(head->orig, blkrc);
}
#endif

	pxtgt_check_q_decongested(pxtgt_dev);

	if (bio_data_dir(&head->clone) != READ) {
		pxtgt_postprocess_write(pxtgt_dev, head);
	}

	__pxtgt_cleanup_block_io(head);
}

STATIC
void __pxtgt_cleanup_block_io(struct pxtgt_io_tracker *head)
{
	BUG_ON(head->magic != PXTGT_IOT_MAGIC);
	head->magic = PXTGT_POISON;
	bio_put(&head->clone);
}

STATIC
struct pxtgt_io_tracker* __pxtgt_init_block_head(struct pxtgt_device *pxtgt_dev,
		struct bio *bio) {
	struct bio* clone_bio;
	struct pxtgt_io_tracker* iot;
	struct address_space *mapping = pxtgt_dev->fp->f_mapping;
	struct inode *inode = mapping->host;
	struct block_device *bdev = I_BDEV(inode);

	pxtgt_printk("pxtgt %px:%s entering with bio %px\n",
			pxtgt_dev, __func__, bio);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	clone_bio = bio_clone_fast(bio, GFP_KERNEL, ppxtgt_bio_set);
#else
	clone_bio = bio_clone_bioset(bio, GFP_KERNEL, ppxtgt_bio_set);
#endif
	if (!clone_bio) {
		pxtgt_printk(KERN_ERR"No memory for io context");
		return NULL;
	}

	iot = container_of(clone_bio, struct pxtgt_io_tracker, clone);
	BUG_ON(&iot->clone != clone_bio);

	iot->magic = PXTGT_IOT_MAGIC;
	iot->pxtgt_dev = pxtgt_dev;
	INIT_LIST_HEAD(&iot->item);
	iot->orig = bio;
	iot->start = jiffies;
	atomic_set(&iot->active, 0);
	iot->status = 0;

	if (bio_data_dir(bio) == READ) {
		INIT_WORK(&iot->wi, pxtgt_process_fileio);
	} else {
		INIT_WORK(&iot->wi, pxtgt_preprocess_write);
	}

	clone_bio->bi_private = pxtgt_dev;
	if (pxtgt_dev->block_io) {
		BIO_SET_DEV(clone_bio, bdev);
		clone_bio->bi_end_io = pxtgt_complete_io;
	} else {
		clone_bio->bi_end_io = pxtgt_complete_io_dummy;
	}

	return iot;
}

static
void pxtgt_process_io(struct pxtgt_io_tracker *head)
{
	struct pxtgt_device *pxtgt_dev = head->pxtgt_dev;
	struct bio *bio = head->orig;
	int dir = bio_data_dir(bio);

	//
	// Based on the nfd mapped on pxtgt_dev, that many cloned bios shall be
	// setup, then each replica takes its own processing path, which could be
	// either file backup or block device backup.
	//
	BUG_ON(head->magic != PXTGT_IOT_MAGIC);
	BUG_ON(pxtgt_dev->magic != PXTGT_DEV_MAGIC);
	atomic_inc(&pxtgt_dev->ncount);
	// initialize active io to configured replicas
	if (dir != READ) {
		/// This needs to populate journal
		atomic_set(&head->active, 1); // one for IO and one for journal
		// submit all replicas linked from head, if not read
		// XXXX - need to initiate journal, checksum compute
		queue_work(pxtgt_dev->wq, &head->wi);
	} else {
		/// Just pass along
		atomic_set(&head->active, 1);
		// submit head bio the last
		if (pxtgt_dev->block_io) {
			SUBMIT_BIO(&head->clone);
		} else {
			queue_work(pxtgt_dev->wq, &head->wi);
		}
	}
}

// fastpath uses this path to punt requests to slowpath
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
blk_qc_t pxtgt_make_request(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
void pxtgt_make_request(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL
#endif
{
	struct pxtgt_device *pxtgt_dev = q->queuedata;
	int rw = bio_data_dir(bio);
	struct pxtgt_io_tracker *head;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
	if (!pxtgt_dev) {
#else
	if (rw == READA) rw = READ;
	if (!pxtgt_dev || (rw != READ && rw != WRITE)) {
#endif
		printk_ratelimited(KERN_ERR"pxtgt basic sanity fail, pxtgt_device %px (%llu), rw %#x\n",
				pxtgt_dev, (pxtgt_dev? pxtgt_dev->dev_id: (uint64_t)0), rw);
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	if (!pxtgt_dev->connected || pxtgt_dev->removing) {
		printk_ratelimited(KERN_ERR"px is disconnected, failing IO.\n");
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	pxtgt_io_printk("%s: dev m %d g %lld %s at %ld len %d bytes %d pages "
			"flags 0x%lx\n", __func__,
			pxtgt_dev->minor, pxtgt_dev->dev_id,
			bio_data_dir(bio) == WRITE ? "wr" : "rd",
			BIO_SECTOR(bio) * SECTOR_SIZE, BIO_SIZE(bio),
			bio->bi_vcnt, bio->bi_flags);

	pxtgt_check_q_congested(pxtgt_dev);
	head = __pxtgt_init_block_head(pxtgt_dev, bio);
	if (!head) {
		BIO_ENDIO(bio, -ENOMEM);

		// trivial high memory pressure failing IO
		return BLK_QC_RETVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,1)
	bio_start_io_acct(bio);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
	generic_start_io_acct(pxtgt_dev->disk->queue, bio_op(bio), REQUEST_GET_SECTORS(bio), &pxtgt_dev->disk->part0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	generic_start_io_acct(bio_data_dir(bio), REQUEST_GET_SECTORS(bio), &pxtgt_dev->disk->part0);
#else
	_generic_start_io_acct(pxtgt_dev->disk->queue, bio_data_dir(bio), REQUEST_GET_SECTORS(bio), &pxtgt_dev->disk->part0);
#endif

	pxtgt_process_io(head);

	pxtgt_printk("pxtgt_make_request for device %llu done\n", pxtgt_dev->dev_id);
	return BLK_QC_RETVAL;
}

static int pxtgt_init_disk(struct pxtgt_device *pxtgt_dev, struct pxtgt_add_out *add)
{
	struct gendisk *disk;
	struct request_queue *q;
	int err = 0;

	if (add->queue_depth < 0 || add->queue_depth > PXTGT_MAX_QDEPTH)
		return -EINVAL;

	/* Create gendisk info. */
	disk = alloc_disk(1);
	if (!disk)
		return -ENOMEM;

	snprintf(disk->disk_name, sizeof(disk->disk_name),
			PXTGT_DEV"%llu", pxtgt_dev->dev_id);
	disk->major = pxtgt_dev->major;
	disk->first_minor = pxtgt_dev->minor;
	disk->flags |= GENHD_FL_EXT_DEVT | GENHD_FL_NO_PART_SCAN;
	disk->fops = &pxtgt_bd_ops;
	disk->private_data = pxtgt_dev;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
	q = blk_alloc_queue(pxtgt_make_request, NUMA_NO_NODE);
#else
	q = blk_alloc_queue(GFP_KERNEL);
#endif
	if (!q) {
		err = -ENOMEM;
		goto out_disk;
	}

	// add hooks to control congestion only while using fastpath
	PXTGT_SETUP_CONGESTION_HOOK(q->backing_dev_info, pxtgt_device_congested, pxtgt_dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
	blk_queue_make_request(q, pxtgt_make_request);
#endif

	blk_queue_max_hw_sectors(q, SEGMENT_SIZE / SECTOR_SIZE);
	blk_queue_max_segment_size(q, SEGMENT_SIZE);
	blk_queue_max_segments(q, (SEGMENT_SIZE / PXTGT_LBS));
	blk_queue_io_min(q, PXTGT_LBS);
	blk_queue_io_opt(q, PXTGT_LBS);
	blk_queue_logical_block_size(q, PXTGT_LBS);
	blk_queue_physical_block_size(q, PXTGT_LBS);

	set_capacity(disk, add->size / SECTOR_SIZE);

	/* Enable discard support. */
	QUEUE_FLAG_SET(QUEUE_FLAG_DISCARD,q);

    q->limits.discard_granularity = PXTGT_LBS;
	q->limits.discard_alignment = PXTGT_LBS;
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
	q->queuedata = pxtgt_dev;
	pxtgt_dev->disk = disk;

	return 0;
out_disk:
	put_disk(disk);
	return err;
}

static void pxtgt_free_disk(struct pxtgt_device *pxtgt_dev)
{
	struct gendisk *disk = pxtgt_dev->disk;

	if (!disk)
		return;

	pxtgt_dev->disk = NULL;
	if (disk->flags & GENHD_FL_UP) {
		del_gendisk(disk);
		if (disk->queue)
			blk_cleanup_queue(disk->queue);
	}
	put_disk(disk);
}

struct pxtgt_device* find_pxtgt_device(struct pxtgt_context *ctx, uint64_t dev_id)
{
	struct pxtgt_device *pxtgt_dev_itr, *pxtgt_dev;

	pxtgt_dev = NULL;
	spin_lock(&ctx->lock);
	list_for_each_entry(pxtgt_dev_itr, &ctx->list, node) {
		if (pxtgt_dev_itr->dev_id == dev_id) {
			pxtgt_dev = pxtgt_dev_itr;
			break;
		}
	}
	spin_unlock(&ctx->lock);

	return pxtgt_dev;
}

ssize_t pxtgt_add(struct pxtgt_context *ctx, struct pxtgt_add_out *add)
{
	struct pxtgt_device *pxtgt_dev = NULL;
	struct pxtgt_device *pxtgt_dev_itr;
	int new_minor;
	int err;
	struct inode *inode;

	err = -ENODEV;
	if (!try_module_get(THIS_MODULE))
		goto out;

	err = -ENOMEM;
	if (ctx->num_devices >= PXTGT_MAX_DEVICES) {
		printk(KERN_ERR "Too many devices attached..\n");
		goto out_module;
	}

	// if device already exists, then return it
	pxtgt_dev = find_pxtgt_device(ctx, add->dev_id);
	if (pxtgt_dev) {
		module_put(THIS_MODULE);

		return pxtgt_dev->minor;
	}

	pxtgt_dev = kzalloc(sizeof(*pxtgt_dev), GFP_KERNEL);
	if (!pxtgt_dev)
		goto out_module;

	pxtgt_dev->magic = PXTGT_DEV_MAGIC;
	spin_lock_init(&pxtgt_dev->lock);
	spin_lock_init(&pxtgt_dev->qlock);

	new_minor = ida_simple_get(&pxtgt_minor_ida,
				    1, 1 << MINORBITS,
				    GFP_KERNEL);
	if (new_minor < 0) {
		err = new_minor;
		goto out_module;
	}

	pxtgt_dev->dev_id = add->dev_id;
	pxtgt_dev->major = pxtgt_major;
	pxtgt_dev->minor = new_minor;
	pxtgt_dev->ctx = ctx;
	pxtgt_dev->connected = true; // fuse slow path connection
	pxtgt_dev->removing = false;
	pxtgt_dev->size = add->size;
	snprintf(pxtgt_dev->source, sizeof(pxtgt_dev->source), add->source);
	pxtgt_dev->source[MAX_PXTGT_DEVPATH_LEN] = '\0';
	pxtgt_dev->block_io = false;

	atomic_set(&pxtgt_dev->suspend, 0);

	// congestion init
	init_waitqueue_head(&pxtgt_dev->suspend_wq);
	// hard coded congestion limits within driver
	atomic_set(&pxtgt_dev->congested, 0);
	pxtgt_dev->qdepth = DEFAULT_CONGESTION_THRESHOLD;
	pxtgt_dev->nr_congestion_on = 0;
	pxtgt_dev->nr_congestion_off = 0;
	atomic_set(&pxtgt_dev->ncount, 0);

	pxtgt_dev->wq = alloc_workqueue("pxtgt%llu", WQ_SYSFS | WQ_UNBOUND | WQ_HIGHPRI, 0, pxtgt_dev->dev_id);
	if (!pxtgt_dev->wq) {
		err = -ENOMEM;
		goto out_id;
	}

	pxtgt_dev->fp = filp_open(add->source, O_DIRECT | O_RDWR | O_LARGEFILE, 0600);
	if (IS_ERR_OR_NULL(pxtgt_dev->fp)) {
		err = -ENXIO;
		goto out_id;
	}
	inode = pxtgt_dev->fp->f_inode;
	if (S_ISBLK(inode->i_mode)) {
		pxtgt_dev->block_io = true;
	} else if (S_ISREG(inode->i_mode)) {
		pxtgt_dev->block_io = false;
	} else {
		filp_close(pxtgt_dev->fp, NULL);
		err = -EINVAL;
		goto out_id;
	}

	get_file(pxtgt_dev->fp);

	printk(KERN_INFO"Device %llu added %px with source %s blockio %d\n",
			pxtgt_dev->dev_id, pxtgt_dev, pxtgt_dev->source, pxtgt_dev->block_io);

	err = pxtgt_init_disk(pxtgt_dev, add);
	if (err) {
		goto out_id;
	}

	spin_lock(&ctx->lock);
	list_for_each_entry(pxtgt_dev_itr, &ctx->list, node) {
		if (pxtgt_dev_itr->dev_id == add->dev_id) {
			err = -EEXIST;
			spin_unlock(&ctx->lock);
			goto out_disk;
		}
	}

	err = pxtgt_bus_add_dev(pxtgt_dev);
	if (err) {
		spin_unlock(&ctx->lock);
		goto out_disk;
	}

	list_add(&pxtgt_dev->node, &ctx->list);
	++ctx->num_devices;
	spin_unlock(&ctx->lock);

	add_disk(pxtgt_dev->disk);

	return pxtgt_dev->minor;

out_disk:
	pxtgt_free_disk(pxtgt_dev);
out_id:
	ida_simple_remove(&pxtgt_minor_ida, new_minor);
out_module:
	if (pxtgt_dev) {
		if (pxtgt_dev->fp) {
			fput(pxtgt_dev->fp);
		}
		kfree(pxtgt_dev);
	}
	module_put(THIS_MODULE);
out:
	return err;
}

ssize_t pxtgt_remove(struct pxtgt_context *ctx, struct pxtgt_remove_out *remove)
{
	int found = false;
	int err;
	struct pxtgt_device *pxtgt_dev;

	spin_lock(&ctx->lock);
	list_for_each_entry(pxtgt_dev, &ctx->list, node) {
		if (pxtgt_dev->dev_id == remove->dev_id) {
			spin_lock(&pxtgt_dev->lock);
			if (!pxtgt_dev->open_count || remove->force) {
				list_del(&pxtgt_dev->node);
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

	if (pxtgt_dev->open_count && !remove->force) {
		err = -EBUSY;
		spin_unlock(&pxtgt_dev->lock);
		goto out;
	}

	pxtgt_dev->removing = true;
	wmb();

	fput(pxtgt_dev->fp);
	filp_close(pxtgt_dev->fp, NULL);

	if (pxtgt_dev->mc != NULL) {
		int rc = pxmgr_cache_dealloc(pxtgt_dev->mc);
		printk("device %llu caching dealloc returned %d\n", pxtgt_dev->dev_id, rc);
	}

	/* Make sure the req_fn isn't called anymore even if the device hangs around */
	if (pxtgt_dev->disk && pxtgt_dev->disk->queue){
		mutex_lock(&pxtgt_dev->disk->queue->sysfs_lock);

		QUEUE_FLAG_SET(QUEUE_FLAG_DYING, pxtgt_dev->disk->queue);

        mutex_unlock(&pxtgt_dev->disk->queue->sysfs_lock);
	}

	spin_unlock(&pxtgt_dev->lock);

	device_unregister(&pxtgt_dev->dev);

	module_put(THIS_MODULE);

	return 0;
out:
	return err;
}

ssize_t pxtgt_update_size(struct pxtgt_context *fc, struct pxtgt_update_size *update_size)
{
	return -EOPNOTSUPP;
}

ssize_t pxtgt_ioc_update_size(struct pxtgt_context *ctx, struct pxtgt_update_size *update_size)
{
	bool found = false;
	int err;
	struct pxtgt_device *pxtgt_dev;

	spin_lock(&ctx->lock);
	list_for_each_entry(pxtgt_dev, &ctx->list, node) {
		if ((pxtgt_dev->dev_id == update_size->dev_id) && !pxtgt_dev->removing) {
			spin_lock(&pxtgt_dev->lock);
			found = true;
			break;
		}
	}
	spin_unlock(&ctx->lock);

	if (!found) {
		err = -ENOENT;
		goto out;
	}

	if (update_size->size < pxtgt_dev->size) {
		spin_unlock(&pxtgt_dev->lock);
		err = -EINVAL;
		goto out;
	}
	(void)get_device(&pxtgt_dev->dev);

	set_capacity(pxtgt_dev->disk, update_size->size / SECTOR_SIZE);
	spin_unlock(&pxtgt_dev->lock);

	err = revalidate_disk(pxtgt_dev->disk);
	BUG_ON(err);
	put_device(&pxtgt_dev->dev);

	return 0;
out:
	return err;
}

ssize_t pxtgt_read_init(struct pxtgt_context *ctx, struct iov_iter *iter)
{
	size_t copied = 0;
	struct pxtgt_device *pxtgt_dev;
	struct pxtgt_init_in pxtgt_init;

	pxtgt_init.num_devices = ctx->num_devices;
	pxtgt_init.version = PXTGT_VERSION;

	if (copy_to_iter(&pxtgt_init, sizeof(pxtgt_init), iter) != sizeof(pxtgt_init)) {
		printk(KERN_ERR "%s: copy pxtgt_init error\n", __func__);
		goto copy_error;
	}
	copied += sizeof(pxtgt_init);

	list_for_each_entry(pxtgt_dev, &ctx->list, node) {
		struct pxtgt_dev_id id = {0};
		id.dev_id = pxtgt_dev->dev_id;
		id.local_minor = pxtgt_dev->minor;
		id.block_io = 0;
		id.size = 0;
		memset(id.source, 0, sizeof(id.source));
		if (copy_to_iter(&id, sizeof(id), iter) != sizeof(id)) {
			printk(KERN_ERR "%s: copy dev id error copied %ld\n", __func__,
				copied);
			goto copy_error;
		}
		copied += sizeof(id);
	}

	printk(KERN_INFO "%s: pxtgt-control-%d init OK %d devs version %d\n", __func__,
		ctx->id, pxtgt_init.num_devices, pxtgt_init.version);

	return copied;

copy_error:
	return -EFAULT;
}

static struct bus_type pxtgt_bus_type = {
	.name		= "pxtgt",
};

static void pxtgt_root_dev_release(struct device *dev)
{
}

static struct device pxtgt_root_dev = {
	.init_name =    "pxtgt",
	.release =      pxtgt_root_dev_release,
};

static struct pxtgt_device *dev_to_pxtgt_dev(struct device *dev)
{
	return container_of(dev, struct pxtgt_device, dev);
}

static ssize_t pxtgt_size_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct pxtgt_device *pxtgt_dev = dev_to_pxtgt_dev(dev);

	return sprintf(buf, "%llu\n",
		(unsigned long long)pxtgt_dev->size);
}

static ssize_t pxtgt_major_show(struct device *dev,
		     struct device_attribute *attr, char *buf)
{
	struct pxtgt_device *pxtgt_dev = dev_to_pxtgt_dev(dev);

	return sprintf(buf, "%llu\n",
			(unsigned long long)pxtgt_dev->major);
}

static ssize_t pxtgt_minor_show(struct device *dev,
		     struct device_attribute *attr, char *buf)
{
	struct pxtgt_device *pxtgt_dev = dev_to_pxtgt_dev(dev);

	return sprintf(buf, "%llu\n",
			(unsigned long long)pxtgt_dev->minor);
}

static ssize_t pxtgt_timeout_show(struct device *dev,
		     struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", pxtgt_timeout_secs);
}

ssize_t pxtgt_timeout_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxtgt_device *pxtgt_dev = dev_to_pxtgt_dev(dev);
	uint32_t new_timeout_secs = 0;
	struct pxtgt_context *ctx = pxtgt_dev->ctx;

	if (ctx == NULL)
		return -ENXIO;

	sscanf(buf, "%u", &new_timeout_secs);
	if (new_timeout_secs < PXTGT_TIMER_SECS_MIN ||
			new_timeout_secs > PXTGT_TIMER_SECS_MAX) {
		return -EINVAL;
	}

	spin_lock(&ctx->lock);
	pxtgt_timeout_secs = new_timeout_secs;
	spin_unlock(&ctx->lock);

	return count;
}

static ssize_t pxtgt_congestion_show(struct device *dev,
                     struct device_attribute *attr, char *buf)
{
	struct pxtgt_device *pxtgt_dev = dev_to_pxtgt_dev(dev);

	return sprintf(buf, "congested: %s (%d/%d)\n",
			atomic_read(&pxtgt_dev->congested) ? "yes" : "no",
			pxtgt_dev->nr_congestion_on,
			pxtgt_dev->nr_congestion_off);
}

static ssize_t pxtgt_congestion_set(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxtgt_device *pxtgt_dev = dev_to_pxtgt_dev(dev);
	int thresh;

	sscanf(buf, "%d", &thresh);

	if (thresh < 0) {
		thresh = pxtgt_dev->qdepth;
	}

	if (thresh > MAX_CONGESTION_THRESHOLD) {
		thresh = MAX_CONGESTION_THRESHOLD;
	}

	spin_lock(&pxtgt_dev->lock);
	pxtgt_dev->qdepth = thresh;
	spin_unlock(&pxtgt_dev->lock);

	return count;
}

STATIC
char* __strtok_r(char *src, const char delim, char **saveptr) {
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

STATIC
void __strip_nl(const char *src, char *dst, int maxlen) {
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

static ssize_t pxtgt_cachealloc_set(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxtgt_device *pxtgt_dev = dev_to_pxtgt_dev(dev);
	struct pxmgr_context *mc;

	if (pxtgt_dev->mc != NULL) {
		printk("px target device %llu already has cache assigned\n", pxtgt_dev->dev_id);
		return count;
	}

	mc = pxmgr_cache_alloc(pxtgt_dev->dev_id, pxtgt_dev->size, PXREALM_SMALL, 0, pxtgt_dev);
	printk("cache alloc result: %p\n", mc);
	pxtgt_dev->mc = mc;

	return count;
}

static ssize_t pxtgt_cachefree_set(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxtgt_device *pxtgt_dev = dev_to_pxtgt_dev(dev);
	int rc;

	if (!pxtgt_dev->mc) {
		printk("px target device %llu already has cache freed\n", pxtgt_dev->dev_id);
		return count;
	}

	rc = pxmgr_cache_dealloc(pxtgt_dev->mc);
	printk("freeing cache returned %d\n", rc);
	pxtgt_dev->mc = NULL;

	return count;
}

static DEVICE_ATTR(size, S_IRUGO, pxtgt_size_show, NULL);
static DEVICE_ATTR(major, S_IRUGO, pxtgt_major_show, NULL);
static DEVICE_ATTR(minor, S_IRUGO, pxtgt_minor_show, NULL);
static DEVICE_ATTR(timeout, S_IRUGO|S_IWUSR, pxtgt_timeout_show, pxtgt_timeout_store);
static DEVICE_ATTR(congested, S_IRUGO|S_IWUSR, pxtgt_congestion_show, pxtgt_congestion_set);
static DEVICE_ATTR(calloc, S_IRUGO|S_IWUSR, NULL, pxtgt_cachealloc_set);
static DEVICE_ATTR(cfree, S_IRUGO|S_IWUSR, NULL, pxtgt_cachefree_set);

static struct attribute *pxtgt_attrs[] = {
	&dev_attr_size.attr,
	&dev_attr_major.attr,
	&dev_attr_minor.attr,
	&dev_attr_timeout.attr,
	&dev_attr_congested.attr,
	&dev_attr_calloc.attr,
	&dev_attr_cfree.attr,
	NULL
};

static struct attribute_group pxtgt_attr_group = {
	.attrs = pxtgt_attrs,
};

static const struct attribute_group *pxtgt_attr_groups[] = {
	&pxtgt_attr_group,
	NULL
};

static void pxtgt_sysfs_dev_release(struct device *dev)
{
}

static struct device_type pxtgt_device_type = {
	.name		= "pxtgt",
	.groups		= pxtgt_attr_groups,
	.release	= pxtgt_sysfs_dev_release,
};

static void pxtgt_dev_device_release(struct device *dev)
{
	struct pxtgt_device *pxtgt_dev = dev_to_pxtgt_dev(dev);

	pxtgt_free_disk(pxtgt_dev);
	ida_simple_remove(&pxtgt_minor_ida, pxtgt_dev->minor);
	pxtgt_dev->magic = PXTGT_POISON;
	kfree(pxtgt_dev);
}

static int pxtgt_bus_add_dev(struct pxtgt_device *pxtgt_dev)
{
	struct device *dev;
	int ret;

	dev = &pxtgt_dev->dev;
	dev->bus = &pxtgt_bus_type;
	dev->type = &pxtgt_device_type;
	dev->parent = &pxtgt_root_dev;
	dev->release = pxtgt_dev_device_release;
	dev_set_name(dev, "%d", pxtgt_dev->minor);
	ret = device_register(dev);

	return ret;
}

static int pxtgt_sysfs_init(void)
{
	int err;

	err = device_register(&pxtgt_root_dev);
	if (err < 0)
		return err;

	err = bus_register(&pxtgt_bus_type);
	if (err < 0)
		device_unregister(&pxtgt_root_dev);

	return err;
}

static void pxtgt_sysfs_exit(void)
{
	bus_unregister(&pxtgt_bus_type);
	device_unregister(&pxtgt_root_dev);
}

static int pxtgt_control_open(struct inode *inode, struct file *file)
{
	struct pxtgt_context *ctx;

	if (!((uintptr_t)pxtgt_contexts <= (uintptr_t)file->f_op &&
		(uintptr_t)file->f_op < (uintptr_t)(pxtgt_contexts + pxtgt_num_contexts))) {
		printk(KERN_ERR "%s: invalid fops struct\n", __func__);
		return -EINVAL;
	}

	ctx = container_of(file->f_op, struct pxtgt_context, fops);
	if (ctx->id >= pxtgt_num_contexts_exported) {
		return 0;
	}

	file->private_data = ctx;

	pxtgtctx_set_connected(ctx, true);

	++ctx->open_seq;

	printk(KERN_INFO "%s: pxtgt-control-%d(%lld) open OK\n", __func__, ctx->id,
		ctx->open_seq);

	return 0;
}

/** Note that this will not be called if userspace doesn't cleanup. */
static int pxtgt_control_release(struct inode *inode, struct file *file)
{
	struct pxtgt_context *ctx;
	ctx = container_of(file->f_op, struct pxtgt_context, fops);
	pxtgtctx_set_connected(ctx, false);
	printk(KERN_INFO "%s: pxtgt-control-%d(%lld) close OK\n", __func__, ctx->id,
		ctx->open_seq);
	return 0;
}

static struct pxtgt_context *dev_to_pxctx(struct device *dev)
{
	struct miscdevice *mdev = dev_get_drvdata(dev);
	struct pxtgt_context *ctx = container_of(mdev, struct pxtgt_context, miscdev);
	BUG_ON(ctx->magic != PXTGT_CTX_MAGIC);
	return ctx;
}


static
ssize_t pxctx_cache_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
	struct pxtgt_context *ctx = dev_to_pxctx(dev);
	struct pxtgt_device *pxtgt_dev;
	extern void pxrealm_debug_dump(void);

	// global realm debug info
	pxrealm_debug_dump();

	pxtgt_dev = NULL;
	spin_lock(&ctx->lock);
	list_for_each_entry(pxtgt_dev, &ctx->list, node) {
		pxmgr_debug_dump(pxtgt_dev->dev_id, pxtgt_dev->mc);
	}
	spin_unlock(&ctx->lock);

	return sprintf(buf, "TODO will extend this for debugging");
}

static
ssize_t pxctx_cache_set(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	int rc;
	char cdevname[MAX_DEVNAME+1];

	strncpy(cdevname, buf, MAX_DEVNAME);
	cdevname[MAX_DEVNAME] = '\0';

	rc = pxmgr_init(cdevname);
	if (rc != 0) {
		printk("cache init failed %d\n", rc);
	}

	return count;
}

static ssize_t pxctx_info_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
	struct pxtgt_context *ctx = dev_to_pxctx(dev);
    return sprintf(buf, "hit show with ctx:%px\n", ctx);
}

static ssize_t pxctx_info_set(struct device *dev,
            struct device_attribute *attr,
            const char *buf, size_t count)
{
	struct pxtgt_context *ctx = dev_to_pxctx(dev);
	(void)ctx;
    printk("Received new msg to send: %s", buf);

	return count;
}

static ssize_t pxctx_attached_show(struct device *dev,
                     struct device_attribute *attr, char *buf)
{
	struct pxtgt_context *ctx = dev_to_pxctx(dev);
	struct pxtgt_device *pxtgt_dev_itr, *pxtgt_dev;
	int count;
	char *cp;

	cp = buf;
	count = 0;
	pxtgt_dev = NULL;
	spin_lock(&ctx->lock);
	list_for_each_entry(pxtgt_dev_itr, &ctx->list, node) {
		count += snprintf(cp, PAGE_SIZE-count, "dev: %llu, source %s\n",
						pxtgt_dev_itr->dev_id, pxtgt_dev_itr->source);
		cp = buf + count;
	}
	spin_unlock(&ctx->lock);

	return count;
}

static ssize_t pxctx_attach_set(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxtgt_context *ctx = dev_to_pxctx(dev);
	struct pxtgt_add_out add;
	struct file *fh;
	int rc;

	add.dev_id = get_random_long();
	snprintf(add.source, MAX_PXTGT_DEVPATH_LEN, buf);
	add.source[MAX_PXTGT_DEVPATH_LEN] = '\0';

	fh = filp_open(add.source, O_LARGEFILE|O_RDWR|O_DIRECT, 0600);
	if (IS_ERR_OR_NULL(fh)) {
		printk("invalid source: %s, failed open\n", add.source);
		return count;
	}

	add.size = i_size_read(fh->f_inode);
	if (add.size < PXTGT_LBS) {
		printk("invalid size of source %s, too small %ld\n", add.source, add.size);
		return count;
	}

	// some hardcoded numbers
	add.queue_depth = 128;
	add.discard_size = 32 * PXTGT_LBS;
	filp_close(fh, NULL);

	rc = pxtgt_add(ctx, &add);
	if (rc <= 0) {
		printk("pxtgt_add source %s, failed with rc %d\n", add.source, rc);
		return count;
	}

	printk("pxtgt_add dev %llu, source %s, success with minor %d\n",
			add.dev_id, add.source, rc);

	return count;
}

static ssize_t pxctx_detach_set(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct pxtgt_context *ctx = dev_to_pxctx(dev);
	struct pxtgt_remove_out remove;
	uint64_t dev_id;
	struct pxtgt_device *pxtgt_dev;

	kstrtou64(buf, 10, &dev_id);

	memset(&remove, 0, sizeof(remove));
	remove.force = true;
	remove.dev_id = dev_id;
	pxtgt_dev = find_pxtgt_device(ctx, dev_id);
	if (pxtgt_dev != NULL) {
		int rc = pxtgt_remove(ctx, &remove);
		printk("pxtgt remove %llu returned rc %d\n", dev_id, rc);
	}


	return count;
}

static DEVICE_ATTR(attach, S_IRUGO|S_IWUSR, pxctx_attached_show, pxctx_attach_set);
static DEVICE_ATTR(detach, S_IRUGO|S_IWUSR, pxctx_attached_show, pxctx_detach_set);
static DEVICE_ATTR(info, S_IRUGO|S_IWUSR, pxctx_info_show, pxctx_info_set);
static DEVICE_ATTR(cache, S_IRUGO|S_IWUSR, pxctx_cache_show, pxctx_cache_set);

static struct attribute *pxtgt_control_attrs[] = {
    &dev_attr_info.attr,
    &dev_attr_attach.attr,
    &dev_attr_detach.attr,
    &dev_attr_cache.attr,
    NULL,
};

static struct attribute_group pxtgt_control_attrgroup = {
    .attrs = pxtgt_control_attrs,
};

static const struct attribute_group *pxtgt_control_attrgroups[] = {
    &pxtgt_control_attrgroup,
    NULL
};


MODULE_ALIAS("devname:pxtgt-control");

static
void pxtgtctx_set_connected(struct pxtgt_context *ctx, bool enable)
{
	struct list_head *cur;
	spin_lock(&ctx->lock);
	list_for_each(cur, &ctx->list) {
		struct pxtgt_device *pxtgt_dev = container_of(cur, struct pxtgt_device, node);

		if (!enable) {
			printk(KERN_NOTICE "device %llu called to disable IO\n", pxtgt_dev->dev_id);
			pxtgt_dev->connected = false;
		} else {
			printk(KERN_NOTICE "device %llu called to enable IO\n", pxtgt_dev->dev_id);
			pxtgt_dev->connected = true;
		}
	}
	spin_unlock(&ctx->lock);
}

int pxtgt_context_init(struct pxtgt_context *ctx, int i)
{
	spin_lock_init(&ctx->lock);
	ctx->id = i;
	ctx->open_seq = 0;
	ctx->fops = pxtgt_ops;
	ctx->fops.owner = THIS_MODULE;
	ctx->fops.open = pxtgt_control_open;
	ctx->fops.release = pxtgt_control_release;
	ctx->fops.unlocked_ioctl = pxtgt_control_ioctl;

	INIT_LIST_HEAD(&ctx->list);
	sprintf(ctx->name, "pxtgt/control-%d", i);
	ctx->miscdev.minor = MISC_DYNAMIC_MINOR;
	ctx->miscdev.name = ctx->name;
	ctx->miscdev.fops = &ctx->fops;
	ctx->miscdev.groups = pxtgt_control_attrgroups;

	ctx->magic = PXTGT_CTX_MAGIC;
	return 0;
}

static void pxtgt_context_destroy(struct pxtgt_context *ctx)
{
	ctx->magic = PXTGT_POISON;
	misc_deregister(&ctx->miscdev);
}

int pxtgt_init(void)
{
	int err, i, j;

	pxtgt_contexts = kzalloc(sizeof(pxtgt_contexts[0]) * pxtgt_num_contexts,
		GFP_KERNEL);
	err = -ENOMEM;
	if (!pxtgt_contexts) {
		printk(KERN_ERR "pxtgt: failed to allocate memory\n");
		goto out;
	}

	for (i = 0; i < pxtgt_num_contexts; ++i) {
		struct pxtgt_context *ctx = &pxtgt_contexts[i];
		err = pxtgt_context_init(ctx, i);
		if (err) {
			printk(KERN_ERR "pxtgt: failed to initialize connection\n");
			goto out_fuse;
		}

		err = misc_register(&ctx->miscdev);
		if (err) {
			printk(KERN_ERR "pxtgt: failed to register dev %s %d: %d\n",
				ctx->miscdev.name, i, err);
			goto out_fuse;
		}
	}

	pxtgt_major = register_blkdev(0, "pxtgt");
	if (pxtgt_major < 0) {
		err = pxtgt_major;
		printk(KERN_ERR "pxtgt: failed to register dev pxtgt: %d\n", err);
		goto out_fuse;
	}

	err = pxtgt_sysfs_init();
	if (err) {
		printk(KERN_ERR "pxtgt: failed to initialize sysfs: %d\n", err);
		goto out_blkdev;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
	if (bioset_init(&pxtgt_bio_set, PXTGT_MIN_POOL_PAGES,
			offsetof(struct pxtgt_io_tracker, clone), 0)) {
		printk(KERN_ERR "pxtgt: failed to initialize bioset_init: -ENOMEM\n");
		goto out_blkdev;
	}
	ppxtgt_bio_set = &pxtgt_bio_set;
#else
	ppxtgt_bio_set = BIOSET_CREATE(PXTGT_MIN_POOL_PAGES, offsetof(struct pxtgt_io_tracker, clone));
#endif

	if (!ppxtgt_bio_set) {
		printk(KERN_ERR "pxtgt: bioset init failed\n");
		goto out_blkdev;
	}

#ifdef __PX_BLKMQ__
	printk(KERN_INFO "pxtgt: blk-mq driver loaded version %s\n",
			gitversion);
#else
	printk(KERN_INFO "pxtgt: driver loaded version %s\n",
			gitversion);
#endif

	return 0;

out_blkdev:
	unregister_blkdev(0, "pxtgt");
out_fuse:
	for (j = 0; j < i; ++j) {
		pxtgt_context_destroy(&pxtgt_contexts[j]);
	}
	kfree(pxtgt_contexts);
out:
	return err;
}

void pxtgt_exit(void)
{
	int i;

	pxmgr_exit();

	if (ppxtgt_bio_set) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
		bioset_exit(ppxtgt_bio_set);
#else
		bioset_free(ppxtgt_bio_set);
#endif
	}
	ppxtgt_bio_set = NULL;

	pxtgt_sysfs_exit();
	unregister_blkdev(pxtgt_major, "pxtgt");

	for (i = 0; i < pxtgt_num_contexts; ++i) {
		/* force cleanup @@@ */
		pxtgt_context_destroy(&pxtgt_contexts[i]);
	}

	kfree(pxtgt_contexts);

	printk(KERN_INFO "pxtgt: driver unloaded\n");
}

module_init(pxtgt_init);
module_exit(pxtgt_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION(VERTOSTR(PXTGT_VERSION));
