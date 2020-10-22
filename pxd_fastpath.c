#include <linux/version.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/genhd.h>
#include <linux/workqueue.h>

#include "pxd.h"
#include "pxd_core.h"
#include "pxd_compat.h"

#ifndef MIN_NICE
#define MIN_NICE (-20)
#endif

static void __pxd_add2failQ(struct pxd_device *pxd_dev, struct pxd_io_tracker *iot);

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
static struct bio_set pxd_bio_set;
#endif
#define PXD_MIN_POOL_PAGES (128)
static struct bio_set* ppxd_bio_set;

static void __pxd_cleanup_block_io(struct pxd_io_tracker *head);
int fastpath_init(void)
{
	printk(KERN_INFO"CPU %d/%d, NUMA nodes %d/%d\n", num_online_cpus(), NR_CPUS, num_online_nodes(), MAX_NUMNODES);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
	if (bioset_init(&pxd_bio_set, PXD_MIN_POOL_PAGES,
			offsetof(struct pxd_io_tracker, clone), 0)) {
		printk(KERN_ERR "pxd: failed to initialize bioset_init: -ENOMEM\n");
		return -ENOMEM;
	}
	ppxd_bio_set = &pxd_bio_set;
#else
	ppxd_bio_set = BIOSET_CREATE(PXD_MIN_POOL_PAGES, offsetof(struct pxd_io_tracker, clone));
#endif

	if (!ppxd_bio_set) {
		printk(KERN_ERR "pxd: bioset init failed\n");
		return -ENOMEM;
	}

	return 0;
}

void fastpath_cleanup(void)
{
	if (ppxd_bio_set) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
		bioset_exit(ppxd_bio_set);
#else
		bioset_free(ppxd_bio_set);
#endif
	}

	ppxd_bio_set = NULL;
}

static int _pxd_flush(struct pxd_device *pxd_dev, struct file *file)
{
	int ret = 0;

	// pxd_dev is opened in o_sync mode. all writes are complete with implicit sync.
	// explicit sync can be treated nop
	if (pxd_dev->mode & O_SYNC) {
		atomic_inc(&pxd_dev->fp.nio_flush_nop);
		return 0;
	}

	ret = vfs_fsync(file, 0);
	if (unlikely(ret && ret != -EINVAL && ret != -EIO)) {
		ret = -EIO;
	}
	atomic_inc(&pxd_dev->fp.nio_flush);
	return ret;
}

static int _pxd_bio_discard(struct pxd_device *pxd_dev, struct file *file, struct bio *bio, loff_t pos)
{
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	int ret;

	atomic_inc(&pxd_dev->fp.nio_discard);

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

	return 0;
}

static int _pxd_write(uint64_t dev_id, struct file *file, struct bio_vec *bvec, loff_t *pos)
{
	ssize_t bw;
	mm_segment_t old_fs = get_fs();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct iov_iter i;
#else
	void *kaddr = kmap(bvec->bv_page) + bvec->bv_offset;
#endif

	pxd_printk("device %llu pxd_write entry offset %lld, length %d entered\n",
			dev_id, *pos, bvec->bv_len);

	if (unlikely(bvec->bv_len != PXD_LBS)) {
		printk(KERN_ERR"Unaligned block writes %d bytes\n", bvec->bv_len);
	}
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
	iov_iter_bvec(&i, WRITE, bvec, 1, bvec->bv_len);
	file_start_write(file);
	bw = vfs_iter_write(file, &i, pos, 0);
	file_end_write(file);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
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
	kunmap(bvec->bv_page);
#endif
	set_fs(old_fs);

	if (likely(bw == bvec->bv_len)) {
		return 0;
	}

	printk_ratelimited(KERN_ERR "device %llu Write error at byte offset %lld, length %i, write %ld\n",
                        dev_id, *pos, bvec->bv_len, bw);
	if (bw >= 0) bw = -EIO;
	return bw;
}

static int pxd_send(struct pxd_device *pxd_dev, struct file *file, struct bio *bio, loff_t pos)
{
	int ret = 0;
	int nsegs = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	bio_for_each_segment(bvec, bio, i) {
		nsegs++;
		ret = _pxd_write(pxd_dev->dev_id, file, &bvec, &pos);
		if (ret < 0) {
			return ret;
		}
	}
#else
	bio_for_each_segment(bvec, bio, i) {
		nsegs++;
		ret = _pxd_write(pxd_dev->dev_id, file, bvec, &pos);
		if (ret < 0) {
			return ret;
		}
	}
#endif
	atomic_inc(&pxd_dev->fp.nio_write);
	return 0;
}

static
ssize_t _pxd_read(uint64_t dev_id, struct file *file, struct bio_vec *bvec, loff_t *pos)
{
	int result = 0;

    /* read from file at offset pos into the buffer */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
	struct iov_iter i;

	iov_iter_bvec(&i, READ, bvec, 1, bvec->bv_len);
	result = vfs_iter_read(file, &i, pos, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
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

	set_fs(KERNEL_DS);
	result = vfs_read(file, kaddr, bvec->bv_len, pos);
	set_fs(old_fs);
	kunmap(bvec->bv_page);
#endif
	if (result < 0)
		printk_ratelimited(KERN_ERR "device %llu: read offset %lld failed %d\n", dev_id, *pos, result);
	return result;
}

static ssize_t pxd_receive(struct pxd_device *pxd_dev, struct file *file, struct bio *bio, loff_t *pos)
{
	ssize_t s;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif

	bio_for_each_segment(bvec, bio, i) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
		s = _pxd_read(pxd_dev->dev_id, file, &bvec, pos);
		if (s < 0) return s;

		if (s != bvec.bv_len) {
			zero_fill_bio(bio);
			break;
		}
#else
		s = _pxd_read(pxd_dev->dev_id, file, bvec, pos);
		if (s < 0) return s;

		if (s != bvec->bv_len) {
			zero_fill_bio(bio);
			break;
		}
#endif
	}
	return 0;
}

static void __pxd_cleanup_block_io(struct pxd_io_tracker *head)
{
	while (!list_empty(&head->replicas)) {
		struct pxd_io_tracker *repl = list_first_entry(&head->replicas, struct pxd_io_tracker, item);
		BUG_ON(repl->magic != PXD_IOT_MAGIC);
		repl->magic = PXD_POISON;
		list_del(&repl->item);
		pxd_mem_printk("freeing repl %px, bio %px dir %d\n", repl, &repl->clone, bio_data_dir(head->orig) == READ);
		bio_put(&repl->clone);
	}

	BUG_ON(head->magic != PXD_IOT_MAGIC);
	head->magic = PXD_POISON;
	pxd_mem_printk("freeing tracker %px, bio %px dir %d\n", head, &head->clone, bio_data_dir(head->orig) == READ);
	bio_put(&head->clone);
}

static void pxd_io_failover(struct work_struct *ws)
{
	struct pxd_io_tracker *head = container_of(ws, struct pxd_io_tracker, wi);
	struct pxd_device *pxd_dev = head->pxd_dev;
	bool cleanup = false;
	bool reroute = false;
	int rc;

	BUG_ON(head->magic != PXD_IOT_MAGIC);
	BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);

	spin_lock(&pxd_dev->fp.fail_lock);
	if (!pxd_dev->fp.active_failover) {
		if (pxd_dev->fp.fastpath) {
			pxd_dev->fp.active_failover = true;
			__pxd_add2failQ(pxd_dev, head);
			cleanup = true;
		} else {
			reroute = true;
		}
	} else {
		__pxd_add2failQ(pxd_dev, head);
	}

	spin_unlock(&pxd_dev->fp.fail_lock);

	if (cleanup) {
		rc = pxd_initiate_failover(pxd_dev);
		// If userspace cannot be informed of a failover event, force abort all IO.
		if (rc) {
			printk_ratelimited(KERN_ERR"%s: pxd%llu: failover failed %d, aborting IO\n", __func__, pxd_dev->dev_id, rc);
			spin_lock(&pxd_dev->fp.fail_lock);
			__pxd_abortfailQ(pxd_dev);
			pxd_dev->fp.active_failover = false;
			spin_unlock(&pxd_dev->fp.fail_lock);
		}
	} else if (reroute) {
		printk_ratelimited(KERN_ERR"%s: pxd%llu: resuming IO in native path.\n", __func__, pxd_dev->dev_id);
		atomic_inc(&pxd_dev->fp.nslowPath);
		pxd_reroute_slowpath(pxd_dev->disk->queue, head->orig);
		__pxd_cleanup_block_io(head);
	}

	pxd_check_q_decongested(pxd_dev);
}

static void pxd_failover_initiate(struct pxd_device *pxd_dev, struct pxd_io_tracker *head)
{
	INIT_WORK(&head->wi, pxd_io_failover);
	queue_work(pxd_dev->fp.wq, &head->wi);
}

static int remap_io_status(int status)
{
	switch (status) {
	case 0: // success
	case -EOPNOTSUPP: // op not supported - no failover
	case -ENOSPC: // no space on device - no failover
	case -ENOMEM: // no memory - no failover
		return status;
	}

	return -EIO;
}

// @head [in] - io head
// @return - update reconciled error code
static int reconcile_io_status(struct pxd_io_tracker *head)
{
	struct pxd_io_tracker *repl;
	int status = 0;
	int tmp;

	BUG_ON(head->magic != PXD_IOT_MAGIC);
	list_for_each_entry(repl, &head->replicas, item) {
		BUG_ON(repl->magic != PXD_IOT_MAGIC);

		tmp = remap_io_status(repl->status);
		if (status == 0 || tmp == -EIO) {
			status = tmp;
		}
	}

	tmp = remap_io_status(head->status);
	if (status == 0 || tmp == -EIO) {
		status = tmp;
	}

	return status;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
static void pxd_complete_io_dummy(struct bio* bio)
#else
static void pxd_complete_io_dummy(struct bio* bio, int error)
#endif
{
	printk("%s: bio %px should never be called\n", __func__, bio);
	BUG();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
static void pxd_complete_io(struct bio* bio)
#else
static void pxd_complete_io(struct bio* bio, int error)
#endif
{
	struct pxd_io_tracker *iot = container_of(bio, struct pxd_io_tracker, clone);
	struct pxd_device *pxd_dev = bio->bi_private;
	struct pxd_io_tracker *head = iot->head;
	unsigned int flags = get_op_flags(bio);
	int blkrc;

	BUG_ON(iot->magic != PXD_IOT_MAGIC);
	BUG_ON(head->magic != PXD_IOT_MAGIC);
	BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
		blkrc = blk_status_to_errno(bio->bi_status);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
		blkrc = bio->bi_error;
#else
		blkrc = error;
#endif

	if (blkrc != 0) {
		printk_ratelimited("FAILED IO %s (err=%d): dev m %d g %lld %s at %lld len %d bytes %d pages "
				"flags 0x%lx\n", __func__, blkrc,
			pxd_dev->minor, pxd_dev->dev_id,
			bio_data_dir(bio) == WRITE ? "wr" : "rd",
			(unsigned long long)(BIO_SECTOR(bio) * SECTOR_SIZE), BIO_SIZE(bio),
			bio->bi_vcnt, (long unsigned int)flags);
	}

	fput(iot->file);
	iot->status = blkrc;
	if (!atomic_dec_and_test(&head->active)) {
		// not all responses have come back
		return;
	}

	// final reconciled status
	blkrc = reconcile_io_status(head);

	// debug condition for force fail
	if (pxd_dev->fp.force_fail) blkrc = -EIO;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,1)
	bio_end_io_acct(bio, iot->start);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) &&  \
     defined(bvec_iter_sectors))
	generic_end_io_acct(pxd_dev->disk->queue, bio_op(bio), &pxd_dev->disk->part0, iot->start);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	generic_end_io_acct(bio_data_dir(bio), &pxd_dev->disk->part0, iot->start);
#else
	_generic_end_io_acct(pxd_dev->disk->queue, bio_data_dir(bio), &pxd_dev->disk->part0, iot->start);
#endif

	atomic_inc(&pxd_dev->fp.ncomplete);
	atomic_dec(&pxd_dev->ncount);

	if (pxd_dev->fp.can_failover && (blkrc == -EIO)) {
		atomic_inc(&pxd_dev->fp.nerror);
		pxd_failover_initiate(pxd_dev, head);
		pxd_check_q_decongested(pxd_dev);
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
{
		iot->orig->bi_status = errno_to_blk_status(blkrc);
		bio_endio(iot->orig);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
{
		iot->orig->bi_error = blkrc;
		bio_endio(iot->orig);
}
#else
{
		bio_endio(iot->orig, blkrc);
}
#endif
	__pxd_cleanup_block_io(head);
	pxd_check_q_decongested(pxd_dev);
}

static void pxd_process_fileio(struct work_struct *wi);
static struct pxd_io_tracker* __pxd_init_block_replica(struct pxd_device *pxd_dev,
		struct bio *bio, struct file *fileh) {
	struct bio* clone_bio;
	struct pxd_io_tracker* iot;
	struct address_space *mapping = fileh->f_mapping;
	struct inode *inode = mapping->host;
	struct block_device *bdev = I_BDEV(inode);

	pxd_printk("pxd %px:__pxd_init_block_replica entering with bio %px, fileh %px\n",
			pxd_dev, bio, fileh);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	clone_bio = bio_clone_fast(bio, GFP_KERNEL, ppxd_bio_set);
#else
	clone_bio = bio_clone_bioset(bio, GFP_KERNEL, ppxd_bio_set);
#endif
	if (!clone_bio) {
		pxd_printk(KERN_ERR"No memory for io context");
		return NULL;
	}

	iot = container_of(clone_bio, struct pxd_io_tracker, clone);
	BUG_ON(&iot->clone != clone_bio);

	iot->magic = PXD_IOT_MAGIC;
	iot->pxd_dev = pxd_dev;
	iot->head = iot;
	INIT_LIST_HEAD(&iot->replicas);
	INIT_LIST_HEAD(&iot->item);
	iot->orig = bio;
	iot->status = 0;
	iot->start = jiffies;
	atomic_set(&iot->active, 0);
	iot->file = get_file(fileh);
	INIT_WORK(&iot->wi, pxd_process_fileio);

	clone_bio->bi_private = pxd_dev;
	if (S_ISBLK(inode->i_mode)) {
		BIO_SET_DEV(clone_bio, bdev);
		clone_bio->bi_end_io = pxd_complete_io;
	} else {
		clone_bio->bi_end_io = pxd_complete_io_dummy;
	}

	return iot;
}

static
struct pxd_io_tracker* __pxd_init_block_head(struct pxd_device *pxd_dev, struct bio* bio, int dir)
{
	struct pxd_io_tracker* head;
	struct pxd_io_tracker *repl;
	int index;

	head = __pxd_init_block_replica(pxd_dev, bio, pxd_dev->fp.file[0]);
	if (!head) {
		return NULL;
	}
	pxd_mem_printk("allocated tracker %px, clone bio %px dir %d\n", head, &head->clone, bio_data_dir(bio) == READ);

	// initialize the replicas only if the request is non-read
	if (dir != READ) {
		for (index = 1; index < pxd_dev->fp.nfd; index++) {
			repl = __pxd_init_block_replica(pxd_dev, bio, pxd_dev->fp.file[index]);
			if (!repl) {
				goto repl_cleanup;
			}

			BUG_ON(repl->magic != PXD_IOT_MAGIC);
			repl->head = head;
			list_add_tail(&repl->item, &head->replicas);
			pxd_mem_printk("allocated repl %px, clone bio %px dir %d\n", repl, &repl->clone, bio_data_dir(bio) == READ);
		}
	}

	BUG_ON(head->magic != PXD_IOT_MAGIC);
	return head;

repl_cleanup:
	__pxd_cleanup_block_io(head);
	return NULL;
}

static void _pxd_setup(struct pxd_device *pxd_dev, bool enable)
{
	if (!enable) {
		printk(KERN_NOTICE "device %llu called to disable IO\n", pxd_dev->dev_id);
		pxd_dev->connected = false;
		pxd_abortfailQ(pxd_dev);
	} else {
		printk(KERN_NOTICE "device %llu called to enable IO\n", pxd_dev->dev_id);
		pxd_dev->connected = true;
	}
}

void pxdctx_set_connected(struct pxd_context *ctx, bool enable)
{
	struct list_head *cur;
	spin_lock(&ctx->lock);
	list_for_each(cur, &ctx->list) {
		struct pxd_device *pxd_dev = container_of(cur, struct pxd_device, node);

		_pxd_setup(pxd_dev, enable);
	}
	spin_unlock(&ctx->lock);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
static int __do_bio_filebacked(struct pxd_device *pxd_dev, struct pxd_io_tracker *iot)
{
	struct bio *bio = &iot->clone;
	unsigned int op = bio_op(bio);
	loff_t pos;
	int ret;

	BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);
	BUG_ON(iot->magic != PXD_IOT_MAGIC);

	pxd_printk("do_bio_filebacked for new bio (pending %u)\n", PXD_ACTIVE(pxd_dev));
	pos = ((loff_t) bio->bi_iter.bi_sector << SECTOR_SHIFT);

	switch (op) {
	case REQ_OP_READ:
		ret = pxd_receive(pxd_dev, iot->file, bio, &pos);
		goto out;
	case REQ_OP_WRITE:

		if (bio->bi_opf & REQ_PREFLUSH) {
			atomic_inc(&pxd_dev->fp.nio_preflush);
			ret = _pxd_flush(pxd_dev, iot->file);
			if (ret < 0) goto out;
		}

		ret = pxd_send(pxd_dev, iot->file, bio, pos);
		if (ret < 0) goto out;

		if (bio->bi_opf & REQ_FUA) {
			atomic_inc(&pxd_dev->fp.nio_fua);
			ret = _pxd_flush(pxd_dev, iot->file);
			if (ret < 0) goto out;
		}

		ret = 0; goto out;

	case REQ_OP_FLUSH:
		ret = _pxd_flush(pxd_dev, iot->file);
		goto out;
	case REQ_OP_DISCARD:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	case REQ_OP_WRITE_ZEROES:
#endif
		ret = _pxd_bio_discard(pxd_dev, iot->file, bio, pos);
		goto out;
	default:
		WARN_ON_ONCE(1);
		ret = -EIO;
		goto out;
	}

out:
	if (ret < 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
		bio->bi_status = ret;
#else
		bio->bi_error = ret;
#endif
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
	pxd_complete_io(bio);
#else
	pxd_complete_io(bio, ret);
#endif

	return ret;
}

#else
static int __do_bio_filebacked(struct pxd_device *pxd_dev, struct pxd_io_tracker *iot)
{
	loff_t pos;
	int ret;
	struct bio *bio = &iot->clone;

	BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);
	BUG_ON(iot->magic != PXD_IOT_MAGIC);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	pos = ((loff_t) bio->bi_iter.bi_sector << SECTOR_SHIFT);
#else
	pos = ((loff_t) bio->bi_sector << SECTOR_SHIFT);
#endif

	// mark status all good to begin with!
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	bio->bi_status = 0;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
	bio->bi_error = 0;
#endif
	if (bio_data_dir(bio) == WRITE) {
		pxd_printk("bio bi_rw %#lx, flush %#llx, fua %#llx, discard %#llx\n",
				bio->bi_rw, REQ_FLUSH, REQ_FUA, REQ_DISCARD);

		if (bio->bi_rw & REQ_DISCARD) {
			ret = _pxd_bio_discard(pxd_dev, iot->file, bio, pos);
			goto out;
		}
		/* Before any newer writes happen, make sure previous write/sync complete */
		ret = pxd_send(pxd_dev, iot->file, bio, pos);

		if (!ret) {
			if ((bio->bi_rw & REQ_FUA)) {
				atomic_inc(&pxd_dev->fp.nio_fua);
				ret = _pxd_flush(pxd_dev, iot->file);
				if (ret < 0) goto out;
			} else if ((bio->bi_rw & REQ_FLUSH)) {
				ret = _pxd_flush(pxd_dev, iot->file);
				if (ret < 0) goto out;
			}
		}

	} else {
		ret = pxd_receive(pxd_dev, iot->file, bio, &pos);
	}

out:
	if (ret < 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		bio->bi_status = ret;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
		bio->bi_error = ret;
#endif
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
	pxd_complete_io(bio);
#else
	pxd_complete_io(bio, ret);
#endif

	return ret;
}
#endif

static void pxd_process_fileio(struct work_struct *wi)
{
	struct pxd_io_tracker *iot = container_of(wi, struct pxd_io_tracker, wi);
	struct pxd_device *pxd_dev = iot->pxd_dev;

	BUG_ON(iot->magic != PXD_IOT_MAGIC);
	BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);
	__do_bio_filebacked(pxd_dev, iot);
}

static void pxd_process_io(struct pxd_io_tracker *head)
{
	struct pxd_device *pxd_dev = head->pxd_dev;
	struct bio *bio = head->orig;
	int dir = bio_data_dir(bio);

	//
	// Based on the nfd mapped on pxd_dev, that many cloned bios shall be
	// setup, then each replica takes its own processing path, which could be
	// either file backup or block device backup.
	//
	struct pxd_io_tracker *curr;

	BUG_ON(head->magic != PXD_IOT_MAGIC);
	BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);
	atomic_inc(&pxd_dev->ncount);
	// initialize active io to configured replicas
	if (dir != READ) {
		atomic_set(&head->active, pxd_dev->fp.nfd);
		// submit all replicas linked from head, if not read
		list_for_each_entry(curr, &head->replicas, item) {
			if (S_ISBLK(curr->file->f_inode->i_mode)) {
				SUBMIT_BIO(&curr->clone);
				atomic_inc(&pxd_dev->fp.nswitch);
			} else {
				queue_work(pxd_dev->fp.wq, &curr->wi);
			}
		}
	} else {
		atomic_set(&head->active, 1);
	}

	// submit head bio the last
	if (S_ISBLK(head->file->f_inode->i_mode)) {
		SUBMIT_BIO(&head->clone);
		atomic_inc(&pxd_dev->fp.nswitch);
	} else {
		queue_work(pxd_dev->fp.wq, &head->wi);
	}
}

// background pxd syncer work function
static void __pxd_syncer(struct work_struct *wi)
{
	struct pxd_sync_ws *ws = (struct pxd_sync_ws*) wi;
	struct pxd_device *pxd_dev = ws->pxd_dev;
	struct pxd_fastpath_extension *fp = &ws->pxd_dev->fp;
	int nfd = fp->nfd;
	int i = ws->index;

	ws->rc = 0; // early complete
	if (i >= nfd || fp->file[i] == NULL) {
		goto out;
	}

	ws->rc = vfs_fsync(fp->file[i], 0);
	if (unlikely(ws->rc)) {
		printk(KERN_ERR"device %llu fsync[%d] failed with %d\n", pxd_dev->dev_id, i, ws->rc);
	}

out:
	BUG_ON(!atomic_read(&fp->sync_done));
	if (atomic_dec_and_test(&fp->sync_done)) {
		complete(&fp->sync_complete);
	}
}

static
bool pxd_sync_work_pending(struct pxd_device *pxd_dev)
{
	int i;
	bool busy = false;

	if (atomic_read(&pxd_dev->fp.sync_done) != 0) {
		return true;
	}

	for (i = 0; i < MAX_PXD_BACKING_DEVS; i++) {
		busy |= work_busy(&pxd_dev->fp.syncwi[i].ws);
	}

	return busy;
}

// external request to initiate failover/fallback on fastpath device
int pxd_request_ioswitch(struct pxd_device *pxd_dev, int code)
{
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;

	// incompat device
	if (pxd_dev->using_blkque) {
		printk("device %llu ioswitch request failed (blkque %d, fastpath %d)\n",
			   pxd_dev->dev_id, pxd_dev->using_blkque, fp->fastpath);
		return -EINVAL;
	}

	switch (code) {
	case PXD_FAILOVER_TO_USERSPACE:
		printk("device %llu initiated failover\n", pxd_dev->dev_id);
		// IO path blocked, a future path refresh will take it to native path
		// enqueue a failover request to userspace on this device.
		return pxd_initiate_failover(pxd_dev);
	case PXD_FALLBACK_TO_KERNEL:
		// IO path already routed to userspace.
		// enqueue a fallback marker request to userspace on this device.
		printk("device %llu initiated fallback\n", pxd_dev->dev_id);
		return pxd_initiate_fallback(pxd_dev);
	default:
		// unsupported opcode
		return -EINVAL;
	}
}

// shall be called internally during iopath switching.
int pxd_request_suspend_internal(struct pxd_device *pxd_dev,
		bool skip_flush, bool coe)
{
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;
	int i;
	int rc;

	if (pxd_dev->using_blkque) {
		return -EINVAL;
	}

	// check if previous sync instance is still active
	if (!skip_flush && pxd_sync_work_pending(pxd_dev)) {
		return -EBUSY;
	}

	pxd_suspend_io(pxd_dev);

	if (skip_flush || !fp->fastpath) return 0;

	atomic_set(&fp->sync_done, MAX_PXD_BACKING_DEVS);
	reinit_completion(&fp->sync_complete);
	for (i = 0; i < MAX_PXD_BACKING_DEVS; i++) {
		queue_work(fp->wq, &fp->syncwi[i].ws);
	}

#define SYNC_TIMEOUT (60000)
	rc = 0;
	if (!wait_for_completion_timeout(&fp->sync_complete,
						msecs_to_jiffies(SYNC_TIMEOUT))) {
		// suspend aborted as sync timedout
		rc = -EBUSY;
		goto fail;
	}

	// consolidate responses
	for (i = 0; i < MAX_PXD_BACKING_DEVS; i++) {
		// capture first failure
		rc = fp->syncwi[i].rc;
		if (rc) goto fail;
	}

	printk(KERN_NOTICE"device %llu suspended IO from userspace\n", pxd_dev->dev_id);
	return 0;
fail:
	// It is possible replicas are down during failover
	// ignore and continue
	if (coe) {
		printk(KERN_NOTICE"device %llu sync failed %d, continuing with suspend\n",
				pxd_dev->dev_id, rc);
		return 0;
	}
	pxd_resume_io(pxd_dev);
	return rc;
}

// external request to suspend IO on fastpath device
int pxd_request_suspend(struct pxd_device *pxd_dev, bool skip_flush, bool coe)
{
	int rc = 0;

	if (atomic_read(&pxd_dev->fp.app_suspend) == 1) {
		return -EBUSY;
	}

	rc = pxd_request_suspend_internal(pxd_dev, skip_flush, coe);
	if (!rc) {
		atomic_set(&pxd_dev->fp.app_suspend, 1);
	}

	return rc;
}

void pxd_suspend_io(struct pxd_device *pxd_dev)
{
	int curr = atomic_inc_return(&pxd_dev->fp.suspend);
	if (curr == 1) {
		write_lock(&pxd_dev->fp.suspend_lock);
		printk("For pxd device %llu IO suspended\n", pxd_dev->dev_id);
	} else {
		printk("For pxd device %llu IO already suspended(%d)\n", pxd_dev->dev_id, curr);
	}
}

int pxd_request_resume_internal(struct pxd_device *pxd_dev)
{
	if (pxd_dev->using_blkque) {
		return -EINVAL;
	}

	pxd_resume_io(pxd_dev);
	printk(KERN_NOTICE"device %llu resumed IO from userspace\n", pxd_dev->dev_id);
	return 0;
}

// external request to resume IO on fastpath device
int pxd_request_resume(struct pxd_device *pxd_dev)
{
	int rc;
	if (atomic_read(&pxd_dev->fp.app_suspend) == 0) {
		return -EINVAL;
	}

	rc = pxd_request_resume_internal(pxd_dev);
	if (!rc) {
		atomic_set(&pxd_dev->fp.app_suspend, 0);
	}
	return rc;
}


void pxd_resume_io(struct pxd_device *pxd_dev)
{
	bool wakeup;
	int curr = atomic_dec_return(&pxd_dev->fp.suspend);

	wakeup = (curr == 0);
	if (wakeup) {
		printk("For pxd device %llu IO resumed\n", pxd_dev->dev_id);
		write_unlock(&pxd_dev->fp.suspend_lock);
		pxd_check_q_decongested(pxd_dev);
	} else {
		printk("For pxd device %llu IO still suspended(%d)\n", pxd_dev->dev_id, curr);
	}
}

/*
 * shall get called last when new device is added/updated or when fuse connection is lost
 * and re-estabilished.
 */
void enableFastPath(struct pxd_device *pxd_dev, bool force)
{
	struct file *f;
	struct inode *inode;
	int i;
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;
	int nfd = fp->nfd;
	mode_t mode = open_mode(pxd_dev->mode);
	char modestr[32];

	if (pxd_dev->using_blkque || !pxd_dev->fp.nfd) {
		pxd_dev->fp.fastpath = false;
		return;
	}

	pxd_suspend_io(pxd_dev);

	decode_mode(mode, modestr);
	for (i = 0; i < nfd; i++) {
		if (fp->file[i] > 0) { /* valid fd exists already */
			if (force) {
				printk("dev %llu:%s closing file desc %px\n",
						pxd_dev->dev_id, __func__, fp->file[i]);
				filp_close(fp->file[i], NULL);
				f = filp_open(fp->device_path[i], mode, 0600);
				if (IS_ERR_OR_NULL(f)) {
					printk(KERN_ERR"Failed attaching path: device %llu, path %s err %ld\n",
						pxd_dev->dev_id, fp->device_path[i], PTR_ERR(f));
					goto out_file_failed;
				}
			} else {
				f = fp->file[i];
			}
		} else {
			f = filp_open(fp->device_path[i], mode, 0600);
			if (IS_ERR_OR_NULL(f)) {
				printk(KERN_ERR"Failed attaching path: device %llu, path %s err %ld\n",
					pxd_dev->dev_id, fp->device_path[i], PTR_ERR(f));
				goto out_file_failed;
			}
		}

		fp->file[i] = f;

		inode = f->f_inode;
		printk(KERN_INFO"device %lld:%d, inode %lu mode %#x\n", pxd_dev->dev_id, i, inode->i_ino, mode);
		if (S_ISREG(inode->i_mode)) {
			printk(KERN_INFO"device[%lld:%d] is a regular file - inode %lu\n",
					pxd_dev->dev_id, i, inode->i_ino);
		} else if (S_ISBLK(inode->i_mode)) {
			printk(KERN_INFO"device[%lld:%d] is a block device - inode %lu\n",
				pxd_dev->dev_id, i, inode->i_ino);
		} else {
			printk(KERN_INFO"device[%lld:%d] inode %lu unknown device %#x\n",
				pxd_dev->dev_id, i, inode->i_ino, inode->i_mode);
		}
	}

	pxd_dev->fp.fastpath = true;
	pxd_resume_io(pxd_dev);

	printk(KERN_INFO"pxd_dev %llu fastpath %d mode %#x setting up with %d backing volumes, [%px,%px,%px]\n",
		pxd_dev->dev_id, fp->fastpath, mode, fp->nfd,
		fp->file[0], fp->file[1], fp->file[2]);

	return;

out_file_failed:
	fp->nfd = 0;
	for (i = 0; i < nfd; i++) {
		if (fp->file[i] > 0) filp_close(fp->file[i], NULL);
	}
	memset(fp->file, 0, sizeof(fp->file));
	memset(fp->device_path, 0, sizeof(fp->device_path));

	pxd_dev->fp.fastpath = false;
	/// volume still remains suspended waiting for CLEANUP request to reopen IO.
	printk(KERN_INFO"%s: Device %llu no backing volume setup, will take slow path\n",
		__func__, pxd_dev->dev_id);
}

int pxd_fastpath_vol_cleanup(struct pxd_device *pxd_dev)
{
	printk(KERN_INFO"%s: Device %llu cleanup IO reactivate received\n",
		__func__, pxd_dev->dev_id);
	disableFastPath(pxd_dev, false);
	pxd_resume_io(pxd_dev);
	return 0;
}

void disableFastPath(struct pxd_device *pxd_dev, bool skipsync)
{
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;
	int nfd = fp->nfd;
	int i;

	if (pxd_dev->using_blkque || !pxd_dev->fp.nfd || !pxd_dev->fp.fastpath) {
		pxd_dev->fp.active_failover = false;
		pxd_dev->fp.fastpath = false;
		return;
	}

	pxd_suspend_io(pxd_dev);
	if (PXD_ACTIVE(pxd_dev)) {
		printk(KERN_WARNING"%s: pxd device %llu fastpath disabled with active IO (%d)\n",
			__func__, pxd_dev->dev_id, PXD_ACTIVE(pxd_dev));
	}

	for (i = 0; i < nfd; i++) {
		if (fp->file[i] > 0) {
			if (!skipsync) {
				int ret = vfs_fsync(fp->file[i], 0);
				if (unlikely(ret && ret != -EINVAL && ret != -EIO)) {
					printk(KERN_WARNING"device %llu fsync failed with %d\n", pxd_dev->dev_id, ret);
				}
			}
			filp_close(fp->file[i], NULL);
			fp->file[i] = NULL;
		}
	}
	pxd_dev->fp.fastpath = false;
	pxd_dev->fp.can_failover = false;

	pxd_resume_io(pxd_dev);
}

int pxd_fastpath_init(struct pxd_device *pxd_dev)
{
	int i;
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;

	// will take slow path, if additional info not provided.
	memset(fp, 0, sizeof(struct pxd_fastpath_extension));

	// device temporary IO suspend
	rwlock_init(&fp->suspend_lock);
	atomic_set(&fp->suspend, 0);
	atomic_set(&fp->app_suspend, 0);
	atomic_set(&fp->ioswitch_active, 0);
	fp->wq = alloc_workqueue("pxd%llu", WQ_SYSFS | WQ_UNBOUND | WQ_HIGHPRI, 0, pxd_dev->dev_id);
	if (!fp->wq) {
		printk(KERN_ERR"pxd_dev:%llu failed allocating workqueue\n", pxd_dev->dev_id);
		return -ENOMEM;
	}
	init_completion(&fp->sync_complete);
	atomic_set(&fp->sync_done, 0);
	for (i = 0; i < MAX_PXD_BACKING_DEVS; i++) {
		INIT_WORK(&fp->syncwi[i].ws, __pxd_syncer);
		fp->syncwi[i].index = i;
		fp->syncwi[i].pxd_dev = pxd_dev;
		fp->syncwi[i].rc = 0;
	}

	// failover init
	spin_lock_init(&fp->fail_lock);
	fp->active_failover = false;
	fp->force_fail = false; // debug to force faspath failover
	INIT_LIST_HEAD(&fp->failQ);

	atomic_set(&fp->nio_discard, 0);
	atomic_set(&fp->nio_flush, 0);
	atomic_set(&fp->nio_flush_nop, 0);
	atomic_set(&fp->nio_preflush, 0);
	atomic_set(&fp->nio_fua, 0);
	atomic_set(&fp->nio_write, 0);
	atomic_set(&fp->nswitch,0);
	atomic_set(&fp->nslowPath,0);
	atomic_set(&pxd_dev->fp.ncomplete, 0);
	atomic_set(&pxd_dev->fp.nerror, 0);

	return 0;
}

void pxd_fastpath_cleanup(struct pxd_device *pxd_dev)
{
	disableFastPath(pxd_dev, false);

	if (pxd_dev->fp.wq) {
		destroy_workqueue(pxd_dev->fp.wq);
		pxd_dev->fp.wq = NULL;
	}
}

int pxd_init_fastpath_target(struct pxd_device *pxd_dev, struct pxd_update_path_out *update_path)
{
	char modestr[32];
	mode_t mode = 0;
	int err = 0;
	int i;

	mode = open_mode(pxd_dev->mode);
	decode_mode(mode, modestr);
	printk("device %llu setting up fastpath target with mode %#x(%s), paths %ld\n",
			pxd_dev->dev_id, mode, modestr, update_path->count);

	if (update_path->count > MAX_PXD_BACKING_DEVS) {
		printk("device %llu path count more than max supported(%ld)\n",
				pxd_dev->dev_id, update_path->count);
		goto out_file_failed;
	}

	pxd_suspend_io(pxd_dev);
	// update only the path below
	for (i = 0; i < update_path->count; i++) {
		pxd_printk("Fastpath %d(%d): %s, current %s, %px\n", i, pxd_dev->fp.nfd,
			update_path->devpath[i], pxd_dev->fp.device_path[i], pxd_dev->fp.file[i]);
		strncpy(pxd_dev->fp.device_path[i], update_path->devpath[i], MAX_PXD_DEVPATH_LEN);
		pxd_dev->fp.device_path[i][MAX_PXD_DEVPATH_LEN] = '\0';
		pxd_printk("dev %llu: successfully installed fastpath %s\n",
			pxd_dev->dev_id, pxd_dev->fp.device_path[i]);
	}
	pxd_dev->fp.nfd = update_path->count;
	pxd_dev->fp.can_failover = update_path->can_failover;
	enableFastPath(pxd_dev, true);
	pxd_resume_io(pxd_dev);

	if (!pxd_dev->fp.fastpath) goto out_file_failed;
	printk("dev%llu completed setting up %d paths\n", pxd_dev->dev_id, pxd_dev->fp.nfd);
	return 0;
out_file_failed:
	disableFastPath(pxd_dev, false);
	for (i = 0; i < pxd_dev->fp.nfd; i++) {
		if (pxd_dev->fp.file[i] > 0) filp_close(pxd_dev->fp.file[i], NULL);
	}
	pxd_dev->fp.nfd = 0;
	memset(pxd_dev->fp.file, 0, sizeof(pxd_dev->fp.file));
	memset(pxd_dev->fp.device_path, 0, sizeof(pxd_dev->fp.device_path));

	// Allow fallback to native path and not report failure outside.
	printk("device %llu setup through nativepath (%d)\n", pxd_dev->dev_id, err);
	return 0;
}

/* fast path make request function, io entry point */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
blk_qc_t pxd_make_request_fastpath(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
void pxd_make_request_fastpath(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL
#endif
{
	struct pxd_device *pxd_dev = q->queuedata;
	int rw = bio_data_dir(bio);
	struct pxd_io_tracker *head;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
	if (!pxd_dev) {
#else
	if (rw == READA) rw = READ;
	if (!pxd_dev || (rw != READ && rw != WRITE)) {
#endif
		printk_ratelimited(KERN_ERR"pxd basic sanity fail, pxd_device %px (%llu), rw %#x\n",
				pxd_dev, (pxd_dev? pxd_dev->dev_id: (uint64_t)0), rw);
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	if (!pxd_dev->connected || pxd_dev->removing) {
		printk_ratelimited(KERN_ERR"px is disconnected, failing IO.\n");
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	if (rw != READ && !write_allowed(pxd_dev->mode)) {
		printk_ratelimited(KERN_ERR"px device %llu is read only, failing IO.\n", pxd_dev->dev_id);
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	pxd_check_q_congested(pxd_dev);
	read_lock(&pxd_dev->fp.suspend_lock);
	if (!pxd_dev->fp.fastpath) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
		int rc;
#endif
		atomic_inc(&pxd_dev->fp.nslowPath);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
		rc =
#endif
		pxd_make_request_slowpath(q, bio);
		read_unlock(&pxd_dev->fp.suspend_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
		return rc;
#else
		return;
#endif
	}

	head = __pxd_init_block_head(pxd_dev, bio, rw);
	if (!head) {
		read_unlock(&pxd_dev->fp.suspend_lock);
		BIO_ENDIO(bio, -ENOMEM);

		// trivial high memory pressure failing IO
		return BLK_QC_RETVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,1)
	bio_start_io_acct(bio);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
	generic_start_io_acct(pxd_dev->disk->queue, bio_op(bio), REQUEST_GET_SECTORS(bio), &pxd_dev->disk->part0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	generic_start_io_acct(bio_data_dir(bio), REQUEST_GET_SECTORS(bio), &pxd_dev->disk->part0);
#else
	_generic_start_io_acct(pxd_dev->disk->queue, bio_data_dir(bio), REQUEST_GET_SECTORS(bio), &pxd_dev->disk->part0);
#endif

	pxd_process_io(head);
	read_unlock(&pxd_dev->fp.suspend_lock);

	return BLK_QC_RETVAL;
}

void pxd_fastpath_adjust_limits(struct pxd_device *pxd_dev, struct request_queue *topque)
{
	int i;
	struct file *file;
	struct inode *inode;
	struct block_device *bdev;
	struct gendisk *disk;
	struct request_queue *bque;
	char name[BDEVNAME_SIZE];

	printk(KERN_INFO"pxd device %llu: adjusting queue limits nfd %d\n", pxd_dev->dev_id, pxd_dev->fp.nfd);

	for (i = 0; i < pxd_dev->fp.nfd; i++) {
		file = pxd_dev->fp.file[i];
		BUG_ON(!file || !file->f_mapping);
		inode = file->f_mapping->host;
		if (!S_ISBLK(inode->i_mode)) {
			// not needed for non-block based backing devices
			continue;
		}

		bdev = I_BDEV(inode);
		if (!bdev || IS_ERR(bdev)) {
			printk(KERN_ERR"pxd device %llu: backing block device lookup for path %s failed %ld\n",
				pxd_dev->dev_id, pxd_dev->fp.device_path[i], PTR_ERR(bdev));
			goto out;
		}

		disk = bdev->bd_disk;
		if (disk) {
			bque = bdev_get_queue(bdev);
			if (bque) {
				printk(KERN_INFO"pxd device %llu queue limits adjusted with block dev %p(%s)\n",
					pxd_dev->dev_id, bdev, bdevname(bdev, name));
				blk_queue_stack_limits(topque, bque);
			}
		}
	}

	// ensure few block properties are still as expected.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	blk_queue_max_write_zeroes_sectors(topque, 0);
#endif
	blk_queue_logical_block_size(topque, PXD_LBS);
	blk_queue_physical_block_size(topque, PXD_LBS);
	return;

out:
	disableFastPath(pxd_dev, false);
}

/*** debug routines */
int pxd_suspend_state(struct pxd_device *pxd_dev)
{
	return atomic_read(&pxd_dev->fp.suspend);
}

int pxd_debug_switch_fastpath(struct pxd_device* pxd_dev)
{
	return 0;
}

int pxd_debug_switch_nativepath(struct pxd_device* pxd_dev)
{
	if (pxd_dev->fp.fastpath) {
		printk(KERN_WARNING"pxd_dev %llu in fastpath, forcing failover\n",
			pxd_dev->dev_id);
		//pxd_dev->fp.force_fail = true;
		disableFastPath(pxd_dev, false);
	} else {
		printk(KERN_WARNING"pxd_dev %llu in already in native path, skipping failover\n",
			pxd_dev->dev_id);
	}
	return 0;
}

/// handle io path switch events and io reroute on failures
/// functions prefixed with ___xxx need to called with fail_lock
static
void __pxd_add2failQ(struct pxd_device *pxd_dev, struct pxd_io_tracker *iot)
{
	list_add_tail(&iot->item, &pxd_dev->fp.failQ);
}

// no locking needed, @ios is a local list of IO to be reissued.
void pxd_reissuefailQ(struct pxd_device *pxd_dev, struct list_head *ios, int status)
{
	while (!list_empty(ios)) {
		struct pxd_io_tracker *head = list_first_entry(ios, struct pxd_io_tracker, item);
		BUG_ON(head->magic != PXD_IOT_MAGIC);
		list_del(&head->item);
		if (!status) {
			// switch to native path, if px is down, then abort IO timer will cleanup
			printk_ratelimited(KERN_ERR"%s: pxd%llu: resuming IO in native path.\n", __func__, pxd_dev->dev_id);
			atomic_inc(&pxd_dev->fp.nslowPath);
			pxd_reroute_slowpath(pxd_dev->disk->queue, head->orig);
		} else {
			// If failover request failed, then route IO fail to user application as is.
			BIO_ENDIO(head->orig, -EIO);
		}
		__pxd_cleanup_block_io(head);
	}
}

void __pxd_abortfailQ(struct pxd_device *pxd_dev)
{
	while (!list_empty(&pxd_dev->fp.failQ)) {
		struct pxd_io_tracker *head = list_first_entry(&pxd_dev->fp.failQ, struct pxd_io_tracker, item);
		BUG_ON(head->magic != PXD_IOT_MAGIC);
		list_del(&head->item);
		BIO_ENDIO(head->orig, -EIO);
		__pxd_cleanup_block_io(head);
	}
}

void pxd_abortfailQ(struct pxd_device *pxd_dev)
{
	spin_lock(&pxd_dev->fp.fail_lock);
	__pxd_abortfailQ(pxd_dev);
	spin_unlock(&pxd_dev->fp.fail_lock);
}
