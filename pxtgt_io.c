#include <linux/kernel.h>
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
#include <linux/falloc.h>

#include "pxtgt.h"
#include "pxtgt_io.h"
#include "pxtgt_core.h"
#include "pxtgt_compat.h"

static long pxtgt_local(struct file *file, unsigned int cmd, unsigned long arg)
{
        switch (cmd) {
        case PXTGT_IOC_GET_VERSION:
                printk("Inside PXTGT_IOC_GET_VERSION\n");
                return 0;
		case PXTGT_IOC_INIT:
                printk("Inside PXTGT_IOC_INIT\n");
                return 0;
		case PXTGT_IOC_RESIZE:
                printk("Inside PXTGT_IOC_RESIZE\n");
                return 0;
        default:
                return -EINVAL;
        }
}


const struct file_operations pxtgt_ops = {
        .owner = THIS_MODULE,
        .unlocked_ioctl = pxtgt_local,
};

int pxtgt_flush(struct pxtgt_device *pxtgt_dev, struct file *file)
{
	int ret = 0;

	ret = vfs_fsync(file, 0);
	if (unlikely(ret && ret != -EINVAL && ret != -EIO)) {
		ret = -EIO;
	}
	atomic_inc(&pxtgt_dev->nio_flush);
	return ret;
}

int pxtgt_bio_discard(struct pxtgt_device *pxtgt_dev, struct file *file, struct bio *bio, loff_t pos)
{
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	int ret;

	atomic_inc(&pxtgt_dev->nio_discard);

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

static int pxtgt_write(uint64_t dev_id, struct file *file, struct bio_vec *bvec, loff_t *pos)
{
	ssize_t bw;
	mm_segment_t old_fs = get_fs();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct iov_iter i;
#else
	void *kaddr = kmap(bvec->bv_page) + bvec->bv_offset;
#endif

	pxtgt_printk("device %llu pxtgt_write entry offset %lld, length %d entered\n",
			dev_id, *pos, bvec->bv_len);

	if (unlikely(bvec->bv_len != PXTGT_LBS)) {
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

int pxtgt_send(struct pxtgt_device *pxtgt_dev, struct file *file, struct bio *bio, loff_t pos)
{
	int ret = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	bio_for_each_segment(bvec, bio, i) {
		ret = pxtgt_write(pxtgt_dev->dev_id, file, &bvec, &pos);
		if (ret < 0) {
			return ret;
		}
	}
#else
	bio_for_each_segment(bvec, bio, i) {
		ret = pxtgt_write(pxtgt_dev->dev_id, file, bvec, &pos);
		if (ret < 0) {
			return ret;
		}
	}
#endif
	atomic_inc(&pxtgt_dev->nio_write);
	return 0;
}

static
ssize_t pxtgt_read(uint64_t dev_id, struct file *file, struct bio_vec *bvec, loff_t *pos)
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

ssize_t pxtgt_receive(struct pxtgt_device *pxtgt_dev, struct file *file, struct bio *bio, loff_t *pos)
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
		s = pxtgt_read(pxtgt_dev->dev_id, file, &bvec, pos);
		if (s < 0) return s;

		if (s != bvec.bv_len) {
			zero_fill_bio(bio);
			break;
		}
#else
		s = pxtgt_read(pxtgt_dev->dev_id, file, bvec, pos);
		if (s < 0) return s;

		if (s != bvec->bv_len) {
			zero_fill_bio(bio);
			break;
		}
#endif
	}
	return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
int do_bio_filebacked(struct pxtgt_device *pxtgt_dev, struct pxtgt_io_tracker *iot)
{
	struct bio *bio = &iot->clone;
	unsigned int op = bio_op(bio);
	loff_t pos;
	int ret;

	BUG_ON(pxtgt_dev->magic != PXTGT_DEV_MAGIC);
	BUG_ON(iot->magic != PXTGT_IOT_MAGIC);

	pxtgt_printk("do_bio_filebacked for new bio (pending %u)\n", PXTGT_ACTIVE(pxtgt_dev));
	pos = ((loff_t) bio->bi_iter.bi_sector << SECTOR_SHIFT);

	switch (op) {
	case REQ_OP_READ:
		ret = pxtgt_receive(pxtgt_dev, pxtgt_dev->fp, bio, &pos);
		goto out;
	case REQ_OP_WRITE:

		if (bio->bi_opf & REQ_PREFLUSH) {
			atomic_inc(&pxtgt_dev->nio_preflush);
			ret = pxtgt_flush(pxtgt_dev, pxtgt_dev->fp);
			if (ret < 0) goto out;
		}

		ret = pxtgt_send(pxtgt_dev, pxtgt_dev->fp, bio, pos);
		if (ret < 0) goto out;

		if (bio->bi_opf & REQ_FUA) {
			atomic_inc(&pxtgt_dev->nio_fua);
			ret = pxtgt_flush(pxtgt_dev, pxtgt_dev->fp);
			if (ret < 0) goto out;
		}

		ret = 0; goto out;

	case REQ_OP_FLUSH:
		ret = pxtgt_flush(pxtgt_dev, pxtgt_dev->fp);
		goto out;
	case REQ_OP_DISCARD:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	case REQ_OP_WRITE_ZEROES:
#endif
		ret = pxtgt_bio_discard(pxtgt_dev, pxtgt_dev->fp, bio, pos);
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
	pxtgt_complete_io(bio);
#else
	pxtgt_complete_io(bio, ret);
#endif

	return ret;
}

#else
int do_bio_filebacked(struct pxtgt_device *pxtgt_dev, struct pxtgt_io_tracker *iot)
{
	loff_t pos;
	int ret;
	struct bio *bio = &iot->clone;

	BUG_ON(pxtgt_dev->magic != PXTGT_DEV_MAGIC);
	BUG_ON(iot->magic != PXTGT_IOT_MAGIC);
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
		pxtgt_printk("bio bi_rw %#lx, flush %#llx, fua %#llx, discard %#llx\n",
				bio->bi_rw, REQ_FLUSH, REQ_FUA, REQ_DISCARD);

		if (bio->bi_rw & REQ_DISCARD) {
			ret = pxtgt_bio_discard(pxtgt_dev, pxtgt_dev->fp, bio, pos);
			goto out;
		}
		/* Before any newer writes happen, make sure previous write/sync complete */
		ret = pxtgt_send(pxtgt_dev, pxtgt_dev->fp, bio, pos);

		if (!ret) {
			if ((bio->bi_rw & REQ_FUA)) {
				atomic_inc(&pxtgt_dev->nio_fua);
				ret = pxtgt_flush(pxtgt_dev, pxtgt_dev->fp);
				if (ret < 0) goto out;
			} else if ((bio->bi_rw & REQ_FLUSH)) {
				ret = pxtgt_flush(pxtgt_dev, pxtgt_dev->fp);
				if (ret < 0) goto out;
			}
		}

	} else {
		ret = pxtgt_receive(pxtgt_dev, pxtgt_dev->fp, bio, &pos);
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
	pxtgt_complete_io(bio);
#else
	pxtgt_complete_io(bio, ret);
#endif

	return ret;
}
#endif
