#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
#include <linux/blk_types.h>
#endif

#include "pxd_compat.h"
#include "pxd_core.h"

static int _pxd_flush(struct pxd_device *pxd_dev, struct file *file) {
        int ret = 0;

        // pxd_dev is opened in o_sync mode. all writes are complete with
        // implicit sync. explicit sync can be treated nop
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

static int _pxd_bio_discard(struct pxd_device *pxd_dev, struct file *file,
                            struct bio *bio, loff_t pos) {
        int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
        int ret;

        atomic_inc(&pxd_dev->fp.nio_discard);

        if ((!file->f_op->fallocate)) {
                return -EOPNOTSUPP;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
        ret = file->f_op->fallocate(file, mode, pos, bio->bi_iter.bi_size);
#else
        ret = file->f_op->fallocate(file, mode, pos, bio->bi_size);
#endif
        if (unlikely(ret && ret != -EINVAL && ret != -EOPNOTSUPP))
                return -EIO;

        return 0;
}

static int _pxd_write(uint64_t dev_id, struct file *file, struct bio_vec *bvec,
                      loff_t *pos) {
        ssize_t bw;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
        struct iov_iter i;
#else
        mm_segment_t old_fs = get_fs();
        void *kaddr = kmap(bvec->bv_page) + bvec->bv_offset;
#endif

        pxd_printk(
            "device %llu pxd_write entry offset %lld, length %d entered\n",
            dev_id, *pos, bvec->bv_len);

        if (unlikely(bvec->bv_len != PXD_LBS)) {
                printk(KERN_ERR "Unaligned block writes %d bytes\n",
                       bvec->bv_len);
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
        iov_iter_bvec(&i, WRITE, bvec, 1, bvec->bv_len);
        file_start_write(file);
        bw = vfs_iter_write(file, &i, pos, 0);
        file_end_write(file);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
        iov_iter_bvec(&i, ITER_BVEC | WRITE, bvec, 1, bvec->bv_len);
        file_start_write(file);
        bw = vfs_iter_write(file, &i, pos, 0);
        file_end_write(file);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
        iov_iter_bvec(&i, ITER_BVEC | WRITE, bvec, 1, bvec->bv_len);
        file_start_write(file);
        bw = vfs_iter_write(file, &i, pos);
        file_end_write(file);
#else
        set_fs(KERNEL_DS);
        bw = vfs_write(file, kaddr, bvec->bv_len, pos);
        kunmap(bvec->bv_page);
        set_fs(old_fs);
#endif

        if (likely(bw == bvec->bv_len)) {
                return 0;
        }

        printk_ratelimited(KERN_ERR "device %llu Write error at byte offset "
                                    "%lld, length %i, write %ld\n",
                           dev_id, *pos, bvec->bv_len, bw);
        if (bw >= 0)
                bw = -EIO;
        return bw;
}

static int pxd_send(struct pxd_device *pxd_dev, struct file *file,
                    struct bio *bio, loff_t pos) {
        int ret = 0;
        int nsegs = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
        struct bio_vec bvec;
        struct bvec_iter i;
#else
        struct bio_vec *bvec;
        int i;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
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

static ssize_t _pxd_read(uint64_t dev_id, struct file *file,
                         struct bio_vec *bvec, loff_t *pos) {
        int result = 0;

        /* read from file at offset pos into the buffer */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
        struct iov_iter i;

        iov_iter_bvec(&i, READ, bvec, 1, bvec->bv_len);
        result = vfs_iter_read(file, &i, pos, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
        struct iov_iter i;

        iov_iter_bvec(&i, ITER_BVEC | READ, bvec, 1, bvec->bv_len);
        result = vfs_iter_read(file, &i, pos, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
        struct iov_iter i;

        iov_iter_bvec(&i, ITER_BVEC | READ, bvec, 1, bvec->bv_len);
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
                printk_ratelimited(KERN_ERR
                                   "device %llu: read offset %lld failed %d\n",
                                   dev_id, *pos, result);
        return result;
}

static ssize_t pxd_receive(struct pxd_device *pxd_dev, struct file *file,
                           struct bio *bio, loff_t *pos) {
        ssize_t s;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
        struct bio_vec bvec;
        struct bvec_iter i;
#else
        struct bio_vec *bvec;
        int i;
#endif

        bio_for_each_segment(bvec, bio, i) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
                s = _pxd_read(pxd_dev->dev_id, file, &bvec, pos);
                if (s < 0)
                        return s;

                if (s != bvec.bv_len) {
                        zero_fill_bio(bio);
                        break;
                }
#else
                s = _pxd_read(pxd_dev->dev_id, file, bvec, pos);
                if (s < 0)
                        return s;

                if (s != bvec->bv_len) {
                        zero_fill_bio(bio);
                        break;
                }
#endif
        }
        return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
int __do_bio_filebacked(struct pxd_device *pxd_dev, struct bio *bio,
                        struct file *file) {
        unsigned int op = bio_op(bio);
        loff_t pos;
        int ret;

        BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);

        pxd_printk("do_bio_filebacked for new bio (pending %u)\n",
                   PXD_ACTIVE(pxd_dev));
        pos = ((loff_t)bio->bi_iter.bi_sector << SECTOR_SHIFT);

        switch (op) {
        case REQ_OP_READ:
                ret = pxd_receive(pxd_dev, file, bio, &pos);
                goto out;
        case REQ_OP_WRITE:

                if (bio->bi_opf & REQ_PREFLUSH) {
                        atomic_inc(&pxd_dev->fp.nio_preflush);
                        ret = _pxd_flush(pxd_dev, file);
                        if (ret < 0)
                                goto out;
                }

                ret = pxd_send(pxd_dev, file, bio, pos);
                if (ret < 0)
                        goto out;

                if (bio->bi_opf & REQ_FUA) {
                        atomic_inc(&pxd_dev->fp.nio_fua);
                        ret = _pxd_flush(pxd_dev, file);
                        if (ret < 0)
                                goto out;
                }

                ret = 0;
                goto out;

        case REQ_OP_FLUSH:
                ret = _pxd_flush(pxd_dev, file);
                goto out;
        case REQ_OP_DISCARD:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
        case REQ_OP_WRITE_ZEROES:
#endif
                ret = _pxd_bio_discard(pxd_dev, file, bio, pos);
                goto out;
        default:
                WARN_ON_ONCE(1);
                ret = -EIO;
                goto out;
        }

out:
        BIO_ENDIO(bio, ret);
        return ret;
}

#else
int __do_bio_filebacked(struct pxd_device *pxd_dev, struct bio *bio,
                        struct file *file) {
        loff_t pos;
        int ret;

        BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
        pos = ((loff_t)bio->bi_iter.bi_sector << SECTOR_SHIFT);
#else
        pos = ((loff_t)bio->bi_sector << SECTOR_SHIFT);
#endif

        // mark status all good to begin with!
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
        bio->bi_status = 0;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
        bio->bi_error = 0;
#endif
        if (bio_data_dir(bio) == WRITE) {
                pxd_printk(
                    "bio bi_rw %#lx, flush %#llx, fua %#llx, discard %#llx\n",
                    bio->bi_rw, REQ_FLUSH, REQ_FUA, REQ_DISCARD);

                if (bio->bi_rw & REQ_DISCARD) {
                        ret = _pxd_bio_discard(pxd_dev, file, bio, pos);
                        goto out;
                }
                /* Before any newer writes happen, make sure previous write/sync
                 * complete */
                ret = pxd_send(pxd_dev, file, bio, pos);

                if (!ret) {
                        if ((bio->bi_rw & REQ_FUA)) {
                                atomic_inc(&pxd_dev->fp.nio_fua);
                                ret = _pxd_flush(pxd_dev, file);
                                if (ret < 0)
                                        goto out;
                        } else if ((bio->bi_rw & REQ_FLUSH)) {
                                ret = _pxd_flush(pxd_dev, file);
                                if (ret < 0)
                                        goto out;
                        }
                }

        } else {
                ret = pxd_receive(pxd_dev, file, bio, &pos);
        }

out:
        BIO_ENDIO(bio, ret);
        return ret;
}
#endif
