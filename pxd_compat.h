#ifndef GDFS_PXD_COMPAT_H
#define GDFS_PXD_COMPAT_H

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
#include <linux/timekeeping.h>
#else
#include <linux/idr.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/part_stat.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#define HAVE_BVEC_ITER
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0) || defined(REQ_PREFLUSH)
#define BLK_QUEUE_FLUSH(q) \
	blk_queue_write_cache(q, true, true)
#else
#define BLK_QUEUE_FLUSH(q) \
	blk_queue_flush(q, REQ_FLUSH | REQ_FUA)
#endif

#ifdef HAVE_BVEC_ITER
#define BIO_SECTOR(bio) bio->bi_iter.bi_sector
#define BIO_SIZE(bio) bio->bi_iter.bi_size
#define BVEC(bvec) (bvec)
#else
#define BIO_SECTOR(bio) bio->bi_sector
#define BIO_SIZE(bio) bio->bi_size
#define BVEC(bvec) (*(bvec))
#endif

#define REQUEST_GET_SECTORS(bio)  (BIO_SIZE(bio) >> 9)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
#define BIO_OP(bio)   bio_op(bio)
#define SUBMIT_BIO(bio) submit_bio(bio)
#else
// only supports read or write
#define BIO_OP(bio)   ((bio)->bi_rw & 1)
#define SUBMIT_BIO(bio)  submit_bio(BIO_OP(bio), bio)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
#define BIOSET_CREATE(sz, pad)   bioset_create(sz, pad, 0)
#else
#define BIOSET_CREATE(sz, pad)   bioset_create(sz, pad)
#endif

#if defined(bio_set_dev)
#define BIO_SET_DEV(bio, bdev)  bio_set_dev(bio, bdev)
#else
#define BIO_SET_DEV(bio, bdev)  \
	do { \
		(bio)->bi_bdev = (bdev); \
	} while (0)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
#define BIO_ENDIO(bio, err) do {                \
    bio->bi_status = err;                       \
    bio_endio(bio);                             \
} while (0)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
#define BIO_ENDIO(bio, err) do { 		\
	if (err != 0) { 			\
		bio_io_error((bio)); 		\
	} else {				\
		bio_endio((bio));		\
	} 					\
} while (0)
#else
#define BIO_ENDIO(bio, err) bio_endio((bio), (err))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#define BLK_RQ_IS_PASSTHROUGH(rq)	(blk_rq_is_passthrough(rq))
#else
#define BLK_RQ_IS_PASSTHROUGH(rq)	(rq->cmd_type != REQ_TYPE_FS)
#endif

// helper macros for PXD_SETUP_CONGESTION_HOOK
#define __type_is_ptr(bdev)  __builtin_types_compatible_p(typeof(bdev), struct backing_dev_info*)
#define __ptr_or_null(bdev) __builtin_choose_expr(__type_is_ptr(bdev), bdev, (struct backing_dev_info*)NULL)
#define __SETUP_CONGESTION_HOOK(bdev, cfn, cdata) \
	({ \
		if (bdev) { \
			(bdev)->congested_fn = cfn;\
			(bdev)->congested_data = cdata;\
		} \
	})

#define PXD_SETUP_CONGESTION_HOOK(bdev, cfn, cdata) \
	__builtin_choose_expr(__type_is_ptr(bdev), \
			__SETUP_CONGESTION_HOOK(__ptr_or_null(bdev), cfn, cdata), \
			__SETUP_CONGESTION_HOOK(__ptr_or_null(&bdev), cfn, cdata))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(blk_queue_fua))
#define QUEUE_FLAG_SET(flag,q) blk_queue_flag_set(flag, q);
#else
#define QUEUE_FLAG_SET(flag,q) queue_flag_set_unlocked(flag, q);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
#define BDEVNAME(bio, b)   bio_devname(bio, b)
#else
#define BDEVNAME(bio, b)   bdevname(bio->bi_bdev, b)
#endif

#endif //GDFS_PXD_COMPAT_H
