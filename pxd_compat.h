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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
#define BIOSET_CREATE(sz, pad)   bioset_create(sz, pad, 0)
#else
#define BIOSET_CREATE(sz, pad)   bioset_create(sz, pad)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
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


#define __COMPAT_CALL_LOOKUP_BDEV_0(fn, path) ({ struct block_device* (*f)(const char*) = fn; struct block_device *p = NULL; if (f) { p = f(path);}  p; })
#define __COMPAT_CALL_LOOKUP_BDEV_1(fn, path) ({ struct block_device* (*f)(const char*, int) = fn; struct block_device *p = NULL; if (f) { p = f(path, 0);}  p; })

#define __lookup_bdev_singlearg(fn) __builtin_types_compatible_p(typeof(fn), struct block_device* (*)(const char*))
#define __lookup_bdev_twoarg(fn) __builtin_types_compatible_p(typeof(fn), struct block_device* (*)(const char*, int))
#define __singlearg_method_or_null(fn) __builtin_choose_expr(__lookup_bdev_singlearg(fn), fn, NULL)
#define __doublearg_method_or_null(fn) __builtin_choose_expr(__lookup_bdev_twoarg(fn), fn, NULL)
#define COMPAT_CALL_LOOKUP_BDEV(path) \
	__builtin_choose_expr(__lookup_bdev_singlearg(lookup_bdev), \
			__COMPAT_CALL_LOOKUP_BDEV_0(__singlearg_method_or_null(lookup_bdev), path), \
			__COMPAT_CALL_LOOKUP_BDEV_1(__doublearg_method_or_null(lookup_bdev), path))


#endif //GDFS_PXD_COMPAT_H
