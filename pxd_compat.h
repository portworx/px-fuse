#ifndef GDFS_PXD_COMPAT_H
#define GDFS_PXD_COMPAT_H

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
#include <linux/timekeeping.h>
#else
#include <linux/idr.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#define HAVE_BVEC_ITER
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
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

#endif //GDFS_PXD_COMPAT_H
