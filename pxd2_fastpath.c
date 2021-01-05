#include <linux/version.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/genhd.h>
#include <linux/workqueue.h>

#include "pxd.h"
#include "pxd_core.h"
#include "pxd_compat.h"
#include "pxd2_fastpath.h"
#include "fuse_i.h"
#include "linux/blk-mq.h"

// A private global bio mempool for punting requests bypassing vfs
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
static struct bio_set pxd_bio_set;
#define get_fpbioset()   (&pxd_bio_set)
#else
static struct bio_set* ppxd_bio_set;
#define get_fpbioset()   (ppxd_bio_set)
#endif
#define PXD_MIN_POOL_PAGES (128)

int fastpath2_init(void)
{
	printk(KERN_INFO"blkmq based fastpath inited\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
	if (bioset_init(get_fpbioset(), PXD_MIN_POOL_PAGES,
			offsetof(struct fp_clone_context, clone), 0)) {
		printk(KERN_ERR "pxd: failed to initialize bioset_init: -ENOMEM\n");
		return -ENOMEM;
	}
#else
	ppxd_bio_set = BIOSET_CREATE(PXD_MIN_POOL_PAGES, offsetof(struct fp_clone_context, clone));
	if (!ppxd_bio_set) {
		printk(KERN_ERR "pxd: bioset init failed\n");
		return -ENOMEM;
	}
#endif

	return 0;
}

void fastpath2_cleanup(void)
{
	printk(KERN_INFO"blkmq based fastpath cleaned up\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
		bioset_exit(get_fpbioset());
#else
	if (get_fpbioset()) bioset_free(get_fpbioset());
#endif
}

static
void pxd_failover_initiate(struct fp_root_context *fproot)
{
	// no failover support, simply fail original
	struct request *rq = fproot_to_request(fproot);

	blk_mq_end_request(rq, errno_to_blk_status(-EIO));
}


static
void end_clone_bio(struct bio *bio)
{
	struct fp_clone_context *cc = container_of(bio, struct fp_clone_context, clone);
	struct fp_root_context *fproot = cc->root;
	struct pxd_device *pxd_dev = fproot_to_pxd(fproot);
	int blkrc;
	unsigned int flags = get_op_flags(bio);
	char b[BDEVNAME_SIZE];
	
	// Just a debug interface
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
				"flags 0x%lx\n", BDEVNAME(bio, b), blkrc,
			pxd_dev->minor, pxd_dev->dev_id,
			bio_data_dir(bio) == WRITE ? "wr" : "rd",
			(unsigned long long)(BIO_SECTOR(bio) * SECTOR_SIZE), BIO_SIZE(bio),
			bio_segments(bio), (long unsigned int)flags);
	}

}

static
void end_clone_request(struct request *clone, blk_status_t status)
{
	struct fp_root_context *fproot = clone->end_io_data;
	struct pxd_device *pxd_dev = fproot_to_pxd(fproot);
	struct request *rq = fproot_to_request(fproot); //orig request
	int blkrc;
	int i;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
		blkrc = blk_status_to_errno(status);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
		blkrc = status;
#else
		blkrc = status;
#endif

	// capture only the first failure
	if (fproot->status == 0) {
		fproot->status = blkrc;
	}

	// release the clone
	blk_rq_unprep_clone(clone);
	blk_put_request(clone);

	if (!atomic_dec_and_test(&fproot->nactive)) {
		// not all clones completed.
		return;
	}

	// release reference on fileh
	for (i=0; i<pxd_dev->fp.nfd; i++) fput(pxd_dev->fp.file[i]);

	// final reconciled status
	blkrc = fproot->status;

	// debug condition for force fail
	if (pxd_dev->fp.force_fail) blkrc = -EIO;

	if (pxd_dev->fp.can_failover && (blkrc == -EIO)) {
		atomic_inc(&pxd_dev->fp.nerror);
		pxd_failover_initiate(fproot);
		// pxd_check_q_decongested(pxd_dev);
		return;
	}


	// finish the original request
	blk_mq_end_request(rq, errno_to_blk_status(blkrc));
}

static
int clone_bio_constructor(struct bio *bio, struct bio *orig, void *ctxt)
{
	struct fp_clone_context *cc = container_of(bio, struct fp_clone_context, clone);
	struct fp_root_context *fproot = (struct fp_root_context *)ctxt;

	cc->root = fproot;
	bio->bi_end_io = end_clone_bio; // just debug interface
	return 0;
}

static
struct request* clone_one(struct pxd_device *pxd_dev, struct file *fileh, struct request *rq)
{
	struct request *clone;
	struct request_queue *q;
	struct address_space *mapping = fileh->f_mapping;
	struct inode *inode = mapping->host;
	struct block_device *bdev = I_BDEV(inode);

	BUG_ON(!bdev);

	q = bdev_get_queue(bdev);
	BUG_ON(!q);

	clone = blk_get_request(q, rq->cmd_flags | REQ_NOMERGE, BLK_MQ_REQ_NOWAIT);
	if (IS_ERR_OR_NULL(clone)) {
		return NULL;
	}

	clone->bio = clone->biotail = NULL;
	clone->rq_disk = bdev->bd_disk;
	clone->cmd_flags |= REQ_FAILFAST_TRANSPORT;
	get_file(fileh);

	return clone;
}

blk_status_t clone_and_map(struct fp_root_context *fproot)
{
	struct pxd_device *pxd_dev = fproot_to_pxd(fproot);
	struct request *rq = fproot_to_request(fproot); // orig request
	struct request *clone;
	struct request *clonerq[MAX_PXD_BACKING_DEVS];
	int i;
	blk_status_t r = BLK_STS_OK;

	memset(clonerq, 0, sizeof(clonerq));
	atomic_set(&fproot->nactive, pxd_dev->fp.nfd);

	for (i=0; i<pxd_dev->fp.nfd; i++) {
		struct file *file = pxd_dev->fp.file[i];
		int rc;

		struct request *clone = clone_one(pxd_dev, file, rq);
		if (!clone) {
			r = BLK_STS_RESOURCE;
			goto err;
		}

		clonerq[i] = clone;
		rc = blk_rq_prep_clone(clone, rq, get_fpbioset(), GFP_ATOMIC | GFP_NOIO, clone_bio_constructor, fproot);
		if (rc) {
			r = BLK_STS_RESOURCE;
			goto err;
		}

		clone->end_io = end_clone_request;
		clone->end_io_data = fproot;
	}

	// all clone setup good, now dispatch request
	for (i=0; i<pxd_dev->fp.nfd; i++) {
		clone = clonerq[i];

		BUG_ON(!clone);
		if (blk_queue_io_stat(clone->q)) {
			clone->rq_flags |= RQF_IO_STAT;
		}

		clone->start_time_ns = ktime_get_ns();
		r = blk_insert_cloned_request(clone->q, clone);
		if (r != BLK_STS_OK) {
			goto err;
		}
	}

	return BLK_STS_OK;
err:
	for (i=0; i<pxd_dev->fp.nfd; i++) {
		if (clonerq[i]) {
			clone = clonerq[i];
			blk_rq_unprep_clone(clone);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
			blk_mq_cleanup_rq(clone);
#endif
			blk_put_request(clone);
			fput(pxd_dev->fp.file[i]);
		}
	}
	return r;
}
