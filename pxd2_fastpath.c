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

inline bool rq_is_special(struct request *rq)
{
	return (req_op(rq) == REQ_OP_DISCARD) || (req_op(rq) == REQ_OP_FLUSH);
}

atomic_t nclones;
atomic_t nrootbios;

static void dump_allocs(void)
{
	printk("blkmq fastpath: nclone: %d, root bios: %d\n", atomic_read(&nclones), atomic_read(&nrootbios));
}

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
#define PXD_MIN_POOL_PAGES (1024)

int fastpath2_init(void)
{
	printk(KERN_INFO"blkmq fastpath: inited\n");

	atomic_set(&nclones, 0);
	atomic_set(&nrootbios, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && \
     defined(bvec_iter_sectors))
	if (bioset_init(&pxd_bio_set, PXD_MIN_POOL_PAGES,
			offsetof(struct fp_clone_context, clone), BIOSET_NEED_BVECS)) {
		printk(KERN_ERR "blkmq fastpath: failed to initialize bioset_init: -ENOMEM\n");
		return -ENOMEM;
	}
#else
	ppxd_bio_set = BIOSET_CREATE(PXD_MIN_POOL_PAGES, offsetof(struct fp_clone_context, clone), BIOSET_NEED_BVECS);
	if (!ppxd_bio_set) {
		printk(KERN_ERR "blkmq fastpath: bioset init failed\n");
		return -ENOMEM;
	}
#endif

	return 0;
}

void fastpath2_cleanup(void)
{
	printk(KERN_INFO"blkmq fastpath: cleaned up\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
		bioset_exit(get_fpbioset());
#else
	if (get_fpbioset()) bioset_free(get_fpbioset());
#endif
}

static
void pxd_failover_initiate(struct fp_root_context *fproot)
{
	// TODO no failover support, simply fail original
	struct request *rq = fproot_to_request(fproot);

	BUG_ON(fproot->magic != FP_ROOT_MAGIC);

	clone_cleanup(fproot);
	blk_mq_end_request(rq, errno_to_blk_status(-EIO));
}

static
void end_clone_bio_stub(struct bio *bio)
{
	BUG_ON("end_clone_bio_stub unexpected call");
}

static
int reconcile_status(struct fp_root_context *fproot)
{
	struct fp_clone_context *cc;
	int status = 0;

	for (cc = fproot->clones; cc != NULL; cc = cc->clones) {
		if (status == 0)
			status = cc->status;
	}

	return status;
}

void clone_cleanup(struct fp_root_context *fproot)
{
	struct fp_clone_context *cc, *next;
	struct request *rq = fproot_to_request(fproot);

	BUG_ON(fproot->magic != FP_ROOT_MAGIC);

	next = NULL;
	for (cc = fproot->clones; cc != NULL; cc = next) {
		next = cc->clones;

		BUG_ON(cc->magic != FP_CLONE_MAGIC);
		fput(cc->file);
		bio_put(&cc->clone);
		atomic_dec(&nclones);
	}
	fproot->clones = NULL;

	if (fproot->bio && (fproot->bio != rq->bio)) {
		bio_put(fproot->bio);
		atomic_dec(&nrootbios);
	}

	fproot->bio = NULL;
	fproot->magic = ~FP_ROOT_MAGIC;
}

static inline
struct block_device* get_bdev(struct file *fileh)
{
	struct address_space *mapping = fileh->f_mapping;
	struct inode *inode = mapping->host;
	struct block_device *bdev = I_BDEV(inode);

	BUG_ON(!bdev);
	return bdev;
}

static inline
unsigned get_mode(struct file *fileh)
{
	struct address_space *mapping = fileh->f_mapping;
	struct inode *inode = mapping->host;

	return inode->i_mode;
}

static
void end_clone_bio(struct bio *bio)
{
	struct fp_clone_context *cc = container_of(bio, struct fp_clone_context, clone);
	struct fp_root_context *fproot = bio->bi_private;
	struct pxd_device *pxd_dev = fproot_to_pxd(fproot);
	struct request *rq = fproot_to_request(fproot);
	int blkrc;
	unsigned int flags = get_op_flags(bio);
	char b[BDEVNAME_SIZE];

	BUG_ON(cc->magic != FP_CLONE_MAGIC);
	BUG_ON(fproot->magic != FP_ROOT_MAGIC);
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
		printk_ratelimited("blkmq fastpath: FAILED IO %s (err=%d): dev m %d g %lld %s at %lld len %d bytes %d pages "
				"flags 0x%lx\n", BDEVNAME(bio, b), blkrc,
			pxd_dev->minor, pxd_dev->dev_id,
			bio_data_dir(bio) == WRITE ? "wr" : "rd",
			(unsigned long long)(BIO_SECTOR(bio) * SECTOR_SIZE), BIO_SIZE(bio),
			bio_segments(bio), (long unsigned int)flags);
	}

	// cache status within context
	cc->status = blkrc;
	if (!atomic_dec_and_test(&fproot->nactive)) {
		// not all clones completed.
		return;
	}

	// final reconciled status
	blkrc = reconcile_status(fproot);
	// debug condition for force fail
	if (pxd_dev->fp.force_fail) blkrc = -EIO;

	if (pxd_dev->fp.can_failover && (blkrc == -EIO)) {
		atomic_inc(&pxd_dev->fp.nerror);
		pxd_failover_initiate(fproot);
		return;
	}

	// complete cleanup of all clones
	clone_cleanup(fproot);
	// CAREFUL NOW - fproot will be lost once end_request below gets called
	// finish the original request
	blk_mq_end_request(rq, errno_to_blk_status(blkrc));

	atomic_inc(&pxd_dev->fp.ncomplete);
	atomic_dec(&pxd_dev->ncount);
}

static
void pxd_process_fileio(struct work_struct *work)
{
	BUG_ON("not ready to handle file io yet");
}

static
struct bio* clone_root(struct fp_root_context *fproot, struct file *fileh)
{
	struct block_device *bdev = get_bdev(fileh);
	struct bio* clone_bio;
	struct fp_clone_context* cc;

	BUG_ON(fproot->magic != FP_ROOT_MAGIC);
	BUG_ON(!bdev);
	BUG_ON(!fproot->bio);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	clone_bio = bio_clone_fast(fproot->bio, GFP_KERNEL, get_fpbioset());
#else
	clone_bio = bio_clone_bioset(fproot->bio, GFP_KERNEL, get_fpbioset());
#endif
	if (!clone_bio) {
		printk(KERN_ERR"blkmq fastpath: No memory for clone context");
		return NULL;
	}

	cc = container_of(clone_bio, struct fp_clone_context, clone);

	fp_clone_context_init(cc, get_file(fileh));
	cc->clones = fproot->clones;
	fproot->clones = cc;
	BUG_ON(!cc->file);

	BIO_SET_DEV(clone_bio, bdev);
	clone_bio->bi_private = fproot;
	if (S_ISBLK(get_mode(cc->file))) {
		clone_bio->bi_end_io = end_clone_bio;
	} else {
		clone_bio->bi_end_io = end_clone_bio_stub;
	}

	atomic_inc(&nclones);
	return clone_bio;
}

// discard and flush are special ops
static
void fp_handle_specialops(struct work_struct *work)
{
	struct fp_root_context *fproot = container_of(work, struct fp_root_context, work);
	struct pxd_device *pxd_dev = fproot_to_pxd(fproot);
	struct request *rq = fproot_to_request(fproot); // orig request
	int i;
	blk_status_t r;
	struct page *pg = ZERO_PAGE(0); // global shared zero page

	BUG_ON(fproot->magic != FP_ROOT_MAGIC);
	BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);


	// submit flush/discard inline to each replica one at a time.
	for(i=0; i<pxd_dev->fp.nfd; i++) {
		int rc;
		struct file *file = pxd_dev->fp.file[i];
		struct block_device *bdev = get_bdev(file);
		struct request_queue *q = bdev_get_queue(bdev);

		if (req_op(rq) == REQ_OP_FLUSH) {
			atomic_inc(&pxd_dev->fp.nio_flush);
			rc = blkdev_issue_flush(bdev, 0, NULL);
		} else if (blk_queue_discard(q)) { // discard supported
			atomic_inc(&pxd_dev->fp.nio_discard);
			rc = blkdev_issue_discard(bdev, blk_rq_pos(rq), blk_rq_sectors(rq), GFP_NOIO, 0);
		} else if (bdev_write_same(bdev)) {
			atomic_inc(&pxd_dev->fp.nio_discard);
			// convert discard to write same
			rc = blkdev_issue_write_same(bdev, blk_rq_pos(rq), blk_rq_sectors(rq), GFP_NOIO, pg);
		} else {
			atomic_inc(&pxd_dev->fp.nio_discard);
			// zero-out
			rc = blkdev_issue_zeroout(bdev, blk_rq_pos(rq), blk_rq_sectors(rq), GFP_NOIO, 0);
		}

		if (rc) {
			r = BLK_STS_IOERR;
			goto err;
		}
	}

	// all replicas completed good.
	r = BLK_STS_OK;
err:
	blk_mq_end_request(rq, r);
}

// entry point to handle IO
void fp_handle_io(struct work_struct* work)
{
	struct fp_root_context *fproot = container_of(work, struct fp_root_context, work);
	struct request *rq = fproot_to_request(fproot); // orig request
	blk_status_t r;

	BUG_ON(fproot->magic != FP_ROOT_MAGIC);

	if (rq_is_special(rq)) {
		fp_handle_specialops(work);
		return;
	}

	r = clone_and_map(fproot);
	if (r != BLK_STS_OK) {
		blk_mq_end_request(rq, r);
	}
}


static
void stub_endio(struct bio *bio)
{
	BUG_ON("stub_endio called");
}

int prep_root_bio(struct fp_root_context *fproot)
{
	struct request *rq = fproot_to_request(fproot); // orig request
	struct bio_vec bv;
	struct req_iterator rq_iter;
	struct bio *bio;
	int nr_bvec = 0;
	unsigned op_flags = rq->cmd_flags & ~REQ_OP_MASK;

	BUG_ON(fproot->magic != FP_ROOT_MAGIC);

	// single bio request
	if (rq->bio == rq->biotail) {
		fproot->bio = rq->bio;
		BUG_ON(BIO_SECTOR(fproot->bio) != blk_rq_pos(rq));
		BUG_ON(BIO_SIZE(fproot->bio) != blk_rq_bytes(rq));
		return 0;
	}

#if 0
	rq_for_each_bvec(bv, rq, rq_iter)
		nr_bvec++;
#else
	rq_for_each_segment(bv, rq, rq_iter)
		nr_bvec++;
#endif

	bio = bio_alloc_bioset(GFP_KERNEL, nr_bvec, get_fpbioset());
	if (!bio) {
		dump_allocs();
		return -ENOMEM;
	}

	atomic_inc(&nrootbios);
	bio->bi_iter.bi_sector = blk_rq_pos(rq);
	bio->bi_iter.bi_size = 0;
	bio_copy_dev(bio, rq->bio);
	bio->bi_end_io = stub_endio; // should never get called
	bio_set_op_attrs(bio, req_op(rq), op_flags);
	bio->bi_private = fproot;

	BUG_ON((req_op(rq) | op_flags) != rq->cmd_flags);

#if 0
	rq_for_each_bvec(bv, rq, rq_iter) {
		BUG_ON(bio_add_page(bio, bv.bv_page, bv.bv_len, bv.bv_offset));
	}
#else
if (req_op(rq) != REQ_OP_FLUSH && req_op(rq) != REQ_OP_DISCARD)
	rq_for_each_segment(bv, rq, rq_iter) {
		unsigned len = bio_add_page(bio, bv.bv_page, bv.bv_len, bv.bv_offset);
		BUG_ON(len != bv.bv_len);
	}
#endif

	BUG_ON(BIO_SECTOR(bio) != blk_rq_pos(rq));
	BUG_ON(BIO_SIZE(bio) != blk_rq_bytes(rq));

	fproot->bio = bio;
	return 0;
}

blk_status_t clone_and_map(struct fp_root_context *fproot)
{
	struct pxd_device *pxd_dev = fproot_to_pxd(fproot);
	struct request *rq = fproot_to_request(fproot); // orig request
	struct bio *clone;
	struct bio *clonerq[MAX_PXD_BACKING_DEVS] = {NULL,NULL,NULL};
	int i,j;
	blk_status_t r = BLK_STS_OK;
	int rc;

	BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);
	BUG_ON(fproot->magic != FP_ROOT_MAGIC);

	// filter out only supported requests
	switch(req_op(rq)) {
	case REQ_OP_READ:
	case REQ_OP_WRITE:
		break;
	case REQ_OP_FLUSH:
	case REQ_OP_DISCARD:
		// all special requests are filtered before in entry point
		BUG_ON("not expected here");
		break;
	default:
		printk("blkmq fastpath: request %p: received unsupported request %d\n", rq, req_op(rq));
		return BLK_STS_NOTSUPP; // not supported
	}

	rc = prep_root_bio(fproot);
	if (rc) {
		printk("blkmq fastpath: prep_root_bio failing %d\n", rc);
		r = BLK_STS_RESOURCE;
		goto err;
	}

	BUG_ON(fproot->bio == NULL);
	// prepare clone contexts
	for (i=0; i<pxd_dev->fp.nfd; i++) {
		struct file *file = pxd_dev->fp.file[i];

		clone = clone_root(fproot, file);
		if (!clone) {
			r = BLK_STS_RESOURCE;
			goto err;
		}

		clonerq[i] = clone;
		// if this is read op, then request to one replica is sufficient.
		if (req_op(rq) == REQ_OP_READ) {
			i = 1;
			break;
		}
	}
	atomic_set(&fproot->nactive, i);

	// all clone setup good, now dispatch request
	for (j=0; j<i; j++) {
		struct fp_clone_context *cc;

		clone = clonerq[j];
		BUG_ON(!clone);
		cc = container_of(clone, struct fp_clone_context, clone);

		atomic_inc(&pxd_dev->ncount);
		// initialize active io to configured replicas
		if (S_ISBLK(get_mode(cc->file))) {
			atomic_inc(&pxd_dev->fp.nswitch);
			SUBMIT_BIO(clone);
			atomic_inc(&pxd_dev->fp.nswitch);
		} else {
			INIT_WORK(&cc->work, pxd_process_fileio);
			queue_work(pxd_dev->fp.wq, &cc->work);
		}
	}

	return BLK_STS_OK;
err:
	clone_cleanup(fproot);
	return r;
}
