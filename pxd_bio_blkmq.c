// enable this only if the px block device IO is
// registered through blkmq
#ifdef __PXD_BIO_BLKMQ__

#include <linux/version.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/genhd.h>
#include <linux/workqueue.h>
#include <linux/errno.h>

#include "fuse_i.h"
#include "kiolib.h"
#include "linux/blk-mq.h"
#include "pxd_core.h"
#include "pxd.h"
#include "pxd_compat.h"
#include "pxd_bio.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
inline bool rq_is_special(struct request *rq) {
  return (req_op(rq) == REQ_OP_DISCARD) || (req_op(rq) == REQ_OP_FLUSH);
}
#else
inline bool rq_is_special(struct request *rq) {
  return (BIO_OP(rq->bio) & (REQ_DISCARD | REQ_FLUSH));
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
static void end_clone_bio(struct bio *bio);
static void stub_endio(struct bio* bio)
#else
static void end_clone_bio(struct bio *bio, int error);
static void stub_endio(struct bio* bio, int error)
#endif
{
	BUG_ON("stub_endio called");
}
static void clone_cleanup(struct fp_root_context *fproot);

static atomic_t nclones;
static atomic_t nrootbios;
static void dump_allocs(void) {
  printk("blkmq fastpath: nclone: %d, root bios: %d\n", atomic_read(&nclones),
         atomic_read(&nrootbios));
}

struct fp_clone_context {
#define FP_CLONE_MAGIC (0xea7ef00du)
  unsigned int magic;
  struct fp_clone_context *clones;
  // struct fp_root_context *root;
  struct file *file;
  int status;
  struct work_struct work;
  struct bio clone;  // should be last
};

static inline void fp_clone_context_init(struct fp_clone_context *cc,
                                         struct file *file) {
  cc->magic = FP_CLONE_MAGIC;
  cc->file = file;
  cc->clones = NULL;
  cc->status = 0;
  // work should get initialized at the point of usage.
}

static int reconcile_status(struct fp_root_context *fproot) {
  struct fp_clone_context *cc;
  int status = 0;

  for (cc = fproot->clones; cc != NULL; cc = cc->clones) {
    if (status == 0) status = cc->status;
  }

  return status;
}

static void pxd_process_fileio(struct work_struct *work) {
  struct fp_clone_context *cc =
      container_of(work, struct fp_clone_context, work);
  struct bio *clone = &cc->clone;
  struct fp_root_context *fproot = clone->bi_private;
  struct pxd_device *pxd_dev = fproot_to_pxd(fproot);

  __do_bio_filebacked(pxd_dev, clone, cc->file);
}

// A private global bio mempool for punting requests bypassing vfs
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
static struct bio_set pxd_bio_set;
#define get_fpbioset() (&pxd_bio_set)
#else
static struct bio_set *ppxd_bio_set;
#define get_fpbioset() (ppxd_bio_set)
#endif
#define PXD_MIN_POOL_PAGES (128)


int __fastpath_init(void)
{
  printk(KERN_INFO "blkmq fastpath: inited\n");

  atomic_set(&nclones, 0);
  atomic_set(&nrootbios, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
  if (bioset_init(&pxd_bio_set, PXD_MIN_POOL_PAGES,
                  offsetof(struct fp_clone_context, clone),
                  BIOSET_NEED_BVECS)) {
    printk(KERN_ERR
           "blkmq fastpath: failed to initialize bioset_init: -ENOMEM\n");
    return -ENOMEM;
  }
#else
  ppxd_bio_set = BIOSET_CREATE(PXD_MIN_POOL_PAGES,
                               offsetof(struct fp_clone_context, clone),
                               BIOSET_NEED_BVECS);
  if (!ppxd_bio_set) {
    printk(KERN_ERR "blkmq fastpath: bioset init failed\n");
    return -ENOMEM;
  }
#endif

  return 0;
}

void __fastpath_cleanup(void)
{
  printk(KERN_INFO "blkmq fastpath: cleaned up\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
  bioset_exit(get_fpbioset());
#else
  if (get_fpbioset()) bioset_free(get_fpbioset());
#endif
}


void pxd_suspend_io(struct pxd_device *pxd_dev)
{
    int curr = atomic_inc_return(&pxd_dev->fp.suspend);
    if (curr == 1) {
        BUG_ON(!pxd_dev->disk || !pxd_dev->disk->queue);
        blk_mq_freeze_queue(pxd_dev->disk->queue);
        printk("For pxd device %llu IO suspended\n", pxd_dev->dev_id);
    } else {
        printk("For pxd device %llu IO already suspended(%d)\n", pxd_dev->dev_id, curr);
    }
}


void pxd_resume_io(struct pxd_device *pxd_dev)
{
    bool wakeup;
    int curr = atomic_dec_return(&pxd_dev->fp.suspend);

    wakeup = (curr == 0);
    if (wakeup) {
        printk("For pxd device %llu IO resumed\n", pxd_dev->dev_id);
        BUG_ON(!pxd_dev->disk || !pxd_dev->disk->queue);
        blk_mq_unfreeze_queue(pxd_dev->disk->queue);
    } else {
        printk("For pxd device %llu IO still suspended(%d)\n", pxd_dev->dev_id, curr);
    }
}

void __pxd_abortfailQ(struct pxd_device *pxd_dev) {
  while (!list_empty(&pxd_dev->fp.failQ)) {
    struct fp_root_context *fproot =
        list_first_entry(&pxd_dev->fp.failQ, struct fp_root_context, wait);
    struct fuse_req *req = fproot_to_fuse_request(fproot);
    BUG_ON(fproot->magic != FP_ROOT_MAGIC);
    list_del(&fproot->wait);
    clone_cleanup(fproot);
#ifndef __PX_BLKMQ__
    blk_end_request(req->rq, -EIO, blk_rq_bytes(req->rq));
    fuse_request_free(req);
#else
    blk_mq_end_request(req->rq, BLK_STS_IOERR);
#endif
  }
}

// no locking needed, @ios is a local list of IO to be reissued.
void pxd_reissuefailQ(struct pxd_device *pxd_dev, struct list_head *ios,
                       int status) {
  while (!list_empty(ios)) {
    struct fp_root_context *fproot =
        list_first_entry(&pxd_dev->fp.failQ, struct fp_root_context, wait);
    struct fuse_req *req = fproot_to_fuse_request(fproot);
    BUG_ON(fproot->magic != FP_ROOT_MAGIC);
    list_del(&fproot->wait);
    clone_cleanup(fproot);
    if (!status) {
      // switch to native path, if px is down, then abort IO timer will cleanup
      printk_ratelimited(KERN_ERR "%s: pxd%llu: resuming IO in native path.\n",
                         __func__, pxd_dev->dev_id);
      atomic_inc(&pxd_dev->fp.nslowPath);
      pxdmq_reroute_slowpath(req);
      continue;
    }
    // If failover request failed, then route IO fail to user application as is.
#ifndef __PX_BLKMQ__
    blk_end_request(req->rq, -EIO, blk_rq_bytes(req->rq));
    fuse_request_free(req);
#else
    blk_mq_end_request(req->rq, BLK_STS_IOERR);
#endif
  }
}

// io prep/setup/clone
static int prep_root_bio(struct fp_root_context *fproot) {
  struct request *rq = fproot_to_request(fproot);  // orig request
#ifdef HAVE_BVEC_ITER
  struct bio_vec bv;
#else
  struct bio_vec *bv = NULL;
#endif
  struct req_iterator rq_iter;
  struct bio *bio;
  int nr_bvec = 0;
  unsigned op_flags = get_op_flags(rq->bio);

  BUG_ON(fproot->magic != FP_ROOT_MAGIC);

  // single bio request
  if (rq->bio == rq->biotail) {
    fproot->bio = rq->bio;
    BUG_ON(BIO_SECTOR(fproot->bio) != blk_rq_pos(rq));
    BUG_ON(BIO_SIZE(fproot->bio) != blk_rq_bytes(rq));
    return 0;
  }

  rq_for_each_segment(bv, rq, rq_iter) nr_bvec++;

  bio = bio_alloc_bioset(GFP_KERNEL, nr_bvec, get_fpbioset());
  if (!bio) {
    dump_allocs();
    return -ENOMEM;
  }

  atomic_inc(&nrootbios);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
  bio->bi_iter.bi_sector = blk_rq_pos(rq);
  bio->bi_iter.bi_size = 0;
#else
  bio->bi_sector = blk_rq_pos(rq);
  bio->bi_size = 0;
#endif
  bio->bi_end_io = stub_endio;  // should never get called
  BIO_COPY_DEV(bio, rq->bio);
  BIO_SET_OP_ATTRS(bio, BIO_OP(rq->bio), op_flags);
  bio->bi_private = fproot;

  BUG_ON((BIO_OP(rq->bio) | op_flags) != rq->cmd_flags);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
  if (BIO_OP(rq->bio) != REQ_OP_FLUSH && BIO_OP(rq->bio) != REQ_OP_DISCARD) {
#else
  if (BIO_OP(rq->bio) & (REQ_FLUSH|REQ_DISCARD)) {
#endif
    rq_for_each_segment(bv, rq, rq_iter) {
      unsigned len = bio_add_page(bio, BVEC(bv).bv_page, BVEC(bv).bv_len, BVEC(bv).bv_offset);
      BUG_ON(len != BVEC(bv).bv_len);
    }
  }

  BUG_ON(BIO_SECTOR(bio) != blk_rq_pos(rq));
  BUG_ON(BIO_SIZE(bio) != blk_rq_bytes(rq));

  fproot->bio = bio;
  return 0;
}

static void clone_cleanup(struct fp_root_context *fproot) {
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


static struct bio *clone_root(struct fp_root_context *fproot,
                              struct file *fileh) {
  struct block_device *bdev = get_bdev(fileh);
  struct bio *clone_bio;
  struct fp_clone_context *cc;

  BUG_ON(fproot->magic != FP_ROOT_MAGIC);
  BUG_ON(!bdev);
  BUG_ON(!fproot->bio);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
  clone_bio = bio_clone_fast(fproot->bio, GFP_KERNEL, get_fpbioset());
#else
  clone_bio = bio_clone_bioset(fproot->bio, GFP_KERNEL, get_fpbioset());
#endif
  if (!clone_bio) {
    printk(KERN_ERR "blkmq fastpath: No memory for clone context");
    return NULL;
  }

  cc = container_of(clone_bio, struct fp_clone_context, clone);

  fp_clone_context_init(cc, get_file(fileh));
  cc->clones = fproot->clones;
  fproot->clones = cc;
  BUG_ON(!cc->file);

  BIO_SET_DEV(clone_bio, bdev);
  clone_bio->bi_private = fproot;
  clone_bio->bi_end_io = end_clone_bio;

  atomic_inc(&nclones);
  return clone_bio;
}


#ifndef __PX_BLKMQ__
static int
#else
static blk_status_t
#endif
clone_and_map(struct fp_root_context *fproot) {
  struct pxd_device *pxd_dev = fproot_to_pxd(fproot);
  struct request *rq = fproot_to_request(fproot);  // orig request
  struct bio *clone;
  struct bio *clonerq[MAX_PXD_BACKING_DEVS] = {NULL, NULL, NULL};
  int i, j;
#ifndef __PX_BLKMQ__
  int r = 0;
#else
  blk_status_t r = BLK_STS_OK;
#endif
  int rc;

  BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);
  BUG_ON(fproot->magic != FP_ROOT_MAGIC);

  // filter out only supported requests
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
  switch (req_op(rq)) {
    case REQ_OP_READ:
    case REQ_OP_WRITE:
      break;
    case REQ_OP_FLUSH:
    case REQ_OP_DISCARD:
      // all special requests are filtered before in entry point
      BUG_ON("not expected here");
      break;
    default:
      printk("blkmq fastpath: request %p: received unsupported request %#lx\n",
             rq, req_op(rq));
#ifndef __PX_BLKMQ__
      return -ENOTSUPP;
#else
      return BLK_STS_NOTSUPP;  // not supported
#endif
  }
#else
  if (BIO_OP(rq->bio) & REQ_DISCARD) {
     BUG_ON("not expected here");
  } else if (BIO_OP(rq->bio) & ~(REQ_WRITE|REQ_FLUSH|REQ_FUA)) {
     printk("blkmq fastpath: request %p: received unsupported request %#lx\n",
             rq, BIO_OP(rq->bio));
#ifndef __PX_BLKMQ__
     return -ENOTSUPP;
#else
     return BLK_STS_NOTSUPP;  // not supported
#endif
  }
#endif

  rc = prep_root_bio(fproot);
  if (rc) {
    printk("blkmq fastpath: prep_root_bio failing %d\n", rc);
#ifndef __PX_BLKMQ__
	r = rc;
#else
    r = BLK_STS_RESOURCE;
#endif
    goto err;
  }

  BUG_ON(fproot->bio == NULL);
  // prepare clone contexts
  for (i = 0; i < pxd_dev->fp.nfd; i++) {
    struct file *file = pxd_dev->fp.file[i];

    clone = clone_root(fproot, file);
    if (!clone) {
#ifndef __PX_BLKMQ__
	  r = -ENOMEM;
#else
      r = BLK_STS_RESOURCE;
#endif
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
  for (j = 0; j < i; j++) {
    struct fp_clone_context *cc;

    clone = clonerq[j];
    BUG_ON(!clone);
    cc = container_of(clone, struct fp_clone_context, clone);

    // initialize active io to configured replicas
    if (S_ISBLK(get_mode(cc->file))) {
      atomic_inc(&pxd_dev->fp.nswitch);
      SUBMIT_BIO(clone);
    } else {
      INIT_WORK(&cc->work, pxd_process_fileio);
      queue_work(pxd_dev->fp.wq, &cc->work);
    }
  }

  return 0;
err:
  clone_cleanup(fproot);
  return r;
}

// failover handling
static void pxd_io_failover(struct work_struct *work) {
  struct fp_root_context *fproot =
      container_of(work, struct fp_root_context, work);
  struct pxd_device *pxd_dev = fproot_to_pxd(fproot);
  bool cleanup = false;
  bool reroute = false;
  int rc;

  BUG_ON(fproot->magic != FP_ROOT_MAGIC);
  BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);

  spin_lock(&pxd_dev->fp.fail_lock);
  if (!pxd_dev->fp.active_failover) {
    if (pxd_dev->fp.fastpath) {
      pxd_dev->fp.active_failover = true;
      list_add_tail(&fproot->wait, &pxd_dev->fp.failQ);
      cleanup = true;
    } else {
      reroute = true;
    }
  } else {
    list_add_tail(&fproot->wait, &pxd_dev->fp.failQ);
  }
  spin_unlock(&pxd_dev->fp.fail_lock);

  if (cleanup) {
    rc = pxd_initiate_failover(pxd_dev);
    // If userspace cannot be informed of a failover event, force abort all IO.
    if (rc) {
      printk_ratelimited(KERN_ERR
                         "%s: pxd%llu: failover failed %d, aborting IO\n",
                         __func__, pxd_dev->dev_id, rc);
      spin_lock(&pxd_dev->fp.fail_lock);
      __pxd_abortfailQ(pxd_dev);
      pxd_dev->fp.active_failover = false;
      spin_unlock(&pxd_dev->fp.fail_lock);
    }
  } else if (reroute) {
    printk_ratelimited(KERN_ERR "%s: pxd%llu: resuming IO in native path.\n",
                       __func__, pxd_dev->dev_id);
    atomic_inc(&pxd_dev->fp.nslowPath);
    clone_cleanup(fproot);
    pxdmq_reroute_slowpath(fproot_to_fuse_request(fproot));
  }
}

static void pxd_failover_initiate(struct fp_root_context *fproot) {
  struct pxd_device *pxd_dev = fproot_to_pxd(fproot);

  BUG_ON(fproot->magic != FP_ROOT_MAGIC);

  INIT_WORK(&fproot->work, pxd_io_failover);
  queue_work(pxd_dev->fp.wq, &fproot->work);
}

// io handling functions
// discard is special ops
static void fp_handle_specialops(struct fp_root_context *fproot) {
  struct pxd_device *pxd_dev = fproot_to_pxd(fproot);
  struct request *rq = fproot_to_request(fproot);  // orig request
  struct page *pg = ZERO_PAGE(0);                  // global shared zero page
#ifndef __PX_BLKMQ__
  int r = 0;
#else
  blk_status_t r = BLK_STS_OK;
#endif
  int i;
  bool isflush = false;

  BUG_ON(fproot->magic != FP_ROOT_MAGIC);
  BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
  if (req_op(rq) == REQ_OP_FLUSH) {
    atomic_inc(&pxd_dev->fp.nio_flush);
    isflush = true;
  } else {
    atomic_inc(&pxd_dev->fp.nio_discard);
  }
#else
  if (BIO_OP(rq->bio) & REQ_FLUSH) {
    atomic_inc(&pxd_dev->fp.nio_flush);
    isflush = true;
  } else {
    atomic_inc(&pxd_dev->fp.nio_discard);
  }
#endif

  // submit flush/discard inline to each replica one at a time.
  for (i = 0; i < pxd_dev->fp.nfd; i++) {
    int rc;
    struct file *file = pxd_dev->fp.file[i];
    struct block_device *bdev = get_bdev(file);
    struct request_queue *q = bdev_get_queue(bdev);

    if (isflush) {
      rc = blkdev_issue_flush(bdev, 0, NULL);
    } else if (blk_queue_discard(q)) {  // discard supported
      rc = blkdev_issue_discard(bdev, blk_rq_pos(rq), blk_rq_sectors(rq),
                                GFP_NOIO, 0);
    } else if (bdev_write_same(bdev)) {
      // convert discard to write same
      rc = blkdev_issue_write_same(bdev, blk_rq_pos(rq), blk_rq_sectors(rq),
                                   GFP_NOIO, pg);
    } else { // zero-out
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
      rc = blkdev_issue_zeroout(bdev, blk_rq_pos(rq), blk_rq_sectors(rq),
                                GFP_NOIO, 0);
#else
      rc = blkdev_issue_zeroout(bdev, blk_rq_pos(rq), blk_rq_sectors(rq),
                                GFP_NOIO);
#endif
    }

    if (rc) {
#ifndef __PX_BLKMQ__
      r = rc;
#else
      r = BLK_STS_IOERR;
#endif
      goto err;
    }
  }

  // all replicas completed good.
#ifndef __PX_BLKMQ__
  r = 0;
#else
  r = BLK_STS_OK;
#endif
err:
  atomic_dec(&pxd_dev->ncount);
  atomic_inc(&pxd_dev->fp.ncomplete);
#ifndef __PX_BLKMQ__
  blk_end_request(rq, r, blk_rq_bytes(rq));
  fuse_request_free(fproot_to_fuse_request(fproot));
#else
  blk_mq_end_request(rq, errno_to_blk_status(r));
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
static void end_clone_bio(struct bio* bio)
#else
static void end_clone_bio(struct bio* bio, int error)
#endif
{
  struct fp_clone_context *cc =
      container_of(bio, struct fp_clone_context, clone);
  struct fp_root_context *fproot = bio->bi_private;
  struct pxd_device *pxd_dev = fproot_to_pxd(fproot);
  struct request *rq = fproot_to_request(fproot);
  int blkrc;
  unsigned int flags = get_op_flags(bio);
  char b[BDEVNAME_SIZE];

  BUG_ON(cc->magic != FP_CLONE_MAGIC);
  BUG_ON(fproot->magic != FP_ROOT_MAGIC);
  BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
  blkrc = blk_status_to_errno(bio->bi_status);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
  blkrc = bio->bi_error;
#else
  blkrc = error;
#endif

  if (blkrc != 0) {
    printk_ratelimited(
        "blkmq fastpath: FAILED IO %s (err=%d): dev m %d g %lld %s at %lld len "
        "%d bytes %d pages "
        "flags 0x%lx\n",
        BDEVNAME(bio, b), blkrc, pxd_dev->minor, pxd_dev->dev_id,
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
#ifndef __PX_BLKMQ__
  blk_end_request(rq, blkrc, blk_rq_bytes(rq));
  fuse_request_free(fproot_to_fuse_request(fproot));
#else
  blk_mq_end_request(rq, errno_to_blk_status(blkrc));
#endif

  atomic_inc(&pxd_dev->fp.ncomplete);
  atomic_dec(&pxd_dev->ncount);
}


// entry point to handle IO
void fp_handle_io(struct work_struct *work) {
  struct fp_root_context *fproot =
      container_of(work, struct fp_root_context, work);
  struct request *rq = fproot_to_request(fproot);  // orig request
  struct pxd_device *pxd_dev = fproot_to_pxd(fproot);
#ifndef __PX_BLKMQ__
  int r;
#else
  blk_status_t r;
#endif

  BUG_ON(fproot->magic != FP_ROOT_MAGIC);
  BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);

  atomic_inc(&pxd_dev->ncount);
  if (rq_is_special(rq)) {
    fp_handle_specialops(fproot);
    return;
  }

  r = clone_and_map(fproot);
#ifndef __PX_BLKMQ__
  if (r != 0) {
    blk_end_request(rq, r, blk_rq_bytes(rq));
    fuse_request_free(fproot_to_fuse_request(fproot));
  }
#else
  if (r != BLK_STS_OK) {
    blk_mq_end_request(rq, r);
  }
#endif
}


#endif
