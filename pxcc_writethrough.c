#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/crc32.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/sysfs.h>
#include <linux/uio.h>

#include "pxcc.h"
#include "pxcc_writethrough.h"
#include "pxtgt.h"
#include "pxtgt_acct.h"
#include "pxtgt_compat.h"
#include "pxtgt_core.h"

#ifndef STATIC
#define STATIC
#endif

#define PT_MIN_POOL_PAGES (128)
struct per_io {
  struct pxtgt_device *pxtgt_dev;
  struct bio *orig_bio;
  struct per_io *head;
  struct per_io *clones;

  int req_nr : 4;
  int status;  // io status

  atomic_t nactive;
  unsigned long start;
  struct work_struct witem;

  struct bio clone;
};

struct wt_context {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
  struct bio_set bs;
#define get_bio_set(c) (&(c).bs)
#else
  struct bio_set *bs;
#define get_bio_set(c) ((c).bs)
#endif
};

// private context for managing writethrough io
static struct wt_context wtcc;

int wt_setup(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
  if (bioset_init(&wtcc.bs, PT_MIN_POOL_PAGES, offsetof(struct per_io, clone),
                  0)) {
    printk(KERN_ERR
           "pxcc writethrough: failed to initialize bioset_init: -ENOMEM\n");
    goto out_blkdev;
  }
#else
  wtcc.bs = BIOSET_CREATE(PT_MIN_POOL_PAGES, offsetof(struct per_io, clone));
#endif

  if (!get_bio_set(wtcc)) {
    printk(KERN_ERR "pxtgt: bioset init failed\n");
    goto out_blkdev;
  }

  return 0;
out_blkdev:
  return -ENOMEM;
}

int wt_init(struct pxcc_c *cc) {
  // nothing to do
  return 0;
}

void wt_destroy(void) {
  if (get_bio_set(wtcc)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
    bioset_exit(get_bio_set(wtcc));
#else
    bioset_free(get_bio_set(wtcc));
#endif
  }
}

void wt_exit(struct pxcc_c *cc) {
  // nothing to do
}

static int remap_io_status(int status) {
  switch (status) {
    case 0:            // success
    case -EOPNOTSUPP:  // op not supported - no failover
    case -ENOSPC:      // no space on device - no failover
    case -ENOMEM:      // no memory - no failover
      return status;
  }

  return -EIO;
}

// @head [in] - io head
// @return - update reconciled error code
static int reconcile_io_status(struct per_io *head) {
  struct per_io *repl;
  int status = 0;
  int tmp;

  // BUG_ON(head->magic != PXD_IOT_MAGIC);
  for (repl = head->clones; repl != NULL; repl = repl->clones) {
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

static void wt_handle_io(struct work_struct *witem) {
  // TODO process cache IO
  // struct per_io *pio = container_of(witem, struct per_io, witem);
}

static void dummy_handler(struct work_struct *witem) {
  BUG_ON(!"this should never be called");
}

// forward decl
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
    void
    wt_clone_endio(struct bio *bio);
#else
    void
    wt_clone_endio(struct bio *bio, int error);
#endif

static int alloc_clones(struct bio_list *l, int count, struct pxcc_c *cc,
                        struct bio *orig) {
  struct bio *clone_bio;
  struct per_io *pio, *head = NULL;
  int i;
  int rc = -EINVAL;

  for (i = 0; i < count; i++) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
    clone_bio = bio_clone_fast(orig, GFP_NOIO, get_bio_set(wtcc));
#else
    clone_bio = bio_clone_bioset(bio, GFP_NOIO, get_bio_set(wtcc));
#endif
    if (!clone_bio) {
      pxtgt_printk(KERN_ERR "No memory for io context");
      rc = -ENOMEM;
      goto fail;
    }

    pio = container_of(clone_bio, struct per_io, clone);
    BUG_ON(&pio->clone != clone_bio);

    pio->pxtgt_dev = cc->priv;
    pio->orig_bio = orig;
    pio->start = jiffies;
    pio->req_nr = i;

    clone_bio->bi_private = cc->priv;
    clone_bio->bi_end_io = wt_clone_endio;
    if (i == 0) {  // cache IO
      BIO_SET_DEV(clone_bio, cc->cdev);
      INIT_WORK(&pio->witem, wt_handle_io);
    } else {                          // origin IO
      bio_copy_dev(clone_bio, orig);  // same target
      INIT_WORK(&pio->witem, dummy_handler);
    }

    if (!head) {
      pio->head = pio;
      pio->clones = NULL;
      head = pio;
    } else {
      pio->head = head;
      pio->clones = head->clones;
      head->clones = pio;
    }

    // only head will have 'nactive' set
    atomic_set(&pio->nactive, 0);
    bio_list_add(l, clone_bio);
  }

  if (!head) goto fail;
  atomic_set(&head->nactive, bio_list_size(l));

  return 0;
fail:
  while ((clone_bio = bio_list_pop(l)) != NULL) {
    bio_put(clone_bio);
  }
  return rc;
}

static void dealloc_clones(struct bio *clone) {
  struct per_io *pio, *head;

  pio = container_of(clone, struct per_io, clone);
  head = pio->head;

  BUG_ON(atomic_read(&head->nactive));
  while (head->clones != NULL) {
    struct per_io *tio = head->clones;

    head->clones = tio->clones;
    bio_put(&tio->clone);
  }

  bio_put(&head->clone);
}

static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
    void
    wt_clone_endio(struct bio *bio)
#else
    void
    wt_clone_endio(struct bio *bio, int error)
#endif
{
  struct per_io *pio = container_of(bio, struct per_io, clone);
  struct pxtgt_device *pxtgt_dev = pio->pxtgt_dev;
  char b[BDEVNAME_SIZE];
  int blkrc;
  struct per_io *head = pio->head;
  unsigned int flags;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
  blkrc = blk_status_to_errno(bio->bi_status);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
  blkrc = bio->bi_error;
#else
  blkrc = error;
#endif

  flags = get_op_flags(bio);
  if (blkrc != 0) {
    printk_ratelimited(
        "FAILED IO %s (err=%d): %s at %lld len %d bytes %d pages "
        "flags 0x%lx\n",
        BDEVNAME(bio, b), blkrc, bio_data_dir(bio) == WRITE ? "wr" : "rd",
        (unsigned long long)(BIO_SECTOR(bio) * SECTOR_SIZE), BIO_SIZE(bio),
        bio_segments(bio), (long unsigned int)flags);
  }

  pio->status = blkrc;
  if (!atomic_dec_and_test(&head->nactive)) {
    // not all responses back
    return;
  }

  blkrc = reconcile_io_status(head);

  // writethrough mode all IO accounting is done in the origin device.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 1)
  bio_end_io_acct(bio, head->start);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) &&  \
     defined(bvec_iter_sectors))
  generic_end_io_acct(pxtgt_dev->disk->queue, bio_data_dir(bio),
                      &pxtgt_dev->disk->part0, head->start);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
  generic_end_io_acct(bio_data_dir(bio), &pxtgt_dev->disk->part0, head->start);
#else
  _generic_end_io_acct(pxtgt_dev->disk->queue, bio_data_dir(bio),
                       &pxtgt_dev->disk->part0, head->start);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
  {
    pio->orig_bio->bi_status = errno_to_blk_status(blkrc);
    bio_endio(pio->orig_bio);
  }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
  {
    pio->orig_bio->bi_error = blkrc;
    bio_endio(pio->orig_bio);
  }
#else
  { bio_endio(pio->orig_bio, blkrc); }
#endif
  dealloc_clones(bio);
}

int wt_process_io(struct pxcc_c *cc, struct bio *orig) {
  struct pxtgt_device *pxtgt_dev = cc->priv;
  struct bio_list bl;
  struct bio *clone;
  struct per_io *pio, *head;
  int ncount;

  bio_list_init(&bl);

  ncount = 1;
  if (bio_data_dir(orig) == WRITE) ncount = 2;

  if (alloc_clones(&bl, ncount, cc, orig)) {
    return -ENOMEM;
  }

  head = NULL;
  // only clone for writethrough requests
  while ((clone = bio_list_pop(&bl)) != NULL) {
    BUG_ON(!clone);

    pio = container_of(clone, struct per_io, clone);

    if (!head) head = pio->head;

    // pio->req_nr == 0 ==> cache IO
    // pio->req_nr == 1 ==> origin IO

    if (pio->req_nr == 0) {  // cache IO
      // reschedule in cache wq
      queue_work(cc->wq, &pio->witem);
    } else {
      cc->enqueue_to_origin(cc->priv, clone);
    }
  }

  // start IO accounting
  BUG_ON(!head);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 1)
  bio_start_io_acct(bio);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) &&  \
     defined(bvec_iter_sectors))
  generic_start_io_acct(pxtgt_dev->disk->queue, bio_op(orig),
                        REQUEST_GET_SECTORS(orig), &pxtgt_dev->disk->part0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
  generic_start_io_acct(bio_data_dir(orig), REQUEST_GET_SECTORS(orig),
                        &pxtgt_dev->disk->part0);
#else
  _generic_start_io_acct(pxtgt_dev->disk->queue, bio_data_dir(orig),
                         REQUEST_GET_SECTORS(orig), &pxtgt_dev->disk->part0);
#endif

  return CACHE_SUBMITTED;
}
