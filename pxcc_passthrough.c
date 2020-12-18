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
#include "pxcc_passthrough.h"
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

  int status;  // io status

  atomic_t nactive;
  unsigned long start;

  struct bio clone;
};

struct pt_context {
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

// private context for managing passthrough io
static struct pt_context ptcc;

int pt_init(struct pxcc_c *cc) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
  if (bioset_init(&ptcc.bs, PT_MIN_POOL_PAGES, offsetof(struct per_io, clone),
                  0)) {
    printk(KERN_ERR
           "pxcc passthrough: failed to initialize bioset_init: -ENOMEM\n");
    goto out_blkdev;
  }
#else
  ptcc.bs = BIOSET_CREATE(PT_MIN_POOL_PAGES, offsetof(struct per_io, clone));
#endif

  if (!get_bio_set(ptcc)) {
    printk(KERN_ERR "pxtgt: bioset init failed\n");
    goto out_blkdev;
  }

  return 0;
out_blkdev:
  return -ENOMEM;
}

void pt_exit(struct pxcc_c *cc) {
  if (get_bio_set(ptcc)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
    bioset_exit(get_bio_set(ptcc));
#else
    bioset_free(get_bio_set(ptcc));
#endif
  }
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

static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
    void
    pt_clone_endio(struct bio *bio)
#else
    void
    pt_clone_endio(struct bio *bio, int error)
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
}

static int alloc_clones(struct bio_list *l, int count, struct pxcc_c *cc,
                        struct bio *orig) {
  struct bio *clone_bio;
  struct per_io *pio, *head = NULL;
  int i;
  int rc = -EINVAL;

  for (i = 0; i < count; i++) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
    clone_bio = bio_clone_fast(orig, GFP_NOIO, get_bio_set(ptcc));
#else
    clone_bio = bio_clone_bioset(bio, GFP_NOIO, get_bio_set(ptcc));
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

STATIC
int dealloc_clones(struct bio *clone) {
  struct per_io *pio, *head;

  pio = container_of(clone, struct per_io, clone);
  head = pio->head;

  while (head->clones != NULL) {
    struct per_io *tio = head->clones;

    head->clones = tio->clones;
    bio_put(&tio->clone);
  }

  bio_put(&head->clone);
  return 0;
}

STATIC
int pt_process_flush_io(struct bio *orig) { return 0; }

STATIC
int pt_process_discard_io(struct bio *orig) { return 0; }

int pt_process_io(struct pxcc_c *cc, struct bio *orig) {
  struct bio_list bl;
  struct bio *clone;
  struct per_io *pio;
  struct pxtgt_device *pxtgt_dev = cc->priv;

  bio_list_init(&bl);
  if (alloc_clones(&bl, 1, cc, orig)) {
    return -ENOMEM;
  }

  // only clone for passthrough requests
  clone = bio_list_pop(&bl);
  BUG_ON(!clone);
  BUG_ON(!bio_list_empty(&bl));

  pio = container_of(clone, struct per_io, clone);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 1)
  pio->head->start = bio_start_io_acct(bio);
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

  clone->bi_private = cc->priv;
  clone->bi_end_io = pt_clone_endio;

  // TODO - set bdev on bio

  cc->enqueue_to_origin(cc->priv, clone);
  return CACHE_SUBMITTED;
}
