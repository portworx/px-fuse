#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/crc32.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/sysfs.h>
#include <linux/uio.h>

#include "pxcc_passthrough.h"
#include "pxtgt.h"

#ifndef STATIC
#define STATIC
#endif

#define PT_MIN_POOL_PAGES (128)
struct per_io {
  struct pxtgt_device *pxtgt_dev;
  struct bio *orig_bio;
  int ncount;

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

struct per_io *alloc_io(struct pxcc_c *cc, struct bio *orig) {
  return NULL;
}

int dealloc_io(struct bio *clone) { return 0; }

STATIC
int pt_process_flush_io(struct bio *orig) { return 0; }

STATIC
int pt_process_discard_io(struct bio *orig) { return 0; }

int pt_process_io(struct pxcc_c *cc, struct bio *orig) {
  // struct bio *clone = alloc_io(cc, orig);
  return 0;
}
