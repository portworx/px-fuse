#ifndef _PXD_BIO_H_
#define _PXD_BIO_H_

struct pxd_device;
struct fuse_req;

// default number of worker threads assigned for fastpath
#define DEFAULT_PXFP_WORKERS_PER_NODE (4) /// keep it power of 2.

#ifdef __PX_FASTPATH__

#include <linux/types.h>
#include <linux/kthread.h>
#include "pxd.h"        // MAX_PXD_BACKING_DEVS

int __fastpath_init(void);
void __fastpath_cleanup(void);


void __pxd_abortfailQ(struct pxd_device *pxd_dev);
void pxd_reissuefailQ(struct pxd_device *pxd_dev, struct list_head *ios, int status);

void pxd_suspend_io(struct pxd_device *pxd_dev);
void pxd_resume_io(struct pxd_device *pxd_dev);

#ifdef __PXD_BIO_BLKMQ__
// io entry point
void fp_handle_io(struct kthread_work *work);

// structure is exported only so, it can be embedded within fuse_context.
// Treat it as private outside fastpath
struct fp_root_context {
#define FP_ROOT_MAGIC (0xbaadf00du)
  unsigned int magic;
  struct kthread_work work; // thread work
  struct bio *bio;          // consolidated bio
  struct fp_clone_context *clones; // linked clones
  struct list_head wait;  // wait for resources
  atomic_t nactive;       // num of clones requests currently active

  // Pinned snapshot of pxd_dev->fp.file[]/nfd taken under RCU by
  // fproot_pin_files, released by fproot_release_files. Handlers on pxfp
  // workers MUST use these and never re-read pxd_dev->fp.
  int nfd;
  struct file *file[MAX_PXD_BACKING_DEVS];
};

static inline void fp_root_context_init(struct fp_root_context *fproot) {
  int i;

  fproot->magic = FP_ROOT_MAGIC;
  fproot->bio = NULL;
  fproot->clones = NULL;
  atomic_set(&fproot->nactive, 0);
  INIT_LIST_HEAD(&fproot->wait);
  fproot->nfd = 0;
  for (i = 0; i < MAX_PXD_BACKING_DEVS; i++) {
    fproot->file[i] = NULL;
  }
  kthread_init_work(&fproot->work, fp_handle_io);
}

// Pin fp->file[] into the fproot snapshot. MUST be called inside the
// same rcu_read_lock() that observed fp->fastpath == true - that pairs
// with synchronize_rcu() in disableFastPath so filp_close cannot race
// the pin. Returns false (with any partial pins released) if the device
// is mid-teardown; caller falls back to native.
bool fproot_pin_files(struct fp_root_context *fproot, struct pxd_device *pxd_dev);

// Release the pins from fproot_pin_files. Idempotent per slot so the
// several disposal paths cannot double-fput.
void fproot_release_files(struct fp_root_context *fproot);

#endif

#endif /* __PX_FASTPATH__ */

#endif /* _PXD_BIO_H_ */
