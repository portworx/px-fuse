#ifndef _PXD_BIO_H_
#define _PXD_BIO_H_

struct pxd_device;
struct fuse_req;

// default number of worker threads assigned for fastpath
#define DEFAULT_PXFP_WORKERS_PER_NODE (4) /// keep it power of 2.

#ifdef __PX_FASTPATH__

#include <linux/types.h>
#include <linux/kthread.h>

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
};

static inline void fp_root_context_init(struct fp_root_context *fproot) {
  fproot->magic = FP_ROOT_MAGIC;
  fproot->bio = NULL;
  fproot->clones = NULL;
  atomic_set(&fproot->nactive, 0);
  INIT_LIST_HEAD(&fproot->wait);
  kthread_init_work(&fproot->work, fp_handle_io);
}

#endif

#endif /* __PX_FASTPATH__ */

#endif /* _PXD_BIO_H_ */
