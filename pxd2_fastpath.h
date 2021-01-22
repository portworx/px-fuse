#ifndef _PXD2_FASTPATH_H_
#define _PXD2_FASTPATH_H_

#include <linux/blk_types.h>

struct fp_root_context;
struct bio;

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

struct fp_root_context {
#define FP_ROOT_MAGIC (0xbaadf00du)
  unsigned int magic;
#if 0
	struct pxd_device *pxd_dev;
	struct request *rq; // original request
#endif
  struct work_struct work;  // for discard handling
  struct bio *bio;          // consolidated bio
  struct fp_clone_context *clones;
  struct list_head wait;  // wait for resources
  atomic_t nactive;       // num of clones requests currently active
};

static inline void fp_root_context_init(struct fp_root_context *fproot) {
  fproot->magic = FP_ROOT_MAGIC;
  fproot->bio = NULL;
  fproot->clones = NULL;
  atomic_set(&fproot->nactive, 0);
  // work struct should get initialized right before use
}

int fastpath2_init(void);
void fastpath2_cleanup(void);

void fp_handle_io(struct work_struct *);
void clone_cleanup(struct fp_root_context *fproot);
void pxd2_reissuefailQ(struct pxd_device *pxd_dev, struct list_head *ios,
                       int status);
void pxd2_abortfailQ(struct pxd_device *);

#endif /* _PXD2_FASTPATH_H_ */
