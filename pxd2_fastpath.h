#ifndef _PXD2_FASTPATH_H_
#define _PXD2_FASTPATH_H_

#include <linux/blk_types.h>

struct fp_root_context;
struct bio;

struct fp_clone_context {
	struct fp_root_context *root;
	struct bio clone; // should be last
};

struct fp_root_context {
#if 0
	struct pxd_device *pxd_dev;
	struct request *rq; // original request
#endif
	atomic_t nactive;
	int status;
};

int fastpath2_init(void);
void fastpath2_cleanup(void);

blk_status_t clone_and_map(struct fp_root_context *fproot);

#endif /* _PXD2_FASTPATH_H_ */
