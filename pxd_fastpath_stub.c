/* Enable stub action if fastpath is not enabled */
#ifndef __PX_FASTPATH__

#include "pxd.h"
#include "pxd_core.h"
#include "pxd_fastpath.h"

int fastpath_init(void) { return 0; }
void fastpath_cleanup(void) {}

// per device initialization for fastpath
int pxd_fastpath_init(struct pxd_device *pxd_dev, loff_t offset) { return 0; }
void pxd_fastpath_cleanup(struct pxd_device *pxd_dev) {}

void pxdctx_set_connected(struct pxd_context *ctx, bool enable) {}

// IO entry point
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
blk_qc_t pxd_make_request_fastpath(struct request_queue *q, struct bio *bio) {
	return pxd_make_request_slowpath(q, bio);
}
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
void pxd_make_request_fastpath(struct request_queue *q, struct bio *bio) {
	return pxd_make_request_slowpath(q, bio);
}
#define BLK_QC_RETVAL
#endif

//
void enableFastPath(struct pxd_device *pxd_dev, bool force) {}
#endif
