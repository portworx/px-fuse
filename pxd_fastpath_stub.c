/* Enable stub action if fastpath is not enabled */
#ifndef __PX_FASTPATH__

#include "pxd.h"
#include "pxd_core.h"
#include "pxd_fastpath.h"

int fastpath_init(void) { return 0; }
void fastpath_cleanup(void) {}

// per device initialization for fastpath
int pxd_fastpath_init(struct pxd_device *pxd_dev) { return 0; }
void pxd_fastpath_cleanup(struct pxd_device *pxd_dev) {}

void pxdctx_set_connected(struct pxd_context *ctx, bool enable) {}

void enableFastPath(struct pxd_device *pxd_dev, bool force) {}
void disableFastPath(struct pxd_device *pxd_dev) {}
int pxd_init_fastpath_target(struct pxd_device *pxd_dev, struct pxd_update_path_out *update_path)
{
	// unsupported
	printk(KERN_WARNING"px driver does not support fastpath - kernel version not supported\n");
	return -1;
}

#endif
