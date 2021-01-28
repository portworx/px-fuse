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

void enableFastPath(struct pxd_device *pxd_dev, bool force) {}
void disableFastPath(struct pxd_device *pxd_dev, bool force) {}
int pxd_init_fastpath_target(struct pxd_device *pxd_dev, struct pxd_update_path_out *update_path)
{
	// unsupported
	printk(KERN_WARNING"px driver does not support fastpath - kernel version not supported\n");
	return 0; // cannot fail
}

void pxd_fastpath_adjust_limits(struct pxd_device *pxd_dev, struct request_queue *topque) {}
int pxd_suspend_state(struct pxd_device *pxd_dev) {return 0;}

void pxd_suspend_io(struct pxd_device* pxd_dev) { }
void pxd_resume_io(struct pxd_device* pxd_dev) { }
int pxd_debug_switch_fastpath(struct pxd_device* pxd_dev) {return -1;}
int pxd_debug_switch_nativepath(struct pxd_device* pxd_dev) {return -1;}
int pxd_request_suspend(struct pxd_device *pxd_dev, bool skip_flush, bool coe) { return 0; }
int pxd_request_suspend_internal(struct pxd_device *pxd_dev, bool skip_flush, bool coe) { return 0; }
int pxd_request_resume(struct pxd_device *pxd_dev) { return 0; }
int pxd_request_resume_internal(struct pxd_device *pxd_dev) { return 0; }
int pxd_request_ioswitch(struct pxd_device *pxd_dev, int code) { return -1; }
int pxd_fastpath_vol_cleanup(struct pxd_device *pxd_dev) { return -1; }

void pxd_reissuefailQ(struct pxd_device *pxd_dev, struct list_head *ios, int status){}
void pxd_abortfailQ(struct pxd_device *pxd_dev) { }

// blkmq based fastpath stubs
int fastpath2_init(void) {return 0;}
void fastpath2_cleanup(void) {}
blk_status_t clone_and_map(struct fp_root_context *fproot) { return 0; }

#endif
