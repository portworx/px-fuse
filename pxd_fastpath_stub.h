#ifndef _PX_FASTPATH_STUB_
#define _PX_FASTPATH_STUB_
#include <linux/kernel.h>
#include <asm/bug.h>

struct pxd_device;
struct pxd_update_path_out;

/// module global fastpath specific setup/cleanup
static inline
int fastpath_init(void) { return 0; }
static inline
void fastpath_cleanup(void) {}

struct workqueue_struct* fastpath_workqueue(void)
{
	BUG_ON(!"unexpected");
	return NULL;
}

/// common failover/fallback code path
static inline
int pxd_request_suspend_internal(struct pxd_device *pxd_dev, bool skip_flush, bool coe)
{
	BUG_ON(!"unexpected");
	return -EINVAL;
}

static inline
int pxd_request_resume_internal(struct pxd_device *pxd_dev)
{
	BUG_ON(!"unexpected");
	return -EINVAL;
}

/// ioctl calls from userspace
static inline
int pxd_request_suspend(struct pxd_device *pxd_dev, bool skip_flush, bool coe)
{
	BUG_ON(!"unexpected");
	return -EINVAL;
}

static inline
int pxd_request_resume(struct pxd_device *pxd_dev)
{
	BUG_ON(!"unexpected");
	return -EINVAL;
}

static inline
int pxd_request_ioswitch(struct pxd_device *pxd_dev, int code)
{
	BUG_ON(!"unexpected");
	return -EINVAL;
}

/// node wipe callback
static inline
int pxd_fastpath_vol_cleanup(struct pxd_device *pxd_dev)
{
	return 0;
}

// restart code path
static inline
void pxd_abortfailQ(struct pxd_device *pxd_dev) {}
static inline
void disableFastPath(struct pxd_device *pxd_dev, bool skipSync) {}

// common volume attach/detach path
static inline
int pxd_fastpath_init(struct pxd_device *pxd_dev) { return 0; }
static inline
void pxd_fastpath_cleanup(struct pxd_device *pxd_dev) {}
/// per volume fastpath specific init
static inline
int pxd_init_fastpath_target(struct pxd_device *pxd_dev, struct pxd_update_path_out *update_path)
{
	BUG_ON(!"unexpected");
	return -EINVAL;
}

/// debug routines
static inline
int pxd_debug_switch_fastpath(struct pxd_device *pxd_dev) { return 0; }
static inline
int pxd_debug_switch_nativepath(struct pxd_device *pxd_dev) { return 0; }
static inline
int pxd_suspend_state(struct pxd_device *pxd_dev) { return 0; }

#endif /* _PX_FASTPATH_STUB_ */
