#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/sysfs.h>
#include <linux/crc32.h>
#include <linux/miscdevice.h>
#include <linux/atomic.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/kthread.h>
#include <linux/dma-mapping.h>
#include <linux/statfs.h>
#include <linux/file.h>
#include <linux/splice.h>
#include <linux/fs.h>
#include <linux/falloc.h>
#include <linux/bio.h>

#include "pxd.h"
#include "pxring.h"
#include "pxshared.h"

#define TOSTRING_(x) #x
#define VERTOSTR(x) TOSTRING_(x)

extern const char *gitversion;
static dev_t pxd_major;
//static DEFINE_IDA(pxd_minor_ida);
static int pxd_num_contexts;
struct pxd_device;

static struct pxd_context *pxd_contexts;

// prefix with underscore not to clash with linux imports
typedef enum {_READ, _WRITE, _WRITESAME, _DISCARD, _SYNC} CMD;

typedef enum {_ALIVE, _TIMEDOUT, _DEAD} reqState;
struct reqHandle {
	struct list_head item;
	struct bio* bio;
	struct pxd_device *dev;
	unsigned long timestamp;
	int cpuid;
	reqState state;

	// indices of iovectors
	unsigned short vectors[MAX_VECTORS_PER_REQUEST];
	unsigned int vec_count;
};

// every control device shall internally have a map setup
// each control device is pinned to a cpu
// there is only one control device per cpu
struct mapInfo {
	spinlock_t          lock;
	int cpu_index;
	STATUS status;
	int minor; // misc device kernel assigned minor id

	char name[64];

	const char *shared_base;
	int shared_length;

	struct ring requestring; /* request receive ring */
	struct ring responsering; /* response transmit ring */

	// iovec bit states managed.
	DECLARE_BITMAP(iovec_index, NIOVEC);

	struct list_head pending_requests;
	// TODO add thread information
};


// single global context for pxd
struct pxd_context {
    spinlock_t lock;
    struct list_head list;
    size_t num_devices;
    struct file_operations fops;
    char name[256];
    struct list_head pending_requests;
    struct timer_list timer;
    bool init_sent;
    uint64_t unique;

	struct mapInfo *maps; // array of maps setup
	struct miscdevice miscdev[0]; // an array initialized during module load time to nr_cpu_ids.
};

static inline 
struct mapInfo* getMapInfo(struct pxd_context *ctx, int cpuid) {
	if (cpuid >= pxd_num_contexts || !ctx || !ctx->maps) return NULL;

	return &ctx->maps[cpuid];
}

static inline
struct mapInfo* getMapInfoByMinor(struct pxd_context *ctx, int minor) {
	int i;

	if (!ctx || !ctx->maps) return NULL;

	for (i=0; i<pxd_num_contexts; i++) {
		if (ctx->maps[i].minor == minor) {
			return &ctx->maps[i];
		}
	}

	return NULL;
}

static inline
int mapInfoInit(struct pxd_context *ctx, int cpuid) {
	int err;
	char *base;

	/*
	 * initialize rings 
	 * setup kernel thread pinned to that cpu
	 */

	struct mapInfo* map = getMapInfo(ctx, cpuid);
	if (!map) return -EINVAL;

	// allocate the shared memory region for this cpu.
	base = kmalloc(SHARED_TOTALSIZE, GFP_KERNEL);
	if (!base) return -ENOMEM;

printk(KERN_INFO"Total shared memory size: %ld\n", SHARED_TOTALSIZE);
printk(KERN_INFO"px_requestRecord size: %ld, records: %d, base: %p\n",
		sizeof(struct px_requestRecord), NREQUEST_RECORDS,
		PX_REQUESTBASE(base));
printk(KERN_INFO"px_responseRecord size: %ld, records: %d, base: %p\n",
		sizeof(struct px_responseRecord), NRESPONSE_RECORDS,
		PX_RESPONSEBASE(base));
printk(KERN_INFO"iovec size: %ld, records: %d, base: %p\n",
		sizeof(struct px_iovec), NIOVEC, PX_IOVECBASE(base));
printk(KERN_INFO"iobuffer size: %d, records: %d, base: %p\n",
		SHARED_IOBLKSIZE, NIOVEC, PX_IOBASE(base));

	map->shared_base = base;
	map->shared_length = SHARED_TOTALSIZE;

	err = ringInit(&map->requestring,
			PX_REQUESTBASE(base), REQUEST_RECORDSIZE, NREQUEST_RECORDS);
	if (err != 0) {
		return err;
	}

	err = ringInit(&map->responsering,
			PX_RESPONSEBASE(base), RESPONSE_RECORDSIZE, NRESPONSE_RECORDS);
	if (err != 0) {
		return err;
	}

	spin_lock_init(&map->lock);
	sprintf(map->name, "pxd/pxd-control-%d", cpuid);
	map->cpu_index = cpuid;
	map->status = _READY;
	bitmap_clear(map->iovec_index, 0, NIOVEC);
	INIT_LIST_HEAD(&map->pending_requests);

printk(KERN_INFO"setup ctx->maps.. for cpu %d\n", cpuid);
	return 0;
}

static inline
void mapInfoDestroy(struct pxd_context *ctx, int cpuid) {
	struct mapInfo* map = getMapInfo(ctx, cpuid);
printk(KERN_INFO"destroying ctx->maps.. for cpu %d\n", cpuid);
	if (!map) return;

	ringDestroy(&map->requestring);
	ringDestroy(&map->responsering);
	map->status = _DESTROYED;

	if (map->shared_base) kfree(map->shared_base);
	map->shared_base = NULL;
}

static int pxdc_open(struct inode *ino, struct file *filp)
{
	// Ensure files are opened from the cpu to which they are pinned
	int cpuid = smp_processor_id();
	int minor = iminor(ino);
	struct mapInfo *map;
	
	
	printk(KERN_INFO"Inside pxdc_open... cpuid %d, minor %d\n",
			cpuid, minor);

	map = getMapInfoByMinor(pxd_contexts, minor);
	if (!map) {
printk(KERN_INFO"No map found...\n");
		return -EINVAL;
	}

	if (cpuid != map->cpu_index) {
		// Do not allow access from other cpu
printk(KERN_INFO"map cpud index mismatch (exp: %d, recv %d)...\n",
		map->cpu_index, cpuid);
		return -EINVAL;
	}

	filp->private_data = map;
	return 0;
}

static int pxdc_release(struct inode *ino, struct file *filp)
{
	return 0;
}

static long pxdc_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int cpuid = smp_processor_id();
	struct mapInfo *map = filp->private_data;
	struct px_sysinfo sysinfo;

	if (!map) {
printk(KERN_INFO"pxdc_ioctl: No map defined on cpu %d\n", cpuid);
		return -EINVAL;
	}

	if (cpuid != map->cpu_index) {
		// Do not allow access from other cpu
printk(KERN_INFO"pxdc_ioctl: map cpu id mismatch (has: %d, recv on: %d)\n",
		map->cpu_index, cpuid);
		return -EINVAL;
	}

	switch (cmd) {
	case PXD_GET_SYSINFO:
	printk(KERN_INFO"Received PXD_GET_SYSINFO ioctl request\n");
		sysinfo.status = map->status;
		sysinfo.cpu_id = map->cpu_index;
		sysinfo.shared_base = map->shared_base;
		sysinfo.shared_length = map->shared_length;
		sysinfo.reqRingSize = NREQUEST_RECORDS;
		sysinfo.reqRecordSize = REQUEST_RECORDSIZE;
		sysinfo.respRingSize = NRESPONSE_RECORDS;
		sysinfo.respRecordSize = RESPONSE_RECORDSIZE;
		sysinfo.niovecs = NIOVEC;
		sysinfo.iovecSize = IOVEC_RECORDSIZE;
		sysinfo.nbuffSize = SHARED_IOBLKSIZE;

		px_dump_sysinfo(&sysinfo);

	    if (copy_to_user((struct px_sysinfo __user *)arg, &sysinfo, sizeof(sysinfo))) {
			printk(KERN_INFO"pxdc_ioctl: failed copy to user..\n");
	        return -EFAULT;
		}
	    return 0;
	}

	return -EINVAL;
}

static
int pxdc_mmap (struct file *filp, struct vm_area_struct *vma) {
printk(KERN_INFO"pxdc_mmap not setup yet\n");
	return -EINVAL;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
const struct file_operations dev_operations = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.read		= NULL,
	.aio_read	= NULL,
	.splice_read	= NULL,
	.write		= NULL,
	.aio_write	= NULL,
	.splice_write	= NULL,
	.poll		= NULL,
	.release	= NULL,
	.fasync		= NULL,
	.unlocked_ioctl = pxdc_ioctl,
	.open = pxdc_open,
	.release = pxdc_release,
	.mmap = pxdc_mmap,
};
#else
const struct file_operations dev_operations = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.read_iter	= NULL,
	.splice_read	= NULL,
	.write_iter	= NULL,
	.splice_write	= NULL,
	.poll		= NULL,
	.release	= NULL,
	.fasync		= NULL,
	.unlocked_ioctl = pxdc_ioctl,
	.open = pxdc_open,
	.release = pxdc_release,
	.mmap = pxdc_mmap,
};
#endif

static void pxd_root_dev_release(struct device *dev)
{
}

static struct bus_type pxd_bus_type = {
    .name       = "pxd",
};

static struct device pxd_root_dev = {
    .init_name =    "pxd",
    .release =      pxd_root_dev_release,
};

#if 0
static int pxd_bus_add_dev(struct pxd_device *pxd_dev)
{
    struct device *dev;
    int ret;

    dev = &pxd_dev->dev;
    dev->bus = &pxd_bus_type;
    dev->type = &pxd_device_type;
    dev->parent = &pxd_root_dev;
    dev->release = pxd_dev_device_release;
    dev_set_name(dev, "%d", pxd_dev->minor);
    ret = device_register(dev);

    return ret;
}
#endif

// file operation handlers
#if 0
static int pxd_control_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "%s: pxd-control-?? open OK\n", __func__);
    return 0;
}

/** Note that this will not be called if userspace doesn't cleanup. */
static int pxd_control_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "%s: pxd-control-?? close OK\n", __func__);
    return 0;
}

static long pxd_control_ioctl(
	struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	//struct pxd_context *ctx = NULL;
	int status = -ENOTTY;
	char ver_data[64];
	int ver_len = 0;

	switch (cmd) {
	case PXD_IOC_DUMP_FC_INFO:
		printk(KERN_INFO "TODO: fill up current status info\n");
		status = 0;
		break;

	case PXD_IOC_GET_VERSION:
		if (argp) {
			ver_len = strlen(gitversion) < 64 ? strlen(gitversion) : 64;
			strncpy(ver_data, gitversion, ver_len);
			if (copy_to_user(argp +
				offsetof(struct pxd_ioctl_version_args, piv_len),
				&ver_len, sizeof(ver_len))) {
				return -EFAULT;
			}
			if (copy_to_user(argp +
				offsetof(struct pxd_ioctl_version_args, piv_data),
				ver_data, ver_len)) {
				return -EFAULT;
			}
		}
		printk(KERN_INFO "pxd driver at version: %s\n", gitversion);
		status = 0;
		break;
	default:
		break;
	}
	return status;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void pxd_timeout(struct timer_list *args)
#else
static void pxd_timeout(unsigned long args)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	struct pxd_context *ctx = from_timer(ctx, args, timer);
#else
	struct pxd_context *ctx = (struct pxd_context *)args;
#endif
	printk(KERN_INFO "PXD_TIMEOUT (%s): Aborting all requests...",
		ctx->name);
}

static int pxd_context_init(struct pxd_context *ctx, int ncontexts)
{
	int i, err;

    spin_lock_init(&ctx->lock);

    ctx->fops = dev_operations;
    ctx->fops.owner = THIS_MODULE;
    //ctx->fops.open = pxd_control_open;
    //ctx->fops.release = pxd_control_release;
    //ctx->fops.unlocked_ioctl = pxd_control_ioctl;

    INIT_LIST_HEAD(&ctx->list);
    INIT_LIST_HEAD(&ctx->pending_requests);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
    timer_setup(&ctx->timer, pxd_timeout, 0);
#else
    setup_timer(&ctx->timer, pxd_timeout, (unsigned long) ctx);
#endif

printk(KERN_INFO"allocating ctx->maps for %d contexts", ncontexts);
	ctx->maps = kzalloc(sizeof(struct mapInfo) * ncontexts, GFP_KERNEL);
	if (!ctx->maps) {
		return -ENOMEM;
	}

	for (i=0; i<ncontexts; i++) {
		err = mapInfoInit(ctx, i);
		if (err != 0) {
			return err;
		}

		ctx->miscdev[i].minor = MISC_DYNAMIC_MINOR;
		ctx->miscdev[i].name = ctx->maps[i].name;
		ctx->miscdev[i].fops = &ctx->fops;

		err = misc_register(&ctx->miscdev[i]);
		if (err) {
			printk(KERN_ERR "pxd: failed to register dev %s %d: %d\n",
				ctx->miscdev[i].name, i, err);
			return err;
		}

		ctx->maps[i].minor = ctx->miscdev[i].minor;
printk(KERN_INFO"Assigned minor id: %d\n", ctx->maps[i].minor);
	}

    return 0;	
}

static void pxd_context_destroy(struct pxd_context *ctx, int ncontexts)
{
	int i;

	for (i=0; i<ncontexts; i++) {
		mapInfoDestroy(ctx, i);
		misc_deregister(&ctx->miscdev[i]);
	}

	del_timer_sync(&ctx->timer);
printk(KERN_INFO"freeing ctx->maps..\n");
	kfree(ctx->maps);
}

static int pxd_sysfs_init(void)
{
	int err;

	err = device_register(&pxd_root_dev);
	if (err < 0) {
		return err;
	}

	err = bus_register(&pxd_bus_type);
	if (err < 0) {
		device_unregister(&pxd_root_dev);
		return err;
	}

	return err;
}

static void pxd_sysfs_exit(void)
{
	bus_unregister(&pxd_bus_type);
	device_unregister(&pxd_root_dev);
}

static int pxd_init(void)
{
	int err;
	struct pxd_context *ctx;
	int context_size = sizeof(struct pxd_context);

	pxd_num_contexts = nr_cpu_ids; // create one context device for each cpu.

	printk(KERN_WARNING "pxd: development driver installed, ncontext=%d\n", pxd_num_contexts);

	context_size += sizeof(struct miscdevice) * pxd_num_contexts;
	pxd_contexts = kzalloc(context_size, GFP_KERNEL);
	err = -ENOMEM;
	if (!pxd_contexts) {
		printk(KERN_ERR "pxd: failed to allocate memory\n");
		goto out_fuse_dev;
	}

	err = pxd_sysfs_init();
	if (err) {
		printk(KERN_ERR "pxd: failed to initialize sysfs: %d\n", err);
		goto out_fuse;
	}

	ctx = pxd_contexts;
	err = pxd_context_init(ctx, pxd_num_contexts);
	if (err) {
		printk(KERN_ERR "pxd: failed to initialize connection\n");
		goto out_sysfs;
	}

	pxd_major = register_blkdev(0, "pxd");
	if (pxd_major < 0) {
		err = pxd_major;
		printk(KERN_ERR "pxd: failed to register dev pxd: %d\n", err);
		goto out_sysfs;
	}

	printk(KERN_INFO "pxd: driver loaded version %s\n", gitversion);
	return 0;

out_sysfs:
	pxd_sysfs_exit();
out_fuse:
	pxd_context_destroy(pxd_contexts, pxd_num_contexts);
	kfree(pxd_contexts);
out_fuse_dev:
	return err;
}

static void pxd_exit(void)
{
	pxd_sysfs_exit();
	unregister_blkdev(pxd_major, "pxd");

	/* force cleanup @@@ */
	pxd_context_destroy(pxd_contexts, pxd_num_contexts);

	kfree(pxd_contexts);

	printk(KERN_WARNING "pxd: development driver unloaded\n");
}

module_init(pxd_init);
module_exit(pxd_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION(VERTOSTR(PXD_VERSION));
