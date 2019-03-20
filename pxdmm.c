#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/idr.h>
#include <linux/timer.h>
#include <linux/parser.h>
#include <linux/uio_driver.h>
#include <linux/radix-tree.h>
#include <linux/stringify.h>
#include <linux/bitops.h>
#include <linux/highmem.h>
#include <linux/configfs.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/uio_driver.h>
#include <linux/slab.h>
#include <linux/device.h>

#include "pxdmm.h"

#define DRIVER_VERSION "0.1"

struct pxdmm_dev {
	struct device dev;
	struct uio_info info;
	DECLARE_BITMAP(io_index, NREQUESTS);

#define PXDMM_DEV_OPEN (0x1)
	unsigned long flags;

	// will be valid only if open
	struct inode *inode;

	// Keep a list of all active requests
	struct list_head active_requests;

	// memory maps
	void *base;
	struct pxdmm_mbox *mbox;
	struct pxdmm_cmdresp *cmdQ;
	struct pxdmm_cmdresp *respQ;
	void *dataWindow;

	uint64_t mboxLength;
	uint64_t cmdQLength;
	uint64_t respQLength;
	uint64_t dataWindowLength;

	uint64_t totalWindowLength;
};

static
int uio_mmap(struct uio_info* info, struct vm_area_struct  *vma) {
	return 0;
}

static
int uio_open(struct uio_info* info, struct inode *inode) {
	struct pxdmm_dev *udev = container_of(info, struct pxdmm_dev, info);

	/* O_EXCL not supported for char devs, so fake it? */
	if (test_and_set_bit(PXDMM_DEV_OPEN, &udev->flags))
		return -EBUSY;

	udev->inode = inode;

	pr_debug("open\n");

	return 0;
}

static
int uio_release(struct uio_info* info, struct inode *inode) {
	struct pxdmm_dev *udev = container_of(info, struct pxdmm_dev, info);

	clear_bit(PXDMM_DEV_OPEN, &udev->flags);

	pr_debug("close\n");
	return 0;
}

static
int uio_irqcontrol(struct uio_info *info, s32 irq_on) {
	return 0;
}

/* parent device */
static void pxdmm_root_dev_release(struct device *dev)
{
}

static struct device pxdmm_root_dev = {
	.init_name =    "pxdmm",
	.release =      pxdmm_root_dev_release,
};


static struct pxdmm_dev *udev;

static inline
struct pxdmm_dev* to_pxdmm_dev(struct uio_info *info) {
	return container_of(info, struct pxdmm_dev, info);
}

#define CMDR_SIZE (8<<20)

static int pxdmm_dev_init(void) {
	int err;
	uint64_t offset;

	udev = kzalloc(sizeof(struct pxdmm_dev), GFP_KERNEL);
	if (!udev) 
		return -ENOMEM;

	udev->base = vzalloc(CMDR_SIZE);
	if (!udev->base) {
		BUG();
		return -ENOMEM;
	}

	udev->mbox = udev->base;
	udev->mboxLength = sizeof(struct pxdmm_mbox);
	offset = roundup(udev->mboxLength, PAGE_SIZE);

	udev->cmdQ = udev->base + offset;
	udev->cmdQLength = NREQUESTS * sizeof(struct pxdmm_cmdresp);
	offset += roundup(udev->cmdQLength, PAGE_SIZE);

	udev->respQ = udev->base + offset;
	udev->respQLength = NREQUESTS * sizeof(struct pxdmm_cmdresp);
	offset += roundup(udev->respQLength, PAGE_SIZE);

	BUG_ON(offset > CMDR_SIZE);

	udev->dataWindowLength = NREQUESTS * MAXDATASIZE;
	udev->dataWindow = (void*) roundup((uintptr_t)udev->base + CMDR_SIZE, PAGE_SIZE);

	udev->totalWindowLength = CMDR_SIZE + roundup(udev->dataWindowLength, PAGE_SIZE);
#if 0
	dataWindow = vzalloc(dataWindowLength);
	if (!dataWindow) {
		BUG();
		vfree(mbox);
		return -ENOMEM;
	}
#endif

	printk("mbox: size: %lu, base: %p, length %llu\n", sizeof(struct pxdmm_mbox), udev->mbox, udev->mboxLength);
	printk("cmdQ: size: %lu, base: %p, length %llu\n", sizeof(struct pxdmm_cmdresp), udev->cmdQ, udev->cmdQLength);
	printk("respQ: size: %lu, base: %p, length %llu\n", sizeof(struct pxdmm_cmdresp), udev->respQ, udev->respQLength);
	printk("dataWindow: size: %u, base: %p, length %llu\n", (uint32_t) MAXDATASIZE, udev->dataWindow, udev->dataWindowLength);
	printk("base: %p, total: %llu, end: %p\n", udev->base, udev->totalWindowLength, 
			(void*)((uintptr_t)udev->base+udev->totalWindowLength));

	// sysfs parent device.

	udev->info.name = "pxdmm";
	udev->info.version = DRIVER_VERSION;
	udev->info.irq = UIO_IRQ_CUSTOM;
	udev->info.irqcontrol = uio_irqcontrol;

	udev->info.open = uio_open;
	udev->info.release = uio_release;
	udev->info.mmap = uio_mmap;

	udev->info.mem[0].name = "pxdmm cmd/resp window";
	udev->info.mem[0].addr = (phys_addr_t)(uintptr_t)udev->base;
	udev->info.mem[0].size = udev->totalWindowLength;
	udev->info.mem[0].memtype = UIO_MEM_NONE;


	err = device_register(&pxdmm_root_dev);
	if (err) {
		pxdmm_exit();
		return err;
	}

	err = uio_register_device(&pxdmm_root_dev, &udev->info);
	if (err) {
		pxdmm_exit();
		return err;
	}

	return 0;
}

int pxdmm_init(void) {
	int err;

	err = pxdmm_dev_init();
	if (err) {
		return err;
	}

	return 0;
}


void pxdmm_exit(void) {
	uio_unregister_device(&udev->info);
	device_unregister(&pxdmm_root_dev);

	printk("Freeing data window @ %p\n", udev->dataWindow);
	// vfree(dataWindow);
	printk("Freeing respQ @ %p\n", udev->respQ);
	printk("Freeing cmdQ @ %p\n", udev->cmdQ);
	printk("Freeing mbox @ %p\n", udev->mbox);
	vfree(udev->base);
	kfree(udev);
}
