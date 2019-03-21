#include <linux/version.h>
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
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/bio.h>

#include "pxd_compat.h"
#include "pxdmm.h"

#define DRIVER_VERSION "0.1"
#define STATIC /* a temporary hack until all gets used */

struct reqhandle {
	struct bio *bio;
	unsigned long starttime;

#define PXDMM_REQUEST_ACTIVE (0x1)
#define PXDMM_REQUEST_TIMEDOUT (0x2)
#define PXDMM_REQUEST_COMPLETE (0x4)
#define PXDMM_REQUEST_WAITING (0x8)
#define PXDMM_REQUEST_FREE    (0x80)
	unsigned long flags;
};


struct pxdmm_dev {
	struct device dev;
	struct uio_info info;
	DECLARE_BITMAP(io_index, NREQUESTS);

	// Keep a list of all active requests
	struct reqhandle requests[NREQUESTS];
#define PXDMM_DEV_OPEN (0x1)
	unsigned long flags;

	// will be valid only if open
	struct inode *inode;

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

static inline
struct reqhandle* getRequestHandle(struct pxdmm_dev* udev, int dbi) {
	BUG_ON(dbi >= NREQUESTS);

	return &udev->requests[dbi];
}

static
const char* pxdmm_vma_name(struct vm_area_struct *vma) {
	return "pxdmm cmd/resp vma";
}

static int pxdmm_find_mem_index(struct vm_area_struct *vma) {
	struct pxdmm_dev *udev = vma->vm_private_data;

	if (vma->vm_pgoff < MAX_UIO_MAPS) {
		if (udev->info.mem[vma->vm_pgoff].size == 0)
			return -1;
		return (int)vma->vm_pgoff;
	}
	return -1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
typedef int vm_fault_t;
#endif


//static vm_fault_t pxdmm_vma_fault(struct vm_fault *vmf) {
static vm_fault_t pxdmm_vma_fault(struct vm_area_struct *vma, struct vm_fault *vmf) {
	//struct pxdmm_dev *udev = vmf->vma->vm_private_data;
	struct pxdmm_dev *udev = vma->vm_private_data;
	struct uio_info *info = &udev->info;
	struct page *page = NULL;
	unsigned long offset;
	void *addr;
	struct reqhandle *handle;

	//int mi = pxdmm_find_mem_index(vmf->vma);
	int mi = pxdmm_find_mem_index(vma);
	if (mi < 0)
		return VM_FAULT_SIGBUS;

	offset = (vmf->pgoff - mi) << PAGE_SHIFT;
	if (offset < CMDR_SIZE) {
		addr = (void*) (unsigned long)info->mem[mi].addr + offset;
		page = vmalloc_to_page(addr);
	} else {
		uint32_t dbi;
		loff_t bufferOffset;
		unsigned int currOffset;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter bvec_iter;
#else
	struct bio_vec *bvec;
	int bvec_iter;
#endif
	struct bio* breq;

		dbi = (offset - CMDR_SIZE) / MAXDATASIZE;
		// find the request that has data buffer index
		handle = getRequestHandle(udev, dbi);
		if (!handle || !(handle->flags & PXDMM_REQUEST_ACTIVE)) return VM_FAULT_SIGBUS;

		breq = handle->bio;

		// then map all the bio pages into the 1MB data window.
		// Fetch all the mapped BIO for this request.
		bufferOffset = offset - CMDR_SIZE - (dbi * MAXDATASIZE);
		currOffset = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
		bio_for_each_segment(bvec, breq, bvec_iter) {
			unsigned int pageSize = bvec.bv_len + bvec.bv_offset;
			if (bufferOffset >= currOffset && bufferOffset < (currOffset + pageSize)) {
				page = bvec.bv_page;
				break;
			}

			currOffset += pageSize;
		}
#else
		bio_for_each_segment(bvec, breq, bvec_iter) {
			unsigned int pageSize = bvec->bv_len + bvec->bv_offset;
			if (bufferOffset >= currOffset && bufferOffset < (currOffset + pageSize)) {
				page = bvec->bv_page;
				break;
			}

			currOffset += pageSize;
		}
#endif
	}

	if (!page) {
		return VM_FAULT_SIGBUS;
	}
	get_page(page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct pxdmm_vma_ops = {
	.name = pxdmm_vma_name,
	.fault = pxdmm_vma_fault,
};

static
int uio_mmap(struct uio_info* info, struct vm_area_struct  *vma) {
	struct pxdmm_dev *udev = container_of(info, struct pxdmm_dev, info);

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops = &pxdmm_vma_ops;

	vma->vm_private_data = udev;

	/* Ensure the mmap is exactly the right size */
	if (vma_pages(vma) != (udev->totalWindowLength >> PAGE_SHIFT))
		return -EINVAL;

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

/* for data buffer */
/* map and unmap pages from bio within the inode address mapping */

#if 0
static
int pxdmm_map_bio(struct mm_struct* mm, uint32_t io_index, struct bio* bio) {
	loff_t offset = pxdmm_dataoffset(io_index);
	const uint32_t dataBufferLength = MAXDATASIZE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif
	struct vm_area_struct *vma;

	if (!bio_has_data(bio)) return 0;

	vma = find_vma(mm, offset);
	if (!vma) {
		return -EINVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	bio_for_each_segment(bvec, bio, i) {
		struct page *pg = bvec.bv_page;
		loff_t length = roundup(bvec.bv_len, PAGE_SIZE);

		vmf_insert_page(vma, offset, length, pg);
		offset += length;
	}
#else
	bio_for_each_segment(bvec, bio, i) {
		struct page *pg = bvec->bv_page;
		loff_t length = roundup(bvec->bv_len, PAGE_SIZE);

		vmf_insert_page(vma, offset, length, pg);
		offset += length;
	}
#endif
}
#endif

STATIC
int pxdmm_unmap_bio(struct inode* inode, uint32_t io_index) {
	loff_t offset = pxdmm_dataoffset(io_index);
	struct address_space *as = inode->i_mapping;
	const uint32_t dataBufferLength = MAXDATASIZE;

	unmap_mapping_range(as, offset, dataBufferLength, 1);

	return 0;
}


/* map/unmap logic ends */

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
