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
#include <linux/miscdevice.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/wait.h>

#include "pxd_compat.h"
#include "pxd_core.h"
#include "pxdmm.h"

#define DRIVER_VERSION "0.1"
#define STATIC /* a temporary hack until all gets used */
//#define DBGMODE

static struct page *apage, *bpage;

static inline
void fillpage (struct page *pg) {
	void *kaddr = kmap_atomic(pg);

	__fillpage(kaddr, PAGE_SIZE);
	kunmap_atomic(kaddr);
}

struct reqhandle {
	unsigned long magichead;
	struct bio *bio;
	struct request_queue *queue;
	unsigned long starttime;

#define PXDMM_REQUEST_ACTIVE (0x1)
#define PXDMM_REQUEST_TIMEDOUT (0x2)
	unsigned long flags;

	unsigned long magictail;
};

#define MAGICHEAD (0xDEADBEEF)
#define MAGICTAIL (0xCAFECAFE)
static inline
bool sanitize(struct reqhandle* handle) {
	return (handle->magichead == MAGICHEAD && handle->magictail == MAGICTAIL);
}

static int pxdmm_queue_completer(void *arg);
struct pxdmm_dev {
	unsigned long magichead;
	struct device dev;
	struct uio_info info;
	DECLARE_BITMAP(io_index, NREQUESTS);

	spinlock_t lock;
	// Keep a list of all active requests
	struct reqhandle requests[NREQUESTS];
#define PXDMM_DEV_OPEN (0x1)
	unsigned long flags;

	// will be valid only if open
	struct inode *inode;
	struct task_struct *task;
	loff_t vm_start;
	loff_t vm_end;

	// memory maps
	void *base;
	struct pxdmm_mbox *mbox;
	struct pxdmm_cmdresp *cmdQ;
	struct pxdmm_cmdresp *respQ;
	struct pxd_dev_id *devList;
	void *dataWindow;

	uint64_t mboxLength;
	uint64_t cmdQLength;
	uint64_t respQLength;
	uint64_t devListLength;
	uint64_t dataWindowLength;

	uint64_t totalWindowLength;

	wait_queue_head_t waitQ;
	struct task_struct *thread;

	wait_queue_head_t serializeQ;
	atomic_t active;

	unsigned long ndevices;
	unsigned long magictail;
};

static inline
bool sanitycheck(struct pxdmm_dev *udev) {
	return (udev &&
			udev->magichead == MAGICHEAD &&
			udev->magictail == MAGICTAIL);
}

static inline
struct reqhandle* getRequestHandle(struct pxdmm_dev* udev, int dbi) {
	BUG_ON(dbi >= NREQUESTS);

	return &udev->requests[dbi];
}

static inline
void pxdmm_init_cmdresp(struct pxdmm_cmdresp *c,
		uint32_t minor,
		uint32_t cmd,
		uint32_t cmd_flags,
		int hasdata,
		unsigned long dev_id,
		loff_t offset,
		loff_t length,
		uint32_t status,
		uintptr_t dev,
		uint32_t io_index) {
	c->minor = minor;
	c->cmd = cmd;
	c->cmd_flags = cmd_flags;
	c->hasdata = hasdata;
	c->dev_id = dev_id;
	c->offset = offset;
	c->length = length;
	c->status = status;
	c->dev = dev;
	c->io_index = io_index;
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
	uint32_t dbi;

	//int mi = pxdmm_find_mem_index(vmf->vma);
	int mi = pxdmm_find_mem_index(vma);
	if (mi < 0)
		return VM_FAULT_SIGBUS;

	printk("vmf: pxdmm_vma_fault [vma pgoff %ld] pgoff: %#lx/%#lx fault addr:%p [%lx:%lx]\n",
			vma->vm_pgoff, vmf->pgoff, vmf->max_pgoff, vmf->virtual_address, vma->vm_start, vma->vm_end);

	offset = (vmf->pgoff - mi) << PAGE_SHIFT;
	if (offset < CMDR_SIZE) {
		addr = (void*) (unsigned long)info->mem[mi].addr + offset;
		page = vmalloc_to_page(addr);
		printk("vmf: cmd register window fault.. base %p, offset %lx, vaddr %p page %p\n",
				(void*) info->mem[mi].addr, offset, addr, page);
	} else {
		dbi = (offset - CMDR_SIZE) / MAXDATASIZE;
		// find the request that has data buffer index
		handle = getRequestHandle(udev, dbi);

		printk("vmf: in data region... dbi %u, handle %p, flags %#lx, bio %p\n",
				dbi, handle, (handle ? handle->flags : -1), (handle ? handle->bio : NULL));

#ifdef DBGMODE
{
		if (dbi & 1) {
			/* odd page map bpage */
			page = bpage;
		} else {
			/* even page map apage */
			page = apage;
		}
}
#else
{
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


		if (!handle || !(handle->flags & PXDMM_REQUEST_ACTIVE)) return VM_FAULT_SIGBUS;

		breq = handle->bio;

		if (!bio_has_data(breq)) return VM_FAULT_SIGBUS;

		// then map all the bio pages into the 1MB data window.
		// Fetch all the mapped BIO for this request.
		bufferOffset = offset - CMDR_SIZE - (dbi * MAXDATASIZE);
		currOffset = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
		bio_for_each_segment(bvec, breq, bvec_iter) {
			unsigned int pageSize = roundup(bvec.bv_len + bvec.bv_offset, PAGE_SIZE);
			if (bufferOffset >= currOffset && bufferOffset < (currOffset + pageSize)) {
				page = bvec.bv_page;
				break;
			}

			currOffset += pageSize;
		}
#else
		bio_for_each_segment(bvec, breq, bvec_iter) {
			unsigned int pageSize = roundup(bvec->bv_len + bvec->bv_offset, PAGE_SIZE);
			if (bufferOffset >= currOffset && bufferOffset < (currOffset + pageSize)) {
				page = bvec->bv_page;
				break;
			}

			currOffset += pageSize;
		}
#endif
}
#endif /* DBGMODE */
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

static void pxdmm_map(struct pxdmm_dev* udev, struct vm_area_struct *,int dbi);
static void pxdmm_unmap(struct pxdmm_dev* udev, int dbi, bool hasdata);

static
int uio_mmap(struct uio_info* info, struct vm_area_struct  *vma) {
	struct pxdmm_dev *udev = container_of(info, struct pxdmm_dev, info);

	printk("uio_mmap called for address space %p [%#lx, %#lx]\n",
			vma->vm_mm, vma->vm_start, vma->vm_end);
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP | VM_MIXEDMAP;
	vma->vm_ops = &pxdmm_vma_ops;

	vma->vm_private_data = udev;
	udev->vm_start = vma->vm_start;
	udev->vm_end = vma->vm_end;

	/* Ensure the mmap is exactly the right size */
	if (vma_pages(vma) != (udev->totalWindowLength >> PAGE_SHIFT))
		return -EINVAL;

#if 0
	printk("mapping dbi 0\n");
	pxdmm_map(udev, vma, 0);
	printk("mapping dbi 1\n");
	pxdmm_map(udev, vma, 1);
#endif

	return 0;
}

static
int uio_open(struct uio_info* info, struct inode *inode) {
	struct pxdmm_dev *udev = container_of(info, struct pxdmm_dev, info);

	printk("uio_open called for inode %p\n", inode);
	/* O_EXCL not supported for char devs, so fake it? */
	if (test_and_set_bit(PXDMM_DEV_OPEN, &udev->flags))
		return -EBUSY;

	printk("uio_open called for inode %p -- passed excl check\n", inode);
	udev->inode = inode;
	udev->task = current;

	pr_debug("open\n");

	return 0;
}

static
int uio_release(struct uio_info* info, struct inode *inode) {
	struct pxdmm_dev *udev = container_of(info, struct pxdmm_dev, info);

	printk("uio_release called for inode %p\n", inode);
	clear_bit(PXDMM_DEV_OPEN, &udev->flags);
	udev->task = NULL;
	udev->inode = NULL;

	pr_debug("close\n");
	return 0;
}

static
int uio_irqcontrol(struct uio_info *info, s32 irq_on) {
	printk("uio_irqcontrol called\n");
	return 0;
}

/* for data buffer */
/* map and unmap pages from bio within the inode address mapping */

static
int pxdmm_map_bio(struct pxdmm_dev *udev, uint32_t io_index, struct bio* bio, unsigned long *csum) {
	struct mm_struct *mm;
	loff_t offset = pxdmm_dataoffset(io_index) + udev->vm_start;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif
	struct vm_area_struct *vma;
	int err;
	unsigned long checksum = *csum;

	if (!udev || !udev->task) {
		printk("No user process to handle IO\n");
		return -EIO;
	}

	mm = udev->task->mm;
	printk("Inside pxdmm_map_bio(dev %p,io_index: %u, bio %p/%d segments)\n",
			udev, io_index, bio, bio_segments(bio));
	if (!bio_has_data(bio)) return 0;

	vma = find_vma(mm, offset);
	if (!vma) {
		return -EINVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	bio_for_each_segment(bvec, bio, i) {
		struct page *pg = bvec.bv_page;
		loff_t length = roundup(bvec.bv_len, PAGE_SIZE);

		BUG_ON(bvec.bv_offset || length != bvec.bv_len);

		printk("for bio: %p, vm_insert_page(vma=%p, offset=%p, pg=[%p,off=%u,len=%u], len=%llu)\n",
				bio, vma, (void*) offset, pg, bvec.bv_offset, bvec.bv_len, length);
		err = vm_insert_page(vma, offset, pg);
		if (err) {
			printk("vm_insert_page(vma=%p[%#lx:%#lx], offset=%p, page=%p) failed with error: %d\n",
				vma, vma->vm_start, vma->vm_end, (void*) offset, pg, err);
			return err;
		}
		offset += length;
		if (bio_data_dir(bio) == WRITE) {
			void *buff = kmap_atomic(pg);
			checksum = compute_checksum(checksum, buff, bvec.bv_len);
			kunmap_atomic(buff);
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
			flush_dcache_page(pg);
#endif
		} else {
			void *buff = kmap_atomic(pg);
			__fillpage(buff, length);
			checksum = compute_checksum(checksum, buff, bvec.bv_len);
			kunmap_atomic(buff);
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
			flush_dcache_page(pg);
#endif
		}
	}
#else
	bio_for_each_segment(bvec, bio, i) {
		struct page *pg = bvec->bv_page;
		loff_t length = roundup(bvec->bv_len, PAGE_SIZE);

		BUG_ON(bvec->bv_offset || length != bvec->bv_len);

		printk("for bio2: %p, vm_insert_page(vma=%p, offset=%p, pg=[%p,off=%u,len=%u], len=%llu)\n",
				bio, vma, (void*) offset, pg, bvec.bv_offset, bvec.bv_len, length);
		err = vm_insert_page(vma, offset, pg);
		if (err) {
			printk("vm_insert_page(vma=%p[%#lx:%#lx], offset=%p, page=%p) failed with error: %d\n",
				vma, vma->vm_start, vma->vm_end, (void*) offset, pg, err);
			return err;
		}
		offset += length;
		if (bio_data_dir(bio) == WRITE) {
			void *buff = kmap_atomic(pg);
			checksum = compute_checksum(checksum, buff, bvec->bv_len);
			kunmap_atomic(buff);
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
			flush_dcache_page(pg);
#endif
		} else {
			void *buff = kmap_atomic(pg);
			__fillpage(buff, length);
			checksum = compute_checksum(checksum, buff, bvec->bv_len);
			kunmap_atomic(buff);
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
			flush_dcache_page(pg);
#endif
		}
	}
#endif

	*csum = checksum;

	return 0;
}

/* map/unmap logic ends */

/* parent device */
static struct device *pxdmm_root_dev;

#if 0
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
const struct file_operations ctldev_fops = {
    .owner      = THIS_MODULE,
    .llseek     = no_llseek,
    .read       = do_sync_read,
    .aio_read   = fuse_dev_read,
    .splice_read    = fuse_dev_splice_read,
    .write      = do_sync_write,
    .aio_write  = fuse_dev_write,
    .splice_write   = fuse_dev_splice_write,
    .poll       = fuse_dev_poll,
    .release    = fuse_dev_release,
    .fasync     = fuse_dev_fasync,
};
#else
const struct file_operations ctldev_fops = {
    .owner      = THIS_MODULE,
    .llseek     = no_llseek,
    .read_iter  = fuse_dev_read_iter,
    .splice_read    = fuse_dev_splice_read,
    .write_iter = fuse_dev_write_iter,
    .splice_write   = fuse_dev_splice_write,
    .poll       = fuse_dev_poll,
    .release    = fuse_dev_release,
    .fasync     = fuse_dev_fasync,
};
#endif
#endif

const struct file_operations ctldev_fops = {
	.owner = THIS_MODULE,
};

static struct miscdevice ctldev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "pxdmm-control",
};

static struct pxdmm_dev *udev;

static
void pxdmm_unmap(struct pxdmm_dev* udev, int dbi, bool hasdata) {
	loff_t offset;
	struct address_space *as = udev->inode->i_mapping;
	const uint32_t dataBufferLength = MAXDATASIZE;

	if (!hasdata) {
		return;
	}
	offset = pxdmm_dataoffset(dbi);
	printk("pxdmm_unmap: unmapping dbi %d, offset %llu\n",
			dbi, offset);

    unmap_mapping_range(as, offset, dataBufferLength, 1);
}

static void pxdmm_map(struct pxdmm_dev* udev, struct vm_area_struct *vma, int dbi) {
	struct mm_struct *mm;
	loff_t offset;
	int err;
	struct page* page;

	if (!udev || !udev->task) {
		printk("No user process to handle IO\n");
		return;
	}

	mm = udev->task->mm;
	offset = pxdmm_dataoffset(dbi) + udev->vm_start;
	printk("Finding vma at offset %#llx for vm_start: %#llx:%#llx, dbi %d\n",
			offset, udev->vm_start, udev->vm_end, dbi);
	if (!vma) vma = find_vma(mm, offset);
	if (!vma) {
		printk("Cannot find vma for process %s\n", udev->task->comm);
		return;
	}
	printk("pxdmm_map: found vma %#lx, %#lx\n", vma->vm_start, vma->vm_end);

	if (dbi & 1) {
		page = bpage;
	} else {
		page = apage;
	}

	fillpage(page);

	err = vm_insert_page(vma, offset, page);
	if (err) {
		printk("vm_insert_page(vma=%p[%#lx:%#lx], offset=%#llx, page=%p) failed with error: %d\n",
				vma, vma->vm_start, vma->vm_end, offset, apage, err);
		return;
	}
}


static inline
struct pxdmm_dev* to_pxdmm_dev(struct uio_info *info) {
	return container_of(info, struct pxdmm_dev, info);
}

static ssize_t pxdmm_do_unmap(struct device *dev,
                     struct device_attribute *attr, const char *buf, size_t count)
{
	long dbi;
	kstrtol(buf, 0, &dbi);
	pxdmm_unmap(udev, (int) dbi, true);

	printk("pxdmm unmapped for dbi %d\n", (int) dbi);
	return count;
}

static ssize_t pxdmm_do_map(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count) {
	long dbi;
	kstrtol(buf, 0, &dbi);

	pxdmm_map(udev, NULL, (int) dbi);

	printk("pxdmm mapped for dbi %d\n", (int) dbi);

	return count;
}

static DEVICE_ATTR(map, S_IRUGO|S_IWUSR, NULL, pxdmm_do_map);
static DEVICE_ATTR(unmap, S_IRUGO|S_IWUSR, NULL, pxdmm_do_unmap);

static struct attribute *pxdmm_attrs[] = {
	&dev_attr_map.attr,
	&dev_attr_unmap.attr,
	NULL
};

static struct attribute_group pxdmm_attr_group = {
	.attrs = pxdmm_attrs,
};

static const struct attribute_group *pxdmm_attr_groups[] = {
	&pxdmm_attr_group,
	NULL
};

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

	udev->devList = udev->base + offset;
	udev->devListLength = NMAXDEVICES * sizeof(struct pxd_dev_id);
	offset += roundup(udev->devListLength, PAGE_SIZE);

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

	pxdmm_mbox_init(udev->mbox,
			(uint64_t) NREQUESTS,
			(uint64_t) ((uintptr_t) udev->cmdQ - (uintptr_t) udev->base),
			(uint64_t) ((uintptr_t) udev->respQ - (uintptr_t) udev->base),
			(uint64_t) ((uintptr_t) udev->devList - (uintptr_t) udev->base),
			(uint64_t) CMDR_SIZE);

	pxdmm_mbox_dump(udev->mbox);

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

	pxdmm_root_dev = root_device_register("pxdmm");
	if (err) {
		pxdmm_exit();
		return err;
	}

	ctldev.fops = &ctldev_fops;
	ctldev.parent = pxdmm_root_dev;
	ctldev.groups = pxdmm_attr_groups;
	err = misc_register(&ctldev);
	if (err) {
		pxdmm_exit();
		return err;
	}

	err = uio_register_device(ctldev.this_device, &udev->info);
	if (err) {
		pxdmm_exit();
		return err;
	}

	spin_lock_init(&udev->lock);
	init_waitqueue_head(&udev->waitQ);
	init_waitqueue_head(&udev->serializeQ);

	udev->thread = kthread_create(pxdmm_queue_completer, udev, "pxdmm");
	if (IS_ERR(udev->thread)) {
		pxd_printk("Init kthread for pxdmm failed %lu\n",
			PTR_ERR(udev->thread));
		pxdmm_exit();
		return PTR_ERR(udev->thread);
	}

	// initialize magic for sanity.
	udev->magichead = MAGICHEAD;
	udev->magictail = MAGICTAIL;

	wake_up_process(udev->thread);
	return 0;
}

int pxdmm_init(void) {
	int err;

	err = pxdmm_dev_init();
	if (err) {
		return err;
	}

	apage = alloc_pages(GFP_KERNEL, get_order(PAGE_SIZE));
	bpage = alloc_pages(GFP_KERNEL, get_order(PAGE_SIZE));

	printk("Allocated apage %p, bpage %p\n", apage, bpage);
	return 0;
}


void pxdmm_exit(void) {
	kthread_stop(udev->thread);

	printk("Freeing apage %p, bpage %p\n", apage, bpage);
	__free_pages(apage, get_order(PAGE_SIZE));
	__free_pages(bpage, get_order(PAGE_SIZE));

	uio_unregister_device(&udev->info);

	misc_deregister(&ctldev);
	root_device_unregister(pxdmm_root_dev);

	printk("Freeing data window @ %p\n", udev->dataWindow);
	// vfree(dataWindow);
	printk("Freeing respQ @ %p\n", udev->respQ);
	printk("Freeing cmdQ @ %p\n", udev->cmdQ);
	printk("Freeing mbox @ %p\n", udev->mbox);
	vfree(udev->base);
	kfree(udev);
}

static
int __pxdmm_add_request(struct pxd_device *pxd_dev,
		struct request_queue *q, struct bio *bio) {

	struct pxdmm_dev *udev = pxd_dev->mmdev;
	int next_idx;
	VOLATILE struct pxdmm_cmdresp *cmd;
	unsigned long f;
	struct reqhandle *handle;
	int err;

	if (!udev || !sanitycheck(udev)) {
		printk("No mm dev (or sanity check failed) %p initialized for pxd_dev\n", udev);
		return -EINVAL;
	}

	//  lock mbox access and get next index
	spin_lock_irqsave(&udev->lock, f);
	while (cmdQFull(udev->mbox) || bitmap_full(udev->io_index, NREQUESTS)) {
		printk("Hit congestion... wait until free cmdQ Head:Tail %llu:%llu, bm full %d [%#lx]\n",
				udev->mbox->cmdHead, udev->mbox->cmdTail,
				bitmap_full(udev->io_index, NREQUESTS),
				udev->io_index[0]);
		spin_unlock_irqrestore(&udev->lock, f);
		/* congestion wait */
		wait_event_timeout(udev->serializeQ,
				!cmdQFull(udev->mbox) && !bitmap_full(udev->io_index, NREQUESTS),
				HZ);
		spin_lock_irqsave(&udev->lock, f);
		printk("congestion wakeup... check if free cmdQ Head:Tail %llu:%llu bm full %d [%#lx]\n",
				udev->mbox->cmdHead, udev->mbox->cmdTail,
				bitmap_full(udev->io_index, NREQUESTS),
				udev->io_index[0]);
	}

	//  fill up the cmd structure
	//  increment head and unlock mbox
	cmd = getCmdQHead(udev->mbox);
	printk("cmdQHead %p, mbox %p, cmdOffset %llu, cmd Head:Tail %llu:%llu bitmap %#lx\n",
			cmd, udev->mbox, udev->mbox->cmdOffset, udev->mbox->cmdHead, udev->mbox->cmdTail,
			udev->io_index[0]);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0) || defined(REQ_PREFLUSH)
	cmd->cmd_flags = bio->bi_opf;
	switch (bio_op(bio)) {
	case REQ_OP_WRITE_SAME:
		cmd->cmd = PXD_WRITE_SAME;
		break;
	case REQ_OP_WRITE:
		cmd->cmd = PXD_WRITE;
		if (cmd->cmd_flags & (REQ_FUA|REQ_PREFLUSH)) {
			cmd->cmd_flags = PXD_FLAGS_FLUSH;
		}

		break;
	case REQ_OP_READ:
		cmd->cmd = PXD_READ;
		break;
	case REQ_OP_DISCARD:
		cmd->cmd = PXD_DISCARD;
		break;
	default:
		BUG();
	}
#else
{
	uint32_t flags = bio->bi_rw;
	cmd->cmd_flags = bio->bi_rw;
	switch (flags & (REQ_WRITE | REQ_DISCARD | REQ_WRITE_SAME)) {
	case REQ_WRITE:
	case (REQ_WRITE | REQ_WRITE_SAME):
		if (flags & REQ_WRITE_SAME) {
			cmd->cmd = PXD_WRITE_SAME;
		} else if (flags & (REQ_FUA|REQ_FLUSH)) {
			cmd->cmd = PXD_WRITE;
			cmd->cmd_flags = PXD_FLAGS_FLUSH;
		} else {
			cmd->cmd = PXD_WRITE;
		}
		break;
	case 0:
		cmd->cmd = PXD_READ;
		break;
	case REQ_DISCARD:
	case REQ_WRITE|REQ_DISCARD:
		cmd->cmd = PXD_DISCARD;
		break;
	default:
		BUG();
	}
}
#endif

	cmd->hasdata = bio_has_data(bio);
	cmd->offset = BIO_SECTOR(bio) * SECTOR_SIZE;
	cmd->status = 0;
	cmd->minor = pxd_dev->minor;
	cmd->dev_id = pxd_dev->dev_id;
	cmd->dev = (uintptr_t) udev;
	cmd->checksum = 0;

	cmd->length = compute_bio_rq_size(bio);
	if (bio_has_data(bio) && cmd->length > MAXDATASIZE) {
		printk("Data Size (%lld bytes) greater than maximum (%d bytes)\n",
				cmd->length, MAXDATASIZE);
		err = -E2BIG;
		goto out;
	}

	next_idx = find_first_zero_bit(udev->io_index, NREQUESTS);
	if (next_idx >= NREQUESTS) {
		// This is BUG condition
		BUG();
	}

	bitmap_set(udev->io_index, next_idx, 1);
	cmd->io_index = next_idx;

	// Find the io_index and initialize request handle for this
	// new outstanding request.
	handle = getRequestHandle(udev, cmd->io_index);
	handle->bio = bio;
	handle->queue = q;
	handle->starttime = jiffies;

	if (handle->flags) {
		printk(KERN_ERR"Request handle flags has unexpected active state set index %u, (%#lx)\n",
				cmd->io_index, handle->flags);
		BUG();
	}

	handle->flags = PXDMM_REQUEST_ACTIVE;

	// fill in the data mapping
	err = pxdmm_map_bio(udev, cmd->io_index, bio, &cmd->checksum);
	if (err) {
		printk("Mapping BIO has failed on index %u, error %d\n",
				cmd->io_index, err);
		handle->flags = 0;
		bitmap_clear(udev->io_index, cmd->io_index, 1);
		goto out;
	}

	// ensure handle magics are set
	handle->magichead = MAGICHEAD;
	handle->magictail = MAGICTAIL;

	pxdmm_cmdresp_dump("add request:", cmd);
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
	flush_dcache_page(vmalloc_to_page(cmd));
#endif
	incrCmdQHead(udev->mbox);

out:
	if (!err) atomic_inc(&udev->active);
	spin_unlock_irqrestore(&udev->lock, f);

	return err;
}

int pxdmm_add_request(struct pxd_device *pxd_dev,
		struct request_queue *q, struct bio *bio) {

	struct pxdmm_dev *udev = pxd_dev->mmdev;
	int err;

	if (!udev) {
		BIO_ENDIO(bio, -EIO);
		return -EIO;
	}

	err = __pxdmm_add_request(pxd_dev, q, bio);
	if (err) {
		/* failed submission */
		printk("Failed submission for a new request bio %p, status %d\n", bio, err);
		BIO_ENDIO(bio, err);
	}
	return err;
}

struct bio* __pxdmm_complete_request(VOLATILE struct pxdmm_cmdresp* resp, int *status) {
	struct pxdmm_dev *udev = (struct pxdmm_dev*) resp->dev;
	unsigned long f;
	struct reqhandle *handle;
	struct bio *bio = NULL;

	pxdmm_cmdresp_dump("got response:", resp);

	if (!udev) {
		printk("pxdmm null device part of response..%p \n", resp);
		return NULL;
	}

	if (!sanitycheck(udev)) {
		printk("pxdmm device sanity checks failed..headmagic:%#lx, tailmagic:%#lx\n",
				udev->magichead, udev->magictail);
		return NULL;
	}

	handle = getRequestHandle(udev, resp->io_index);
	// sanitize context.
	if (!sanitize(handle)) {
		printk("Detected handle corruption...index %u, head %#lx, tail %#lx\n",
				resp->io_index, handle->magichead, handle->magictail);
		//BUG();
		return NULL;
	}

	// BUG condition
	if (!(handle->flags & PXDMM_REQUEST_ACTIVE)) {
		printk(KERN_ERR"pxdmm response handling for index %u not active (flags: %#lx)\n",
				resp->io_index, handle->flags);
		goto out;
	}

	// unmap the data buffer from window
	pxdmm_unmap(udev, resp->io_index, bio_has_data(handle->bio));

	/* bio already completed... free up handle and return NULL */
	if (!(handle->flags & PXDMM_REQUEST_TIMEDOUT)) {
		bio = handle->bio;
	}

	*status = resp->status;
out:
	handle->flags = 0;
	handle->magichead = handle->magictail = ~0UL;
	// free up the io index
	spin_lock_irqsave(&udev->lock, f);
	bitmap_clear(udev->io_index, resp->io_index, 1);
	atomic_dec(&udev->active);
	spin_unlock_irqrestore(&udev->lock, f);

	wake_up(&udev->serializeQ);

	return bio;
}

int pxdmm_complete_request (struct pxdmm_dev *udev) {
	struct pxdmm_cmdresp top;
	int status;
	struct bio *bio;

	if (!sanitycheck(udev)) {
		printk("pxdmm_dev %p sanity check failed\n", udev);
		return -EINVAL;
	}

	while (!respQEmpty(udev->mbox)) {
		VOLATILE struct pxdmm_cmdresp *resp = getRespQTail(udev->mbox);
#if defined(__KERNEL__) && defined(SHOULDFLUSH)
		flush_dcache_page(vmalloc_to_page(resp));
#endif
		memcpy(&top, (struct pxdmm_cmdresp*) resp, sizeof(top));
		// increment response tail.
		printk("[%d] respQTail %p, mbox %p, respOffset %llu, resp Head/Tail %llu:%llu bitmap[%#lx]\n",
			atomic_read(&udev->active), resp, udev->mbox,
			udev->mbox->respOffset, udev->mbox->respHead, udev->mbox->respTail,
			udev->io_index[0]);

		incrRespQTail(udev->mbox);

		bio = __pxdmm_complete_request(&top, &status);
		printk("completing[%u]: cmd %d, BIO %p with status %u\n",
					atomic_read(&udev->active), top.cmd, bio, status);
		if (bio) {
			BIO_ENDIO(bio, status);
		}
	}

	return 0;
}

int pxdmm_devlist_add(struct pxdmm_dev *udev, struct pxd_device *pxd_dev) {
	struct pxd_dev_id *base = getDeviceListBase(udev->mbox);
	unsigned long currVer = udev->mbox->devVersion;
	unsigned long currCsum = udev->mbox->devChecksum;
	struct pxd_dev_id *newdevice;

	if (udev->ndevices >= NMAXDEVICES) {
		return -ENOSPC;
	}

	LOCK_DEVWINDOW(udev->mbox);

	if (udev->ndevices) {
		unsigned long csum;
		csum = compute_checksum(0, base, sizeof(struct pxd_dev_id) * udev->ndevices);
		BUG_ON(csum != currCsum);
	}

	newdevice = &base[udev->ndevices];
	memset(newdevice, 0, sizeof(*newdevice));

	newdevice->local_minor = pxd_dev->minor;
	newdevice->dev_id = pxd_dev->dev_id;
	newdevice->size = pxd_dev->size;

	udev->ndevices++;
	udev->mbox->devChecksum = compute_checksum(0, base, sizeof(struct pxd_dev_id) * udev->ndevices);
	udev->mbox->ndevices = udev->ndevices;

	UNLOCK_DEVWINDOW(udev->mbox, currVer+1);
	return 0;
}

int pxdmm_devlist_remove(struct pxdmm_dev *udev, struct pxd_device *pxd_dev) {
	struct pxd_dev_id *base = getDeviceListBase(udev->mbox);
	const int maxSize = NMAXDEVICES * sizeof(struct pxd_dev_id);
	unsigned long currVer = udev->mbox->devVersion;
	unsigned long currCsum = udev->mbox->devChecksum;

	struct pxd_dev_id *tmp, *dst, *scratch;
	bool found = false;
	int i;

	dst = scratch = (struct pxd_dev_id*) kzalloc(GFP_KERNEL, maxSize);
	if (!scratch) {
		return -ENOMEM;
	}

	LOCK_DEVWINDOW(udev->mbox);

	if (udev->ndevices) {
		unsigned long csum;
		csum = compute_checksum(0, base, sizeof(struct pxd_dev_id) * udev->ndevices);
		BUG_ON(csum != currCsum);
	}

	for (i=0; i<udev->ndevices; i++) {
		tmp = &base[i];

		if (!found && tmp->local_minor == pxd_dev->minor &&
				tmp->dev_id == pxd_dev->dev_id) {
			/* found the item to be deleted */
			found = true;
			continue;
		}
		memcpy(dst, tmp, sizeof(*tmp));
		dst++;
	}

	if (found) {
		udev->ndevices--;
		if (udev->ndevices) {
			memcpy(base, scratch, sizeof(struct pxd_dev_id) * udev->ndevices);
			udev->mbox->devChecksum =
				compute_checksum(0, base, sizeof(struct pxd_dev_id) * udev->ndevices);
		} else {
			udev->mbox->devChecksum = 0;
		}
		udev->mbox->ndevices = udev->ndevices;
		UNLOCK_DEVWINDOW(udev->mbox, currVer+1);
	} else {
		UNLOCK_DEVWINDOW(udev->mbox, currVer);
	}
	kfree(scratch);
	return 0;
}


int pxdmm_init_dev(struct pxd_device *pxd_dev){
	// assign global pxdmm_dev to all pxd_devices for now
	pxd_dev->mmdev = udev;
	return pxdmm_devlist_add(udev, pxd_dev);
}

int pxdmm_cleanup_dev(struct pxd_device *pxd_dev) {
	return pxdmm_devlist_remove(pxd_dev->mmdev, pxd_dev);
}

static
int pxdmm_queue_completer(void *arg) {
	struct pxdmm_dev *udev = (struct pxdmm_dev *) arg;

	while (!kthread_should_stop()) {
		wait_event_interruptible_timeout(udev->waitQ,
				respQEmpty(udev->mbox) == false || kthread_should_stop(),
				HZ/1000); // once every millisec

		if (pxdmm_complete_request(udev)) {
			printk("pxdmm_queue_completer() failed.. exiting thread\n");
			break;
		}
	}

	printk("pxdmm_queue_completer exiting..\n");
	return 0;
}
