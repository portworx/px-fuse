#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/hash.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/math64.h>
#include <linux/bitmap.h>
#include <linux/blk_types.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "pxtgt_core.h"
#include "pxlib.h"
#include "pxmgr.h"
#include "pxcc.h"

void pxcc_debug_dump(struct pxcc_c *cc)
{
	printk("cache context: cdev %p, realm [start: %lu, end: %lu, nsectors: %u] logical block size %u\n",
			cc->cdev, cc->realm_start, cc->realm_end, cc->realm_sectors, cc->cdev_logical_block_size);
	printk("cache block size: %u, sectors: %u\n", cc->cache_blk_size, cc->cache_blk_sectors);
	printk("cache reserved: %lu sectors, sb [start: %lu, len %lu], md [start: %lu, len %lu]\n",
		cc->nreserved, cc->sb_start, cc->sb_len, cc->md_start, cc->md_len);
	printk("cache blocks: nblocks %u, cdata [start: %lu, len %lu]\n", cc->nblocks, cc->cdata_start, cc->cdata_len);
}

// cache_blk_size [0=auto, any other value use as is, should be atleast logical_blk_size),
// do we need origin_size?
struct pxcc_c* pxcc_init(struct block_device *cdev, sector_t start, uint32_t nsectors,
		uint32_t cache_blk_size, uint64_t origin_size)
{
	struct pxcc_c *cc;

	if (!cdev) {
		return ERR_PTR(-EINVAL);
	}

	cc = kzalloc(sizeof(struct pxcc_c), GFP_KERNEL);
	if (!cc) {
		return ERR_PTR(-ENOMEM);
	}

	// cache device properties
	cc->cdev = cdev;
	cc->realm_start = start;
	cc->realm_sectors = nsectors;
	cc->realm_end = start + nsectors;
	cc->cdev_logical_block_size = 4096;
	if (cdev->bd_disk != NULL && cdev->bd_disk->queue != NULL) {
		cc->cdev_logical_block_size = queue_logical_block_size(cdev->bd_disk->queue);
	}

	cc->origin_device_size = origin_size; // is this needed?

	cc->sb_start = 0;
	cc->sb_len = 8;
	cc->md_start = 8;
	cc->md_len = 8;
	cc->nreserved = MIN_RESERVED_SECTORS;

	if (!cache_blk_size) {
		cc->cache_blk_size = DEFAULT_CACHE_BLOCK_SIZE;
	} else {
		cc->cache_blk_size = cache_blk_size;
	}
	// ensure cache block size is a multiple of logical block size.
	cc->cache_blk_size = pow2_roundup(cc->cache_blk_size, cc->cdev_logical_block_size);
	cc->cache_blk_sectors = cc->cache_blk_size >> SECTOR_SHIFT;

	cc->cdata_len = cc->realm_sectors - MIN_RESERVED_SECTORS;
	cc->nblocks = safe_div(cc->cdata_len, cc->cache_blk_sectors);
	cc->cdata_len = cc->nblocks * cc->cache_blk_sectors;
	cc->cdata_start = cc->realm_sectors - cc->cdata_len;

	// adjust reserved sectors for alignment
	cc->nreserved = cc->cdata_start;

	pxcc_debug_dump(cc);
	return cc;
}


int pxcc_exit(struct pxcc_c *cc)
{
	kfree(cc);
	return 0;
}
