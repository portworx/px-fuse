#ifndef _PXCC_H_
#define _PXCC_H_

typedef uint32_t pxcc_block_t;

struct pxcc_c {
	struct block_device *cdev;
	sector_t realm_start;
	sector_t realm_end;
	uint32_t realm_sectors;
	uint32_t cdev_logical_block_size;

#define DEFAULT_CACHE_BLOCK_SIZE  (1U << 20)
	uint32_t cache_blk_size;
	uint32_t cache_blk_sectors;
	uint64_t origin_device_size;

	// work only in blocks... sanitize with boundary regions before passing to other layers.

	// reserved sectors.
#define MIN_RESERVED_SECTORS (16)
	sector_t nreserved; // so many reserved from the begin of realm.
	sector_t sb_start, sb_len; // relative to realm start
	sector_t md_start, md_len; // relative to realm start

	// cache data blocks
	pxcc_block_t nblocks;
	sector_t cdata_start, cdata_len; // relative to realm start
};

void pxcc_debug_dump(struct pxcc_c *cc);

// cache_blk_size [0=auto, any other value use as is, should be atleast logical_blk_size),
// do we need origin_size?
struct pxcc_c* pxcc_init(struct block_device *cdev, sector_t start, uint32_t nsectors,
		uint32_t cache_blk_size, uint64_t origin_size);
int pxcc_exit(struct pxcc_c *cc);

#endif /* _PXCC_H_ */
