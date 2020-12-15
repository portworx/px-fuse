#ifndef _PXCC_H_
#define _PXCC_H_

#include "pxlib.h"

enum { CACHE_SUBMITTED, // IO submitted to cache
       REMAP_TO_ORIGIN, // submit IO to origin
};

#define NR_HOTSPOT_LEVELS 64u
#define NR_CACHE_LEVELS 64u

#define WRITEBACK_PERIOD (10ul * HZ)
#define DEMOTE_PERIOD (60ul * HZ)

#define HOTSPOT_UPDATE_PERIOD (HZ)
#define CACHE_UPDATE_PERIOD (60ul * HZ)

typedef uint32_t pxcc_block_t;

struct background_tracker;

enum { CMODE_PASSTHROUGH,
       CMODE_WRITETHROUGH,
       CMODE_WRITEBACK_LRU,
       CMODE_WRITEBACK_WRITEPREFER,
};

struct pxcc_c {
        struct block_device *cdev;
        sector_t realm_start;
        sector_t realm_end;
        uint32_t realm_sectors;
        uint32_t cdev_logical_block_size;

        int cmode; // one of CMODE_xxx above

#define DEFAULT_CACHE_BLOCK_SIZE (1U << 20)
        uint32_t cache_blk_size;
        uint32_t cache_blk_sectors;
        uint32_t cache_blk_shift;

        uint64_t origin_device_size;
        uint32_t origin_sectors;
        uint32_t origin_blocks;

        // work only in blocks... sanitize with boundary regions before passing
        // to other layers.

        // reserved sectors.
#define MIN_RESERVED_SECTORS (16)
        sector_t nreserved;        // so many reserved from the begin of realm.
        sector_t sb_start, sb_len; // relative to realm start
        sector_t md_start, md_len; // relative to realm start

        // cache data blocks
        pxcc_block_t nblocks;
        sector_t cdata_start, cdata_len; // relative to realm start

        // hotspot config
        sector_t hotspot_block_size;
        unsigned nr_hotspot_blocks;
        unsigned cache_blocks_per_hotspot_block;
        unsigned hotspot_level_jump;

        struct entry_space es;
        struct entry_alloc writeback_sentinel_alloc;
        struct entry_alloc demote_sentinel_alloc;
        struct entry_alloc hotspot_alloc;
        struct entry_alloc cache_alloc;

        unsigned long *hotspot_hit_bits;
        unsigned long *cache_hit_bits;

        struct lqueue hotspot;
        struct lqueue clean;
        struct lqueue dirty;

        struct smq_hash_table lookup_table;
        struct smq_hash_table hotspot_table;

        unsigned write_promote_level, read_promote_level;
        uint64_t next_hotspot_period, next_cache_period;

        bool current_writeback_sentinels, current_demote_sentinels;
        unsigned long next_writeback_period, next_demote_period;

        struct stats hotspot_stats;
        struct stats cache_stats;

        struct background_tracker *bt_work;

        // periodic background op
        struct workqueue_struct *wq;
        struct delayed_work waker;
        struct bio_prison_v2 *prison;
};

void pxcc_debug_dump(struct pxcc_c *cc);

// cache_blk_size [0=auto, any other value use as is, should be atleast
// logical_blk_size), do we need origin_size?
struct pxcc_c *pxcc_init(struct block_device *cdev, sector_t start,
                         uint32_t nsectors, uint32_t cache_blk_size,
                         uint64_t origin_size, int cmode);
int pxcc_exit(struct pxcc_c *cc);

#endif /* _PXCC_H_ */
