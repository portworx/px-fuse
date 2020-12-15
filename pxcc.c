#include <linux/bitmap.h>
#include <linux/blk_types.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include "background-tracker.h"
#include "bio-prison-v2.h"
#include "pxcc.h"
#include "pxlib.h"
#include "pxmgr.h"
#include "pxtgt_core.h"

#define CDEV_LOGICAL_BLOCK_SIZE (4096)

void pxcc_debug_dump(struct pxcc_c *cc) {
        printk("cache context: cdev %p, realm [start: %lu, end: %lu, nsectors: "
               "%u] logical block size %u mode %u\n",
               cc->cdev, cc->realm_start, cc->realm_end, cc->realm_sectors,
               cc->cdev_logical_block_size, cc->cmode);
        printk("cache origin: size %llu, blocks %u\n", cc->origin_device_size,
               cc->origin_sectors);
        printk("cache block size: %u, sectors: %u, shift: %u\n",
               cc->cache_blk_size, cc->cache_blk_sectors, cc->cache_blk_shift);
        printk(
            "cache reserved: %lu sectors, sb [start: %lu, len %lu], md [start: "
            "%lu, len %lu]\n",
            cc->nreserved, cc->sb_start, cc->sb_len, cc->md_start, cc->md_len);
        printk("cache blocks: nblocks %u, cdata [start: %lu, len %lu]\n",
               cc->nblocks, cc->cdata_start, cc->cdata_len);
}

static struct entry *get_sentinel(struct entry_alloc *ea, unsigned level,
                                  bool which) {
        return get_entry(ea, which ? level : NR_CACHE_LEVELS + level);
}

static struct entry *writeback_sentinel(struct pxcc_c *cc, unsigned level) {
        return get_sentinel(&cc->writeback_sentinel_alloc, level,
                            cc->current_writeback_sentinels);
}

static struct entry *demote_sentinel(struct pxcc_c *cc, unsigned level) {
        return get_sentinel(&cc->demote_sentinel_alloc, level,
                            cc->current_demote_sentinels);
}

static void __update_writeback_sentinels(struct pxcc_c *cc) {
        unsigned level;
        struct lqueue *q = &cc->dirty;
        struct entry *sentinel;

        for (level = 0; level < q->nr_levels; level++) {
                sentinel = writeback_sentinel(cc, level);
                q_del(q, sentinel);
                q_push(q, sentinel);
        }
}

static void __update_demote_sentinels(struct pxcc_c *cc) {
        unsigned level;
        struct lqueue *q = &cc->clean;
        struct entry *sentinel;

        for (level = 0; level < q->nr_levels; level++) {
                sentinel = demote_sentinel(cc, level);
                q_del(q, sentinel);
                q_push(q, sentinel);
        }
}

STATIC
void update_sentinels(struct pxcc_c *cc) {
        if (time_after(jiffies, cc->next_writeback_period)) {
                cc->next_writeback_period = jiffies + WRITEBACK_PERIOD;
                cc->current_writeback_sentinels =
                    !cc->current_writeback_sentinels;
                __update_writeback_sentinels(cc);
        }

        if (time_after(jiffies, cc->next_demote_period)) {
                cc->next_demote_period = jiffies + DEMOTE_PERIOD;
                cc->current_demote_sentinels = !cc->current_demote_sentinels;
                __update_demote_sentinels(cc);
        }
}

static void __sentinels_init(struct pxcc_c *cc) {
        unsigned level;
        struct entry *sentinel;

        for (level = 0; level < NR_CACHE_LEVELS; level++) {
                sentinel = writeback_sentinel(cc, level);
                sentinel->level = level;
                q_push(&cc->dirty, sentinel);

                sentinel = demote_sentinel(cc, level);
                sentinel->level = level;
                q_push(&cc->clean, sentinel);
        }
}

static void sentinels_init(struct pxcc_c *cc) {
        cc->next_writeback_period = jiffies + WRITEBACK_PERIOD;
        cc->next_demote_period = jiffies + DEMOTE_PERIOD;

        cc->current_writeback_sentinels = false;
        cc->current_demote_sentinels = false;
        __sentinels_init(cc);

        cc->current_writeback_sentinels = !cc->current_writeback_sentinels;
        cc->current_demote_sentinels = !cc->current_demote_sentinels;
        __sentinels_init(cc);
}

static bool too_many_hotspot_blocks(sector_t origin_size,
                                    sector_t hotspot_block_size,
                                    unsigned nr_hotspot_blocks) {
        return (hotspot_block_size * nr_hotspot_blocks) > origin_size;
}

static void calc_hotspot_params(sector_t origin_size, sector_t cache_block_size,
                                unsigned nr_cache_blocks,
                                sector_t *hotspot_block_size,
                                unsigned *nr_hotspot_blocks) {
        *hotspot_block_size = cache_block_size * 16u;
        *nr_hotspot_blocks = max(nr_cache_blocks / 4u, 1024u);

        while ((*hotspot_block_size > cache_block_size) &&
               too_many_hotspot_blocks(origin_size, *hotspot_block_size,
                                       *nr_hotspot_blocks))
                *hotspot_block_size /= 2u;
}

STATIC
oblock_t get_bio_block(struct pxcc_c *cc, struct bio *bio) {
        sector_t block_nr = bio->bi_iter.bi_sector;

        block_nr >>= (cc->cache_blk_shift - SECTOR_SHIFT);

        return to_oblock(block_nr);
}

static void periodic_waker(struct work_struct *ws) {}

static void cache_destroy(struct pxcc_c *cc) {
        // TODO Introduce below wq draining logic outside cache destroy
        // cancel_delayed_work_sync(&cache->waker);
        // drain_workqueue(cache->wq);

        if (cc->prison)
                bio_prison_destroy_v2(cc->prison);
        if (cc->wq)
                destroy_workqueue(cc->wq);
        if (cc->bt_work)
                btracker_destroy(cc->bt_work);
        h_exit(&cc->hotspot_table);
        h_exit(&cc->lookup_table);
        if (cc->cache_hit_bits)
                bitmap_free(cc->cache_hit_bits);
        if (cc->hotspot_hit_bits)
                bitmap_free(cc->hotspot_hit_bits);
        space_exit(&cc->es);

        bio_prison_exit_v2();
}

static int cache_create(struct pxcc_c *cc) {
        unsigned i;
        uint64_t cache_size = cc->nblocks;
        uint64_t origin_sectors = cc->origin_sectors;
        uint64_t cache_blk_sectors = cc->cache_blk_sectors;

        unsigned nr_sentinels_per_queue = 2u * NR_CACHE_LEVELS;
        unsigned total_sentinels = 2u * nr_sentinels_per_queue;

        calc_hotspot_params(origin_sectors, cache_blk_sectors, cache_size,
                            &cc->hotspot_block_size, &cc->nr_hotspot_blocks);

        cc->cache_blocks_per_hotspot_block =
            cc->hotspot_block_size >> cc->cache_blk_shift;
        cc->hotspot_level_jump = 1u;

        if (bio_prison_init_v2()) {
                return -ENOMEM;
        }

        if (space_init(&cc->es,
                       total_sentinels + cc->nr_hotspot_blocks + cache_size)) {
                bio_prison_exit_v2();
                return -ENOMEM;
        }

        init_allocator(&cc->writeback_sentinel_alloc, &cc->es, 0,
                       nr_sentinels_per_queue);
        for (i = 0; i < nr_sentinels_per_queue; i++)
                get_entry(&cc->writeback_sentinel_alloc, i)->sentinel = true;

        init_allocator(&cc->demote_sentinel_alloc, &cc->es,
                       nr_sentinels_per_queue, total_sentinels);
        for (i = 0; i < nr_sentinels_per_queue; i++)
                get_entry(&cc->demote_sentinel_alloc, i)->sentinel = true;

        init_allocator(&cc->hotspot_alloc, &cc->es, total_sentinels,
                       total_sentinels + cc->nr_hotspot_blocks);

        init_allocator(&cc->cache_alloc, &cc->es,
                       total_sentinels + cc->nr_hotspot_blocks,
                       total_sentinels + cc->nr_hotspot_blocks + cache_size);

        cc->hotspot_hit_bits = bitmap_zalloc(cc->nr_hotspot_blocks, GFP_KERNEL);
        if (!cc->hotspot_hit_bits) {
                space_exit(&cc->es);
                return -ENOMEM;
        }

        cc->cache_hit_bits = bitmap_zalloc(cc->nblocks, GFP_KERNEL);
        if (!cc->cache_hit_bits) {
                cache_destroy(cc);
                return -ENOMEM;
        }

        q_init(&cc->hotspot, &cc->es, NR_HOTSPOT_LEVELS);
        cc->hotspot.nr_top_levels = 8;
        cc->hotspot.nr_in_top_levels =
            cc->nr_hotspot_blocks / NR_HOTSPOT_LEVELS;

        q_init(&cc->clean, &cc->es, NR_CACHE_LEVELS);
        q_init(&cc->dirty, &cc->es, NR_CACHE_LEVELS);

        if (h_init(&cc->lookup_table, &cc->es, cc->nblocks)) {
                // no memory
                cache_destroy(cc);
                return -ENOMEM;
        }

        if (h_init(&cc->hotspot_table, &cc->es, cc->nr_hotspot_blocks)) {
                // no memory
                cache_destroy(cc);
                return -ENOMEM;
        }

        sentinels_init(cc);
        cc->write_promote_level = cc->read_promote_level = NR_HOTSPOT_LEVELS;

        stats_init(&cc->hotspot_stats, NR_HOTSPOT_LEVELS);
        stats_init(&cc->cache_stats, NR_CACHE_LEVELS);

        // bg work
        cc->bt_work = btracker_create(4096);
        if (IS_ERR_OR_NULL(cc->bt_work)) {
                cache_destroy(cc);
                return -ENOMEM;
        }

        cc->wq = alloc_workqueue("pxcc", WQ_MEM_RECLAIM, 0);
        if (!cc->wq) {
                cache_destroy(cc);
                return -ENOMEM;
        }
        INIT_DELAYED_WORK(&cc->waker, periodic_waker);

        cc->prison = bio_prison_create_v2(cc->wq);
        if (!cc->prison) {
                cache_destroy(cc);
                return -ENOMEM;
        }

        return 0;
}

#if 0
static int cache_map(struct pxcc_c *cc, struct bio *bio)
{
	oblock_t block = get_bio_block(cc, bio);
	bool commit_needed;
	int r;

	if (block >= cc->origin_blocks) {
		// last block maybe... or resized backend... not caching.
		return REMAP_TO_ORIGIN;
	}

	// TODO defered bio handling need to be setup
	if (discard_or_flush(bio)) {
		defer_bio(cc, bio);
		return CACHE_SUBMITTED;
	}


	r = map_bio(cc, bio, block, &commit_needed);
	// TODO persistent meta support not ready yet.
	if (commit_needed)
		schedule_commit(&cc->commiter);

	return r;
}
#endif

// cache_blk_size [0=auto, any other value use as is, should be atleast
// logical_blk_size), do we need origin_size?
struct pxcc_c *pxcc_init(struct block_device *cdev, sector_t start,
                         uint32_t nsectors, uint32_t cache_blk_size,
                         uint64_t origin_size, int cmode) {
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
        cc->cdev_logical_block_size = CDEV_LOGICAL_BLOCK_SIZE;
        if (cdev->bd_disk != NULL && cdev->bd_disk->queue != NULL) {
                cc->cdev_logical_block_size =
                    queue_logical_block_size(cdev->bd_disk->queue);
        }

        cc->origin_device_size = origin_size; // is this needed?
        cc->origin_sectors = cc->origin_device_size >> SECTOR_SHIFT;

        cc->cmode = cmode; // cache mode

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
        cc->cache_blk_size =
            pow2_roundup(cc->cache_blk_size, cc->cdev_logical_block_size);
        cc->cache_blk_sectors = cc->cache_blk_size >> SECTOR_SHIFT;
        cc->cache_blk_shift = __ffs(cc->cache_blk_size);

        cc->cdata_len = cc->realm_sectors - MIN_RESERVED_SECTORS;
        cc->nblocks = safe_div(cc->cdata_len, cc->cache_blk_sectors);
        cc->cdata_len = cc->nblocks * cc->cache_blk_sectors;
        cc->cdata_start = cc->realm_sectors - cc->cdata_len;

        // adjust reserved sectors for alignment
        cc->nreserved = cc->cdata_start;
        cc->origin_blocks = cc->origin_sectors >> cc->cache_blk_sectors;

        // setup for policy
        // writethrough, writecache, writeback, passthrough

        // cache size - count of cache blocks
        // origin size - size of origin in 512byte sectors
        // cache block size - size of cache block size in 512byte sectors
        if (cache_create(cc)) {
                printk("cache initialized failed\n");
                return ERR_PTR(-EINVAL);
        }

        pxcc_debug_dump(cc);
        return cc;
}

int pxcc_exit(struct pxcc_c *cc) {
        cancel_delayed_work_sync(&cc->waker);
        drain_workqueue(cc->wq);
        cache_destroy(cc);
        kfree(cc);
        return 0;
}
