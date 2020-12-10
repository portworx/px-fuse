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

#include "pxtgt.h"
#include "pxtgt_core.h"
#include "pxrealm.h"

#define REALM_SIZE (1ULL << 30) // each realm is 1G
#define MIN_REALM_MAP (1) // 1GB
#define MAX_REALM_MAP (256) // 256GB
#define MIN_ORIGIN_SIZE (REALM_SIZE * 10)

#define MAX_REALM_MAPS (2*PXTGT_MAX_DEVICES)

#define REALM_SB_SIZE (8192) // first 8K (sb, spare etc)

#define PRIMARY_JOURNAL_SIZE REALM_SIZE
#define SECONDARY_JOURNAL_SIZE PRIMARY_JOURNAL_SIZE

#define REALM_OFFSET (3 * REALM_SIZE)

#define PXREALM_ROUND_UP(sz)  (((sz) + REALM_SIZE - 1) & (REALM_SIZE - 1))

typedef unsigned long pxrealm_offset_t;

struct pxrealm_t {
#define MAX_DEVNAME (127)
	char cdevname[MAX_DEVNAME+1];
	uint64_t cdev_size; // in bytes
	uint64_t cdev_sectors;// in 512 byte sectors

	int max_realms;

	unsigned long *realm_inuse_bitmap;
	unsigned long *map_indices;

	int initialized:1;
	struct block_device *cdev;
};

struct pxrealm_map_t {
	pxrealm_index_t id;

	pxrealm_offset_t off;
	int nrealms;

	int inuse:1;

	void *private;
	uint64_t origin_size;
	uint64_t volume_id;
};

static struct pxrealm_t pxrealm;
static struct pxrealm_map_t maps[MAX_REALM_MAPS];

static
void pxrealm_map_dump(struct pxrealm_map_t *m)
{
	printk("%lu: offset %lu nrealms %d inuse %x private %p origin vol %llu size %llu\n",
			m->id, m->off, m->nrealms, m->inuse, m->private, m->volume_id, m->origin_size);
}

void pxrealm_debug_dump(void)
{
	int i;

	printk("global realm: cachedev %s\n\tcdev_size %llu\n\tcdev_sectors %llu\n\t"
			"max_realms %d\n\trealm_inuse_bitmap %p\n\tmap_indices %p\n\t"
			"initialized %d\n\tcdev %p\n",
			pxrealm.cdevname, pxrealm.cdev_size, pxrealm.cdev_sectors,
			pxrealm.max_realms, pxrealm.realm_inuse_bitmap,
			pxrealm.map_indices,
			pxrealm.initialized,
			pxrealm.cdev);

	for (i=0; i<MAX_REALM_MAPS; i++) {
		if (maps[i].inuse) {
			pxrealm_map_dump(&maps[i]);
		}
	}
}

static
struct pxrealm_map_t* pxrealm_map(pxrealm_index_t id)
{
	if (id >= MAX_REALM_MAPS) {
		return NULL;
	}

	return &maps[id];
}


static
int compute_needed_realms(uint64_t size, pxrealm_hint_t hint)
{
	switch (hint) {
	case PXREALM_LARGE:
		// min(MAX_REALM_MAP, 20% of origin)
		size = size/5;
		break;
	case PXREALM_MEDIUM:
		// 15% of origin
		size = size * 15/100;
		break;
	case PXREALM_SMALL:
	default:
		// 10% of origin
		size = size /10;
	}

	printk("%s size %llu, hint %d, nrealms %d\n",
			__func__, size, hint,
			min(MAX_REALM_MAP, (int)safe_div64(size, REALM_SIZE)));

	return min(MAX_REALM_MAP, (int)safe_div64(size, REALM_SIZE));
}

static
uint64_t realm_byte_offset(pxrealm_offset_t off)
{
	return (off * REALM_SIZE);
}

//static
sector_t realm_sector_offset(pxrealm_offset_t off)
{
	return to_sector(realm_byte_offset(off));
}

static 
int pxrealm_assign(struct pxrealm_t *r, struct pxrealm_map_t *map, int nrealms)
{
	unsigned long v;

	v = bitmap_find_next_zero_area_off(r->realm_inuse_bitmap,
			r->max_realms, 0, nrealms, 0, 0);
	if (v >= r->max_realms) {
		return -EBUSY;
	}

	__bitmap_set(r->realm_inuse_bitmap, v, nrealms);

	map->off = v;
	map->nrealms = nrealms;
	map->inuse = 1; // realm mapped
	return 0;
}

static
int pxrealm_dealloc(struct pxrealm_map_t *pmap)
{
	if (!pmap || !pmap->inuse) {
		return -EINVAL;
	}

	pmap->inuse = 0;
	bitmap_clear(pxrealm.realm_inuse_bitmap, pmap->off, pmap->nrealms);
	return 0;
}

pxrealm_index_t pxrealm_alloc(uint64_t volume_id, uint64_t origin_size,
		pxrealm_hint_t hint, void *context)
{
	struct pxrealm_map_t *pmap;
	int nrealms = compute_needed_realms(origin_size, hint);
	pxrealm_index_t id;
	int rc;


	printk("%s volume %llu, origin size %llu, hint %d, context %p, nrealms %d\n",
			__func__,
			volume_id, origin_size, hint, context,
			nrealms);

	// if the origin px volume is smaller then do not apply caching
	if (MIN_ORIGIN_SIZE > origin_size || nrealms <= 0) {
		return (pxrealm_index_t) -EINVAL;
	}

	id = pxrealm_lookup(volume_id);
	if (id >= 0) { // lookup passed
		printk("cache mapping for volume %llu exists with id %lu\n", volume_id, id);
		return id;
	}

	// search for first zero bit, position is index.
	id = bitmap_find_next_zero_area_off(pxrealm.map_indices, MAX_REALM_MAPS,
			0, 1, 0, 0);
	if (id >= MAX_REALM_MAPS) {
		return (pxrealm_index_t) -EBUSY;
	}
	bitmap_set(pxrealm.map_indices, id, 1);

	pmap = pxrealm_map(id);
	BUG_ON(!pmap);
	BUG_ON(pmap->inuse);

	// allocate a context to track cache state for this realm
	rc = pxrealm_assign(&pxrealm, pmap, nrealms);
	if (rc < 0) {
		bitmap_clear(pxrealm.map_indices, id, 1);
		return (pxrealm_index_t) rc;
	}

	pmap->id = id;
	pmap->private = context;
	pmap->origin_size = origin_size;
	pmap->volume_id = volume_id;

	return id;
}

pxrealm_index_t pxrealm_lookup(uint64_t vol)
{
	pxrealm_index_t id;

	for (id = 0; id < MAX_REALM_MAPS; id++) {
		if (!maps[id].inuse) continue;
		if (maps[id].volume_id == vol) {
			return id;
		}
	}

	return (pxrealm_index_t) -EINVAL;
}


int pxrealm_free(pxrealm_index_t id)
{
	struct pxrealm_map_t *pmap;

	if (id >= MAX_REALM_MAPS) {
		printk("%s index out of range %lu\n", __func__, id);
		return -EINVAL;
	}

	pmap = pxrealm_map(id);
	if (!pmap || !pmap->inuse) {
		printk("%s index not in use %lu\n", __func__, id);
		return -EINVAL;
	}

	pxrealm_dealloc(pmap);
	bitmap_clear(pxrealm.map_indices, id, 1);
	return 0; // successful
}


int pxrealm_properties(pxrealm_index_t id, struct pxrealm_properties* prop)
{
	struct pxrealm_map_t *pmap = pxrealm_map(id);

	if (!pmap || !pmap->inuse) {
		return -EINVAL;
	}

	prop->id = id;
	prop->offset = realm_byte_offset(pmap->off);
	prop->size = pmap->nrealms * REALM_SIZE;
	prop->context = pmap->private;
	prop->origin_size = pmap->origin_size;
	prop->volume_id = pmap->volume_id;

	return 0;
}


int pxrealm_init(const char* cdevpath)
{
	struct block_device *cdev;

	if (pxrealm.initialized) {
		return -EBUSY;
	}

    cdev = lookup_bdev(cdevpath);
    if (IS_ERR(cdev)) {
        return -EINVAL;
    }

	pxrealm.cdev = cdev;
    bdput(cdev);

	strncpy(pxrealm.cdevname, cdevpath, sizeof(pxrealm.cdevname));
	pxrealm.cdevname[MAX_DEVNAME] = '\0';

	// find cdev size and compute max realms
	pxrealm.cdev_size = i_size_read(cdev->bd_inode);
	pxrealm.cdev_sectors = i_size_read(cdev->bd_inode) >> SECTOR_SHIFT;

	pxrealm.max_realms = pxrealm.cdev_size / REALM_SIZE;


	// realm 0, 1 and 2 are blocked for internal consumption
	pxrealm.realm_inuse_bitmap = bitmap_zalloc(pxrealm.max_realms, GFP_KERNEL);
	if (!pxrealm.realm_inuse_bitmap) {
		return -ENOMEM;
	}

	pxrealm.map_indices = bitmap_zalloc(MAX_REALM_MAPS, GFP_KERNEL);
	if (!pxrealm.map_indices) {
		bitmap_free(pxrealm.realm_inuse_bitmap);
		return -ENOMEM;
	}

	__bitmap_set(pxrealm.realm_inuse_bitmap, 0, 3);
	pxrealm.initialized = 1;

	pxrealm_debug_dump();

	return 0;
}

void pxrealm_exit()
{
	if (pxrealm.map_indices) {
		bitmap_free(pxrealm.map_indices);
		pxrealm.map_indices = NULL;
	}
	if (pxrealm.realm_inuse_bitmap) {
		bitmap_free(pxrealm.realm_inuse_bitmap);
		pxrealm.realm_inuse_bitmap = NULL;
	}

	pxrealm.initialized = 0;
}
