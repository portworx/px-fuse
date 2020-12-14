#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "pxcc.h"
#include "pxmgr.h"
#include "pxrealm.h"

struct pxmgr_context {
        struct pxrealm_properties prop;
        struct pxcc_c *cc;
};

static void pxrealm_dump_property(struct pxrealm_properties *prop) {
        printk("realm %lu[%p]: offset %lu end %lu nsectors %lu hint %d origin "
               "vol %llu size %llu private %p\n",
               prop->id, prop->cdev, prop->offset, prop->end, prop->nsectors,
               prop->hint, prop->volume_id, prop->origin_size, prop->context);
}

void pxmgr_debug_dump(uint64_t dev_id, struct pxmgr_context *mc) {
        if (!mc) {
                printk("device %llu does not have mapped cache\n", dev_id);
                return;
        }

        pxrealm_dump_property(&mc->prop);
        pxcc_debug_dump(mc->cc);
}

struct pxmgr_context *pxmgr_cache_alloc(uint64_t vol_id, uint64_t vol_size,
                                        pxrealm_hint_t cache_hint,
                                        uint32_t cache_blksize, void *priv) {
        struct pxmgr_context *mc;
        pxrealm_index_t id;
        struct pxcc_c *cc;
        int rc;

        printk("%s for volume %llu size %llu hint %d private %p\n", __func__,
               vol_id, vol_size, cache_hint, priv);

        mc = kzalloc(sizeof(struct pxmgr_context), GFP_KERNEL);
        if (!mc) {
                return NULL;
        }

        id = pxrealm_alloc(vol_id, vol_size, cache_hint, priv);
        if (id < 0) {
                kfree(mc);
                return NULL;
        }

        rc = pxrealm_properties(id, &mc->prop);
        if (rc < 0) {
                pxrealm_free(id);
                kfree(mc);
                return NULL;
        }

        cc = pxcc_init(mc->prop.cdev, mc->prop.offset, mc->prop.nsectors,
                       cache_blksize, vol_size);
        if (IS_ERR_OR_NULL(cc)) {
                pxrealm_free(id);
                kfree(mc);
                return NULL;
        }

        mc->cc = cc;
        return mc;
}

int pxmgr_cache_dealloc(struct pxmgr_context *mc) {
        printk("%s with mc %p\n", __func__, mc);
        if (!mc) {
                return 0;
        }
        pxcc_exit(mc->cc);
        pxrealm_free(mc->prop.id);
        kfree(mc);

        return 0;
}

int pxmgr_init(const char *cdevpath) {
        int rc;

        rc = pxrealm_init(cdevpath);

        return rc;
}

void pxmgr_exit(void) { pxrealm_exit(); }
