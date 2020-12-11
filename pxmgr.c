#include <linux/types.h>
#include <linux/slab.h>

#include "pxmgr.h"
#include "pxrealm.h"
#include "pxcc.h"

struct pxmgr_context {
	struct pxrealm_properties prop;
	struct pxcc_c *cc;
};

void pxmgr_debug_dump(struct pxmgr_context *mc)
{
	if (!mc) {
		return;
	}

	pxrealm_debug_dump();
	pxcc_debug_dump(mc->cc);
}


struct pxmgr_context* pxmgr_cache_alloc(uint64_t vol_id, uint64_t vol_size,
        pxrealm_hint_t cache_hint, void *priv)
{
	struct pxmgr_context *mc;
	pxrealm_index_t id;
	struct pxcc_c *cc;
	int rc;

	mc = kzalloc(sizeof(*mc), GFP_KERNEL);
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

	cc = pxcc_init(mc->prop.cdev, mc->prop.offset, mc->prop.nsectors, 0 /* use default */,
			vol_size);
	if (IS_ERR_OR_NULL(cc)) {
		pxrealm_free(id);
		kfree(mc);
		return NULL;
	}

	mc->cc = cc;
	return mc;
}

int pxmgr_cache_dealloc(struct pxmgr_context *mc)
{
	pxcc_exit(mc->cc);
	pxrealm_free(mc->prop.id);
	kfree(mc);

	return 0;
}

int pxmgr_init(const char *cdevpath)
{
	int rc;

	rc = pxrealm_init(cdevpath);

	return rc;
}

void pxmgr_exit(void)
{
	pxrealm_exit();
}
