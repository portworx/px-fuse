#ifndef _PXMGR_H_
#define _PXMGR_H_

#define MAX_DEVNAME (127)

struct pxd_device;
struct pxmgr_context;

typedef enum {
        PXREALM_AUTO, // allow on the fly changing cache size! not supported
        PXREALM_SMALL,
        PXREALM_MEDIUM,
        PXREALM_LARGE,
} pxrealm_hint_t;

void pxmgr_debug_dump(uint64_t dev_id, struct pxmgr_context *cc);

struct pxmgr_context *pxmgr_cache_alloc(uint64_t vol_id, uint64_t vol_size,
                                        pxrealm_hint_t, uint32_t cblksize,
                                        void *priv);

int pxmgr_cache_dealloc(struct pxmgr_context *);

int pxmgr_init(const char *cdev);
void pxmgr_exit(void);

#endif /* _PXMGR_H_ */
