#ifndef _PXMGR_H_
#define _PXMGR_H_

#define MAX_DEVNAME (127)

struct pxtgt_device;
struct pxmgr_context;
struct bio;

typedef enum {
  PXREALM_AUTO,  // allow on the fly changing cache size! not supported
  PXREALM_SMALL,
  PXREALM_MEDIUM,
  PXREALM_LARGE,
} pxrealm_hint_t;

enum {
  CMODE_PASSTHROUGH,
  CMODE_WRITETHROUGH,
  CMODE_WRITEBACK,   // writeback cache based on hotspot/lru
  CMODE_WRITECACHE,  // writeback cache writes
};

void pxmgr_debug_dump(uint64_t dev_id, struct pxmgr_context *cc);

struct pxmgr_context *pxmgr_cache_alloc(
    uint64_t vol_id, uint64_t vol_size, pxrealm_hint_t, int cmode,
    uint32_t cblksize, void *priv,
    void (*enqueue_to_origin)(struct pxtgt_device *, struct bio *));

int pxmgr_cache_dealloc(struct pxmgr_context *);

// setup once the global cache device
int pxmgr_init(const char *cdev);

void pxmgr_cache_submit_io(struct pxmgr_context *mc, struct bio *b);

// one time global init/cleanup
int pxmgr_setup(void);
void pxmgr_destroy(void);

#endif /* _PXMGR_H_ */
