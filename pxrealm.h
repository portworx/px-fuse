#ifndef _PXREALM_H_
#define _PXREALM_H_

typedef long pxrealm_index_t;

typedef enum {
	PXREALM_AUTO, // allow on the fly changing cache size! not supported
	PXREALM_SMALL,
	PXREALM_MEDIUM,
	PXREALM_LARGE,
} pxrealm_hint_t;


struct pxrealm_properties {
	pxrealm_index_t id;
	uint64_t offset; // begin byte offset
	uint64_t size; // number of bytes in this realm

	void* context;
	uint64_t origin_size;
	uint64_t volume_id;
};

sector_t pxrealm_sector_offset(pxrealm_index_t id);
sector_t pxrealm_sector_end(pxrealm_index_t id);
sector_t pxrealm_sector_size(pxrealm_index_t id);

pxrealm_index_t pxrealm_lookup(uint64_t vol);
int pxrealm_properties(pxrealm_index_t, struct pxrealm_properties*);

pxrealm_index_t pxrealm_alloc(uint64_t volumeId, uint64_t origin_size,
		pxrealm_hint_t hint, void *context);
int pxrealm_free(pxrealm_index_t);

int pxrealm_init(const char* cdevpath);
void pxrealm_exit(void);

void pxrealm_debug_dump(void);
#endif /* _PXREALM_H_ */
