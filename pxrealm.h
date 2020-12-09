#ifndef _PXREALM_H_
#define _PXREALM_H_

typedef long pxrealm_index_t;

typedef enum {
	PXREALM_AUTO, // allow on the fly changing cache size! not supported
	PXREALM_LARGE,
	PXREALM_MEDIUM,
	PXREALM_SMALL,
} pxrealm_hint_t;


struct pxrealm_properties {
	pxrealm_index_t id;
	uint64_t offset; // begin byte offset
	uint64_t size; // number of bytes in this realm

	void* context;
	uint64_t origin_size;
	uint64_t volume_id;
};

int pxrealm_properties(pxrealm_index_t, struct pxrealm_properties*);

pxrealm_index_t pxrealm_alloc(uint64_t volumeId, uint64_t origin_size,
		pxrealm_hint_t hint, void *context);
void pxrealm_free(pxrealm_index_t);

int pxrealm_init(const char* cdevpath);
void pxrealm_exit(void);

#endif /* _PXREALM_H_ */
