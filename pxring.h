#ifndef _PXRING_H_
#define _PXRING_H_

#include <linux/types.h>
#include <linux/string.h>

struct ring {
	void *base;
	unsigned int length_bytes;
	unsigned int recordSize;
	unsigned int ringSize; /* a.k.a max number of records */
	atomic_t index[2];  /* XXX atomic may not be needed */
};
#define WRITEINDEX(r)  (atomic_read(&(r)->index[1]))
#define READINDEX(r)   (atomic_read(&(r)->index[0]))

#define RECORD(r, i)   ((r)->base + (i) * (r)->recordSize)

static inline bool ringEmpty(struct ring* r) {
	return (WRITEINDEX(r) == READINDEX(r));
}

static inline bool ringFull(struct ring* r) {
	unsigned int wrIndex = WRITEINDEX(r);
	unsigned int rdIndex = READINDEX(r);
	
	wrIndex = (wrIndex + 1) % r->ringSize;
	return (wrIndex == rdIndex);	
}

static inline int ringPendingCount(struct ring* r) {
	unsigned int wrIndex = WRITEINDEX(r);
	unsigned int rdIndex = READINDEX(r);
	
	if (wrIndex >= rdIndex) {
		return (wrIndex - rdIndex);
	}
	
	return (wrIndex + r->ringSize - rdIndex);
}

static inline 
int ringInit(struct ring* r, void *buffer,
		unsigned int recordSize, unsigned int ringSize) {
	unsigned int nbytes = recordSize * ringSize;

	r->base = buffer;
	r->recordSize = recordSize;
	r->ringSize = ringSize;

	r->base = buffer;
	r->length_bytes = nbytes;
	return 0;	
}

static inline
void ringDestroy(struct ring* r) {
	memset(r, 0, sizeof(*r));
}

static inline
void ringEnqueue(struct ring* r, int nrecords) {
	unsigned int _current;
	unsigned int tmp;

	unsigned int new;
	do {
		_current = WRITEINDEX(r);
		new = (_current + nrecords) % r->ringSize;
		tmp = atomic_cmpxchg(&r->index[1], _current, new);
	} while (tmp != _current);
}

static inline
void ringDequeue(struct ring* r, int nrecords) {
	unsigned int _current;
	unsigned int tmp;

	unsigned int new;
	do {
		_current = READINDEX(r);
		new = (_current + nrecords) % r->ringSize;
		tmp = atomic_cmpxchg(&r->index[0], _current, new);
	} while (tmp != _current);
}

#endif /* _PXRING_H_ */
