#ifndef _PXSHARED_H_
#define _PXSHARED_H_

#ifndef __KERNEL__
#include <stdint.h>
#endif

#define _ALIGN(x,v) (((x) + (v) - 1) & ~((v)-1))


// IOCTL
#define PXD_GET_SYSINFO (0xFC00)
typedef enum {_INITIALIZING, _READY, _FAILED, _DESTROYED} STATUS;
struct px_sysinfo {
	STATUS status;
	int cpu_id;

	const char *shared_base;
	int shared_length;

	int reqRingSize;
	int reqRecordSize;

	int respRingSize;
	int respRecordSize;

	int niovecs;
	int iovecSize;

	int nbuffSize;
} __attribute__((aligned(8)));

static inline
void px_dump_sysinfo(const struct px_sysinfo* info) {
#ifdef __KERNEL__
	printk(KERN_INFO"[%d]: status: %x, shared_base %p, length %#x\n"
			"\tRequest Records %d, RecordSize %d\n"
			"\tResponse Records %d, ResponseSize %d\n"
			"\tIOVEC Records %d, Size %d\n"
			"\tIO Buffer Size %d\n",
			info->cpu_id,
			info->status,
			info->shared_base, info->shared_length,
			info->reqRingSize, info->reqRecordSize,
			info->respRingSize, info->respRecordSize,
			info->niovecs, info->iovecSize,
			info->nbuffSize);
#else
	printf("[%d]: status: %x, shared_base %p, length %#x\n"
			"\tRequest Records %d, RecordSize %d\n"
			"\tResponse Records %d, ResponseSize %d\n"
			"\tIOVEC Records %d, Size %d\n"
			"\tIO Buffer Size %d\n",
			info->cpu_id,
			info->status,
			info->shared_base, info->shared_length,
			info->reqRingSize, info->reqRecordSize,
			info->respRingSize, info->respRecordSize,
			info->niovecs, info->iovecSize,
			info->nbuffSize);
#endif
}

/* shared structures between user and kernel */
struct px_iovec {
	unsigned int length;
	unsigned int offset;
};

// define MAX_VECTORS_PER_REQUEST to cover maximum io size per request.
// below maps 256 * 4k = 1M
#define MAX_VECTORS_PER_REQUEST (256)
struct px_requestRecord {
	// 0 byte
	uintptr_t handle; // internal reference to this request.

	// 8 byte
	unsigned int minor;
	unsigned char cmd;
	unsigned char pad[3];

	// 16 byte
	loff_t length; // request length
	loff_t offset; // request offset

	// 32 bytes
	unsigned short vectors[MAX_VECTORS_PER_REQUEST];

	// 512+32 bytes
	unsigned int vec_count;
} __attribute__((aligned(1024)));

struct px_responseRecord {
	// 0 byte
	uintptr_t handle; // internal reference to this request.

	// 8 byte
	unsigned int minor;
	unsigned char cmd;
	unsigned char status;
	unsigned char pad1[2];

	// 16 byte
	loff_t length; // request length
	loff_t offset; // request offset

	// 32 bytes
	struct px_iovec* vectors; // kmalloc region in kernel
	unsigned int vec_count;
	unsigned int pad2[2];

	// 48 bytes
	struct px_iovec  inlinev; // if one vector, then it can be inline.
} __attribute__((aligned(1024)));

#define TESTSMALL

#ifdef TESTSMALL
#define NREQUEST_RECORDS (64)
#define NRESPONSE_RECORDS (64)
#define NIOVEC  (256)
#else
#define NREQUEST_RECORDS (1024)
#define NRESPONSE_RECORDS (1024)
#define NIOVEC  (4096)
#endif

#define REQUEST_RECORDSIZE  sizeof(struct px_requestRecord)
#define SHARED_REQUEST_SIZE  (NREQUEST_RECORDS * REQUEST_RECORDSIZE)

#define RESPONSE_RECORDSIZE sizeof(struct px_responseRecord)
#define SHARED_RESPONSE_SIZE  (NRESPONSE_RECORDS * RESPONSE_RECORDSIZE)

#define IOVEC_RECORDSIZE   sizeof(struct px_iovec)
#define SHARED_IOVEC_SIZE  (IOVEC_RECORDSIZE * NIOVEC)

#define SHARED_IOBLKSIZE   (4<<10) // should match PXD_LBS
#define SHARED_IOSIZE      (NIOVEC * SHARED_IOBLKSIZE)

#define SHARED_TOTALSIZE _ALIGN((SHARED_REQUEST_SIZE + SHARED_RESPONSE_SIZE + SHARED_IOVEC_SIZE + SHARED_IOSIZE), 4096)

#define PX_REQUESTBASE(b)  ((struct px_requestRecord*)(b))
#define PX_RESPONSEBASE(b) ((struct px_responseRecord*)((char*)(b) + SHARED_REQUEST_SIZE))
#define PX_IOVECBASE(b)    ((struct px_iovec*)((char*)(b) + SHARED_REQUEST_SIZE + SHARED_RESPONSE_SIZE))
#define PX_IOBASE(b)       ((char*)(b) + SHARED_REQUEST_SIZE + SHARED_RESPONSE_SIZE + SHARED_IOVEC_SIZE)

#endif /* _PXSHARED_H_ */
