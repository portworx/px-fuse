#ifndef _PXDMM_H_
#define _PXDMM_H_

int pxdmm_init(void);
void pxdmm_exit(void);

#define NREQUESTS (256)
#define MAXDATASIZE (1<<20)


// ioctl
struct pxdmm_mbox {
	const int queueSize; // const
	uint64_t cmdHead __attribute__((aligned(64)));
	uint64_t cmdTail __attribute__((aligned(64)));
	uint64_t respHead __attribute__((aligned(64)));
	uint64_t respTail __attribute__((aligned(64)));
} __attribute__((aligned(64)));

struct pxdmm_cmdresp {
	uint32_t minor;
	uint32_t cmd;
	void* handle;

	loff_t offset;
	loff_t length;

	uint32_t io_index;
	uint32_t status;
} __attribute__((aligned(64)));

static inline
loff_t pxdmm_dataoffset(uint32_t io_index) {
	return io_index * MAXDATASIZE;
}

#endif /* _PXDMM_H_ */
