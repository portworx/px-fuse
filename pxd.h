#ifndef PXD_H_
#define PXD_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/param.h>
#endif

#include "linux/fuse.h"

/// @file pxd/pxd.h

#define PXD_CONTROL_DEV "/dev/pxd/pxd-control"	/**< control device prefix */
#define PXD_DEV  		"pxd/pxd"				/**< block device prefix */
#define PXD_DEV_PATH	"/dev/" PXD_DEV		/**< block device path prefix */

#define PXD_VERSION 1		/**< driver version */

#define PXD_MAX_DEVICES 1024	/**< maximum number of devices supported */
#define PXD_MAX_IO (1024*1024)	/**< maximum io size in bytes */

/** fuse opcodes */
enum pxd_opcode {
	PXD_INIT = 8192, /**< send on device open from kernel */
	PXD_WRITE,	/**< write to device */
	PXD_READ,	/**< read from device */
	PXD_DISCARD,	/**< discard blocks */
	PXD_ADD,	/**< add device to kernel */
	PXD_REMOVE,	/**< remove device from kernel */
	PXD_LAST,
};

#define PXD_FLAGS_FLUSH 0x1	/**< REQ_FLUSH set on bio */
#define PXD_FLAGS_FUA	0x2	/**< REQ_FUA set on bio */
#define PXD_FLAGS_META	0x4	/**< REQ_META set on bio */
#define PXD_FLAGS_SYNC (PXD_FLAGS_FLUSH | PXD_FLAGS_FUA)

#define PXD_LBS (4 * 1024) 	/**< logical block size */
#define PXD_LBS_MASK (PXD_LBS - 1)

/** Device identification passed from kernel on initialization */
struct pxd_dev_id {
	uint32_t local_minor; /**< minor number assigned by kernel */
	uint32_t pad;
	uint64_t dev_id;	/**< global device id */
	uint64_t size;		/**< device size known by kernel in bytes */
};

/** PXD_INIT message passed from kernel.
 *
 * Includes array of registered pxd devices in the end of the message.
 */
struct pxd_init_in {
	uint32_t version;	/**< kernel driver version */
	uint32_t num_devices;	/**< number of devices in the list */
	/* followed by array of struct pxd_dev_id */
};

/**
 * PXD_INIT response
 */
struct pxd_init_out {
	uint32_t dummy;
};

/**
 * PXD_ADD request from user space
 */
struct pxd_add_out {
	uint64_t dev_id;	/**< device global id */
	size_t size;		/**< block device size in bytes */
};

/**
 * PXD_REMOVE request from user space
 */
struct pxd_remove_out {
	uint64_t dev_id;	/**< device global id */
};

/**
 * PXD_READ/PXD_WRITE kernel request structure
 */
struct pxd_rdwr_in {
#ifdef __cplusplus
	pxd_rdwr_in(uint32_t i_minor, uint32_t i_size, uint64_t i_offset,
		uint64_t i_chksum, uint32_t i_flags) : size(i_size),
			flags(i_flags), chksum(i_chksum), offset(i_offset) {
		minor = i_minor;
	}

	pxd_rdwr_in() = default;
#endif
	uint32_t minor;		/**< minor device number */
	uint32_t size;		/**< read/write/discard size in bytes */
	uint32_t flags;		/**< bio flags */
	uint64_t chksum;	/**< buffer checksum */
	uint32_t pad;
	uint64_t offset;	/**< device offset in bytes */
};

/**
 * PXD_READ/PXD_WRITE kernel request structure
 */
struct rdwr_in {
	struct fuse_in_header in;	/**< fuse header */
	struct pxd_rdwr_in rdwr;	/**< read/write request */
};

static inline uint64_t pxd_aligned_offset(uint64_t offset)
{
	return offset & ~PXD_LBS_MASK;
}

static inline uint64_t pxd_aligned_len(uint64_t len, uint64_t offset)
{
	return roundup(offset % PXD_LBS + len, PXD_LBS);
}

#endif /* PXD_H_ */
