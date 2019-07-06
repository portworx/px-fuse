#ifndef PXD_H_
#define PXD_H_

#include <linux/version.h>
#include <linux/kernel.h>
#ifdef __PXKERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/param.h>
#include <string.h>
#endif

#include "fuse.h"

/// @file px_fuse/pxd.h

#define PXD_CONTROL_DEV "/dev/pxd/pxd-control"	/**< control device prefix */
#define PXD_DEV  	"pxd/pxd"		/**< block device prefix */
#define PXD_DEV_PATH	"/dev/" PXD_DEV		/**< block device path prefix */

#define PXD_VERSION 8				/**< driver version */

#define PXD_NUM_CONTEXTS			11	/**< Total available control devices */
#define PXD_NUM_CONTEXT_EXPORTED	1	/**< Available for external use */

#define PXD_IOCTL_MAGIC			(('P' << 8) | 'X')
#define PXD_IOC_DUMP_FC_INFO	_IO(PXD_IOCTL_MAGIC, 1)		/* 0x505801 */
#define PXD_IOC_GET_VERSION		_IO(PXD_IOCTL_MAGIC, 2)		/* 0x505802 */

#define PXD_MAX_DEVICES	512			/**< maximum number of devices supported */
#define PXD_MAX_IO		(1024*1024)	/**< maximum io size in bytes */
#define PXD_MAX_QDEPTH  256			/**< maximum device queue depth */

#define MAX_PXD_BACKING_DEVS (3)  /**< maximum number of replica targets for each user vol */
#define MAX_PXD_DEVPATH_LEN (127) /**< device path length */

/** fuse opcodes */
enum pxd_opcode {
	PXD_INIT = 8192,	/**< send on device open from kernel */
	PXD_WRITE,			/**< write to device */
	PXD_READ,			/**< read from device */
	PXD_DISCARD,		/**< discard blocks */
	PXD_ADD,			/**< add device to kernel */
	PXD_REMOVE,			/**< remove device from kernel */
	PXD_READ_DATA,		/**< read data from kernel */
	PXD_UPDATE_SIZE,	/**< update device size */
	PXD_WRITE_SAME,		/**< write_same operation */
	PXD_LAST,
};

/** flags set by driver */
#define PXD_FLAGS_FLUSH 0x1	/**< REQ_FLUSH set on bio */
#define PXD_FLAGS_FUA	0x2	/**< REQ_FUA set on bio */
#define PXD_FLAGS_META	0x4	/**< REQ_META set on bio */
#define PXD_FLAGS_SYNC (PXD_FLAGS_FLUSH | PXD_FLAGS_FUA)

#define PXD_LBS (4 * 1024) 	/**< logical block size */
#define PXD_LBS_MASK (PXD_LBS - 1)

/** Device identification passed from kernel on initialization */
struct pxd_dev_id {
	uint32_t local_minor; 	/**< minor number assigned by kernel */
	uint32_t pad;
	uint64_t dev_id;	/**< global device id */
	uint64_t size;		/**< device size known by kernel in bytes */
};

/**
 * PXD_INIT message passed from kernel.
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
	int32_t queue_depth;	/**< use queue depth 0 to bypass queueing */
	int32_t discard_size;	/**< block device discard size in bytes */
};

/**
 * PXD_REMOVE request from user space
 */
struct pxd_remove_out {
	uint64_t dev_id;	/**< device global id */
	bool force;		/**< force remove device */
	char pad[7];
};

/**
 * PXD_READ_DATA request from user space
 */
struct pxd_read_data_out {
	uint64_t unique;	/**< request id */
	int32_t iovcnt;		/**< number of iovec entries */
	uint32_t offset;	/**< offset into data */
};

/**
 * PXD_UPDATE_SIZE request from user space
 */
struct pxd_update_size_out {
	uint64_t dev_id;
	size_t size;
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
#ifdef __cplusplus
	rdwr_in(uint32_t opcode, uint32_t i_minor, uint32_t i_size,
		uint64_t i_offset, uint64_t i_chksum, uint32_t i_flags) :
		rdwr(i_minor, i_size, i_offset, i_chksum, i_flags) {
		memset(&in, 0, sizeof(in));
		in.opcode = opcode;
	}
	rdwr_in(uint32_t i_minor, uint32_t i_size,
		uint64_t i_offset, uint64_t i_chksum, uint32_t i_flags) :
		rdwr(i_minor, i_size, i_offset, i_chksum, i_flags) {
		memset(&in, 0, sizeof(in));
	}

	rdwr_in() = default;
#endif
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

static inline uint64_t pxd_wr_blocks(const struct rdwr_in *rdwr)
{
	const struct pxd_rdwr_in *prw = &rdwr->rdwr;
	if (prw->size && rdwr->in.opcode == PXD_WRITE_SAME)
		return 1;
	else
		return prw->size && rdwr->in.opcode == PXD_WRITE ?
	       	pxd_aligned_len(prw->size, prw->offset) / PXD_LBS : 0;
}

static inline uint64_t pxd_rd_blocks(const struct rdwr_in *rdwr)
{
	const struct pxd_rdwr_in *prw = &rdwr->rdwr;
	return pxd_aligned_len(prw->size, prw->offset) / PXD_LBS;
}

struct pxd_ioctl_version_args {
	int piv_len;
	char piv_data[64];
};

#endif /* PXD_H_ */
