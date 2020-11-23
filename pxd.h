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

#define PXD_POISON (0xdeadbeef)
#define PXD_CONTROL_DEV "/dev/pxd/pxd-control"	/**< control device prefix */
#define PXD_DEV  	"pxd/pxd"		/**< block device prefix */
#define PXD_DEV_PATH	"/dev/" PXD_DEV		/**< block device path prefix */

#define PXD_VERSION 11				/**< driver version */

#define PXD_NUM_CONTEXTS			11	/**< Total available control devices */
#define PXD_NUM_CONTEXT_EXPORTED	1	/**< Available for external use */

#define PXD_IOCTL_MAGIC		(('P' << 8) | 'X')
#define PXD_IOC_DUMP_FC_INFO	_IO(PXD_IOCTL_MAGIC, 1)		/* 0x505801 */
#define PXD_IOC_GET_VERSION	_IO(PXD_IOCTL_MAGIC, 2)		/* 0x505802 */
#define PXD_IOC_INIT		_IO(PXD_IOCTL_MAGIC, 3)		/* 0x505803 */
#define PXD_IOC_RUN_USER_QUEUE	_IO(PXD_IOCTL_MAGIC, 4)		/* 0x505804 */
#define PXD_IOC_RUN_IO_QUEUE	_IO(PXD_IOCTL_MAGIC, 5)		/* 0x505805 */
#define PXD_IOC_REGISTER_FILE	_IO(PXD_IOCTL_MAGIC, 6)		/* 0x505806 */
#define PXD_IOC_UNREGISTER_FILE	_IO(PXD_IOCTL_MAGIC, 7)		/* 0x505807 */
#define PXD_IOC_RESIZE			_IO(PXD_IOCTL_MAGIC, 8)		/* 0x505808 */
#define PXD_IOC_FPCLEANUP		_IO(PXD_IOCTL_MAGIC, 9)		/* 0x505809 */
#define PXD_IOC_NODEWIPE		_IO(PXD_IOCTL_MAGIC, 10)	/* 0x50580a */

#define PXD_MAX_DEVICES	512			/**< maximum number of devices supported */
#define PXD_MAX_IO		(1024*1024)	/**< maximum io size in bytes */
#define PXD_MAX_QDEPTH  256			/**< maximum device queue depth */

// NOTE: nvme devices can go upto 1023 queue depth
#define MAX_CONGESTION_THRESHOLD (1024)
// use by fastpath for congestion control
#define DEFAULT_CONGESTION_THRESHOLD MAX_CONGESTION_THRESHOLD

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
	PXD_ADD_EXT,		/**< add device with extended info to kernel */
	PXD_UPDATE_PATH,    /**< update backing file/device path for a volume */
	PXD_SET_FASTPATH,   /**< enable/disable fastpath */
	PXD_GET_FEATURES,   /**< get features */
	PXD_COMPLETE,		/**< complete kernel operation */
	PXD_SUSPEND,		/**< IO suspend */
	PXD_RESUME,			/**< IO resume */
	PXD_FAILOVER_TO_USERSPACE,   /**< Failover requests suspend IO and send in a marker req
						  from kernel on a suspended device */
	PXD_FALLBACK_TO_KERNEL,   /**< Fallback requests suspend IO and send in a marker req
						  from kernel on a suspended device */
	PXD_LAST,
};

/** flags set by driver */
#define PXD_FLAGS_FLUSH 0x1	/**< REQ_FLUSH set on bio */
#define PXD_FLAGS_FUA	0x2	/**< REQ_FUA set on bio */
#define PXD_FLAGS_META	0x4	/**< REQ_META set on bio */
#define PXD_FLAGS_SYNC (PXD_FLAGS_FLUSH | PXD_FLAGS_FUA)
#define PXD_FLAGS_LAST PXD_FLAGS_META

#define PXD_LBS (4 * 1024) 	/**< logical block size */
#define PXD_LBS_MASK (PXD_LBS - 1)

/** Device identification passed from kernel on initialization */
struct pxd_dev_id {
	uint32_t local_minor; 	/**< minor number assigned by kernel */
	uint8_t pad[3];
	uint8_t fastpath:1, blkmq_device:1, suspend:1, unused:5;
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
 * PXD_UPDATE_PATH request from user space
 */
struct pxd_update_path_out {
	uint64_t dev_id;
	bool   can_failover; /***< switch IO to userspace on any error */
	size_t count; // count of paths below.
	char devpath[MAX_PXD_BACKING_DEVS][MAX_PXD_DEVPATH_LEN+1];
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
 * PXD_ADD_EXT request from user space
 */
struct pxd_add_ext_out {
	uint64_t dev_id;	/**< device global id */
	size_t size;		/**< block device size in bytes */
	int32_t queue_depth;	/**< use queue depth 0 to bypass queueing */
	int32_t discard_size;	/**< block device discard size in bytes */
	mode_t  open_mode; /**< backing file open mode O_RDONLY|O_SYNC|O_DIRECT etc */
	bool    enable_fp; /**< enable fast path */
	struct pxd_update_path_out paths; /**< backing device paths */
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
 * PXD_UPDATE_SIZE ioctl from user space
 */
struct pxd_update_size {
	uint64_t dev_id;
	size_t size;
	int context_id;
};

/**
 * PXD_SET_FASTPATH request from user space
 */
struct pxd_fastpath_out {
	uint64_t dev_id;
	int enable;
	int cleanup; // only meaningful while disabling
	int context_id;
};

/**
 * PXD_SUSPEND/PXD_RESUME request from user space
 */
struct pxd_suspend {
	uint64_t dev_id;
	bool skip_flush;
	bool coe; // continue to be in suspend state, even on error
};

struct pxd_resume {
	uint64_t dev_id;
};

/**
 * PXD_FALLBACK|FAILOVER request from user space
 */
struct pxd_ioswitch {
	uint64_t dev_id;
};

struct pxd_context;
struct pxd_device* find_pxd_device(struct pxd_context *ctx, uint64_t dev_id);

/**
 * PXD_GET_FEATURES request from user space
 * response contains feature set
 */
// No arguments necessary other than opcode
#define PXD_FEATURE_FASTPATH (0x1)

static inline
int pxd_supported_features(void)
{
	int features = 0;
#ifdef __PX_FASTPATH__
	features |= PXD_FEATURE_FASTPATH;
#endif

	return features;
}


/**
 * PXD_READ/PXD_WRITE kernel request structure
 */
struct pxd_rdwr_in {
#ifdef __cplusplus
	static_assert(PXD_FLAGS_LAST <= 1 << 15, "flags do not fit in 16 bits");

	pxd_rdwr_in(uint16_t minor, uint32_t size, uint64_t offset, uint16_t flags) :
		dev_minor(minor), flags(flags), size(size), offset(offset) {
	}

	pxd_rdwr_in() = default;
#endif
	uint16_t dev_minor;	/**< minor device number */
	uint16_t flags;		/**< bio flags */
	uint32_t size;		/**< read/write/discard size in bytes */
	uint64_t offset;	/**< device offset in bytes */
};

struct pxd_rdwr_in_v1 {
	uint32_t dev_minor;		/**< minor device number */
	uint32_t size;		/**< read/write/discard size in bytes */
	uint32_t flags;		/**< bio flags */
	uint64_t chksum;	/**< buffer checksum */
	uint32_t pad; 
	uint64_t offset;	/**< device offset in bytes */
};

/** completion of user operation */
struct pxd_completion {
	uint64_t user_data;	/**< user data passed in request */
	int32_t res;		/**< result code */
};

/**
 * PXD_READ/PXD_WRITE kernel request structure
 */
struct rdwr_in {
#ifdef __cplusplus
	rdwr_in(uint32_t opcode, uint32_t minor, uint32_t size,
		uint64_t offset, uint32_t flags) :
		rdwr(minor, size, offset, flags) {
		in.opcode = opcode;
	}
	rdwr_in(uint32_t minor, uint32_t size, uint64_t offset, uint32_t flags) :
		rdwr(minor, size, offset, flags) {
	}

	rdwr_in() = default;
#endif
	struct fuse_in_header in;	/**< fuse header */
	union {
		struct pxd_rdwr_in rdwr;	/**< read/write request */
		struct pxd_completion completion; /**< user request completion */
	};
};

struct rdwr_in_v1 {
	struct fuse_in_header_v1 in;	/**< fuse header */
	struct pxd_rdwr_in_v1 rdwr;	/**< read/write request */
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

struct pxd_ioctl_init_args {
	struct pxd_init_in hdr;

	/** list of devices */
	struct pxd_dev_id devices[PXD_MAX_DEVICES];
};

#endif /* PXD_H_ */
