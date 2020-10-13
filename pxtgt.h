#ifndef PXTGT_H_
#define PXTGT_H_

#include <linux/version.h>
#include <linux/kernel.h>
#ifdef __PXKERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/param.h>
#include <string.h>
#endif

#define PXTGT_POISON (0xdeadbeef)
#define PXTGT_CONTROL_DEV "/dev/pxtgt/control"	/**< control device prefix */
#define PXTGT_DEV  	"pxtgt/"		/**< block device prefix */
#define PXTGT_DEV_PATH	"/dev/" PXTGT_DEV		/**< block device path prefix */

#define PXTGT_VERSION 1				/**< driver version */

#define PXTGT_NUM_CONTEXTS			11	/**< Total available control devices */
#define PXTGT_NUM_CONTEXT_EXPORTED	1	/**< Available for external use */

#define PXTGT_IOCTL_MAGIC		(('P' << 8) | 'T')
#define PXTGT_IOC_GET_VERSION	_IO(PXTGT_IOCTL_MAGIC, 2)		/* 0x505802 */
#define PXTGT_IOC_INIT		_IO(PXTGT_IOCTL_MAGIC, 3)		/* 0x505803 */
#define PXTGT_IOC_RESIZE			_IO(PXTGT_IOCTL_MAGIC, 4)		/* 0x505808 */

#define PXTGT_MAX_DEVICES	512			/**< maximum number of devices supported */
#define PXTGT_MAX_IO		(1024*1024)	/**< maximum io size in bytes */
#define PXTGT_MAX_QDEPTH  1024			/**< maximum device queue depth */

#define MAX_PXTGT_DEVPATH_LEN (127) /**< device path length */

// NOTE: nvme devices can go upto 1023 queue depth
#define MAX_CONGESTION_THRESHOLD (1024)
// use by fastpath for congestion control
#define DEFAULT_CONGESTION_THRESHOLD MAX_CONGESTION_THRESHOLD

/** flags set by driver */
#define PXTGT_FLAGS_FLUSH 0x1	/**< REQ_FLUSH set on bio */
#define PXTGT_FLAGS_FUA	0x2	/**< REQ_FUA set on bio */
#define PXTGT_FLAGS_META	0x4	/**< REQ_META set on bio */
#define PXTGT_FLAGS_SYNC (PXTGT_FLAGS_FLUSH | PXTGT_FLAGS_FUA)
#define PXTGT_FLAGS_LAST PXTGT_FLAGS_META

#define PXTGT_LBS (4 * 1024) 	/**< logical block size */
#define PXTGT_LBS_MASK (PXTGT_LBS - 1)

/** Device identification passed from kernel on initialization */
struct pxtgt_dev_id {
	uint32_t local_minor; 	/**< minor number assigned by kernel */
	uint8_t pad[3];
	uint8_t block_io:1, unused:7;
	uint64_t dev_id;	/**< global device id */
	uint64_t size;		/**< device size known by kernel in bytes */
	char source[MAX_PXTGT_DEVPATH_LEN+1]; /**< replica source device or file */
};

/**
 * PXTGT_INIT message passed from kernel.
 *
 * Includes array of registered pxd devices in the end of the message.
 */
struct pxtgt_init_in {
	uint32_t version;	/**< kernel driver version */
	uint32_t num_devices;	/**< number of devices in the list */
	/* followed by array of struct pxtgt_dev_id */
};

/**
 * PXTGT_INIT response
 */
struct pxtgt_init_out {
	uint32_t dummy;
};

/**
 * PXTGT_ADD request from user space
 */
struct pxtgt_add_out {
	uint64_t dev_id;	/**< device global id */
	char source[128];
	size_t size;		/**< block device size in bytes */
	uint32_t queue_depth;
	uint32_t discard_size;
};

/**
 * PXTGT_REMOVE request from user space
 */
struct pxtgt_remove_out {
	uint64_t dev_id;	/**< device global id */
	bool force;		/**< force remove device */
	char pad[7];
};

/**
 * PXTGT_UPDATE_SIZE ioctl from user space
 */
struct pxtgt_update_size {
	uint64_t dev_id;
	size_t size;
	int context_id;
};


/**
 * PXTGT_SUSPEND/PXTGT_RESUME request from user space
 */
struct pxtgt_suspend {
	uint64_t dev_id;
	bool skip_flush;
	bool coe; // continue to be in suspend state, even on error
};

struct pxtgt_resume {
	uint64_t dev_id;
};

struct pxtgt_context;
struct pxtgt_io_tracker;
struct pxtgt_device* find_pxtgt_device(struct pxtgt_context *ctx, uint64_t dev_id);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
void pxtgt_complete_io(struct bio* bio);
#else
void pxtgt_complete_io(struct bio* bio, int error);
#endif

struct pxtgt_ioctl_version_args {
	int piv_len;
	char piv_data[64];
};

struct pxtgt_ioctl_init_args {
	struct pxtgt_init_in hdr;

	/** list of devices */
	struct pxtgt_dev_id devices[PXTGT_MAX_DEVICES];
};

#endif /* PXTGT_H_ */
