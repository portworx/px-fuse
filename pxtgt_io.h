#ifndef __PXTGT_IO_H_
#define __PXTGT_IO_H_

extern const struct file_operations pxtgt_ops;

/** fuse opcodes */
enum pxtgt_opcode {
	PXTGT_INIT = 8192,	/**< send on device open from kernel */
	PXTGT_WRITE,			/**< write to device */
	PXTGT_READ,			/**< read from device */
	PXTGT_DISCARD,		/**< discard blocks */
	PXTGT_ADD,			/**< add device to kernel */
	PXTGT_REMOVE,			/**< remove device from kernel */
	PXTGT_READ_DATA,		/**< read data from kernel */
	PXTGT_UPDATE_SIZE,	/**< update device size */
	PXTGT_WRITE_SAME,		/**< write_same operation */
	PXTGT_ADD_EXT,		/**< add device with extended info to kernel */
	PXTGT_UPDATE_PATH,    /**< update backing file/device path for a volume */
	PXTGT_SET_FASTPATH,   /**< enable/disable fastpath */
	PXTGT_GET_FEATURES,   /**< get features */
	PXTGT_COMPLETE,		/**< complete kernel operation */
	PXTGT_SUSPEND,		/**< IO suspend */
	PXTGT_RESUME,			/**< IO resume */
	PXTGT_FAILOVER_TO_USERSPACE,   /**< Failover requests suspend IO and send in a marker req
						  from kernel on a suspended device */
	PXTGT_FALLBACK_TO_KERNEL,   /**< Fallback requests suspend IO and send in a marker req
						  from kernel on a suspended device */
	PXTGT_LAST,
};


struct pxtgt_device;
struct work_struct;
struct fuse_req {
	enum pxtgt_opcode opcode;
	struct pxtgt_device *pxtgt_dev;
	struct bio *bio;
	/** Associate request queue */
	struct request_queue *queue;

	uint64_t unique;
	int dev_minor;
	loff_t offset;
	size_t size;
	unsigned flags;

	struct work_struct work;
};

ssize_t pxtgt_read_init(struct pxtgt_context *ctx, struct iov_iter *iter);
ssize_t pxtgt_ioc_update_size(struct pxtgt_context *ctx, struct pxtgt_update_size *update_size);

int pxtgt_flush(struct pxtgt_device *pxtgt_dev, struct file *file);
int pxtgt_bio_discard(struct pxtgt_device *pxtgt_dev, struct file *file, struct bio *bio, loff_t pos);
int pxtgt_send(struct pxtgt_device *pxtgt_dev, struct file *file, struct bio *bio, loff_t pos);
ssize_t pxtgt_receive(struct pxtgt_device *pxtgt_dev, struct file *file, struct bio *bio, loff_t *pos);
int do_bio_filebacked(struct pxtgt_device *pxtgt_dev, struct pxtgt_io_tracker *iot);

#endif /* __PXTGT_IO_H_ */
