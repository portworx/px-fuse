/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#ifndef _FS_FUSE_I_H
#define _FS_FUSE_I_H

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/poll.h>
#include <linux/workqueue.h>
#include <linux/hash.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#include "iov_iter.h"

#define iov_iter_advance __iov_iter_advance
#define iov_iter __iov_iter
#define iov_iter_init __iov_iter_init
#define copy_page_to_iter __copy_page_to_iter
#define copy_page_from_iter __copy_page_from_iter

#endif

#include "fuse.h"
#include "pxd.h"

/** Max number of pages that can be used in a single read request */
#define FUSE_MAX_PAGES_PER_REQ 32

/** Bias for fi->writectr, meaning new writepages must not be sent */
#define FUSE_NOWRITE INT_MIN

/** It could be as large as PATH_MAX, but would that have any uses? */
#define FUSE_NAME_MAX 1024

/** Number of dentries for each connection in the control filesystem */
#define FUSE_CTL_NUM_DENTRIES 5

/** If the FUSE_DEFAULT_PERMISSIONS flag is given, the filesystem
    module will check permissions based on the file mode.  Otherwise no
    permission checking is done in the kernel */
#define FUSE_DEFAULT_PERMISSIONS (1 << 0)

/** If the FUSE_ALLOW_OTHER flag is given, then not only the user
    doing the mount will be allowed to access the filesystem */
#define FUSE_ALLOW_OTHER         (1 << 1)

/** Number of page pointers embedded in fuse_req */
#define FUSE_REQ_INLINE_PAGES 1

/** List of active connections */
extern struct list_head fuse_conn_list;

/** Global mutex protecting fuse_conn_list and the control filesystem */
extern struct mutex fuse_mutex;

/** Module parameters */
extern unsigned max_user_bgreq;
extern unsigned max_user_congthresh;

/* One forget request */
struct fuse_forget_link {
	struct fuse_forget_one forget_one;
	struct fuse_forget_link *next;
};

/** FUSE inode */
struct fuse_inode {
	/** Inode data */
	struct inode inode;

	/** Unique ID, which identifies the inode between userspace
	 * and kernel */
	u64 nodeid;

	/** Number of lookups on this inode */
	u64 nlookup;

	/** The request used for sending the FORGET message */
	struct fuse_forget_link *forget;

	/** Time in jiffies until the file attributes are valid */
	u64 i_time;

	/** The sticky bit in inode->i_mode may have been removed, so
	    preserve the original mode */
	umode_t orig_i_mode;

	/** 64 bit inode number */
	u64 orig_ino;

	/** Version of last attribute change */
	u64 attr_version;

	/** Files usable in writepage.  Protected by fc->lock */
	struct list_head write_files;

	/** Writepages pending on truncate or fsync */
	struct list_head queued_writes;

	/** Number of sent writes, a negative bias (FUSE_NOWRITE)
	 * means more writes are blocked */
	int writectr;

	/** Waitq for writepage completion */
	wait_queue_head_t page_waitq;

	/** List of writepage requestst (pending or sent) */
	struct list_head writepages;

	/** Miscellaneous bits describing inode state */
	unsigned long state;
};

/** FUSE inode state bits */
enum {
	/** Advise readdirplus  */
	FUSE_I_ADVISE_RDPLUS,
	/** Initialized with readdirplus */
	FUSE_I_INIT_RDPLUS,
	/** An operation changing file size is in progress  */
	FUSE_I_SIZE_UNSTABLE,
};

struct fuse_conn;

/** FUSE specific file data */
struct fuse_file {
	/** Fuse connection for this file */
	struct fuse_conn *fc;

	/** Kernel file handle guaranteed to be unique */
	u64 kh;

	/** File handle used by userspace */
	u64 fh;

	/** Node id of this file */
	u64 nodeid;

	/** Refcount */
	atomic_t count;

	/** FOPEN_* flags returned by open */
	u32 open_flags;

	/** Entry on inode's write_files list */
	struct list_head write_entry;

	/** RB node to be linked on fuse_conn->polled_files */
	struct rb_node polled_node;

	/** Wait queue head for poll */
	wait_queue_head_t poll_wait;

	/** Has flock been performed on this file? */
	bool flock:1;
};

/** One input argument of a request */
struct fuse_in_arg {
	unsigned size;
	const void *value;
};

/** The request input */
struct fuse_in {
	/** The request header */
	struct fuse_in_header h;

	/** Number of arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_in_arg args[3];
};

/** One output argument of a request */
struct fuse_arg {
	unsigned size;
	void *value;
};

/** The request output */
struct fuse_out {
	/** Header returned from userspace */
	struct fuse_out_header h;
};

/** FUSE page descriptor */
struct fuse_page_desc {
	unsigned int length;
	unsigned int offset;
};

/** The request state */
enum fuse_req_state {
	FUSE_REQ_INIT = 0,
	FUSE_REQ_PENDING,
	FUSE_REQ_READING,
	FUSE_REQ_SENT,
	FUSE_REQ_WRITING,
	FUSE_REQ_FINISHED
};

/** The request IO state (for asynchronous processing) */
struct fuse_io_priv {
	int async;
	spinlock_t lock;
	unsigned reqs;
	ssize_t bytes;
	size_t size;
	__u64 offset;
	bool write;
	int err;
	struct kiocb *iocb;
	struct file *file;
};

/**
 * A request to the client
 */
struct fuse_req {
	/** This can be on either pending processing or io lists in
	    fuse_conn */
	struct list_head list;

	/** The request input */
	struct fuse_in in;

	/** The request output */
	struct fuse_out out;

	/** Data for asynchronous requests */
	union {
		struct pxd_init_in pxd_init_in;
		struct pxd_init_out pxd_init_out;
		struct pxd_rdwr_in pxd_rdwr_in;
	} misc;

	union {
		/** Associated request structrure. */
		struct request *rq;

		/** Associated bio structrure. */
 		struct bio *bio;
	};

	/** Request completion callback */
	void (*end)(struct fuse_conn *, struct fuse_req *);

	/** Associate request queue */
	struct request_queue *queue;
};

#define FUSE_MAX_PER_CPU_IDS 256

struct ____cacheline_aligned fuse_per_cpu_ids {
	/** number of free ids in stack */
	u32 num_free_ids;

	/** followed by list of free ids */
	u64 free_ids[FUSE_MAX_PER_CPU_IDS];
};

/**
 * A Fuse connection.
 *
 * This structure is created, when the filesystem is mounted, and is
 * destroyed, when the client device is closed and the filesystem is
 * unmounted.
 */
struct fuse_conn {
	/** Lock protecting accessess to  members of this structure */
	spinlock_t lock;

	/** Readers of the connection are waiting on this */
	wait_queue_head_t waitq;

	/** The list of pending requests */
	struct list_head pending;

	/** The list of requests being processed */
	struct list_head processing;

	/** maps request ids to requests */
	struct fuse_req **request_map;

	/** stack of free ids */
	u64 *free_ids;

	/** number of free ids in stack */
	u32 num_free_ids;

	/** per cpu id allocators */
	struct fuse_per_cpu_ids __percpu *per_cpu_ids;

	/** The next unique request id */
	u64 reqctr;

	/** Connection established, cleared on umount, connection
	    abort and device release */
	bool connected;

	/** open in progress, cleared on completion */
	bool pend_open;

	/* Alow operations on disconnected fuse conenction. */
	bool allow_disconnected;

	/** Refcount */
	atomic_t count;

	/** Entry on the fuse_conn_list */
	struct list_head entry;

	/** O_ASYNC requests */
	struct fasync_struct *fasync;

	/** Called on final put */
	void (*release)(struct fuse_conn *);


};

static inline struct fuse_conn *get_fuse_conn_super(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct fuse_conn *get_fuse_conn(struct inode *inode)
{
	return get_fuse_conn_super(inode->i_sb);
}

static inline struct fuse_inode *get_fuse_inode(struct inode *inode)
{
	return container_of(inode, struct fuse_inode, inode);
}

static inline u64 get_node_id(struct inode *inode)
{
	return get_fuse_inode(inode)->nodeid;
}

/** Device operations */
extern const struct file_operations fuse_dev_operations;

extern const struct dentry_operations fuse_dentry_operations;

/**
 * Inode to nodeid comparison.
 */
int fuse_inode_eq(struct inode *inode, void *_nodeidp);

/**
 * Get a filled in inode
 */
struct inode *fuse_iget(struct super_block *sb, u64 nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version);

int fuse_lookup_name(struct super_block *sb, u64 nodeid, struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode);

struct fuse_forget_link *fuse_alloc_forget(void);

/**
 * Initialize READ or READDIR request
 */
void fuse_read_fill(struct fuse_req *req, struct file *file,
		    loff_t pos, size_t count, int opcode);

/**
 * Send OPEN or OPENDIR request
 */
int fuse_open_common(struct inode *inode, struct file *file, bool isdir);

struct fuse_file *fuse_file_alloc(struct fuse_conn *fc);
struct fuse_file *fuse_file_get(struct fuse_file *ff);
void fuse_file_free(struct fuse_file *ff);
void fuse_finish_open(struct inode *inode, struct file *file);

void fuse_sync_release(struct fuse_file *ff, int flags);

/**
 * Send RELEASE or RELEASEDIR request
 */
void fuse_release_common(struct file *file, int opcode);

/**
 * Send FSYNC or FSYNCDIR request
 */
int fuse_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int isdir);

/**
 * Notify poll wakeup
 */
int fuse_notify_poll_wakeup(struct fuse_conn *fc,
			    struct fuse_notify_poll_wakeup_out *outarg);

/**
 * Initialize file operations on a regular file
 */
void fuse_init_file_inode(struct inode *inode);

/**
 * Initialize inode operations on regular files and special files
 */
void fuse_init_common(struct inode *inode);

/**
 * Initialize inode and file operations on a directory
 */
void fuse_init_dir(struct inode *inode);

/**
 * Initialize inode operations on a symlink
 */
void fuse_init_symlink(struct inode *inode);

/**
 * Change attributes of an inode
 */
void fuse_change_attributes(struct inode *inode, struct fuse_attr *attr,
			    u64 attr_valid, u64 attr_version);

void fuse_change_attributes_common(struct inode *inode, struct fuse_attr *attr,
				   u64 attr_valid);

/**
 * Initialize the client device
 */
int fuse_dev_init(void);

/**
 * Cleanup the client device
 */
void fuse_dev_cleanup(void);

int fuse_ctl_init(void);
void __exit fuse_ctl_cleanup(void);

/**
 * Allocate a request
 */
struct fuse_req *fuse_request_alloc(void);

struct fuse_req *fuse_request_alloc_nofs(void);

/**
 * Free a request
 */
void fuse_request_free(struct fuse_req *req);

/**
 * Get a request, may fail with -ENOMEM,
 */
struct fuse_req *fuse_get_req(struct fuse_conn *fc);
struct fuse_req *fuse_get_req_for_background(struct fuse_conn *fc);

/**
 * Send a request in the background
 */
void fuse_request_send_nowait(struct fuse_conn *fc, struct fuse_req *req);

/* Abort all requests */
void fuse_abort_conn(struct fuse_conn *fc);

/**
 * Invalidate inode attributes
 */
void fuse_invalidate_attr(struct inode *inode);

void fuse_invalidate_entry_cache(struct dentry *entry);

void fuse_invalidate_atime(struct inode *inode);

/**
 * Acquire reference to fuse_conn
 */
struct fuse_conn *fuse_conn_get(struct fuse_conn *fc);

void fuse_conn_kill(struct fuse_conn *fc);

/**
 * Initialize fuse_conn
 */
int fuse_conn_init(struct fuse_conn *fc);

/**
 * Release reference to fuse_conn
 */
void fuse_conn_put(struct fuse_conn *fc);

/**
 * Add connection to control filesystem
 */
int fuse_ctl_add_conn(struct fuse_conn *fc);

/**
 * Remove connection from control filesystem
 */
void fuse_ctl_remove_conn(struct fuse_conn *fc);

/**
 * Is file type valid?
 */
int fuse_valid_type(int m);

/**
 * Is current process allowed to perform filesystem operation?
 */
int fuse_allow_current_process(struct fuse_conn *fc);

u64 fuse_lock_owner_id(struct fuse_conn *fc, fl_owner_t id);

int fuse_update_attributes(struct inode *inode, struct kstat *stat,
			   struct file *file, bool *refreshed);

void fuse_flush_writepages(struct inode *inode);

void fuse_set_nowrite(struct inode *inode);
void fuse_release_nowrite(struct inode *inode);

u64 fuse_get_attr_version(struct fuse_conn *fc);

/**
 * File-system tells the kernel to invalidate cache for the given node id.
 */
int fuse_reverse_inval_inode(struct super_block *sb, u64 nodeid,
			     loff_t offset, loff_t len);

/**
 * File-system tells the kernel to invalidate parent attributes and
 * the dentry matching parent/name.
 *
 * If the child_nodeid is non-zero and:
 *    - matches the inode number for the dentry matching parent/name,
 *    - is not a mount point
 *    - is a file or oan empty directory
 * then the dentry is unhashed (d_delete()).
 */
int fuse_reverse_inval_entry(struct super_block *sb, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name);

int fuse_do_open(struct fuse_conn *fc, u64 nodeid, struct file *file,
		 bool isdir);

/**
 * fuse_direct_io() flags
 */

/** If set, it is WRITE; otherwise - READ */
#define FUSE_DIO_WRITE (1 << 0)

/** CUSE pass fuse_direct_io() a file which f_mapping->host is not from FUSE */
#define FUSE_DIO_CUSE  (1 << 1)

ssize_t fuse_direct_io(struct fuse_io_priv *io, struct iov_iter *iter,
		       loff_t *ppos, int flags);
long fuse_do_ioctl(struct file *file, unsigned int cmd, unsigned long arg,
		   unsigned int flags);
long fuse_ioctl_common(struct file *file, unsigned int cmd,
		       unsigned long arg, unsigned int flags);
unsigned fuse_file_poll(struct file *file, poll_table *wait);
int fuse_dev_release(struct inode *inode, struct file *file);
void fuse_restart_requests(struct fuse_conn *fc);

bool fuse_write_update_size(struct inode *inode, loff_t pos);

int fuse_flush_times(struct inode *inode, struct fuse_file *ff);
int fuse_write_inode(struct inode *inode, struct writeback_control *wbc);

int fuse_do_setattr(struct inode *inode, struct iattr *attr,
		    struct file *file);

ssize_t pxd_add(struct fuse_conn *fc, struct pxd_add_out *add);
ssize_t pxd_remove(struct fuse_conn *fc, struct pxd_remove_out *remove);
ssize_t pxd_update_size(struct fuse_conn *fc, struct pxd_update_size_out *update_size);
ssize_t pxd_read_init(struct fuse_conn *fc, struct iov_iter *iter);

void fuse_request_init(struct fuse_req *req);
void fuse_req_init_context(struct fuse_req *req);

#endif /* _FS_FUSE_I_H */
