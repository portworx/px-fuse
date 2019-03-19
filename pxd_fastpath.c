#include <linux/types.h>

#include "pxd.h"
#include "pxd_core.h"

static int pxd_io_thread(void *data) {
	return 0;
}

/*
 * shall get called last when new device is added/updated or when fuse connection is lost
 * and re-estabilished.
 */
void enableFastPath(struct pxd_device *pxd_dev, bool force) {
	struct file *f;
	struct inode *inode;
	int i;
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;
	int nfd = fp->nfd;

	for (i=0; i<nfd; i++) {
		if (fp->file[i] > 0) { /* valid fd exists already */
			if (force) {
				filp_close(fp->file[i], NULL);
				f = filp_open(fp->device_path[i], O_DIRECT | O_LARGEFILE | O_RDWR, 0600);
				if (IS_ERR_OR_NULL(f)) {
					printk(KERN_ERR"Failed attaching path: device %llu, path %s err %ld\n",
						pxd_dev->dev_id, fp->device_path[i], PTR_ERR(f));
					goto out_file_failed;
				}
			} else {
				f = fp->file[i];
			}
		} else {
			f = filp_open(fp->device_path[i], O_DIRECT | O_LARGEFILE | O_RDWR, 0600);
			if (IS_ERR_OR_NULL(f)) {
				printk(KERN_ERR"Failed attaching path: device %llu, path %s err %ld\n",
					pxd_dev->dev_id, fp->device_path[i], PTR_ERR(f));
				goto out_file_failed;
			}
		}

		fp->file[i] = f;

		inode = f->f_inode;
		printk(KERN_INFO"device %lld:%d, inode %lu\n", pxd_dev->dev_id, i, inode->i_ino);
		if (S_ISREG(inode->i_mode)) {
			fp->block_device = false; /* override config to use file io */
			printk(KERN_INFO"device[%lld:%d] is a regular file - inode %lu\n",
					pxd_dev->dev_id, i, inode->i_ino);
		} else if (S_ISBLK(inode->i_mode)) {
			printk(KERN_INFO"device[%lld:%d] is a block device - inode %lu\n",
				pxd_dev->dev_id, i, inode->i_ino);
		} else {
			fp->block_device = false; /* override config to use file io */
			printk(KERN_INFO"device[%lld:%d] inode %lu unknown device %#x\n",
				pxd_dev->dev_id, i, inode->i_ino, inode->i_mode);
		}
	}

	printk(KERN_INFO"pxd_dev %llu setting up with %d backing volumes, [%p,%p,%p]\n",
		pxd_dev->dev_id, fp->nfd,
		fp->file[0], fp->file[1], fp->file[2]);

	return;

out_file_failed:
	fp->nfd = 0;
	for (i=0; i<nfd; i++) {
		if (fp->file[i] > 0) filp_close(fp->file[i], NULL);
	}
	memset(fp->file, 0, sizeof(fp->file));
	memset(fp->device_path, 0, sizeof(fp->device_path));
	printk(KERN_INFO"Device %llu no backing volume setup, will take slow path\n",
		pxd_dev->dev_id);
}

void disableFastPath(struct pxd_device *pxd_dev, bool force) {
}

int pxd_fastpath_init(struct pxd_device *pxd_dev, loff_t offset) {
	int err = -EINVAL;
	int i;
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;

	fp->offset = offset;
	fp->block_device = true; // always default to considering as block device
	fp->nfd = 0; // will take slow path, if additional info not provided.

	pxd_printk("Number of cpu ids %d\n", MAX_THREADS);
	fp->bg_flush_enabled = false; // introduces high latency
	fp->n_flush_wrsegs = MAX_WRITESEGS_FOR_FLUSH;

	// congestion init
	init_waitqueue_head(&fp->congestion_wait);
	init_waitqueue_head(&fp->sync_event);
	spin_lock_init(&fp->sync_lock);

	atomic_set(&fp->nsync_active, 0);
	atomic_set(&fp->nsync, 0);
	atomic_set(&fp->ncount,0);
	atomic_set(&fp->nswitch,0);
	atomic_set(&fp->nslowPath,0);
	atomic_set(&fp->ncomplete,0);
	atomic_set(&fp->nwrite_counter,0);

	fp->offset = 0;

	fp->tc = kzalloc(MAX_THREADS * sizeof(struct thread_context), GFP_NOIO);
	if (!fp->tc) {
		printk(KERN_ERR"Initializing backing volumes for pxd failed %d\n", err);
		return -ENOMEM;
	}

	for (i=0; i<nr_node_ids; i++) {
		atomic_set(&fp->index[i], 0);
	}

	for (i=0; i<MAX_THREADS; i++) {
		struct thread_context *tc = &fp->tc[i];
		tc->pxd_dev = pxd_dev;
		spin_lock_init(&tc->lock);
		init_waitqueue_head(&tc->pxd_event);
		tc->pxd_thread = kthread_create_on_node(pxd_io_thread, tc, cpu_to_node(i),
				"pxd%d:%llu", i, pxd_dev->dev_id);
		if (IS_ERR(tc->pxd_thread)) {
			pxd_printk("Init kthread for device %llu failed %lu\n",
				pxd_dev->dev_id, PTR_ERR(tc->pxd_thread));
			err = -EINVAL;
			goto fail;
		}

		kthread_bind(tc->pxd_thread, i);
		wake_up_process(tc->pxd_thread);
	}

	enableFastPath(pxd_dev, true);

	return 0;
fail:
	for (i=0; i<MAX_THREADS; i++) {
		struct thread_context *tc = &fp->tc[i];
		if (tc->pxd_thread) kthread_stop(tc->pxd_thread);
	}

	if (fp->tc) kfree(fp->tc);
	return err;
}

void pxd_fastpath_cleanup(struct pxd_device *pxd_dev) {
}
