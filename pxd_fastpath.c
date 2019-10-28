#include <linux/types.h>
#include <linux/delay.h>

#include "pxd.h"
#include "pxd_core.h"
#include "pxd_compat.h"

// cached info at px loadtime, to gracefully handle hot plugging cpus
static int __px_ncpus;

// A one-time built, static lookup table to distribute requests to cpu
// within same numa node
static struct node_cpu_map *node_cpu_map;

static inline
int getnextcpu(int node, int pos) {
	const struct node_cpu_map *map = &node_cpu_map[node];
	if (map->ncpu == 0) { return 0; }
	return map->cpu[(pos) % map->ncpu];
}

// A private global bio mempool for punting requests bypassing vfs
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
static struct bio_set pxd_bio_set;
#endif
#define PXD_MIN_POOL_PAGES (128)
static struct bio_set* ppxd_bio_set;


// global thread contexts
static struct thread_context *g_tc;

// forward decl
static int pxd_io_writer(void *data);
static int pxd_io_reader(void *data);
static void __pxd_cleanup_block_io(struct pxd_io_tracker *head);
static struct pxd_io_tracker* pxd_get_io(struct thread_context *tc, int rw);
#define pxd_get_writeio(tc)  pxd_get_io(tc, WRITE)
#define pxd_get_readio(tc)   pxd_get_io(tc, READ)

static inline
int pxd_io_empty(struct thread_context *tc, int rw) {
	int empty;

	if (rw == WRITE) {
		spin_lock_irq(&tc->write_lock);
		empty = list_empty(&tc->iot_writers);
		spin_unlock_irq(&tc->write_lock);
	} else {
		spin_lock_irq(&tc->read_lock);
		empty = list_empty(&tc->iot_readers);
		spin_unlock_irq(&tc->read_lock);
	}

	return empty;
}

static inline
void pxd_wait_io(struct thread_context *tc, int rw) {
	if (rw == READ) {
		wait_event_interruptible(tc->read_event,
                            !pxd_io_empty(tc, rw) || kthread_should_stop());
	} else {
		wait_event_interruptible(tc->write_event,
                            !pxd_io_empty(tc, rw) || kthread_should_stop());
	}
}

static int fastpath_global_threadctx_init(struct thread_context *tc, int cpuid) {
	int i;
	int err;
	int node = cpu_to_node(cpuid);

	spin_lock_init(&tc->read_lock);
	init_waitqueue_head(&tc->read_event);
	INIT_LIST_HEAD(&tc->iot_readers);

	spin_lock_init(&tc->write_lock);
	init_waitqueue_head(&tc->write_event);
	INIT_LIST_HEAD(&tc->iot_writers);

	// setup readers
	for (i=0; i<PXD_MAX_THREAD_PER_CPU;i++) {
		// set dedicated thread function
		tc->reader[i] = kthread_create_on_node(pxd_io_reader, tc,
				node, "pxwr%d:%d:%d", node, cpuid, i);
		if (IS_ERR(tc->reader[i])) {
			pxd_printk("Init global reader kthread for cpu %d failed %lu\n",
				cpuid, PTR_ERR(tc->reader[i]));
			err = -EINVAL;
			goto fail_rd;
		}

		//  bind readers on any cpu but on same numa node
		set_cpus_allowed_ptr(tc->reader[i], cpumask_of_node(node));
		set_user_nice(tc->reader[i], MIN_NICE);
		wake_up_process(tc->reader[i]);
	}

	// setup writers
	for (i=0; i<PXD_MAX_THREAD_PER_CPU;i++) {
		// set dedicated thread function
		tc->writer[i] = kthread_create_on_node(pxd_io_writer, tc,
				node, "pxrd%d:%d:%d", node, cpuid, i);
		if (IS_ERR(tc->writer[i])) {
			pxd_printk("Init global writer kthread for cpu %d failed %lu\n",
				cpuid, PTR_ERR(tc->writer[i]));
			err = -EINVAL;
			goto fail_wr;
		}

		//  bind all writers on the same cpu
		kthread_bind(tc->writer[i], cpuid);
		set_user_nice(tc->writer[i], MIN_NICE);
		wake_up_process(tc->writer[i]);
	}

	return 0;

fail_wr:
	for(;i>=0; i--) {
		if (tc->writer[i]) kthread_stop(tc->writer[i]);
	}
	i = PXD_MAX_THREAD_PER_CPU;
fail_rd:
	for(;i>=0; i--) {
		if (tc->reader[i]) kthread_stop(tc->reader[i]);
	}
	return err;
}

static void fastpath_global_threadctx_cleanup(void) {
	int i,t;
	struct pxd_io_tracker *head;
	struct thread_context *tc;

	if (!g_tc) return;

	for (i=0;i<__px_ncpus;i++) {
		tc = &g_tc[i];
		for (t=0;t<PXD_MAX_THREAD_PER_CPU; t++) {
			if (tc->writer[t]) kthread_stop(tc->writer[t]);
			if (tc->reader[t]) kthread_stop(tc->reader[t]);
		}

		// fail all enqueue'd IOs
		while ((head = pxd_get_readio(tc)) != NULL) {
			if (head->orig) BIO_ENDIO(head->orig, -ENXIO);
			__pxd_cleanup_block_io(head);
		}

		while ((head = pxd_get_writeio(tc)) != NULL) {
			if (head->orig) BIO_ENDIO(head->orig, -ENXIO);
			__pxd_cleanup_block_io(head);
		}
	}
}

int fastpath_init(void) {
	int i, err;

	// cache the count of cpu information at module load time.
	// if there is any subsequent hot plugging of cpus, will still handle gracefully.
	__px_ncpus = nr_cpu_ids;

	printk(KERN_INFO"CPU %d/%d, NUMA nodes %d/%d\n", __px_ncpus, NR_CPUS, nr_node_ids, MAX_NUMNODES);
	node_cpu_map = kzalloc(sizeof(struct node_cpu_map) * nr_node_ids, GFP_KERNEL);
	if (!node_cpu_map) {
		printk(KERN_ERR "pxd: failed to initialize node_cpu_map: -ENOMEM\n");
		return -ENOMEM;
	}

	g_tc = kzalloc(sizeof(struct thread_context) * __px_ncpus, GFP_KERNEL);
	if (!g_tc) {
		printk(KERN_ERR "pxd: failed to initialize global thread context: -ENOMEM\n");
		kfree(node_cpu_map);
		return -ENOMEM;
	}

	// capturing all the cpu's on a given numa node during run-time
	for (i=0;i<__px_ncpus;i++) {
		struct node_cpu_map *map=&node_cpu_map[cpu_to_node(i)];
		map->cpu[map->ncpu++] = i;

		// also initialize global thread context
		err = fastpath_global_threadctx_init(&g_tc[i], i);
		if (err) {
			fastpath_global_threadctx_cleanup();
			kfree(g_tc);
			kfree(node_cpu_map);
			return err;
		}
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
	if (bioset_init(&pxd_bio_set, PXD_MIN_POOL_PAGES,
			offsetof(struct pxd_io_tracker, clone), 0)) {
		printk(KERN_ERR "pxd: failed to initialize bioset_init: -ENOMEM\n");
		fastpath_global_threadctx_cleanup();
		kfree(g_tc);
		kfree(node_cpu_map);
		return -ENOMEM;
	}
	ppxd_bio_set = &pxd_bio_set;
#else
	ppxd_bio_set = BIOSET_CREATE(PXD_MIN_POOL_PAGES, offsetof(struct pxd_io_tracker, clone));
#endif

	if (!ppxd_bio_set) {
		printk(KERN_ERR "pxd: bioset init failed");
		fastpath_global_threadctx_cleanup();
		kfree(g_tc);
		kfree(node_cpu_map);
		return -ENOMEM;
	}

	return 0;
}

void fastpath_cleanup(void) {
	fastpath_global_threadctx_cleanup();

	if (ppxd_bio_set) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
		bioset_exit(ppxd_bio_set);
#else
		bioset_free(ppxd_bio_set);
#endif
	}

	if (g_tc) kfree(g_tc);
	if (node_cpu_map) kfree(node_cpu_map);
	ppxd_bio_set = NULL;
	g_tc = NULL;
	node_cpu_map = NULL;
}

// forward decl
void disableFastPath(struct pxd_device *pxd_dev);

static int _pxd_flush(struct pxd_device *pxd_dev, struct file *file) {
	int ret = 0;

	// pxd_dev is opened in o_sync mode. all writes are complete with implicit sync.
	// explicit sync can be treated nop
	if (pxd_dev->mode & O_SYNC) {
		atomic_inc(&pxd_dev->fp.nio_flush_nop);
		return 0;
	}

	ret = vfs_fsync(file, 0);
	if (unlikely(ret && ret != -EINVAL && ret != -EIO)) {
		ret = -EIO;
	}
	atomic_inc(&pxd_dev->fp.nio_flush);
	atomic_set(&pxd_dev->fp.nwrite_counter, 0);
	return ret;
}

static int pxd_should_flush(struct pxd_device *pxd_dev, int *active) {
	*active = atomic_read(&pxd_dev->fp.nsync_active);
	if (pxd_dev->fp.bg_flush_enabled &&
		(atomic_read(&pxd_dev->fp.nwrite_counter) > pxd_dev->fp.n_flush_wrsegs) &&
		!*active) {
		atomic_set(&pxd_dev->fp.nsync_active, 1);
		return 1;
	}
	return 0;
}

static void pxd_issue_sync(struct pxd_device *pxd_dev, struct file *file) {
	struct block_device *bdev = bdget_disk(pxd_dev->disk, 0);
	if (!bdev) return;

	vfs_fsync(file, 0);

	spin_lock_irq(&pxd_dev->fp.sync_lock);
	atomic_set(&pxd_dev->fp.nwrite_counter, 0);
	atomic_set(&pxd_dev->fp.nsync_active, 0);
	atomic_inc(&pxd_dev->fp.nsync);
	spin_unlock_irq(&pxd_dev->fp.sync_lock);

	wake_up(&pxd_dev->fp.sync_event);
}

static void pxd_check_write_cache_flush(struct pxd_device *pxd_dev, struct file *file) {
	int sync_wait, sync_now;
	spin_lock_irq(&pxd_dev->fp.sync_lock);
	sync_now = pxd_should_flush(pxd_dev, &sync_wait);

	if (sync_wait) {
		wait_event_lock_irq(pxd_dev->fp.sync_event,
				!atomic_read(&pxd_dev->fp.nsync_active),
				pxd_dev->fp.sync_lock);
	}
	spin_unlock_irq(&pxd_dev->fp.sync_lock);

	if (sync_now) pxd_issue_sync(pxd_dev, file);
}

static int _pxd_bio_discard(struct pxd_device *pxd_dev, struct file *file, struct bio *bio, loff_t pos) {
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	int ret;

	atomic_inc(&pxd_dev->fp.nio_discard);

	if ((!file->f_op->fallocate)) {
		return -EOPNOTSUPP;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	ret = file->f_op->fallocate(file, mode, pos, bio->bi_iter.bi_size);
#else
	ret = file->f_op->fallocate(file, mode, pos, bio->bi_size);
#endif
	if (unlikely(ret && ret != -EINVAL && ret != -EOPNOTSUPP))
		return -EIO;

	return 0;
}

static int _pxd_write(struct file *file, struct bio_vec *bvec, loff_t *pos)
{
	ssize_t bw;
	mm_segment_t old_fs = get_fs();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct iov_iter i;
#else
	void *kaddr = kmap(bvec->bv_page) + bvec->bv_offset;
#endif

	pxd_printk("_pxd_write entry offset %lld, length %d entered\n", *pos, bvec->bv_len);

	if (bvec->bv_len != PXD_LBS) {
		printk(KERN_ERR"Unaligned block writes %d bytes\n", bvec->bv_len);
	}
	set_fs(get_ds());
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
	iov_iter_bvec(&i, WRITE, bvec, 1, bvec->bv_len);
	file_start_write(file);
	bw = vfs_iter_write(file, &i, pos, 0);
	file_end_write(file);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	iov_iter_bvec(&i, ITER_BVEC | WRITE, bvec, 1, bvec->bv_len);
	file_start_write(file);
	bw = vfs_iter_write(file, &i, pos, 0);
	file_end_write(file);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	iov_iter_bvec(&i, ITER_BVEC | WRITE, bvec, 1, bvec->bv_len);
	file_start_write(file);
	bw = vfs_iter_write(file, &i, pos);
	file_end_write(file);
#else
	bw = vfs_write(file, kaddr, bvec->bv_len, pos);
	kunmap(bvec->bv_page);
#endif
	set_fs(old_fs);

	if (likely(bw == bvec->bv_len)) {
		pxd_printk("Write successful at byte offset %llu, length %i.\n",
                        (unsigned long long)*pos, bvec->bv_len);
		return 0;
	}
	printk(KERN_ERR "Write error at byte offset %llu, length %i.\n",
                        (unsigned long long)*pos, bvec->bv_len);
	if (bw >= 0) bw = -EIO;
	return bw;
}

static int do_pxd_send(struct pxd_device *pxd_dev, struct file *file, struct bio *bio, loff_t pos) {
	int ret = 0;
	int nsegs = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif

	pxd_printk("do_pxd_send bio%p, off%lld bio_segments %d\n", bio, pos, bio_segments(bio));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	bio_for_each_segment(bvec, bio, i) {
		nsegs++;
		ret = _pxd_write(file, &bvec, &pos);
		if (ret < 0) {
			printk(KERN_ERR"do_pxd_write pos %lld page %p, off %u for len %d FAILED %d\n",
				pos, bvec.bv_page, bvec.bv_offset, bvec.bv_len, ret);
			return ret;
		}

		cond_resched();
	}
#else
	bio_for_each_segment(bvec, bio, i) {
		nsegs++;
		ret = _pxd_write(file, bvec, &pos);
		if (ret < 0) {
			pxd_printk("do_pxd_write pos %lld page %p, off %u for len %d FAILED %d\n",
				pos, bvec->bv_page, bvec->bv_offset, bvec->bv_len, ret);
			return ret;
		}

		cond_resched();
	}
#endif
	atomic_add(nsegs, &pxd_dev->fp.nwrite_counter);
	atomic_inc(&pxd_dev->fp.nio_write);
	return 0;
}

static
ssize_t _pxd_read(struct file *file, struct bio_vec *bvec, loff_t *pos) {
	int result = 0;

    /* read from file at offset pos into the buffer */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
	struct iov_iter i;

	iov_iter_bvec(&i, READ, bvec, 1, bvec->bv_len);
	result = vfs_iter_read(file, &i, pos, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	struct iov_iter i;

	iov_iter_bvec(&i, ITER_BVEC|READ, bvec, 1, bvec->bv_len);
	result = vfs_iter_read(file, &i, pos, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct iov_iter i;

	iov_iter_bvec(&i, ITER_BVEC|READ, bvec, 1, bvec->bv_len);
	result = vfs_iter_read(file, &i, pos);
#else
	mm_segment_t old_fs = get_fs();
	void *kaddr = kmap(bvec->bv_page) + bvec->bv_offset;

	set_fs(get_ds());
	result = vfs_read(file, kaddr, bvec->bv_len, pos);
	set_fs(old_fs);
	kunmap(bvec->bv_page);
#endif
	if (result < 0) printk(KERN_ERR "__vfs_read return %d\n", result);
	return result;
}

static ssize_t pxd_receive(struct pxd_device *pxd_dev, struct file *file, struct bio *bio, loff_t *pos)
{
	ssize_t s;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	struct bio_vec bvec;
	struct bvec_iter i;
#else
	struct bio_vec *bvec;
	int i;
#endif

	pxd_printk("pxd_receive[%llu] with bio=%p, pos=%llu, nsects=%u\n",
				pxd_dev->dev_id, bio, *pos, REQUEST_GET_SECTORS(bio));
	bio_for_each_segment(bvec, bio, i) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
		s = _pxd_read(file, &bvec, pos);
		if (s < 0) return s;

		if (s != bvec.bv_len) {
			zero_fill_bio(bio);
			break;
		}
#else
		s = _pxd_read(file, bvec, pos);
		if (s < 0) return s;

		if (s != bvec->bv_len) {
			zero_fill_bio(bio);
			break;
		}
#endif
	}
	return 0;
}

static void __pxd_cleanup_block_io(struct pxd_io_tracker *head) {
	pxd_printk("__pxd_cleanup_block_io for bio %p, head %p\n", head->orig, head);

	while (!list_empty(&head->replicas)) {
		struct pxd_io_tracker *repl = list_first_entry(&head->replicas, struct pxd_io_tracker, item);
		pxd_printk("__pxd_cleanup_block_io for head %p, repl %p\n", head, repl);
		list_del(&repl->item);
		bio_put(&repl->clone);
	}

	pxd_printk("__pxd_cleanup_block_io freeing head %p\n", head);
	bio_put(&head->clone);
}

static void pxd_complete_io(struct bio* bio) {
	struct pxd_io_tracker *iot = container_of(bio, struct pxd_io_tracker, clone);
	struct pxd_device *pxd_dev = bio->bi_private;
	struct pxd_io_tracker *head = iot->head;

	pxd_io_printk("%s: dev m %d g %lld %s at %ld len %d bytes %d pages "
			"flags 0x%x op %#x op_flags 0x%x\n", __func__,
			pxd_dev->minor, pxd_dev->dev_id,
			bio_data_dir(bio) == WRITE ? "wr" : "rd",
			BIO_SECTOR(bio) * SECTOR_SIZE, BIO_SIZE(bio),
			bio->bi_vcnt, bio->bi_flags,
			(bio->bi_opf & REQ_OP_MASK),
			((bio->bi_opf & ~REQ_OP_MASK) >> REQ_OP_BITS));

	pxd_printk("pxd_complete_io for bio %p (pxd %p) with head %p active %d\n",
			bio, pxd_dev, head, atomic_read(&head->active));

	if (!atomic_dec_and_test(&head->active)) {
		// not all responses have come back
		// but update head status if this is a failure
		//int error = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		if (bio->bi_status) {
			atomic_inc(&head->fails);
		}
		//error = bio->bi_status;
#else
		if (bio->bi_error) {
			atomic_inc(&head->fails);
		}
		//error = bio->bi_error;
#endif
		pxd_printk("pxd_complete_io for bio %p (pxd %p) with head %p active %d with error %d early return\n",
			bio, pxd_dev, head, atomic_read(&head->active), error);

		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	generic_end_io_acct(pxd_dev->disk->queue, bio_op(bio), &pxd_dev->disk->part0, iot->start);
#else
	generic_end_io_acct(bio_data_dir(bio), &pxd_dev->disk->part0, iot->start);
#endif

	pxd_printk("pxd_complete_io for bio %p (pxd %p) with head %p active %d - completing orig %p\n",
			bio, pxd_dev, head, atomic_read(&head->active), iot->orig);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
{
	iot->orig->bi_status = bio->bi_status;
	if (atomic_read(&head->fails)) {
		iot->orig->bi_status = -EIO; // mark failure
	}
	bio_endio(iot->orig);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
{
	int status = bio->bi_error;
	if (atomic_read(&head->fails)) {
		status = -EIO; // mark failure
	}
	if (status) {
		bio_io_error(iot->orig);
	} else {
		bio_endio(iot->orig);
	}
}
#else
	int status = bio->bi_error;
	if (atomic_read(&head->fails)) {
		status = -EIO; // mark failure
	}
	bio_endio(iot->orig, status);
#endif

	__pxd_cleanup_block_io(head);

	/* free up from any prior congestion wait */
	spin_lock_irq(&pxd_dev->lock);

	atomic_dec(&pxd_dev->fp.ncount);
	atomic_inc(&pxd_dev->fp.ncomplete);

	if (atomic_read(&pxd_dev->fp.ncount) < pxd_dev->fp.nr_congestion_off) {
		wake_up(&pxd_dev->fp.congestion_wait);
	}
	spin_unlock_irq(&pxd_dev->lock);
}

static struct pxd_io_tracker* __pxd_init_block_replica(struct pxd_device *pxd_dev,
		struct bio *bio, struct file *fileh) {
	struct bio* clone_bio;
	struct pxd_io_tracker* iot;
	struct address_space *mapping = fileh->f_mapping;
	struct inode *inode = mapping->host;
	struct block_device *bdi = I_BDEV(inode);

	pxd_printk("pxd %p:__pxd_init_block_replica entering with bio %p, fileh %p with blkg %p\n",
			pxd_dev, bio, fileh, bio->bi_blkg);

	clone_bio = bio_clone_fast(bio, GFP_KERNEL, ppxd_bio_set);
	if (!clone_bio) {
		pxd_printk(KERN_ERR"No memory for io context");
		return NULL;
	}

	iot = container_of(clone_bio, struct pxd_io_tracker, clone);

	iot->pxd_dev = pxd_dev;
	iot->head = iot;
	INIT_LIST_HEAD(&iot->replicas);
	INIT_LIST_HEAD(&iot->item);
	iot->orig = bio;
	iot->start = jiffies;
	atomic_set(&iot->active, 0);
	atomic_set(&iot->fails, 0);
	iot->file = fileh;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
	iot->read = (bio_op(bio) == REQ_OP_READ);
#else
	iot->read = (bio_data_dir(bio) == READ);
#endif

	pxd_printk("pxd %p:__pxd_init_block_replica clone bio %p (blkg %p), resetting backing block dev to %p\n",
			pxd_dev, clone_bio, clone_bio->bi_blkg, bdi);

	if (S_ISBLK(inode->i_mode)) {
		BIO_SET_DEV(clone_bio, bdi);
	}
	clone_bio->bi_private = pxd_dev;
	clone_bio->bi_end_io = pxd_complete_io;

	pxd_printk("pxd %p:__pxd_init_block_replica allocated repl %p for orig bio %p\n",
			pxd_dev, iot, bio);

	return iot;
}

static
struct pxd_io_tracker* __pxd_init_block_head(struct pxd_device *pxd_dev, struct bio* bio) {
	struct pxd_io_tracker* head;
	struct pxd_io_tracker *repl;
	int index;

	pxd_printk("pxd %p:__pxd_init_block_replica to allocate iotracker for bio %p\n",
			pxd_dev, bio);

	head = __pxd_init_block_replica(pxd_dev, bio, pxd_dev->fp.file[0]);
	if (!head) {
		return NULL;
	}
	// initialize the replicas only if the request is non-read
	if (!head->read) {
		for (index=1; index<pxd_dev->fp.nfd; index++) {
			repl = __pxd_init_block_replica(pxd_dev, bio, pxd_dev->fp.file[index]);
			if (!repl) {
				goto repl_cleanup;
			}

			repl->head = head;
			list_add(&repl->item, &head->replicas);
		}
	}

	pxd_printk("pxd %p:__pxd_init_block_head allocated head %p for orig bio %p nfd %d\n",
			pxd_dev, head, bio, pxd_dev->fp.nfd);
	return head;

repl_cleanup:
	__pxd_cleanup_block_io(head);
	return NULL;
}

static void _pxd_setup(struct pxd_device *pxd_dev, bool enable) {
	if (!enable) {
		printk(KERN_ERR "_pxd_setup called to disable IO\n");
		pxd_dev->connected = false;
	} else {
		printk(KERN_ERR "_pxd_setup called to enable IO\n");
	}

	if (enable) {
		spin_lock_irq(&pxd_dev->lock);
		enableFastPath(pxd_dev, true);
		spin_unlock_irq(&pxd_dev->lock);
	}

	if (enable) pxd_dev->connected = true;
}

void pxdctx_set_connected(struct pxd_context *ctx, bool enable) {
	struct list_head *cur;
	spin_lock(&ctx->lock);
	list_for_each(cur, &ctx->list) {
		struct pxd_device *pxd_dev = container_of(cur, struct pxd_device, node);

		_pxd_setup(pxd_dev, enable);
	}
	spin_unlock(&ctx->lock);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
static int __do_bio_filebacked(struct pxd_device *pxd_dev, struct pxd_io_tracker *iot)
{
	struct bio *bio = &iot->clone;
	loff_t pos;
	unsigned int op = bio_op(bio);
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	generic_start_io_acct(pxd_dev->disk->queue, bio_op(bio), REQUEST_GET_SECTORS(bio), &pxd_dev->disk->part0);
#else
	generic_start_io_acct(bio_data_dir(bio), REQUEST_GET_SECTORS(bio), &pxd_dev->disk->part0);
#endif

	pxd_printk("do_bio_filebacked for new bio (pending %u)\n",
				atomic_read(&pxd_dev->fp.ncount));
	pos = ((loff_t) bio->bi_iter.bi_sector << 9);

	switch (op) {
	case REQ_OP_READ:
		ret = pxd_receive(pxd_dev, iot->file, bio, &pos);
		goto out;
	case REQ_OP_WRITE:

		if (bio->bi_opf & REQ_PREFLUSH) {
			atomic_inc(&pxd_dev->fp.nio_preflush);
			ret = _pxd_flush(pxd_dev, iot->file);
			if (ret < 0) goto out;
		}

		/* Before any newer writes happen, make sure previous write/sync complete */
		pxd_check_write_cache_flush(pxd_dev, iot->file);

		ret = do_pxd_send(pxd_dev, iot->file, bio, pos);
		if (ret < 0) goto out;

		if (bio->bi_opf & REQ_FUA) {
			atomic_inc(&pxd_dev->fp.nio_fua);
			ret = _pxd_flush(pxd_dev, iot->file);
			if (ret < 0) goto out;
		}

		ret = 0; goto out;

	case REQ_OP_FLUSH:
		ret = _pxd_flush(pxd_dev, iot->file);
		goto out;
	case REQ_OP_DISCARD:
	case REQ_OP_WRITE_ZEROES:
		ret = _pxd_bio_discard(pxd_dev, iot->file, bio, pos);
		goto out;
	default:
		WARN_ON_ONCE(1);
		ret = -EIO;
		goto out;
	}

out:
	if (ret < 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		bio->bi_status = ret;
#else
		bio->bi_error = ret;
#endif
	}
	pxd_complete_io(bio);

	return ret;
}

#else
static int __do_bio_filebacked(struct pxd_device *pxd_dev, struct pxd_io_tracker *iot)
{
	loff_t pos;
	int ret;
	struct bio *bio = &iot->clone;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	pos = ((loff_t) bio->bi_iter.bi_sector << 9);
#else
	pos = ((loff_t) bio->bi_sector << 9);
#endif

	// mark status all good to begin with!
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	bio->bi_status = 0;
#else
	bio->bi_error = 0;
#endif
	if (bio_data_dir(bio) == WRITE) {
		pxd_printk("bio bi_rw %#lx, flush %#llx, fua %#llx, discard %#llx\n", bio->bi_rw, REQ_FLUSH, REQ_FUA, REQ_DISCARD);

		/*
		 * We use punch hole to reclaim the free space used by the
		 * image a.k.a. discard. However we do not support discard if
		 * encryption is enabled, because it may give an attacker
		 * useful information.
		 */
		if (bio->bi_rw & REQ_DISCARD) {
			ret = _pxd_bio_discard(pxd_dev, iot->file, bio, pos);
			goto out;
		}
		/* Before any newer writes happen, make sure previous write/sync complete */
		pxd_check_write_cache_flush(pxd_dev, iot->file);
		ret = do_pxd_send(pxd_dev, iot->file, bio, pos);

		if (!ret) {
			if ((bio->bi_rw & REQ_FUA)) {
				atomic_inc(&pxd_dev->fp.nio_fua);
				ret = _pxd_flush(pxd_dev, iot->file);
				if (ret < 0) goto out;
			} else if ((bio->bi_rw & REQ_FLUSH)) {
				ret = _pxd_flush(pxd_dev, iot->file);
				if (ret < 0) goto out;
			}
		}

	} else {
		ret = pxd_receive(pxd_dev, iot->file, bio, &pos);
	}

out:
	if (ret < 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		bio->bi_status = ret;
#else
		bio->bi_error = ret;
#endif
	}
	pxd_complete_io(bio);

	return ret;
}

#endif

static inline void pxd_handle_io(struct thread_context *tc, struct pxd_io_tracker *head)
{
	struct pxd_device *pxd_dev = head->pxd_dev;
	struct bio *bio = head->orig;

	//
	// Based on the nfd mapped on pxd_dev, that many cloned bios shall be
	// setup, then each replica takes its own processing path, which could be
	// either file backup or block device backup.
	//
	struct pxd_io_tracker *curr;

	// NOTE NOTE NOTE accessing out of lock
	if (!pxd_dev->connected) {
		printk(KERN_ERR"px is disconnected, failing IO.\n");
		__pxd_cleanup_block_io(head);
		BIO_ENDIO(bio, -ENXIO);
		goto wake_up;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	generic_start_io_acct(pxd_dev->disk->queue, bio_op(bio), REQUEST_GET_SECTORS(bio), &pxd_dev->disk->part0);
#else
	generic_start_io_acct(bio_data_dir(bio), REQUEST_GET_SECTORS(bio), &pxd_dev->disk->part0);
#endif

	// initialize active io to configured replicas
	if (!head->read) {
		atomic_set(&head->active, pxd_dev->fp.nfd);
		// submit all replicas linked from head, if not read
		list_for_each_entry(curr, &head->replicas, item) {
			if (S_ISBLK(curr->file->f_inode->i_mode)) {
				SUBMIT_BIO(&curr->clone);
				atomic_inc(&pxd_dev->fp.nswitch);
			} else {
				__do_bio_filebacked(pxd_dev, curr);
			}
		}
	} else {
		atomic_set(&head->active, 1);
	}

	// submit head bio the last
	if (S_ISBLK(head->file->f_inode->i_mode)) {
		SUBMIT_BIO(&head->clone);
		atomic_inc(&pxd_dev->fp.nswitch);
	} else {
		__do_bio_filebacked(pxd_dev, head);
	}
}

static void pxd_add_io(struct thread_context *tc, struct pxd_io_tracker *head, int rw) {
	if (rw != READ) {
		spin_lock_irq(&tc->write_lock);
		list_add(&head->item, &tc->iot_writers);
		spin_unlock_irq(&tc->write_lock);

		wake_up(&tc->write_event);
	} else {
		spin_lock_irq(&tc->read_lock);
		list_add(&head->item, &tc->iot_readers);
		spin_unlock_irq(&tc->read_lock);

		wake_up(&tc->read_event);
	}
}

static struct pxd_io_tracker* pxd_get_io(struct thread_context *tc, int rw) {
	struct pxd_io_tracker* head = NULL;

	if (rw != READ) {
		spin_lock_irq(&tc->write_lock);
		if (!list_empty(&tc->iot_writers)) {
			head = list_first_entry(&tc->iot_writers, struct pxd_io_tracker, item);
			list_del(&head->item);
		}
		spin_unlock_irq(&tc->write_lock);
	} else {
		spin_lock_irq(&tc->read_lock);
		if (!list_empty(&tc->iot_readers)) {
			head = list_first_entry(&tc->iot_readers, struct pxd_io_tracker, item);
			list_del(&head->item);
		}
		spin_unlock_irq(&tc->read_lock);
	}

	return head;
}

static int pxd_io_thread(void *data, int rw) {
	struct thread_context *tc = data;
	struct pxd_io_tracker *head;

	while (!kthread_should_stop()) {
		pxd_wait_io(tc, rw);

		head = pxd_get_io(tc, rw);
		if (!head) {
			continue;
		}

		pxd_handle_io(tc, head);
	}
	return 0;
}

static int pxd_io_reader(void *data) {
	return pxd_io_thread(data, READ);
}

static int pxd_io_writer(void *data) {
	return pxd_io_thread(data, WRITE);
}

static void pxd_suspend_io(struct pxd_device *pxd_dev) {
	int need_flush = 0;
	spin_lock_irq(&pxd_dev->fp.suspend_lock);
	if (!pxd_dev->fp.suspend++) {
		printk("For pxd device %llu IO suspended\n", pxd_dev->dev_id);
		need_flush = 1;
	} else {
		printk("For pxd device %llu IO already suspended\n", pxd_dev->dev_id);
	}
	spin_unlock_irq(&pxd_dev->fp.suspend_lock);

	// need to wait for inflight IOs to complete
	if (need_flush) {
		do {
			int nactive = atomic_read(&pxd_dev->fp.ncount);
			if (!nactive) break;
			printk(KERN_WARNING"pxd device %llu still has %d active IO, waiting completion to suspend",
					pxd_dev->dev_id, nactive);
			msleep_interruptible(100);
		} while (1);
	}
}

static void pxd_resume_io(struct pxd_device *pxd_dev) {
	spin_lock_irq(&pxd_dev->fp.suspend_lock);
	pxd_dev->fp.suspend--;
	if (!pxd_dev->fp.suspend) {
		printk("For pxd device %llu IO resumed\n", pxd_dev->dev_id);
		wake_up(&pxd_dev->fp.suspend_wait);
	} else {
		printk("For pxd device %llu IO still suspended(%d)\n",
				pxd_dev->dev_id, pxd_dev->fp.suspend);
	}
	spin_unlock_irq(&pxd_dev->fp.suspend_lock);
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
	mode_t mode = open_mode(pxd_dev->mode);
	char modestr[32];

	pxd_suspend_io(pxd_dev);

	decode_mode(mode, modestr);
	printk("device %llu mode %s\n", pxd_dev->dev_id, modestr);
	for (i=0; i<nfd; i++) {
		if (fp->file[i] > 0) { /* valid fd exists already */
			if (force) {
				filp_close(fp->file[i], NULL);
				f = filp_open(fp->device_path[i], mode, 0600);
				if (IS_ERR_OR_NULL(f)) {
					printk(KERN_ERR"Failed attaching path: device %llu, path %s err %ld\n",
						pxd_dev->dev_id, fp->device_path[i], PTR_ERR(f));
					goto out_file_failed;
				}
			} else {
				f = fp->file[i];
			}
		} else {
			f = filp_open(fp->device_path[i], mode, 0600);
			if (IS_ERR_OR_NULL(f)) {
				printk(KERN_ERR"Failed attaching path: device %llu, path %s err %ld\n",
					pxd_dev->dev_id, fp->device_path[i], PTR_ERR(f));
				goto out_file_failed;
			}
		}

		fp->file[i] = f;

		inode = f->f_inode;
		printk(KERN_INFO"device %lld:%d, inode %lu mode %#x\n", pxd_dev->dev_id, i, inode->i_ino, mode);
		if (S_ISREG(inode->i_mode)) {
			printk(KERN_INFO"device[%lld:%d] is a regular file - inode %lu\n",
					pxd_dev->dev_id, i, inode->i_ino);
		} else if (S_ISBLK(inode->i_mode)) {
			printk(KERN_INFO"device[%lld:%d] is a block device - inode %lu\n",
				pxd_dev->dev_id, i, inode->i_ino);
		} else {
			printk(KERN_INFO"device[%lld:%d] inode %lu unknown device %#x\n",
				pxd_dev->dev_id, i, inode->i_ino, inode->i_mode);
		}
	}

	pxd_resume_io(pxd_dev);

	printk(KERN_INFO"pxd_dev %llu mode %#x setting up with %d backing volumes, [%p,%p,%p]\n",
		pxd_dev->dev_id, mode, fp->nfd,
		fp->file[0], fp->file[1], fp->file[2]);

	return;

out_file_failed:
	fp->nfd = 0;
	for (i=0; i<nfd; i++) {
		if (fp->file[i] > 0) filp_close(fp->file[i], NULL);
	}
	memset(fp->file, 0, sizeof(fp->file));
	memset(fp->device_path, 0, sizeof(fp->device_path));

	pxd_resume_io(pxd_dev);
	printk(KERN_INFO"Device %llu no backing volume setup, will take slow path\n",
		pxd_dev->dev_id);
}

void disableFastPath(struct pxd_device *pxd_dev) {
	int i;
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;

	pxd_suspend_io(pxd_dev);

	for (i=0; i<fp->nfd; i++) {
		filp_close(fp->file[i], NULL);
	}
	fp->nfd=0;

	pxd_resume_io(pxd_dev);
}

int pxd_fastpath_init(struct pxd_device *pxd_dev) {
	int i;
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;

	fp->nfd = 0; // will take slow path, if additional info not provided.

	pxd_printk("Number of cpu ids %d\n", __px_ncpus);
#if 0
	// configure bg flush based on passed mode of operation
	if (pxd_dev->mode & O_DIRECT) {
		fp->bg_flush_enabled = false; // avoids high latency
		printk("For pxd device %llu background flush disabled\n", pxd_dev->dev_id);
	} else {
		fp->bg_flush_enabled = true; // introduces high latency
		printk("For pxd device %llu background flush enabled\n", pxd_dev->dev_id);
	}
#else
	fp->bg_flush_enabled = false; // avoids high latency
#endif

	fp->n_flush_wrsegs = MAX_WRITESEGS_FOR_FLUSH;

	// device temporary IO suspend
	init_waitqueue_head(&fp->suspend_wait);
	spin_lock_init(&fp->suspend_lock);
	fp->suspend = 0;

	// congestion init
	// hard coded congestion limits within driver
	fp->nr_congestion_on = 128;
	fp->nr_congestion_off = 3/4*128;

	init_waitqueue_head(&fp->congestion_wait);
	init_waitqueue_head(&fp->sync_event);
	spin_lock_init(&fp->sync_lock);

	atomic_set(&fp->nsync_active, 0);
	atomic_set(&fp->nsync, 0);
	atomic_set(&fp->nio_discard, 0);
	atomic_set(&fp->nio_flush, 0);
	atomic_set(&fp->nio_flush_nop, 0);
	atomic_set(&fp->nio_preflush, 0);
	atomic_set(&fp->nio_fua, 0);
	atomic_set(&fp->nio_write, 0);
	atomic_set(&fp->ncount,0);
	atomic_set(&fp->nswitch,0);
	atomic_set(&fp->nslowPath,0);
	atomic_set(&fp->ncomplete,0);
	atomic_set(&fp->nwrite_counter,0);

	for (i=0; i<nr_node_ids; i++) {
		atomic_set(&fp->index[i], 0);
	}

	enableFastPath(pxd_dev, true);

	return 0;
}

void pxd_fastpath_cleanup(struct pxd_device *pxd_dev) {
	disableFastPath(pxd_dev);
}

int pxd_init_fastpath_target(struct pxd_device *pxd_dev, struct pxd_update_path_out *update_path)
{
	mode_t mode = 0;
	int err = 0;
	int i;
	struct file* f;

	mode = open_mode(pxd_dev->mode);
	for (i=0; i<update_path->size; i++) {
		if (!strcmp(pxd_dev->fp.device_path[i], update_path->devpath[i])) {
			// if previous paths are same.. then skip anymore config
			printk(KERN_INFO"pxd%llu already configured for path %s\n",
				pxd_dev->dev_id, pxd_dev->fp.device_path[i]);
			continue;
		}

		if (pxd_dev->fp.file[i] > 0) filp_close(pxd_dev->fp.file[i], NULL);
		f = filp_open(update_path->devpath[i], mode, 0600);
		if (IS_ERR_OR_NULL(f)) {
			printk(KERN_ERR"Failed attaching path: device %llu, path %s, err %ld\n",
				pxd_dev->dev_id, update_path->devpath[i], PTR_ERR(f));
			err = PTR_ERR(f);
			goto out_file_failed;
		}
		pxd_dev->fp.file[i] = f;
		strncpy(pxd_dev->fp.device_path[i], update_path->devpath[i],MAX_PXD_DEVPATH_LEN);
		pxd_dev->fp.device_path[i][MAX_PXD_DEVPATH_LEN] = '\0';
	}
	pxd_dev->fp.nfd = update_path->size;

	/* setup whether access is block or file access */
	enableFastPath(pxd_dev, false);

	return 0;

out_file_failed:
	for (i=0; i<pxd_dev->fp.nfd; i++) {
		if (pxd_dev->fp.file[i] > 0) filp_close(pxd_dev->fp.file[i], NULL);
	}
	pxd_dev->fp.nfd = 0;
	memset(pxd_dev->fp.file, 0, sizeof(pxd_dev->fp.file));
	memset(pxd_dev->fp.device_path, 0, sizeof(pxd_dev->fp.device_path));

	// even if there are errors setting up fastpath, initialize to take slow path,
	// do not report failure outside
	return 0;
}

/* fast path make request function, io entry point */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
blk_qc_t pxd_make_request_fastpath(struct request_queue *q, struct bio *bio)
#else
void pxd_make_request_fastpath(struct request_queue *q, struct bio *bio)
#endif
{
	struct pxd_device *pxd_dev = q->queuedata;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	unsigned int rw = bio_op(bio);
#else
	unsigned int rw = bio_rw(bio);
#endif
	int cpu = smp_processor_id();
	int thread = cpu % __px_ncpus;

	struct pxd_io_tracker *head;
	struct thread_context *tc;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	if (!pxd_dev) {
#else
	if (rw == READA) rw = READ;
	if (!pxd_dev || (rw!=READ && rw != WRITE)) {
#endif
		printk(KERN_ERR"pxd basic sanity fail, pxd_device %p (%llu), rw %#x\n",
				pxd_dev, (pxd_dev? pxd_dev->dev_id: (uint64_t)0), rw);
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	if (!pxd_dev->connected) {
		printk(KERN_ERR"px is disconnected, failing IO.\n");
		bio_io_error(bio);
		return BLK_QC_RETVAL;
	}

	// If IO suspended, then hang IO onto the suspend wait queue
	{
		spin_lock_irq(&pxd_dev->fp.suspend_lock);
		if (pxd_dev->fp.suspend) {
			printk("pxd device %llu is suspended, IO blocked until device activated[bio %p, wr %d]\n",
				pxd_dev->dev_id, bio, (bio_data_dir(bio) == WRITE));
			wait_event_lock_irq(pxd_dev->fp.suspend_wait, !pxd_dev->fp.suspend, pxd_dev->fp.suspend_lock);
			printk("pxd device %llu re-activated, IO resumed[bio %p, wr %d]\n",
				pxd_dev->dev_id, bio, (bio_data_dir(bio) == WRITE));
		}
		spin_unlock_irq(&pxd_dev->fp.suspend_lock);
	}

	if (!pxd_dev->fp.nfd) {
		pxd_printk("px has no backing path yet, should take slow path IO.\n");
		atomic_inc(&pxd_dev->fp.nslowPath);
		return pxd_make_request_slowpath(q, bio);
	}

	pxd_printk("pxd_make_fastpath_request for device %llu queueing with thread %d\n", pxd_dev->dev_id, thread);

	pxd_io_printk("%s: dev m %d g %lld %s at %ld len %d bytes %d pages "
			"flags 0x%x op %#x op_flags 0x%x\n", __func__,
			pxd_dev->minor, pxd_dev->dev_id,
			bio_data_dir(bio) == WRITE ? "wr" : "rd",
			BIO_SECTOR(bio) * SECTOR_SIZE, BIO_SIZE(bio),
			bio->bi_vcnt, bio->bi_flags,
			(bio->bi_opf & REQ_OP_MASK),
			((bio->bi_opf & ~REQ_OP_MASK) >> REQ_OP_BITS));

	#if 1
	{ /* add congestion handling */
		spin_lock_irq(&pxd_dev->lock);
		if (atomic_read(&pxd_dev->fp.ncount) >= pxd_dev->fp.nr_congestion_on) {
			pxd_printk("Hit congestion... wait until clear\n");
			atomic_inc(&pxd_dev->fp.ncongested);
			wait_event_lock_irq(pxd_dev->fp.congestion_wait,
				atomic_read(&pxd_dev->fp.ncount) < pxd_dev->fp.nr_congestion_off,
				pxd_dev->lock);
			pxd_printk("congestion cleared\n");
		}

		atomic_inc(&pxd_dev->fp.ncount);
		spin_unlock_irq(&pxd_dev->lock);

	}
	#endif

#if 0
	/* keep writes on same cpu, but allow reads to spread but within same numa node */
	if (rw == READ) {
		int node = cpu_to_node(cpu);
		thread = getnextcpu(node, atomic_add_return(1, &pxd_dev->fp.index[node]));
	}
#endif


	head = __pxd_init_block_head(pxd_dev, bio);
	if (!head) {
		BIO_ENDIO(bio, -ENOMEM);

		// non-trivial high memory pressure failing IO
		spin_lock_irq(&pxd_dev->lock);
		atomic_dec(&pxd_dev->fp.ncount);
		spin_unlock_irq(&pxd_dev->lock);

		return BLK_QC_RETVAL;
	}

	tc = &g_tc[thread];
	BUG_ON(!tc);
	pxd_add_io(tc, head, rw);

	pxd_printk("pxd_make_request for device %llu done\n", pxd_dev->dev_id);
	return BLK_QC_RETVAL;
}
