#ifdef __PX_FASTPATH__
#include <linux/version.h>
#include <linux/types.h>
#include <linux/delay.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)  || (LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0) && (defined(__EL8__) || defined(__SUSE_EQ_SP5__)))
#include <linux/kdev_t.h>
#include <linux/uuid.h>
#include <linux/blk_types.h>
#include <linux/device.h>
#include <linux/xarray.h>
#include <linux/printk.h>
#else
#include <linux/genhd.h>
#endif
#include <linux/workqueue.h>

#include "pxd_bio.h"
#include "pxd.h"
#include "pxd_core.h"
#include "pxd_compat.h"
#include "pxd_trace.h"
#include "kiolib.h"

// global fastpath IO work queue
static struct workqueue_struct *gwq;

extern uint32_t pxd_num_fpthreads;

#define MAX_PXFP_WORKERS_PER_NODE (pxd_num_fpthreads) /// keep it power of 2.

struct pxfpcontext_per_node {
	bool valid;
#define MAX_ALLOC_PXFP_WORKER_THREADS_PER_NODE (NR_CPUS)
	struct kthread_worker *fpworker[MAX_ALLOC_PXFP_WORKER_THREADS_PER_NODE];
};
struct kthread_worker *fpdefault = NULL;
struct pxfpcontext_per_node pxfpctxt[MAX_NUMNODES];

#define BURST_IO (8)
#define BURST_MASK (BURST_IO-1)
struct pxfpcontext_percpu {
  uint8_t fpbatch;
  unsigned mapped_cpu;
};
struct pxfpcontext_percpu pxfp_percpu[NR_CPUS];

static void fastpath_map_workers(void)
{
    int i;

    for (i=0; i<NR_CPUS; i++) {
	pxfp_percpu[i].mapped_cpu = i;
    }
}

/*
 * Flush all fastpath kthread workers.
 *
 * Called from disableFastPath (and pxd_fp_freeze_start) to drain any
 * fastpath work items so filp_close is safe. Two things this must NOT
 * do:
 *
 * 1. Self-flush. If we're running as a work item on one of these very
 *    workers (e.g. pxd_io_failover branch (b) chained into
 *    disableFastPath), kthread_flush_worker on our own worker enqueues
 *    a barrier and wait_for_completion's on it. The barrier can only
 *    run after we return, and we can't return until the completion
 *    fires - deadlock. Skip the current worker by comparing its
 *    ->task against `current`.
 *
 * 2. Assume it drained follow-up work queued by items it flushed.
 *    kthread_flush_worker's barrier is enqueued once at call time;
 *    work items enqueued by a running flushed item land after the
 *    barrier and are not waited for. That's a limitation of the
 *    primitive, not this wrapper. Callers must not depend on
 *    fastpath_flush_work draining chained work.
 */
static void fastpath_flush_work(void) {
       int node;
       struct task_struct *self = current;

       for (node = 0; node < MAX_NUMNODES; node++) {
               struct pxfpcontext_per_node *c = &pxfpctxt[node];
               if (c->valid) {
                       int i;
                       for (i = 0; i < MAX_PXFP_WORKERS_PER_NODE; i++) {
                               struct kthread_worker *worker = c->fpworker[i];
                               if (worker != NULL && worker->task != self) {
                                       kthread_flush_worker(worker);
                               }
                       }
               }
       }
}

int fastpath_adjust_fpthreads(int new_pxd_num_fpthreads)
{
	int old_pxd_num_fpthreads = pxd_num_fpthreads;
	int node, cpu;
	int rc = 0;
	char namefmt[64];

	if (new_pxd_num_fpthreads > MAX_ALLOC_PXFP_WORKER_THREADS_PER_NODE) {
		printk(KERN_WARNING"pxd_num_fpthreads(%d) over max limit(%d), reset to max\n", new_pxd_num_fpthreads, MAX_ALLOC_PXFP_WORKER_THREADS_PER_NODE);
		new_pxd_num_fpthreads = MAX_ALLOC_PXFP_WORKER_THREADS_PER_NODE;
	}
	if (new_pxd_num_fpthreads == old_pxd_num_fpthreads) {
		return 0;
	}

	if (new_pxd_num_fpthreads == 0) {
		new_pxd_num_fpthreads = DEFAULT_PXFP_WORKERS_PER_NODE;
	}

	for_each_online_node(node) {
		struct pxfpcontext_per_node *c = &pxfpctxt[node];
		const cpumask_t *cpumask = cpumask_of_node(node);
		int active;

		if (cpumask_empty(cpumask)) {
			// NUMA node with no cpu's?! - skip it.
			printk(KERN_NOTICE"skipping online numa node %d with no attached cpus\n", node);
			continue;
		}

		active = 0;
		// Count already created threads and create more if required
		for_each_cpu(cpu, cpumask) {
			struct kthread_worker* worker;
			if (!cpu_online(cpu)) {
				continue;
			}

			if (active == new_pxd_num_fpthreads) {
				break;
			}

			// Thread is already created just increment count
			// While decreasing active will reach new_pxd_num_fpthreads
			// without creating new threads
			if (c->fpworker[active] != NULL) {
				active++;
				continue;
			}

			// We need increase num threads, so create more threads
			snprintf(namefmt, sizeof(namefmt), "pxfpn%dc%d", node, cpu);
			worker = kthread_create_worker_on_cpu(cpu, 0, namefmt);
			if (IS_ERR_OR_NULL(worker)) {
				rc = PTR_ERR(worker);
				goto out;
			}
			c->valid = true;
			c->fpworker[active++] = worker;
			if (fpdefault == NULL) {
				fpdefault = worker;
			}
		}

		// If active is less than new_pxd_num_fpthreads,
		// num cpu is less than new_pxd_num_fpthreads and we cannot create more threads
		if (active < new_pxd_num_fpthreads) {
			new_pxd_num_fpthreads = active;
		}
	}

	fastpath_map_workers();

	printk(KERN_NOTICE"Updated fpthreads from %d to %d", pxd_num_fpthreads, new_pxd_num_fpthreads);
	pxd_num_fpthreads = new_pxd_num_fpthreads;
	return 0;

out:
	printk(KERN_ERR"fastpath fpthread init failure %d\n", rc);
	for (node=0; node < MAX_NUMNODES; node++) {
		struct pxfpcontext_per_node *c = &pxfpctxt[node];
		if (c->valid) {
			int i;
			for (i=pxd_num_fpthreads; i<MAX_ALLOC_PXFP_WORKER_THREADS_PER_NODE; i++) {
				if (c->fpworker[i] != NULL) {
					kthread_destroy_worker(c->fpworker[i]);
					c->fpworker[i] = NULL;
				}
			}
		}
	}
	return rc;
}

int fastpath_init(void)
{
	int rc = 0;
	int node, cpu;
	char namefmt[64];

	// sanity check the pxfp worker thread values from mod param
	if (MAX_PXFP_WORKERS_PER_NODE > MAX_ALLOC_PXFP_WORKER_THREADS_PER_NODE) {
		printk(KERN_WARNING"pxd_num_fpthreads(%d) over max limit(%d), reset to max\n", MAX_PXFP_WORKERS_PER_NODE, MAX_ALLOC_PXFP_WORKER_THREADS_PER_NODE);
		MAX_PXFP_WORKERS_PER_NODE = MAX_ALLOC_PXFP_WORKER_THREADS_PER_NODE;
	}

	printk(KERN_INFO"PXD_BIO_BLKMQ CPU %d/%d, NUMA nodes %d/%d\n", num_online_cpus(), NR_CPUS, num_online_nodes(), MAX_NUMNODES);
	printk(KERN_INFO"pxd inited with %d workers per numa node\n", MAX_PXFP_WORKERS_PER_NODE);
	gwq = alloc_workqueue("pxwq", WQ_HIGHPRI, 0);
	if (!gwq) {
		printk(KERN_ERR"fastpath workqueue alloc failure\n");
		rc = -ENOMEM;
		goto out;
	}

	memset(&pxfpctxt, 0, sizeof(pxfpctxt));
	for_each_online_node(node) {
		struct pxfpcontext_per_node *c = &pxfpctxt[node];
		const cpumask_t *cpumask = cpumask_of_node(node);
		int active;

		// unexpected!
		if (c->valid) {
			printk(KERN_NOTICE"pxd fastpath context on numa node %d already initialized, skipping\n", node);
			continue;
		}

		if (cpumask_empty(cpumask)) {
			// NUMA node with no cpu's?! - skip it.
			printk(KERN_NOTICE"skipping online numa node %d with no attached cpus\n", node);
			continue;
		}

		active = 0;
		for_each_cpu(cpu, cpumask) {
			struct kthread_worker* worker;
			if (!cpu_online(cpu)) {
				continue;
			}
			snprintf(namefmt, sizeof(namefmt), "pxfpn%dc%d", node, cpu);
			worker = kthread_create_worker_on_cpu(cpu, 0, namefmt);
			if (IS_ERR_OR_NULL(worker)) {
				rc = PTR_ERR(worker);
				goto out;
			}
			c->valid = true;
			c->fpworker[active++] = worker;
			if (fpdefault == NULL) {
				fpdefault = worker;
			}
			if (active == MAX_PXFP_WORKERS_PER_NODE) {
				break;
			}
		}
	}
	// always confirm default
	if (fpdefault == NULL) {
		// fastpath init failed.
		printk(KERN_ERR"found no online node with online cpus\n");
		rc = -EINVAL;
		goto out;
	}

	fastpath_map_workers();

	rc = __fastpath_init();
	if (rc == 0) {
		return rc;
	}
	/* fallthrough */
out:
	printk(KERN_ERR"fastpath workqueue init failure %d\n", rc);
	for (node=0; node < MAX_NUMNODES; node++) {
		struct pxfpcontext_per_node *c = &pxfpctxt[node];
		if (c->valid) {
			int i;
			for (i=0; i<MAX_ALLOC_PXFP_WORKER_THREADS_PER_NODE; i++) {
				if (c->fpworker[i] != NULL) {
					kthread_destroy_worker(c->fpworker[i]);
					c->fpworker[i] = NULL;
				}
			}
		}
	}
	if (gwq != NULL) {
		destroy_workqueue(gwq);
	}
	return rc;
}

void fastpath_cleanup(void)
{
	int i;
	int node;

	if (gwq != NULL) {
		destroy_workqueue(gwq);
	}

	for (node=0; node < MAX_NUMNODES; node++) {
		struct pxfpcontext_per_node *c = &pxfpctxt[node];
		if (c->valid) {
			for (i=0; i<MAX_ALLOC_PXFP_WORKER_THREADS_PER_NODE; i++) {
				if (c->fpworker[i] != NULL) {
					kthread_destroy_worker(c->fpworker[i]);
					c->fpworker[i] = NULL;
				}
			}
		}
	}
	__fastpath_cleanup();
}

struct workqueue_struct* fastpath_workqueue(void)
{
	return gwq; // only used by non-blkmq code and special cases
}

/* Ctx-scoped quiescent window for fastpath transitions.
 *
 * Kernel workqueues have no module-callable "freeze" primitive
 * (freeze_workqueues_begin/thaw_workqueues are not EXPORT_SYMBOL'd and
 * are driven only by the PM subsystem). WQ_FREEZABLE only participates
 * in system suspend/resume. We implement the freeze semantic ourselves
 * for the fastpath IO path.
 *
 * Invariant enforced by this pair:
 *   Every writer of pxd_dev->connected, pxd_dev->fp.fastpath, or
 *   ctx->fc.connected runs INSIDE a freeze window. Every reader that
 *   makes a branch decision (pxd_io_failover) either observed the
 *   pre-window state (started before the gate; drained by freeze_start)
 *   or the post-window state (parked during the window; drained by
 *   freeze_end or the intervening pxdctx_reset_fastpath). It never
 *   observes a mid-transition state.
 *
 * Park zone: pxd_dev->fp.failQ. When gate is set, pxd_io_failover
 * simply list_add_tail(&fproot->wait, &pxd_dev->fp.failQ) under
 * fp.fail_lock and returns. The existing drain functions
 * (pxd_reissuefailQ / __pxd_abortfailQ) handle the parked items.
 *
 * Note during a failover_work/abort_work-driven freeze, ctx->fc.connected
 * is already 0 (pxd_control_release wrote it before scheduling). So a
 * fastpath IO error that races the freeze naturally would take branch (b)
 * or (a); neither uses failQ. The only way an item lands on failQ during
 * this window is via the park path here. That means the drain in
 * freeze_end catches only parked items, never mid-branch-(c) items.
 */
void pxd_fp_freeze_start(struct pxd_context *ctx)
{
	WRITE_ONCE(ctx->fp_freeze, 1);
	/* Order gate-set ahead of the flush; readers of fp_freeze in
	 * pxd_io_failover use READ_ONCE and pair with this. */
	smp_wmb();
	/* Drain: any pxd_io_failover kthread work already running gets to
	 * complete with pre-freeze state. New pxd_io_failover work queued
	 * after this write observes fp_freeze=1 and parks. */
	fastpath_flush_work();
	if (gwq != NULL) {
		flush_workqueue(gwq);
	}
}

void pxd_fp_freeze_end(struct pxd_context *ctx, bool fail_io)
{
	struct pxd_device *pxd_dev;
	size_t ndevs;
	struct pxd_device **snap_list;
	size_t i = 0;
	size_t j;
	unsigned long flags;
	struct list_head ios;

	/* Clear the gate. New pxd_io_failover items entering after this
	 * observe fp_freeze=0 and take the normal (a)/(b)/(c) branches.
	 * They do NOT touch failQ under the park path.
	 *
	 * Ordering: smp_wmb before the write so writers who set device
	 * state during the freeze window are visible to readers who see
	 * fp_freeze=0. */
	smp_wmb();
	WRITE_ONCE(ctx->fp_freeze, 0);

	/* Drain any items that parked between pxdctx_reset_fastpath's
	 * per-device failQ drain and the gate-clear above. Because we're
	 * in a failover_work/abort_work path, ctx->fc.connected is still 0,
	 * so branch (c) can't fire; anything on failQ right now is a parked
	 * item from the freeze window (see the note in freeze_start).
	 *
	 * Use snapshot+refcount to avoid holding ctx->lock across
	 * pxd_reissuefailQ (which does bio submission through the native
	 * path and can sleep). */
	spin_lock(&ctx->lock);
	ndevs = ctx->num_devices;
	spin_unlock(&ctx->lock);

	if (ndevs == 0) {
		return;
	}

	snap_list = kcalloc(ndevs, sizeof(*snap_list), GFP_KERNEL);
	if (!snap_list) {
		/* Best-effort: without allocation we can't do the drain safely.
		 * The stragglers will be caught by any subsequent teardown or
		 * by pxd_abort_context's __pxd_abortfailQ if that fires. Log
		 * loudly so this is visible. */
		pr_warn("%s: ctx %s: kcalloc failed; parked IOs may linger on failQ\n",
			__func__, ctx->name);
		return;
	}

	spin_lock(&ctx->lock);
	list_for_each_entry(pxd_dev, &ctx->list, node) {
		if (i >= ndevs) {
			break;
		}
		if (READ_ONCE(pxd_dev->removing)) {
			continue;
		}
		if (!fastpath_enabled(pxd_dev)) {
			continue;
		}
		get_device(&pxd_dev->dev);
		snap_list[i++] = pxd_dev;
	}
	spin_unlock(&ctx->lock);

	for (j = 0; j < i; j++) {
		struct pxd_device *dev = snap_list[j];

		INIT_LIST_HEAD(&ios);
		spin_lock_irqsave(&dev->fp.fail_lock, flags);
		list_splice_init(&dev->fp.failQ, &ios);
		spin_unlock_irqrestore(&dev->fp.fail_lock, flags);

		if (list_empty(&ios)) {
			put_device(&dev->dev);
			continue;
		}

		if (fail_io) {
			/* Hard-fail path: put the items back on failQ under lock
			 * and run the abort helper (it walks failQ and ends each
			 * request with -EIO). */
			spin_lock_irqsave(&dev->fp.fail_lock, flags);
			list_splice(&ios, &dev->fp.failQ);
			__pxd_abortfailQ(dev);
			dev->fp.active_failover = false;
			spin_unlock_irqrestore(&dev->fp.fail_lock, flags);
		} else {
			/* Soft path: reissue to native (status=0). */
			pxd_reissuefailQ(dev, &ios, 0);
		}
		put_device(&dev->dev);
	}
	kfree(snap_list);
}

void pxd_abortfailQ(struct pxd_device *pxd_dev)
{
	unsigned long flags;
	spin_lock_irqsave(&pxd_dev->fp.fail_lock, flags);
	__pxd_abortfailQ(pxd_dev);
	spin_unlock_irqrestore(&pxd_dev->fp.fail_lock, flags);
}

// background pxd syncer work function
static void __pxd_syncer(struct work_struct *wi)
{
	struct pxd_sync_ws *ws = (struct pxd_sync_ws*) wi;
	struct pxd_device *pxd_dev = ws->pxd_dev;
	struct pxd_fastpath_extension *fp = &ws->pxd_dev->fp;
	int nfd = fp->nfd;
	int i = ws->index;

	ws->rc = 0; // early complete
	if (i >= nfd || fp->file[i] == NULL) {
		goto out;
	}

	ws->rc = vfs_fsync(fp->file[i], 0);
	if (unlikely(ws->rc)) {
		printk(KERN_ERR"device %llu fsync[%d] failed with %d\n", pxd_dev->dev_id, i, ws->rc);
	}

out:
	BUG_ON(!atomic_read(&fp->sync_done));
	if (atomic_dec_and_test(&fp->sync_done)) {
		complete(&fp->sync_complete);
	}
}

static
bool pxd_sync_work_pending(struct pxd_device *pxd_dev)
{
	int i;
	bool busy = false;

	if (atomic_read(&pxd_dev->fp.sync_done) != 0) {
		return true;
	}

	for (i = 0; i < MAX_PXD_BACKING_DEVS; i++) {
		busy |= work_busy(&pxd_dev->fp.syncwi[i].ws);
	}

	return busy;
}

// external request to initiate failover/fallback on fastpath device
int pxd_request_ioswitch(struct pxd_device *pxd_dev, int code)
{
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;

	// incompat device
	if (!fastpath_enabled(pxd_dev)) {
		printk("device %llu ioswitch request failed (fpenabled %d, fastpath %d)\n",
			   pxd_dev->dev_id, fastpath_enabled(pxd_dev), fp->fastpath);
		return -EINVAL;
	}

	// Check FUSE connection before attempting ioswitch
	if (!pxd_dev->ctx || !READ_ONCE(pxd_dev->ctx->fc.connected)) {
		printk(KERN_WARNING "device %llu ioswitch failed: FUSE disconnected.\n",
			pxd_dev->dev_id);
		return -ENOTCONN;
	}

	switch (code) {
	case PXD_FAILOVER_TO_USERSPACE:
		printk("device %llu initiated failover\n", pxd_dev->dev_id);
		// IO path blocked, a future path refresh will take it to native path
		// enqueue a failover request to userspace on this device.
		trace_pxd_initiate_failover(pxd_dev->dev_id, pxd_dev->minor, FAILOVER_REASON_USERSPACE);
		return pxd_initiate_failover(pxd_dev);
	case PXD_FALLBACK_TO_KERNEL:
		// IO path already routed to userspace.
		// enqueue a fallback marker request to userspace on this device.
		printk("device %llu initiated fallback\n", pxd_dev->dev_id);
		return pxd_initiate_fallback(pxd_dev);
	default:
		// unsupported opcode
		return -EINVAL;
	}
}

#define SYNC_TIMEOUT (60000)
static int wait_for_sync(struct pxd_device *pxd_dev, bool skipsync)
{
        struct pxd_fastpath_extension *fp = &pxd_dev->fp;
        int i;
        // assumes fastpath_enabled() is true
        // and IO is already suspended
        BUG_ON(!fastpath_enabled(pxd_dev));
        BUG_ON(!atomic_read(&fp->suspend));

        if (skipsync) return 0;

        if (pxd_sync_work_pending(pxd_dev)) {
                printk(KERN_INFO "device %llu sync work pending\n", pxd_dev->dev_id);
                return -EBUSY;
        }

        atomic_set(&fp->sync_done, MAX_PXD_BACKING_DEVS);
        reinit_completion(&fp->sync_complete);
        for (i = 0; i < MAX_PXD_BACKING_DEVS; i++) {
                queue_work(fastpath_workqueue(), &fp->syncwi[i].ws);
        }

        if (!wait_for_completion_timeout(&fp->sync_complete,
                                                msecs_to_jiffies(SYNC_TIMEOUT))) {
                // suspend aborted as sync timedout
                return -EBUSY;
        }

        for (i = 0; i < MAX_PXD_BACKING_DEVS; i++) {
                // capture first failure
                if (fp->syncwi[i].rc) return fp->syncwi[i].rc;
        }

        return 0;
}

// shall be called internally during iopath switching.
int pxd_request_suspend_internal(struct pxd_device *pxd_dev,
		bool skip_flush, bool coe)
{
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;
	int rc;

	if (!fastpath_enabled(pxd_dev)) {
		return -EINVAL;
	}

	// check if previous sync instance is still active
	if (!skip_flush && pxd_sync_work_pending(pxd_dev)) {
		return -EBUSY;
	}

	pxd_suspend_io(pxd_dev);

	if (skip_flush || !fp->fastpath) return 0;

	rc = wait_for_sync(pxd_dev, skip_flush);
	if (rc)
		goto fail;
	printk(KERN_NOTICE"device %llu suspended IO from userspace\n", pxd_dev->dev_id);
	return 0;
fail:
	// It is possible replicas are down during failover
	// ignore and continue
	if (coe) {
		printk(KERN_NOTICE"device %llu sync failed %d, continuing with suspend\n",
				pxd_dev->dev_id, rc);
		return 0;
	}
	pxd_resume_io(pxd_dev);
	return rc;
}

// external request to suspend IO on fastpath device
int pxd_request_suspend(struct pxd_device *pxd_dev, bool skip_flush, bool coe)
{
	int rc = 0;

	if (atomic_cmpxchg(&pxd_dev->fp.app_suspend, 0, 1) != 0) {
		return -EBUSY;
	}

	rc = pxd_request_suspend_internal(pxd_dev, skip_flush, coe);
	if (rc) {
		// reset on failure
		atomic_set(&pxd_dev->fp.app_suspend, 0);
	}

	return rc;
}

int pxd_request_resume_internal(struct pxd_device *pxd_dev)
{
	if (!fastpath_enabled(pxd_dev)) {
		return -EINVAL;
	}

	pxd_resume_io(pxd_dev);
	printk(KERN_NOTICE"device %llu resumed IO from userspace\n", pxd_dev->dev_id);
	return 0;
}

// external request to resume IO on fastpath device
int pxd_request_resume(struct pxd_device *pxd_dev)
{
	int rc;

	if (atomic_cmpxchg(&pxd_dev->fp.app_suspend, 1, 0) != 1) {
		return -EINVAL;
	}

	rc = pxd_request_resume_internal(pxd_dev);
	if (rc) {
		atomic_set(&pxd_dev->fp.app_suspend, 1);
	}
	return rc;
}

/*
 * shall get called last when new device is added/updated or when fuse connection is lost
 * and re-estabilished.
 */
void enableFastPath(struct pxd_device *pxd_dev, bool force)
{
	struct file *f;
	struct inode *inode;
	int i;
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;
	int nfd = fp->nfd;
	mode_t mode = open_mode(pxd_dev->mode);
	char modestr[32];

	if (!fastpath_enabled(pxd_dev) || !pxd_dev->fp.nfd) {
		pxd_dev->fp.fastpath = false;
		return;
	}

	pxd_suspend_io(pxd_dev);

	decode_mode(mode, modestr);
	for (i = 0; i < nfd; i++) {
		if (fp->file[i]) { /* valid fd exists already */
			if (force) {
				printk("dev %llu:%s closing file desc %px\n",
						pxd_dev->dev_id, __func__, fp->file[i]);
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

		inode = file_inode(f);
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
			goto out_file_failed;
		}
	}

	pxd_dev->fp.fastpath = true;

	pxd_resume_io(pxd_dev);

	printk(KERN_INFO"pxd_dev %llu fastpath %d mode %#x setting up with %d backing volumes, [%px,%px,%px]\n",
		pxd_dev->dev_id, fp->fastpath, mode, fp->nfd,
		fp->file[0], fp->file[1], fp->file[2]);

	return;

out_file_failed:
	fp->nfd = 0;
	for (i = 0; i < nfd; i++) {
		if (fp->file[i]) filp_close(fp->file[i], NULL);
	}
	memset(fp->file, 0, sizeof(fp->file));
	memset(fp->device_path, 0, sizeof(fp->device_path));

	pxd_dev->fp.fastpath = false;
	/// volume still remains suspended waiting for CLEANUP request to reopen IO.
	printk(KERN_INFO"%s: Device %llu no backing volume setup, will take slow path\n",
		__func__, pxd_dev->dev_id);
}

int pxd_fastpath_vol_cleanup(struct pxd_device *pxd_dev)
{
	if (atomic_read(&pxd_dev->fp.suspend) == 0) {
		printk(KERN_WARNING"device %llu is already active, cleanup failed\n", pxd_dev->dev_id);
		return -EINVAL;
	}
	disableFastPath(pxd_dev, false);
	pxd_resume_io(pxd_dev);
	return 0;
}

/*
 * Concurrency model:
 *   disableFastPath can be reached from multiple call sites concurrently
 *   for the same device:
 *     - pxdctx_reset_fastpath (inside a freeze window)
 *     - pxd_io_failover branch (b) (on a fastpath kthread worker,
 *       outside the freeze window)
 *     - pxd_fastpath_vol_cleanup / pxd_debug_switch_nativepath (ioctl)
 *     - pxd_init_fastpath_target's out_file_failed unwind
 *     - pxd_finish_remove via pxd_fastpath_reset_device
 *
 *   We do NOT hold a mutex across this function because pxd_suspend_io
 *   waits on the blk_mq freeze counter, and a fastpath work item that
 *   holds an rq ref may be trying to enter disableFastPath itself
 *   (branch (b)). That would produce circular wait: A holds mutex and
 *   waits on B's rq; B holds rq and waits on A's mutex.
 *
 *   Instead, ownership is decided by an atomic xchg on fp->fastpath.
 *   Exactly one caller sees prev=true and runs the full disable
 *   sequence; every other caller observes fp->fastpath=false and
 *   returns immediately. The file-close loop uses xchg on each
 *   fp->file[i] so a stale entry can't be closed twice even if a
 *   caller sneaks between the top gate and the loop.
 *
 *   xchg is atomic and full-barrier on every arch Linux supports
 *   (x86 XCHG, arm64 SWP/LL-SC, ppc/riscv LL-SC, s390 CS). It works
 *   on any word-sized lvalue including plain struct pointer fields;
 *   the fp->file[i] slot qualifies.
 */
void disableFastPath(struct pxd_device *pxd_dev, bool skipsync)
{
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;
	int i;
	bool prev;

	/* If the device was never configured for fastpath (or nfd is
	 * already zero from a prior teardown), normalize state and exit.
	 * WRITE_ONCE the gate so any spinning reader observes the value. */
	if (!fastpath_enabled(pxd_dev) || !fp->nfd) {
		fp->nfd = 0;
		WRITE_ONCE(fp->fastpath, false);
		return;
	}

	/* Claim ownership. Only the caller that flips true->false runs the
	 * disable sequence. Others get prev=false and return - fp->fastpath
	 * is already false from their perspective, which is the sole
	 * post-condition callers depend on. */
	prev = xchg(&fp->fastpath, false);
	if (!prev) {
		return;
	}

	/* pxd_suspend_io freezes the blk_mq queue and waits for in-flight
	 * requests to drop their refs. Combined with the WRITE_ONCE above
	 * (via xchg) and the RCU grace period below, no new fastpath IO
	 * can be dispatched and no in-flight fastpath IO is still running
	 * by the time we get past synchronize_rcu(). */
	pxd_suspend_io(pxd_dev);
	/* in pxd_queue_rq, if there are existing readers in the RCU read
	 * side critical section synchronize_rcu will wait for them to end
	 * (queue to fastpath kthread). */
	synchronize_rcu();
	/* at this point, all readers would see fp->fastpath = false */
	fastpath_flush_work();

	if (PXD_ACTIVE(pxd_dev)) {
		printk(KERN_WARNING"%s: pxd device %llu fastpath disabled with active IO (%d)\n",
			__func__, pxd_dev->dev_id, PXD_ACTIVE(pxd_dev));
	}

	if (!skipsync) {
		int rc;
		rc = wait_for_sync(pxd_dev, skipsync);
		if (unlikely(rc) && rc != -EINVAL && rc != -EIO) {
			printk(KERN_ERR"device %llu sync failed %d, continuing with disable\n",
					pxd_dev->dev_id, rc);
		}
	}

	/* Atomically claim each file slot. Only the caller that xchg's out
	 * a non-NULL pointer closes it - no double-close even if a stale
	 * caller past the ownership xchg above (there shouldn't be one,
	 * but this is belt-and-braces) reaches this loop. Iterate the full
	 * array rather than nfd, because nfd could race concurrently and
	 * a NULL slot is a no-op. */
	for (i = 0; i < MAX_PXD_BACKING_DEVS; i++) {
		struct file *f = xchg(&fp->file[i], NULL);
		if (f) {
			filp_close(f, NULL);
		}
	}
	fp->nfd = 0;

	pxd_resume_io(pxd_dev);
}

int pxd_fastpath_init(struct pxd_device *pxd_dev)
{
	int i;
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;

	// will take slow path, if additional info not provided.
	memset(fp, 0, sizeof(struct pxd_fastpath_extension));

	// device temporary IO suspend
#ifdef __PXD_BIO_BLKMQ__
	atomic_set(&fp->blkmq_frozen, 0);
#else
	rwlock_init(&fp->suspend_lock);
#endif
	atomic_set(&fp->suspend, 0);
	atomic_set(&fp->app_suspend, 0);
	atomic_set(&fp->ioswitch_active, 0);
	init_completion(&fp->sync_complete);
	atomic_set(&fp->sync_done, 0);
	for (i = 0; i < MAX_PXD_BACKING_DEVS; i++) {
		INIT_WORK(&fp->syncwi[i].ws, __pxd_syncer);
		fp->syncwi[i].index = i;
		fp->syncwi[i].pxd_dev = pxd_dev;
		fp->syncwi[i].rc = 0;
	}

	// failover init
	spin_lock_init(&fp->fail_lock);
	fp->active_failover = false;
	fp->force_fail = false; // debug to force faspath failover
	INIT_LIST_HEAD(&fp->failQ);

	atomic_set(&fp->nio_discard, 0);
	atomic_set(&fp->nio_flush, 0);
	atomic_set(&fp->nio_flush_nop, 0);
	atomic_set(&fp->nio_preflush, 0);
	atomic_set(&fp->nio_fua, 0);
	atomic_set(&fp->nio_write, 0);
	atomic_set(&fp->nswitch,0);
	atomic_set(&fp->nslowPath,0);
	atomic_set(&pxd_dev->fp.ncomplete, 0);
	atomic_set(&pxd_dev->fp.nerror, 0);

	return 0;
}

void pxd_fastpath_cleanup(struct pxd_device *pxd_dev)
{
	disableFastPath(pxd_dev, false);
}

int pxd_init_fastpath_target(struct pxd_device *pxd_dev, struct pxd_update_path_out *update_path)
{
	char modestr[32];
	mode_t mode = 0;
	int err = 0;
	int i;

	mode = open_mode(pxd_dev->mode);
	decode_mode(mode, modestr);
	printk("device %llu setting up fastpath target with mode %#x(%s), paths %ld\n",
			pxd_dev->dev_id, mode, modestr, update_path->count);

	if (update_path->count > MAX_PXD_BACKING_DEVS) {
		printk("device %llu path count more than max supported(%ld)\n",
				pxd_dev->dev_id, update_path->count);
		goto out_file_failed;
	}

	pxd_suspend_io(pxd_dev);
	// update only the path below
	for (i = 0; i < update_path->count; i++) {
		pxd_printk("Fastpath %d(%d): %s, current %s, %px\n", i, pxd_dev->fp.nfd,
			update_path->devpath[i], pxd_dev->fp.device_path[i], pxd_dev->fp.file[i]);
		strncpy(pxd_dev->fp.device_path[i], update_path->devpath[i], MAX_PXD_DEVPATH_LEN);
		pxd_dev->fp.device_path[i][MAX_PXD_DEVPATH_LEN] = '\0';
		pxd_printk("dev %llu: successfully installed fastpath %s\n",
			pxd_dev->dev_id, pxd_dev->fp.device_path[i]);
	}
	pxd_dev->fp.nfd = update_path->count;
	pxd_dev->fp.can_failover = update_path->can_failover;
	enableFastPath(pxd_dev, true);
	pxd_resume_io(pxd_dev);

	if (!pxd_dev->fp.fastpath) goto out_file_failed;
	printk("dev%llu completed setting up %d paths\n", pxd_dev->dev_id, pxd_dev->fp.nfd);
	return 0;
out_file_failed:
	disableFastPath(pxd_dev, false);
	for (i = 0; i < pxd_dev->fp.nfd; i++) {
		if (pxd_dev->fp.file[i]) filp_close(pxd_dev->fp.file[i], NULL);
	}
	pxd_dev->fp.nfd = 0;
	memset(pxd_dev->fp.file, 0, sizeof(pxd_dev->fp.file));
	memset(pxd_dev->fp.device_path, 0, sizeof(pxd_dev->fp.device_path));

	// Allow fallback to native path and not report failure outside.
	printk("device %llu setup through nativepath (%d)\n", pxd_dev->dev_id, err);
	return 0;
}

// reset device called during device cleanup actions from any internal state.
// consider node wipe, device remove while suspended etc. Also invoked from
// the abort_work backstop (pxd_abort_context) via pxdctx_reset_fastpath()
// at T+pxd_timeout_secs when PX never reopened the control fd.
//
// All below is true when @fail_io is true, otherwise, IOs are held within failQ waiting for either abort timer to fail them
// or px-storage to come online and process them.
// Important: this function never requeues IO. Any IO that hasn't already
// completed must be failed here. Requeueing to native path is unsafe in
// the node-wipe / device-remove case because:
//   - the device may be going away, so references held by requeued IOs
//     would keep the pxd_device alive indefinitely;
//   - calling threads can end up in D state waiting on IO that will never
//     complete because the very thing that would complete it (PX userspace
//     servicing the fuse channel) is the thing being torn down.
// Routing to native is only safe inside pxd_process_ioswitch_complete after
// a real PX ack of PXD_FAILOVER_TO_USERSPACE.
void pxd_fastpath_reset_device(struct pxd_device *pxd_dev, bool skip_sync, bool fail_io)
{
	struct pxd_fastpath_extension *fp = &pxd_dev->fp;
	struct pxd_context *ctx = pxd_dev->ctx;
	struct fuse_conn *fc = &ctx->fc;
	struct fuse_req *req;
	unsigned long flags;
	bool ioswitch_active;
	struct list_head ios;

	if (!fastpath_enabled(pxd_dev)) {
		return;
	}

	disableFastPath(pxd_dev, skip_sync);

	ioswitch_active = atomic_read(&fp->ioswitch_active);
	// abort any inflight ioswitch.
	// On request_end with error, pxd_process_ioswitch_complete fires and
	// calls pxd_reissuefailQ(.., status != 0) which fails every failQ IO
	// with -EIO - exactly the behavior we want here.
	if (ioswitch_active) {
		req = request_find(fc, pxd_dev->fp.switch_uid);
		if (!IS_ERR_OR_NULL(req)) {
			trace_pxd_fastpath_reset_device(pxd_dev->dev_id, pxd_dev->minor,
				ioswitch_active, pxd_dev->fp.switch_uid);
			// overwrite switch request to fail all pending IOs
			req->in.h.opcode = PXD_FAILOVER_TO_USERSPACE;
			req->out.h.error = -EIO; // force failure status
			request_end(fc, req, true /* should lock */);
		} else {
			pxd_dev->fp.switch_uid = 0;
			atomic_set(&fp->ioswitch_active, 0);
		}
	} else {
		trace_pxd_fastpath_reset_device(pxd_dev->dev_id, pxd_dev->minor,
			ioswitch_active, 0);
	}

	// Defensive backstop: if there's no in-flight ioswitch (so the
	// completer path above did not run, or it ran but failed to find the
	// req), failQ may still hold IOs. Fail them with -EIO so callers in
	// D state on these requests are released; never requeue.
	if (fail_io) {
		spin_lock_irqsave(&fp->fail_lock, flags);
		if (!list_empty(&fp->failQ)) {
			printk(KERN_WARNING "pxd device %llu: reset with %s failQ; failing all\n",
				pxd_dev->dev_id,
				ioswitch_active ? "leftover" : "non-empty");
			__pxd_abortfailQ(pxd_dev);
			fp->active_failover = false;
		}
		spin_unlock_irqrestore(&fp->fail_lock, flags);
	} else {
		// reissue IOs to native path
                INIT_LIST_HEAD(&ios);
                spin_lock_irqsave(&pxd_dev->fp.fail_lock, flags);
                list_splice_init(&pxd_dev->fp.failQ, &ios);
                spin_unlock_irqrestore(&pxd_dev->fp.fail_lock, flags);
                pxd_reissuefailQ(pxd_dev, &ios, 0);
	}

	// resume from userspace IO suspends
	pxd_request_resume(pxd_dev);

	// resume all suspended callstacks
	while (atomic_read(&fp->suspend) > 0) {
		pxd_resume_io(pxd_dev);
	}

	printk("pxd fastpath device %llu reset complete\n", pxd_dev->dev_id);
}

/*** debug routines */
int pxd_suspend_state(struct pxd_device *pxd_dev)
{
	return atomic_read(&pxd_dev->fp.suspend);
}

int pxd_debug_switch_fastpath(struct pxd_device* pxd_dev)
{
	return 0;
}

int pxd_debug_switch_nativepath(struct pxd_device* pxd_dev)
{
	if (pxd_dev->fp.fastpath) {
		printk(KERN_WARNING"pxd_dev %llu in fastpath, forcing failover\n",
				pxd_dev->dev_id);
		pxd_dev->fp.force_fail = true;
		disableFastPath(pxd_dev, false);
	} else {
		printk(KERN_WARNING"pxd_dev %llu in already in native path, skipping failover\n",
				pxd_dev->dev_id);
	}

	return 0;
}

static
unsigned int balanceIO(struct pxfpcontext_per_node *c, unsigned int cpuid, bool completion)
{
	if (completion)
		return cpuid;

	if (cpuid < NR_CPUS) {
		struct pxfpcontext_percpu *this = &pxfp_percpu[cpuid];
		int burst = ++this->fpbatch;
		if ((burst & BURST_MASK)== 0) {
			this->mapped_cpu++;
		}
		return this->mapped_cpu;
	}

	return 0; // not possible case
}

// assign work on the worker thread with least penalty. loadbalance
// across threads if no hint provided through 'qnum'
void fastpath_queue_work(struct kthread_work* work, bool completion)
{
	unsigned int cpuid = smp_processor_id();
	int node = cpu_to_node(cpuid);
	struct kthread_worker *worker = fpdefault;

	if (node < MAX_NUMNODES) {
		struct pxfpcontext_per_node *c = &pxfpctxt[node];
		if (c->valid) {
			cpuid = balanceIO(c, cpuid, completion);
			worker = c->fpworker[cpuid % MAX_PXFP_WORKERS_PER_NODE];
		}
	}
	kthread_queue_work(worker, work);
}

#endif /* __PX_FASTPATH__ */
