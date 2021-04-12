// enable this only if the px block device IO is
// registered through make_request() fn.
#ifdef __PXD_BIO_MAKEREQ__

#include <linux/version.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/genhd.h>
#include <linux/workqueue.h>

#include "pxd_core.h"
#include "pxd.h"
#include "pxd_compat.h"
#include "kiolib.h"
#include "pxd_bio.h"

// Added metadata for each bio
struct pxd_io_tracker {
#define PXD_IOT_MAGIC (0xbeefcafe)
  unsigned int magic;
  struct pxd_device *pxd_dev;   // back pointer to pxd device
  struct pxd_io_tracker *head;  // back pointer to head copy [ALL]
  struct list_head replicas;    // only replica needs this
  struct list_head item;        // only HEAD needs this
  atomic_t active;              // only HEAD has refs to all active IO
  struct file *file;

  unsigned long start;  // start time [HEAD]
  struct bio *orig;     // original request bio [HEAD]
  int status;  // should be zero, non-zero indicates consolidated fail status

  struct work_struct wi;  // work item

  // THIS SHOULD BE LAST ITEM
  struct bio clone;  // cloned bio [ALL]
};

/// forward decl
static void pxd_process_fileio(struct work_struct *wi);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
static inline bool special_op(unsigned int op) {
  return (op == REQ_OP_DISCARD);
}
#else
static inline bool special_op(unsigned int op) {
  // flush gets handled inline to a write
  return (op & REQ_DISCARD);
}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
static void pxd_complete_io(struct bio *bio);
#else
static void pxd_complete_io(struct bio *bio, int error);
#endif

// A private global bio mempool for punting requests bypassing vfs
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
static struct bio_set pxd_bio_set;
#endif
#define PXD_MIN_POOL_PAGES (128)
static struct bio_set *ppxd_bio_set;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)

#ifdef RHEL_RELEASE_CODE

#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 6)
static void _generic_end_io_acct(struct request_queue *q, int rw,
                                 struct hd_struct *part,
                                 unsigned long start_time) {
  unsigned long duration = jiffies - start_time;
  int cpu = part_stat_lock();

  part_stat_add(cpu, part, ticks[rw], duration);
  part_round_stats(q, cpu, part);
  part_dec_in_flight(q, part, rw);

  part_stat_unlock();
}

static void _generic_start_io_acct(struct request_queue *q, int rw,
                                   unsigned long sectors,
                                   struct hd_struct *part) {
  int cpu = part_stat_lock();

  part_round_stats(q, cpu, part);
  part_stat_inc(cpu, part, ios[rw]);
  part_stat_add(cpu, part, sectors[rw], sectors);
  part_inc_in_flight(q, part, rw);

  part_stat_unlock();
}
#else
static void _generic_end_io_acct(struct request_queue *q, int rw,
                                 struct hd_struct *part,
                                 unsigned long start_time) {
  unsigned long duration = jiffies - start_time;
  int cpu = part_stat_lock();

  part_stat_add(cpu, part, ticks[rw], duration);
  part_round_stats(cpu, part);
  part_dec_in_flight(part, rw);

  part_stat_unlock();
}

static void _generic_start_io_acct(struct request_queue *q, int rw,
                                   unsigned long sectors,
                                   struct hd_struct *part) {
  int cpu = part_stat_lock();

  part_round_stats(cpu, part);
  part_stat_inc(cpu, part, ios[rw]);
  part_stat_add(cpu, part, sectors[rw], sectors);
  part_inc_in_flight(part, rw);

  part_stat_unlock();
}
#endif

#else
// non RHEL distro
// based on unpatched pristine kernel release
static void _generic_end_io_acct(struct request_queue *q, int rw,
                                 struct hd_struct *part,
                                 unsigned long start_time) {
  unsigned long duration = jiffies - start_time;
  int cpu = part_stat_lock();

  part_stat_add(cpu, part, ticks[rw], duration);
  part_round_stats(cpu, part);
  part_dec_in_flight(part, rw);

  part_stat_unlock();
}

static void _generic_start_io_acct(struct request_queue *q, int rw,
                                   unsigned long sectors,
                                   struct hd_struct *part) {
  int cpu = part_stat_lock();

  part_round_stats(cpu, part);
  part_stat_inc(cpu, part, ios[rw]);
  part_stat_add(cpu, part, sectors[rw], sectors);
  part_inc_in_flight(part, rw);

  part_stat_unlock();
}

#endif
#endif

int __fastpath_init(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
  if (bioset_init(&pxd_bio_set, PXD_MIN_POOL_PAGES,
                  offsetof(struct pxd_io_tracker, clone), 0)) {
    printk(KERN_ERR "pxd: failed to initialize bioset_init: -ENOMEM\n");
    return -ENOMEM;
  }
  ppxd_bio_set = &pxd_bio_set;
#else
  ppxd_bio_set =
      BIOSET_CREATE(PXD_MIN_POOL_PAGES, offsetof(struct pxd_io_tracker, clone),
                    BIOSET_NEED_BVECS);
#endif

  if (!ppxd_bio_set) {
    printk(KERN_ERR "pxd: bioset init failed\n");
    return -ENOMEM;
  }

  return 0;
}

void __fastpath_cleanup(void) {
  if (ppxd_bio_set) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    bioset_exit(ppxd_bio_set);
#else
    bioset_free(ppxd_bio_set);
#endif
  }

  ppxd_bio_set = NULL;
}

static void __pxd_cleanup_block_io(struct pxd_io_tracker *head) {
  while (!list_empty(&head->replicas)) {
    struct pxd_io_tracker *repl =
        list_first_entry(&head->replicas, struct pxd_io_tracker, item);
    BUG_ON(repl->magic != PXD_IOT_MAGIC);
    repl->magic = PXD_POISON;
    list_del(&repl->item);
    pxd_mem_printk("freeing repl %px, bio %px dir %d\n", repl, &repl->clone,
                   bio_data_dir(head->orig) == READ);
    bio_put(&repl->clone);
  }

  BUG_ON(head->magic != PXD_IOT_MAGIC);
  head->magic = PXD_POISON;
  pxd_mem_printk("freeing tracker %px, bio %px dir %d\n", head, &head->clone,
                 bio_data_dir(head->orig) == READ);
  bio_put(&head->clone);
}

static struct pxd_io_tracker *__pxd_init_block_replica(
    struct pxd_device *pxd_dev, struct bio *bio, struct file *fileh) {
  struct bio *clone_bio;
  struct pxd_io_tracker *iot;
  struct block_device *bdev = get_bdev(fileh);

  pxd_printk(
      "pxd %px:__pxd_init_block_replica entering with bio %px, fileh %px\n",
      pxd_dev, bio, fileh);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
  clone_bio = bio_clone_fast(bio, GFP_KERNEL, ppxd_bio_set);
#else
  clone_bio = bio_clone_bioset(bio, GFP_KERNEL, ppxd_bio_set);
#endif
  if (!clone_bio) {
    pxd_printk(KERN_ERR "No memory for io context");
    return NULL;
  }

  iot = container_of(clone_bio, struct pxd_io_tracker, clone);
  BUG_ON(&iot->clone != clone_bio);

  iot->magic = PXD_IOT_MAGIC;
  iot->pxd_dev = pxd_dev;
  iot->head = iot;
  INIT_LIST_HEAD(&iot->replicas);
  INIT_LIST_HEAD(&iot->item);
  iot->orig = bio;
  iot->status = 0;
  iot->start = jiffies;
  atomic_set(&iot->active, 0);
  iot->file = get_file(fileh);
  INIT_WORK(&iot->wi, pxd_process_fileio);

  clone_bio->bi_private = pxd_dev;
  BIO_SET_DEV(clone_bio, bdev);
  clone_bio->bi_end_io = pxd_complete_io;

  return iot;
}

static struct pxd_io_tracker *__pxd_init_block_head(struct pxd_device *pxd_dev,
                                                    struct bio *bio, int dir) {
  struct pxd_io_tracker *head;
  struct pxd_io_tracker *repl;
  int index;

  head = __pxd_init_block_replica(pxd_dev, bio, pxd_dev->fp.file[0]);
  if (!head) {
    return NULL;
  }
  pxd_mem_printk("allocated tracker %px, clone bio %px dir %d\n", head,
                 &head->clone, bio_data_dir(bio) == READ);

  // initialize the replicas only if the request is non-read
  if (dir != READ) {
    for (index = 1; index < pxd_dev->fp.nfd; index++) {
      repl = __pxd_init_block_replica(pxd_dev, bio, pxd_dev->fp.file[index]);
      if (!repl) {
        goto repl_cleanup;
      }

      BUG_ON(repl->magic != PXD_IOT_MAGIC);
      repl->head = head;
      list_add_tail(&repl->item, &head->replicas);
      pxd_mem_printk("allocated repl %px, clone bio %px dir %d\n", repl,
                     &repl->clone, bio_data_dir(bio) == READ);
    }
  }

  BUG_ON(head->magic != PXD_IOT_MAGIC);
  return head;

repl_cleanup:
  __pxd_cleanup_block_io(head);
  return NULL;
}

void pxd_suspend_io(struct pxd_device *pxd_dev) {
  int curr = atomic_inc_return(&pxd_dev->fp.suspend);
  if (curr == 1) {
    write_lock(&pxd_dev->fp.suspend_lock);
    printk("For pxd device %llu IO suspended\n", pxd_dev->dev_id);
  } else {
    printk("For pxd device %llu IO already suspended(%d)\n", pxd_dev->dev_id,
           curr);
  }
}

void pxd_resume_io(struct pxd_device *pxd_dev) {
  bool wakeup;
  int curr = atomic_dec_return(&pxd_dev->fp.suspend);

  wakeup = (curr == 0);
  if (wakeup) {
    printk("For pxd device %llu IO resumed\n", pxd_dev->dev_id);
    write_unlock(&pxd_dev->fp.suspend_lock);
    pxd_check_q_decongested(pxd_dev);
  } else {
    printk("For pxd device %llu IO still suspended(%d)\n", pxd_dev->dev_id,
           curr);
  }
}

// no locking needed, @ios is a local list of IO to be reissued.
void pxd_reissuefailQ(struct pxd_device *pxd_dev, struct list_head *ios,
                      int status) {
  while (!list_empty(ios)) {
    struct pxd_io_tracker *head =
        list_first_entry(ios, struct pxd_io_tracker, item);
    BUG_ON(head->magic != PXD_IOT_MAGIC);
    list_del(&head->item);
    if (!status) {
      // switch to native path, if px is down, then abort IO timer will cleanup
      printk_ratelimited(KERN_ERR "%s: pxd%llu: resuming IO in native path.\n",
                         __func__, pxd_dev->dev_id);
      atomic_inc(&pxd_dev->fp.nslowPath);
      pxd_reroute_slowpath(pxd_dev->disk->queue, head->orig);
    } else {
      // If failover request failed, then route IO fail to user application as
      // is.
      BIO_ENDIO(head->orig, -EIO);
    }
    __pxd_cleanup_block_io(head);
  }
}

/// handle io path switch events and io reroute on failures
/// functions prefixed with ___xxx need to called with fail_lock
static void __pxd_add2failQ(struct pxd_device *pxd_dev,
                            struct pxd_io_tracker *head) {
  list_add_tail(&head->item, &pxd_dev->fp.failQ);
}

void __pxd_abortfailQ(struct pxd_device *pxd_dev) {
  while (!list_empty(&pxd_dev->fp.failQ)) {
    struct pxd_io_tracker *head =
        list_first_entry(&pxd_dev->fp.failQ, struct pxd_io_tracker, item);
    BUG_ON(head->magic != PXD_IOT_MAGIC);
    list_del(&head->item);
    BIO_ENDIO(head->orig, -EIO);
    __pxd_cleanup_block_io(head);
  }
}

// @head [in] - io head
// @return - update reconciled error code
static int reconcile_io_status(struct pxd_io_tracker *head) {
  struct pxd_io_tracker *repl;
  int status = 0;
  int tmp;

  BUG_ON(head->magic != PXD_IOT_MAGIC);
  list_for_each_entry(repl, &head->replicas, item) {
    BUG_ON(repl->magic != PXD_IOT_MAGIC);

    tmp = remap_io_status(repl->status);
    if (status == 0 || tmp == -EIO) {
      status = tmp;
    }
  }

  tmp = remap_io_status(head->status);
  if (status == 0 || tmp == -EIO) {
    status = tmp;
  }

  return status;
}

static void pxd_io_failover(struct work_struct *ws) {
  struct pxd_io_tracker *head = container_of(ws, struct pxd_io_tracker, wi);
  struct pxd_device *pxd_dev = head->pxd_dev;
  bool cleanup = false;
  bool reroute = false;
  int rc;
  unsigned long flags;

  BUG_ON(head->magic != PXD_IOT_MAGIC);
  BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);

  spin_lock_irqsave(&pxd_dev->fp.fail_lock, flags);
  if (!pxd_dev->fp.active_failover) {
    if (pxd_dev->fp.fastpath) {
      pxd_dev->fp.active_failover = true;
      __pxd_add2failQ(pxd_dev, head);
      cleanup = true;
    } else {
      reroute = true;
    }
  } else {
    __pxd_add2failQ(pxd_dev, head);
  }

  spin_unlock_irqrestore(&pxd_dev->fp.fail_lock, flags);

  if (cleanup) {
    rc = pxd_initiate_failover(pxd_dev);
    // If userspace cannot be informed of a failover event, force abort all IO.
    if (rc) {
      printk_ratelimited(KERN_ERR
                         "%s: pxd%llu: failover failed %d, aborting IO\n",
                         __func__, pxd_dev->dev_id, rc);
      spin_lock_irqsave(&pxd_dev->fp.fail_lock, flags);
      __pxd_abortfailQ(pxd_dev);
      pxd_dev->fp.active_failover = false;
      spin_unlock_irqrestore(&pxd_dev->fp.fail_lock, flags);
    }
  } else if (reroute) {
    printk_ratelimited(KERN_ERR "%s: pxd%llu: resuming IO in native path.\n",
                       __func__, pxd_dev->dev_id);
    atomic_inc(&pxd_dev->fp.nslowPath);
    pxd_reroute_slowpath(pxd_dev->disk->queue, head->orig);
    __pxd_cleanup_block_io(head);
  }

  pxd_check_q_decongested(pxd_dev);
}

static void pxd_failover_initiate(struct pxd_device *pxd_dev,
                                  struct pxd_io_tracker *head) {
  INIT_WORK(&head->wi, pxd_io_failover);
  queue_work(pxd_dev->fp.wq, &head->wi);
}

// special handling for discards
static void fp_handle_special(struct work_struct *work) {
  struct pxd_io_tracker *iot = container_of(work, struct pxd_io_tracker, wi);
  struct bio *b = &iot->clone;
  sector_t start = BIO_SECTOR(b);
  unsigned nsectors = BIO_SIZE(b) >> SECTOR_SHIFT;
  struct block_device *bdev = get_bdev(iot->file);
  struct request_queue *q = bdev_get_queue(bdev);
  struct page *pg = ZERO_PAGE(0);  // global shared zero page
  int rc;

  if (blk_queue_discard(q)) {  // discard supported
    rc = blkdev_issue_discard(bdev, start, nsectors, GFP_NOIO, 0);
  } else if (bdev_write_same(bdev)) {  // convert discard to write same
    rc = blkdev_issue_write_same(bdev, start, nsectors, GFP_NOIO, pg);
  } else {  // zero-out
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
    rc = blkdev_issue_zeroout(bdev, start, nsectors, GFP_NOIO, 0);
#else
    rc = blkdev_issue_zeroout(bdev, start, nsectors, GFP_NOIO);
#endif
  }

  BIO_ENDIO(b, rc);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
static void pxd_complete_io(struct bio *bio)
#else
static void pxd_complete_io(struct bio *bio, int error)
#endif
{
  struct pxd_io_tracker *iot = container_of(bio, struct pxd_io_tracker, clone);
  struct pxd_device *pxd_dev = bio->bi_private;
  struct pxd_io_tracker *head = iot->head;
  unsigned int flags = get_op_flags(bio);
  int blkrc;
  char b[BDEVNAME_SIZE];

  BUG_ON(iot->magic != PXD_IOT_MAGIC);
  BUG_ON(head->magic != PXD_IOT_MAGIC);
  BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
  blkrc = blk_status_to_errno(bio->bi_status);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
  blkrc = bio->bi_error;
#else
  blkrc = error;
#endif

  if (blkrc != 0) {
    printk_ratelimited(
        "FAILED IO %s (err=%d): dev m %d g %lld %s at %lld len %d bytes %d "
        "pages "
        "flags 0x%lx\n",
        BDEVNAME(bio, b), blkrc, pxd_dev->minor, pxd_dev->dev_id,
        bio_data_dir(bio) == WRITE ? "wr" : "rd",
        (unsigned long long)(BIO_SECTOR(bio) * SECTOR_SIZE), BIO_SIZE(bio),
        bio_segments(bio), (long unsigned int)flags);
  }

  fput(iot->file);
  iot->status = blkrc;
  if (!atomic_dec_and_test(&head->active)) {
    // not all responses have come back
    return;
  }

  // final reconciled status
  blkrc = reconcile_io_status(head);

  // debug condition for force fail
  if (pxd_dev->fp.force_fail) blkrc = -EIO;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  bio_end_io_acct(bio, iot->start);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) &&  \
     defined(bvec_iter_sectors))
  generic_end_io_acct(pxd_dev->disk->queue, bio_data_dir(bio),
                      &pxd_dev->disk->part0, iot->start);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
  generic_end_io_acct(bio_data_dir(bio), &pxd_dev->disk->part0, iot->start);
#else
  _generic_end_io_acct(pxd_dev->disk->queue, bio_data_dir(bio),
                       &pxd_dev->disk->part0, iot->start);
#endif

  atomic_inc(&pxd_dev->fp.ncomplete);
  atomic_dec(&pxd_dev->ncount);

  if (pxd_dev->fp.can_failover && (blkrc == -EIO)) {
    atomic_inc(&pxd_dev->fp.nerror);
    pxd_failover_initiate(pxd_dev, head);
    pxd_check_q_decongested(pxd_dev);
    return;
  }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) ||  \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) && \
     defined(bvec_iter_sectors))
  {
    iot->orig->bi_status = errno_to_blk_status(blkrc);
    bio_endio(iot->orig);
  }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
  {
    iot->orig->bi_error = blkrc;
    bio_endio(iot->orig);
  }
#else
  { bio_endio(iot->orig, blkrc); }
#endif
  __pxd_cleanup_block_io(head);
  pxd_check_q_decongested(pxd_dev);
}

static void pxd_process_fileio(struct work_struct *wi) {
  struct pxd_io_tracker *iot = container_of(wi, struct pxd_io_tracker, wi);
  struct pxd_device *pxd_dev = iot->pxd_dev;

  BUG_ON(iot->magic != PXD_IOT_MAGIC);
  BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);
  __do_bio_filebacked(pxd_dev, &iot->clone, iot->file);
}

static void pxd_process_io(struct pxd_io_tracker *head) {
  struct pxd_device *pxd_dev = head->pxd_dev;
  struct bio *bio = head->orig;
  int dir = bio_data_dir(bio);

  //
  // Based on the nfd mapped on pxd_dev, that many cloned bios shall be
  // setup, then each replica takes its own processing path, which could be
  // either file backup or block device backup.
  //
  struct pxd_io_tracker *curr;

  BUG_ON(head->magic != PXD_IOT_MAGIC);
  BUG_ON(pxd_dev->magic != PXD_DEV_MAGIC);
  atomic_inc(&pxd_dev->ncount);
  // initialize active io to configured replicas
  if (dir != READ) {
    atomic_set(&head->active, pxd_dev->fp.nfd);
    // submit all replicas linked from head, if not read
    list_for_each_entry(curr, &head->replicas, item) {
      if (S_ISBLK(curr->file->f_inode->i_mode)) {
        if (special_op(BIO_OP(&curr->clone))) {
          INIT_WORK(&curr->wi, fp_handle_special);
          queue_work(pxd_dev->fp.wq, &curr->wi);
        } else {
          SUBMIT_BIO(&curr->clone);
        }
        atomic_inc(&pxd_dev->fp.nswitch);
      } else {
        queue_work(pxd_dev->fp.wq, &curr->wi);
      }
    }
  } else {
    atomic_set(&head->active, 1);
  }

  // submit head bio the last
  if (S_ISBLK(head->file->f_inode->i_mode)) {
    if (special_op(BIO_OP(&head->clone))) {
      INIT_WORK(&head->wi, fp_handle_special);
      queue_work(pxd_dev->fp.wq, &head->wi);
    } else {
      SUBMIT_BIO(&head->clone);
    }
    atomic_inc(&pxd_dev->fp.nswitch);
  } else {
    queue_work(pxd_dev->fp.wq, &head->wi);
  }
}

/* fast path make request function, io entry point */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
#define BLK_QC_RETVAL BLK_QC_T_NONE
blk_qc_t pxd_bio_make_request_entryfn(struct bio *bio) {
  struct request_queue *q = bio->bi_disk->queue;
  struct pxd_device *pxd_dev = bio->bi_disk->private_data;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
blk_qc_t pxd_bio_make_request_entryfn(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL BLK_QC_T_NONE
{
  struct pxd_device *pxd_dev = q->queuedata;
#else
void pxd_bio_make_request_entryfn(struct request_queue *q, struct bio *bio)
#define BLK_QC_RETVAL
{
  struct pxd_device *pxd_dev = q->queuedata;
#endif
  int rw = bio_data_dir(bio);
  struct pxd_io_tracker *head;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
  if (!pxd_dev) {
#else
  if (rw == READA) rw = READ;
  if (!pxd_dev || (rw != READ && rw != WRITE)) {
#endif
    printk_ratelimited(KERN_ERR
                       "pxd basic sanity fail, pxd_device %px (%llu), rw %#x\n",
                       pxd_dev, (pxd_dev ? pxd_dev->dev_id : (uint64_t)0), rw);
    bio_io_error(bio);
    return BLK_QC_RETVAL;
  }

  if (!pxd_dev->connected || pxd_dev->removing) {
    printk_ratelimited(KERN_ERR "px is disconnected, failing IO.\n");
    bio_io_error(bio);
    return BLK_QC_RETVAL;
  }

  // is a fastpath device
  if (rw != READ && !write_allowed(pxd_dev->mode)) {
    printk_ratelimited(KERN_ERR "px device %llu is read only, failing IO.\n",
                       pxd_dev->dev_id);
    bio_io_error(bio);
    return BLK_QC_RETVAL;
  }

/*
 * Use blk_queue_split() to ensure queue limits are always honoured.
 * same as kernel dm commit: 89f5fa47476eda56402e29fff3c5097f5c2a1e19
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
  blk_queue_split(&bio);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
  blk_queue_split(q, &bio);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
blk_queue_split(q, &bio, q->bio_split);
#else
{
  unsigned op = 0;  // READ
  sector_t rq_sectors = BIO_SIZE(bio) >> SECTOR_SHIFT;
  sector_t max_sectors;
  unsigned flags = bio->bi_rw;

  switch (flags & (REQ_WRITE | REQ_DISCARD | REQ_WRITE_SAME)) {
    case REQ_WRITE:
    /* FALLTHROUGH */
    case(REQ_WRITE | REQ_WRITE_SAME) :
      if (flags & REQ_WRITE_SAME)
        op = REQ_WRITE_SAME;
      else
        op = REQ_WRITE;
      break;
    case REQ_DISCARD:
    /* FALLTHROUGH */
    case REQ_WRITE | REQ_DISCARD:
      op = REQ_DISCARD;
      break;
    case 0:  // read
      break;
    default:
      printk(KERN_ERR "[%llu] REQ_OP_UNKNOWN(flags=%#x): size=%lu, minor=%d\n",
             pxd_dev->dev_id, flags, rq_sectors, pxd_dev->minor);
      bio_io_error(bio);
      return BLK_QC_RETVAL;
  }

  max_sectors = blk_queue_get_max_sectors(q, op);
  if (!max_sectors) {
    bio_io_error(bio);
    return BLK_QC_RETVAL;
  }

  if (rq_sectors > max_sectors) {
    struct bio_pair *bp = bio_split(bio, max_sectors);
    if (!bp) {
      bio_io_error(bio);
      return BLK_QC_RETVAL;
    }

    // process the split BIOs in next submission
    generic_make_request(&bp->bio1);
    generic_make_request(&bp->bio2);
    bio_pair_release(bp);
    return BLK_QC_RETVAL;
  }
}
#endif

  pxd_check_q_congested(pxd_dev);
  read_lock(&pxd_dev->fp.suspend_lock);
  if (!pxd_dev->fp.fastpath) {
    atomic_inc(&pxd_dev->fp.nslowPath);
    pxd_reroute_slowpath(q, bio);
    read_unlock(&pxd_dev->fp.suspend_lock);
    return BLK_QC_RETVAL;
  }

  head = __pxd_init_block_head(pxd_dev, bio, rw);
  if (!head) {
    read_unlock(&pxd_dev->fp.suspend_lock);
    BIO_ENDIO(bio, -ENOMEM);

    // trivial high memory pressure failing IO
    return BLK_QC_RETVAL;
  }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  head->start = bio_start_io_acct(bio);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) &&  \
     defined(bvec_iter_sectors))
  generic_start_io_acct(pxd_dev->disk->queue, bio_op(bio),
                        REQUEST_GET_SECTORS(bio), &pxd_dev->disk->part0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
generic_start_io_acct(bio_data_dir(bio), REQUEST_GET_SECTORS(bio),
                      &pxd_dev->disk->part0);
#else
_generic_start_io_acct(pxd_dev->disk->queue, bio_data_dir(bio),
                       REQUEST_GET_SECTORS(bio), &pxd_dev->disk->part0);
#endif

  pxd_process_io(head);
  read_unlock(&pxd_dev->fp.suspend_lock);

  return BLK_QC_RETVAL;
}

#endif
