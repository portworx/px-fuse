#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/timer.h>
#include <linux/vmstat.h>

#define MAXPOOLS (16)
#define BGFLUSH_CHECK_TIMEOUT (30*HZ)
static struct timer_list bgtimer;

static
bool shouldFlush(void)
{
	struct sysinfo i;
	unsigned long pages;

	// installed ram, fetched every cycle to handle ram hot plug cases as well.
	si_meminfo(&i);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
	pages = global_node_page_state(LRU_ACTIVE_FILE) + global_node_page_state(LRU_ACTIVE_ANON);
#else
	pages = global_page_state(LRU_ACTIVE_FILE) + global_page_state(LRU_ACTIVE_ANON);
#endif
	// if active page cache utilization is higher than 50% of installed ram
	if (pages > i.totalram/2) return true;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
	pages = global_node_page_state(NR_FILE_DIRTY);
#else
	pages = global_page_state(NR_FILE_DIRTY);
#endif

	// if dirty pages are more than 10% of installed ram
	if (pages > i.totalram/10) return true;

	return false;
}

static
struct block_device* init_bdi(struct file *f)
{
        struct address_space *mapping;
        struct inode *inode;

        mapping = f->f_mapping;
        if (!mapping) return NULL;

        inode = mapping->host;
        return I_BDEV(inode);
}

static
void pagecache_flush(void) {
        const mode_t mode = O_RDONLY;
        struct file *f;
        struct block_device *bdi;
        char devpath[256];
        int i;

	// NOTE currently particular to btrfs implementation
        for (i = 0;i <= MAXPOOLS; i++) {
		// look for specific prefix that portworx uses
                sprintf(devpath, "/var/.px/%d", i);
                f = filp_open(devpath, mode, 0700);
                if (IS_ERR_OR_NULL(f)) {
                        // printk("no pool %d found, skipping sync/flush operation\n", i);
                        continue;
                }

                bdi = init_bdi(f);
                /* printk("for pool %d successfully opened %s with block_device %p\n",
                                i, devpath, bdi); */

                if (bdi) {
                        fsync_bdev(bdi);
                        invalidate_bdev(bdi);
                        // printk("for pool %d successfully completed sync/flush operation\n", i);
                }
                filp_close(f, NULL);
        }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void bgflusher(struct timer_list *unused) {
#else
static void bgflusher(unsigned long unused) {
#endif
	if (shouldFlush()) 
		pagecache_flush();

	mod_timer(&bgtimer, jiffies + BGFLUSH_CHECK_TIMEOUT);
}


void init_bgthread(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	timer_setup(&bgtimer, bgflusher, 0);
#else
	setup_timer(&bgtimer, bgflusher, 0);
#endif
	mod_timer(&bgtimer, jiffies + BGFLUSH_CHECK_TIMEOUT);
}

void cleanup_bgthread(void) {
	del_timer_sync(&bgtimer);
}
