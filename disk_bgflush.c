#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/timer.h>

#define MAXPOOLS (16)
static void bgflusher(struct timer_list *unused);
#define BGFLUSH_CHECK_TIMEOUT (30*HZ)
static DEFINE_TIMER(bgtimer, bgflusher);


static
bool shouldFlush(void) {
	struct sysinfo i;
	unsigned long pages;

	si_meminfo(&i);

	pages = global_node_page_state(LRU_ACTIVE_FILE) + global_node_page_state(LRU_ACTIVE_ANON);

	return (i.totalram/2 < pages);
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

//static
void pagecache_flush(void) {
        struct file *f;
        struct block_device *bdi;
        int i;
        const mode_t mode = O_RDONLY;
        char devpath[256];

        for (i=0;i <=MAXPOOLS; i++) {
                sprintf(devpath, "/var/.px/%d", i);
                f = filp_open(devpath, mode, 0700);
                if (IS_ERR_OR_NULL(f)) {
                        printk("no pool %d found, skipping sync/flush operation\n", i);
                        continue;
                }

                bdi = init_bdi(f);
                printk("for pool %d successfully opened %s with block_device %p\n",
                                i, devpath, bdi);

                if (bdi) {
                        fsync_bdev(bdi);
                        invalidate_bdev(bdi);
                        printk("for pool %d successfully completed sync/flush operation\n", i);
                }
                filp_close(f, NULL);
        }
}

static void bgflusher(struct timer_list *unused) {
	if (shouldFlush()) 
		pagecache_flush();

	mod_timer(&bgtimer, jiffies + BGFLUSH_CHECK_TIMEOUT);
}


void init_bgthread(void) {
	bgtimer.expires = jiffies + BGFLUSH_CHECK_TIMEOUT;
	add_timer(&bgtimer);
}

void cleanup_bgthread(void) {
	del_timer_sync(&bgtimer);
}
