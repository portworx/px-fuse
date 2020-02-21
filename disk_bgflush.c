#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/timer.h>
#include <linux/vmstat.h>
#include <linux/workqueue.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/sched.h>

//#define STANDALONE_HACK

#define MAXPOOLS (16)
#define BGFLUSH_CHECK_TIMEOUT (30*HZ)
static struct delayed_work bgflush;

const bool fsbased = 1;

static struct sysinfo si[2];
unsigned long inactpages[2];
unsigned long dirtypages[2];

static void vmstats_init(int index) {
	si_meminfo(&si[index]);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
	inactpages[index] = global_node_page_state(LRU_INACTIVE_FILE) + global_node_page_state(LRU_INACTIVE_ANON);
#else
	inactpages[index] = global_page_state(LRU_INACTIVE_FILE) + global_page_state(LRU_INACTIVE_ANON);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
	dirtypages[index] = global_node_page_state(NR_FILE_DIRTY);
#else
	dirtypages[index] = global_page_state(NR_FILE_DIRTY);
#endif
}

static void vmstats_dump(char *msgprefix, int index) {
	printk("%s: vm stats {totalram %ld(%ldkB), freeram %ld(%ldkB), inactive %ld(%ldkB), dirty %ld(%ldkB)}\n",
			msgprefix,
			si[index].totalram, ((si[index].totalram * PAGE_SIZE) >> 10),
			si[index].freeram, ((si[index].freeram * PAGE_SIZE) >> 10),
			inactpages[index], ((inactpages[index] * PAGE_SIZE) >> 10),
			dirtypages[index], ((dirtypages[index] * PAGE_SIZE) >> 10));
}

static void drop_pagecache_sb(struct super_block *sb, void *unused)
{
    struct inode *inode, *toput_inode = NULL;
	static const char* _disk_none = "none";
	static const char* _disk_nobdev = "nobdev";
	static const char* _disk_nodisk = "nodisk";

	const char *disk_name = _disk_none;

	if (sb->s_bdev) {
		if (sb->s_bdev->bd_disk) {
			disk_name = sb->s_bdev->bd_disk->disk_name;
		} else {
			disk_name = _disk_nodisk;
		}
	} else {
		disk_name = _disk_nobdev;
	}
	printk("for filesystem %s, with bdev disk %s\n",
			sb->s_type->name, disk_name);

	vmstats_init(0);
	vmstats_dump("before", 0);
	sync_filesystem(sb);

    spin_lock(&sb->s_inode_list_lock);
    list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
        spin_lock(&inode->i_lock);
        /*
         * We must skip inodes in unusual state. We may also skip
         * inodes without pages but we deliberately won't in case
         * we need to reschedule to avoid softlockups.
         */
        if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
            (inode->i_mapping->nrpages == 0 && !need_resched())) {
            spin_unlock(&inode->i_lock);
            continue;
        }

        // __iget(inode); not exported
		atomic_inc(&inode->i_count);

        spin_unlock(&inode->i_lock);
        spin_unlock(&sb->s_inode_list_lock);

        invalidate_mapping_pages(inode->i_mapping, 0, -1);
        iput(toput_inode);
        toput_inode = inode;

        cond_resched();
        spin_lock(&sb->s_inode_list_lock);
    }
    spin_unlock(&sb->s_inode_list_lock);
    iput(toput_inode);

    if (sb->s_bdev) invalidate_bdev(sb->s_bdev);

	vmstats_init(1);
	vmstats_dump("after", 1);
}

static
bool shouldFlush(void)
{
	struct sysinfo i;
	unsigned long pages;

	// installed ram, fetched every cycle to handle ram hot plug cases as well.
	si_meminfo(&i);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
	pages = global_node_page_state(LRU_INACTIVE_FILE) + global_node_page_state(LRU_INACTIVE_ANON);
#else
	pages = global_page_state(LRU_INACTIVE_FILE) + global_page_state(LRU_INACTIVE_ANON);
#endif
	// if inactive page cache utilization is higher than available freeram
	// or if inactive pages are higher than 50% of total ram
	if (pages > i.freeram || pages > i.totalram/2) return true;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
	pages = global_node_page_state(NR_FILE_DIRTY);
#else
	pages = global_page_state(NR_FILE_DIRTY);
#endif

	// if dirty pages are more than 10% of installed ram
	if (pages > i.totalram/10) return true;

	// HACKED to always flush
	return true;
}

//static
struct block_device* init_bdev(struct file *f)
{
        struct address_space *mapping;
        struct inode *inode;

        mapping = f->f_mapping;
        if (!mapping) return NULL;

        inode = mapping->host;
        return I_BDEV(inode);
}

static const char *bdevs[] = {
	"/dev/nvme0n1p2"
};

static
void pagecache_flush(void) {
    struct block_device *bdev;
	int i;

	for (i=0; i<sizeof(bdevs)/sizeof(char*); i++) {
		const char * path = bdevs[i];
		bdev = lookup_bdev(path);
	    printk("for path %s successfully with block_device %p\n", path, bdev);

		if (bdev) {
			struct super_block *sb;

			sb = get_super(bdev);
			if (sb) {
				printk("target device %s, filesystem %s\n", path, sb->s_type->name);
				drop_pagecache_sb(sb, NULL);
				drop_super(sb);
			}

        	printk("for path %s successfully completed sync/flush operation\n", path);
    	}
	}
}

static const char *fsnames[] = {
	"btrfs", "ext4",
};

static
void pagecache_flush2(void) {
	int i;
	struct file_system_type *fstype;
	for (i=0; i<sizeof(fsnames)/sizeof(char*); i++) {
		fstype = get_fs_type(fsnames[i]);
		printk("for fs %s, fs type %px\n",
				fsnames[i], fstype);
		if (!fstype) continue;
		iterate_supers_type(fstype, drop_pagecache_sb, NULL);
	}
}

static void bgflusher(struct work_struct *work)
{
	if (shouldFlush()) {
		if (!fsbased) {
			pagecache_flush();
		} else {
			pagecache_flush2();
		}
	}

	schedule_delayed_work(&bgflush, BGFLUSH_CHECK_TIMEOUT);
}

int init_bgthread(void) {
	INIT_DELAYED_WORK(&bgflush, bgflusher);
	schedule_delayed_work(&bgflush, BGFLUSH_CHECK_TIMEOUT);

	return 0;
}

void cleanup_bgthread(void) {
	cancel_delayed_work_sync(&bgflush);
}

#ifdef STANDALONE_HACK
module_init(init_bgthread);
module_exit(cleanup_bgthread);

MODULE_LICENSE("GPL");
#endif
