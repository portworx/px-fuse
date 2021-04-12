#ifndef _PXD_BIO_H_
#define _PXD_BIO_H_

struct pxd_device;
struct fuse_req;

int __fastpath_init(void);
void __fastpath_cleanup(void);

#ifdef __PXD_BIO_MAKEREQ__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
blk_qc_t pxd_bio_make_request_entryfn(struct bio *bio);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
blk_qc_t pxd_bio_make_request_entryfn(struct request_queue *q, struct bio *bio);
#define BLK_QC_RETVAL BLK_QC_T_NONE
#else
void pxd_bio_make_request_entryfn(struct request_queue *q, struct bio *bio);
#define BLK_QC_RETVAL
#endif
#endif

void __pxd_abortfailQ(struct pxd_device *pxd_dev);
void pxd_reissuefailQ(struct pxd_device *pxd_dev, struct list_head *ios,
                      int status);

void pxd_suspend_io(struct pxd_device *pxd_dev);
void pxd_resume_io(struct pxd_device *pxd_dev);

#ifdef __PXD_BIO_BLKMQ__
// structure is exported only so, it can be embedded within fuse_context.
// Treat it as private outside fastpath
struct fp_root_context {
#define FP_ROOT_MAGIC (0xbaadf00du)
        unsigned int magic;
        struct work_struct work;         // for discard handling
        struct bio *bio;                 // consolidated bio
        struct fp_clone_context *clones; // linked clones
        struct list_head wait;           // wait for resources
        atomic_t nactive; // num of clones requests currently active
};

static inline void fp_root_context_init(struct fp_root_context *fproot) {
        fproot->magic = FP_ROOT_MAGIC;
        fproot->bio = NULL;
        fproot->clones = NULL;
        atomic_set(&fproot->nactive, 0);
        // work struct should get initialized right before use
}

// io entry point
void fp_handle_io(struct work_struct *work);
#endif

#endif /* _PXD_BIO_H_ */
