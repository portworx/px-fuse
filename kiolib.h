#ifndef _KIOLIB_H_
#define _KIOLIB_H_

struct file;
struct pxd_device;
struct bio;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
int __do_bio_filebacked(struct pxd_device *pxd_dev, struct bio *bio, struct file *file);
#else
int __do_bio_filebacked(struct pxd_device *pxd_dev, struct bio *bio, struct file *file);
#endif

#endif /* _KIOLIB_H_ */


