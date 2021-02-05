#ifndef _KIOLIB_H_
#define _KIOLIB_H_

struct file;
struct pxd_device;
struct bio;

int __do_bio_filebacked(struct pxd_device *pxd_dev, struct bio *bio, struct file *file);

#endif /* _KIOLIB_H_ */


