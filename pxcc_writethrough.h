#ifndef _PXCC_WRITETHROUGH_H_
#define _PXCC_WRITETHROUGH_H_

struct pxcc_c;

int wt_setup(void);
void wt_destroy(void);

int wt_init(struct pxcc_c *cc);
void wt_exit(struct pxcc_c *cc);

int wt_process_io(struct pxcc_c *cc, struct bio *);

#endif /* _PXCC_WRITETHROUGH_H_ */
