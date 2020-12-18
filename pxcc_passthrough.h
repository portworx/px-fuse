#ifndef _PXCC_PASSTHROUGH_H_
#define _PXCC_PASSTHROUGH_H_

struct pxcc_c;

int pt_setup(void);
void pt_destroy(void);

int pt_init(struct pxcc_c *cc);
void pt_exit(struct pxcc_c *cc);

int pt_process_io(struct pxcc_c *cc, struct bio *);

#endif /* _PXCC_PASSTHROUGH_H_ */
