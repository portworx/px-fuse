#ifndef _PXTGT_HASH_H_
#define _PXTGT_HASH_H_

#include <linux/types.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <linux/completion.h>

#define DIGEST_LEN (MD5_DIGEST_SIZE)

struct pxtgt_io_tracker;

struct crypto_result {
	struct completion completion;
	int err;
};


int pxtgt_hash_init(void);
void pxtgt_hash_exit(void);
int pxtgt_hash_compute(struct pxtgt_io_tracker* iot);

#endif /* _PXTGT_HASH_H_ */
