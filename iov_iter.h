/*
 *	Berkeley style UIO structures	-	Alan Cox 1994.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef ____iov_iter_H
#define ____iov_iter_H


#include <linux/kernel.h>
#include <linux/uio.h>

struct page;

enum {
	ITER_IOVEC = 0,
	ITER_KVEC = 2,
	ITER_BVEC = 4,
};

struct __iov_iter {
	int type;
	size_t iov_offset;
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec *bvec;
	};
	unsigned long nr_segs;
};

static inline struct iovec __iov_iter_iovec(const struct __iov_iter *iter)
{
	return (struct iovec) {
		.iov_base = iter->iov->iov_base + iter->iov_offset,
		.iov_len = min(iter->count,
			       iter->iov->iov_len - iter->iov_offset),
	};
}

#define iov_for_each(iov, iter, start)				\
	if (!((start).type & ITER_BVEC))			\
	for (iter = (start);					\
	     (iter).count &&					\
	     ((iov = __iov_iter_iovec(&(iter))), 1);		\
	     __iov_iter_advance(&(iter), (iov).iov_len))

unsigned long iov_shorten(struct iovec *iov, unsigned long nr_segs, size_t to);

size_t __iov_iter_copy_from_user_atomic(struct page *page,
		struct __iov_iter *i, unsigned long offset, size_t bytes);
void __iov_iter_advance(struct __iov_iter *i, size_t bytes);
int __iov_iter_fault_in_readable(struct __iov_iter *i, size_t bytes);
int __iov_iter_fault_in_multipages_readable(struct __iov_iter *i, size_t bytes);
size_t __iov_iter_single_seg_count(const struct __iov_iter *i);
size_t __copy_page_to_iter(struct page *page, size_t offset, size_t bytes,
			 struct __iov_iter *i);
size_t __copy_page_from_iter(struct page *page, size_t offset, size_t bytes,
			 struct __iov_iter *i);
size_t copy_to_iter(const void *addr, size_t bytes, struct __iov_iter *i);
size_t copy_from_iter(void *addr, size_t bytes, struct __iov_iter *i);
size_t copy_from_iter_nocache(void *addr, size_t bytes, struct __iov_iter *i);
size_t __iov_iter_zero(size_t bytes, struct __iov_iter *);
unsigned long __iov_iter_alignment(const struct __iov_iter *i);
unsigned long __iov_iter_gap_alignment(const struct __iov_iter *i);
void __iov_iter_init(struct __iov_iter *i, int direction, const struct iovec *iov,
			unsigned long nr_segs, size_t count);
void __iov_iter_kvec(struct __iov_iter *i, int direction, const struct kvec *kvec,
			unsigned long nr_segs, size_t count);
void __iov_iter_bvec(struct __iov_iter *i, int direction, const struct bio_vec *bvec,
			unsigned long nr_segs, size_t count);
ssize_t __iov_iter_get_pages(struct __iov_iter *i, struct page **pages,
			size_t maxsize, unsigned maxpages, size_t *start);
ssize_t __iov_iter_get_pages_alloc(struct __iov_iter *i, struct page ***pages,
			size_t maxsize, size_t *start);
int __iov_iter_npages(const struct __iov_iter *i, int maxpages);

const void *dup_iter(struct __iov_iter *new, struct __iov_iter *old, gfp_t flags);

static inline size_t __iov_iter_count(struct __iov_iter *i)
{
	return i->count;
}

static inline bool iter_is_iovec(struct __iov_iter *i)
{
	return !(i->type & (ITER_BVEC | ITER_KVEC));
}

/*
 * Get one of READ or WRITE out of iter->type without any other flags OR'd in
 * with it.
 *
 * The ?: is just for type safety.
 */
#define __iov_iter_rw(i) ((0 ? (struct __iov_iter *)0 : (i))->type & RW_MASK)

/*
 * Cap the __iov_iter by given limit; note that the second argument is
 * *not* the new size - it's upper limit for such.  Passing it a value
 * greater than the amount of data in __iov_iter is fine - it'll just do
 * nothing in that case.
 */
static inline void __iov_iter_truncate(struct __iov_iter *i, u64 count)
{
	/*
	 * count doesn't have to fit in size_t - comparison extends both
	 * operands to u64 here and any value that would be truncated by
	 * conversion in assignement is by definition greater than all
	 * values of size_t, including old i->count.
	 */
	if (i->count > count)
		i->count = count;
}

/*
 * reexpand a previously truncated iterator; count must be no more than how much
 * we had shrunk it.
 */
static inline void __iov_iter_reexpand(struct __iov_iter *i, size_t count)
{
	i->count = count;
}
size_t csum_and_copy_to_iter(const void *addr, size_t bytes, __wsum *csum, struct __iov_iter *i);
size_t csum_and_copy_from_iter(void *addr, size_t bytes, __wsum *csum, struct __iov_iter *i);

int import_iovec(int type, const struct iovec __user * uvector,
		 unsigned nr_segs, unsigned fast_segs,
		 struct iovec **iov, struct __iov_iter *i);

#ifdef CONFIG_COMPAT
struct compat_iovec;
int compat_import_iovec(int type, const struct compat_iovec __user * uvector,
		 unsigned nr_segs, unsigned fast_segs,
		 struct iovec **iov, struct __iov_iter *i);
#endif

int import_single_range(int type, void __user *buf, size_t len,
		 struct iovec *iov, struct __iov_iter *i);

#endif
