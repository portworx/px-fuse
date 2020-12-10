#ifndef _PX_LIB_H_
#define _PX_LIB_H_

// references datastructures from dm-cache-policy-smq
#include <linux/hash.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/math64.h>

// for origin block and cache block
typedef uint64_t block_t;
typedef uint64_t oblock_t, cblock_t, dblock_t;

static inline oblock_t to_oblock(block_t b)
{
	return (__force oblock_t) b;
}

static inline block_t from_oblock(oblock_t b)
{
	return (__force block_t) b;
}

static inline cblock_t to_cblock(uint32_t b)
{
	return (__force cblock_t) b;
}

static inline uint32_t from_cblock(cblock_t b)
{
	return (__force uint32_t) b;
}

static inline dblock_t to_dblock(block_t b)
{
	return (__force dblock_t) b;
}

static inline block_t from_dblock(dblock_t b)
{
	return (__force block_t) b;
}

static inline sector_t to_sector(uint64_t  n)
{
	return (n >> SECTOR_SHIFT);
}

static inline uint64_t  to_bytes(sector_t n)
{
	return (n << SECTOR_SHIFT);
}

/*
 * Some utility functions commonly used by policies and the core target.
 */
#define dm_sector_div64(x, y)( \
{ \
	u64 _res; \
	(x) = div64_u64_rem(x, y, &_res); \
	_res; \
} \
)

/*
 * Ceiling(n / sz)
 */
#define dm_div_up(n, sz) (((n) + (sz) - 1) / (sz))

#define dm_sector_div_up(n, sz) ( \
{ \
	sector_t _r = ((n) + (sz) - 1); \
	sector_div(_r, (sz)); \
	_r; \
} \
)

/*
 * ceiling(n / size) * size
 */
#define dm_round_up(n, sz) (dm_div_up((n), (sz)) * (sz))

static inline size_t bitset_size_in_bytes(unsigned nr_entries)
{
	return sizeof(unsigned long) * dm_div_up(nr_entries, BITS_PER_LONG);
}

static inline unsigned long *alloc_bitset(unsigned nr_entries)
{
	size_t s = bitset_size_in_bytes(nr_entries);
	return vzalloc(s);
}

static inline void clear_bitset(void *bitset, unsigned nr_entries)
{
	size_t s = bitset_size_in_bytes(nr_entries);
	memset(bitset, 0, s);
}

static inline void free_bitset(unsigned long *bits)
{
	vfree(bits);
}


/*----------------------------------------------------------------*/

/*
 * Safe division functions that return zero on divide by zero.
 */
static inline unsigned safe_div(unsigned n, unsigned d)
{
	return d ? n / d : 0u;
}

static inline unsigned safe_div64(uint64_t n, uint64_t d)
{
	return d ? n / d : 0u;
}

static inline unsigned safe_mod(unsigned n, unsigned d)
{
	return d ? n % d : 0u;
}

/*----------------------------------------------------------------*/

struct entry {
	unsigned hash_next:28;
	unsigned prev:28;
	unsigned next:28;
	unsigned level:6;
	bool dirty:1;
	bool allocated:1;
	bool sentinel:1;
	bool pending_work:1;

	oblock_t oblock;
};

/*----------------------------------------------------------------*/

#define INDEXER_NULL ((1u << 28u) - 1u)

/*
 * An entry_space manages a set of entries that we use for the queues.
 * The clean and dirty queues share entries, so this object is separate
 * from the queue itself.
 */
struct entry_space {
	struct entry *begin;
	struct entry *end;
};

static inline int space_init(struct entry_space *es, unsigned nr_entries)
{
	if (!nr_entries) {
		es->begin = es->end = NULL;
		return 0;
	}

	es->begin = vzalloc(array_size(nr_entries, sizeof(struct entry)));
	if (!es->begin)
		return -ENOMEM;

	es->end = es->begin + nr_entries;
	return 0;
}

static inline void space_exit(struct entry_space *es)
{
	vfree(es->begin);
}

static inline struct entry *__get_entry(struct entry_space *es, unsigned block)
{
	struct entry *e;

	e = es->begin + block;
	BUG_ON(e >= es->end);

	return e;
}

static inline unsigned to_index(struct entry_space *es, struct entry *e)
{
	BUG_ON(e < es->begin || e >= es->end);
	return e - es->begin;
}

static inline struct entry *to_entry(struct entry_space *es, unsigned block)
{
	if (block == INDEXER_NULL)
		return NULL;

	return __get_entry(es, block);
}

/*----------------------------------------------------------------*/

struct ilist {
	unsigned nr_elts;	/* excluding sentinel entries */
	unsigned head, tail;
};

static inline void l_init(struct ilist *l)
{
	l->nr_elts = 0;
	l->head = l->tail = INDEXER_NULL;
}

static inline struct entry *l_head(struct entry_space *es, struct ilist *l)
{
	return to_entry(es, l->head);
}

static inline struct entry *l_tail(struct entry_space *es, struct ilist *l)
{
	return to_entry(es, l->tail);
}

static inline struct entry *l_next(struct entry_space *es, struct entry *e)
{
	return to_entry(es, e->next);
}

static inline struct entry *l_prev(struct entry_space *es, struct entry *e)
{
	return to_entry(es, e->prev);
}

static inline bool l_empty(struct ilist *l)
{
	return l->head == INDEXER_NULL;
}

static inline void l_add_head(struct entry_space *es, struct ilist *l, struct entry *e)
{
	struct entry *head = l_head(es, l);

	e->next = l->head;
	e->prev = INDEXER_NULL;

	if (head)
		head->prev = l->head = to_index(es, e);
	else
		l->head = l->tail = to_index(es, e);

	if (!e->sentinel)
		l->nr_elts++;
}

static inline void l_add_tail(struct entry_space *es, struct ilist *l, struct entry *e)
{
	struct entry *tail = l_tail(es, l);

	e->next = INDEXER_NULL;
	e->prev = l->tail;

	if (tail)
		tail->next = l->tail = to_index(es, e);
	else
		l->head = l->tail = to_index(es, e);

	if (!e->sentinel)
		l->nr_elts++;
}

static inline void l_add_before(struct entry_space *es, struct ilist *l,
			 struct entry *old, struct entry *e)
{
	struct entry *prev = l_prev(es, old);

	if (!prev)
		l_add_head(es, l, e);

	else {
		e->prev = old->prev;
		e->next = to_index(es, old);
		prev->next = old->prev = to_index(es, e);

		if (!e->sentinel)
			l->nr_elts++;
	}
}

static inline void l_del(struct entry_space *es, struct ilist *l, struct entry *e)
{
	struct entry *prev = l_prev(es, e);
	struct entry *next = l_next(es, e);

	if (prev)
		prev->next = e->next;
	else
		l->head = e->next;

	if (next)
		next->prev = e->prev;
	else
		l->tail = e->prev;

	if (!e->sentinel)
		l->nr_elts--;
}

static inline struct entry *l_pop_head(struct entry_space *es, struct ilist *l)
{
	struct entry *e;

	for (e = l_head(es, l); e; e = l_next(es, e))
		if (!e->sentinel) {
			l_del(es, l, e);
			return e;
		}

	return NULL;
}

static inline struct entry *l_pop_tail(struct entry_space *es, struct ilist *l)
{
	struct entry *e;

	for (e = l_tail(es, l); e; e = l_prev(es, e))
		if (!e->sentinel) {
			l_del(es, l, e);
			return e;
		}

	return NULL;
}

/*----------------------------------------------------------------*/

/*
 * The stochastic-multi-queue is a set of lru lists stacked into levels.
 * Entries are moved up levels when they are used, which loosely orders the
 * most accessed entries in the top levels and least in the bottom.  This
 * structure is *much* better than a single lru list.
 */
#define MAX_LEVELS 64u

struct queue {
	struct entry_space *es;

	unsigned nr_elts;
	unsigned nr_levels;
	struct ilist qs[MAX_LEVELS];

	/*
	 * We maintain a count of the number of entries we would like in each
	 * level.
	 */
	unsigned last_target_nr_elts;
	unsigned nr_top_levels;
	unsigned nr_in_top_levels;
	unsigned target_count[MAX_LEVELS];
};

static inline void q_init(struct queue *q, struct entry_space *es, unsigned nr_levels)
{
	unsigned i;

	q->es = es;
	q->nr_elts = 0;
	q->nr_levels = nr_levels;

	for (i = 0; i < q->nr_levels; i++) {
		l_init(q->qs + i);
		q->target_count[i] = 0u;
	}

	q->last_target_nr_elts = 0u;
	q->nr_top_levels = 0u;
	q->nr_in_top_levels = 0u;
}

static inline unsigned q_size(struct queue *q)
{
	return q->nr_elts;
}

/*
 * Insert an entry to the back of the given level.
 */
static inline void q_push(struct queue *q, struct entry *e)
{
	BUG_ON(e->pending_work);

	if (!e->sentinel)
		q->nr_elts++;

	l_add_tail(q->es, q->qs + e->level, e);
}

static inline void q_push_front(struct queue *q, struct entry *e)
{
	BUG_ON(e->pending_work);

	if (!e->sentinel)
		q->nr_elts++;

	l_add_head(q->es, q->qs + e->level, e);
}

static inline void q_push_before(struct queue *q, struct entry *old, struct entry *e)
{
	BUG_ON(e->pending_work);

	if (!e->sentinel)
		q->nr_elts++;

	l_add_before(q->es, q->qs + e->level, old, e);
}

static inline void q_del(struct queue *q, struct entry *e)
{
	l_del(q->es, q->qs + e->level, e);
	if (!e->sentinel)
		q->nr_elts--;
}

/*
 * Return the oldest entry of the lowest populated level.
 */
static inline struct entry *q_peek(struct queue *q, unsigned max_level, bool can_cross_sentinel)
{
	unsigned level;
	struct entry *e;

	max_level = min(max_level, q->nr_levels);

	for (level = 0; level < max_level; level++)
		for (e = l_head(q->es, q->qs + level); e; e = l_next(q->es, e)) {
			if (e->sentinel) {
				if (can_cross_sentinel)
					continue;
				else
					break;
			}

			return e;
		}

	return NULL;
}

static inline struct entry *q_pop(struct queue *q)
{
	struct entry *e = q_peek(q, q->nr_levels, true);

	if (e)
		q_del(q, e);

	return e;
}

/*
 * This function assumes there is a non-sentinel entry to pop.  It's only
 * used by redistribute, so we know this is true.  It also doesn't adjust
 * the q->nr_elts count.
 */
static inline struct entry *__redist_pop_from(struct queue *q, unsigned level)
{
	struct entry *e;

	for (; level < q->nr_levels; level++)
		for (e = l_head(q->es, q->qs + level); e; e = l_next(q->es, e))
			if (!e->sentinel) {
				l_del(q->es, q->qs + e->level, e);
				return e;
			}

	return NULL;
}

static inline void q_set_targets_subrange_(struct queue *q, unsigned nr_elts, unsigned lbegin, unsigned lend)
{
	unsigned level, nr_levels, entries_per_level, remainder;

	BUG_ON(lbegin > lend);
	BUG_ON(lend > q->nr_levels);
	nr_levels = lend - lbegin;
	entries_per_level = safe_div(nr_elts, nr_levels);
	remainder = safe_mod(nr_elts, nr_levels);

	for (level = lbegin; level < lend; level++)
		q->target_count[level] =
			(level < (lbegin + remainder)) ? entries_per_level + 1u : entries_per_level;
}

/*
 * Typically we have fewer elements in the top few levels which allows us
 * to adjust the promote threshold nicely.
 */
static inline void q_set_targets(struct queue *q)
{
	if (q->last_target_nr_elts == q->nr_elts)
		return;

	q->last_target_nr_elts = q->nr_elts;

	if (q->nr_top_levels > q->nr_levels)
		q_set_targets_subrange_(q, q->nr_elts, 0, q->nr_levels);

	else {
		q_set_targets_subrange_(q, q->nr_in_top_levels,
					q->nr_levels - q->nr_top_levels, q->nr_levels);

		if (q->nr_in_top_levels < q->nr_elts)
			q_set_targets_subrange_(q, q->nr_elts - q->nr_in_top_levels,
						0, q->nr_levels - q->nr_top_levels);
		else
			q_set_targets_subrange_(q, 0, 0, q->nr_levels - q->nr_top_levels);
	}
}

static inline void q_redistribute(struct queue *q)
{
	unsigned target, level;
	struct ilist *l, *l_above;
	struct entry *e;

	q_set_targets(q);

	for (level = 0u; level < q->nr_levels - 1u; level++) {
		l = q->qs + level;
		target = q->target_count[level];

		/*
		 * Pull down some entries from the level above.
		 */
		while (l->nr_elts < target) {
			e = __redist_pop_from(q, level + 1u);
			if (!e) {
				/* bug in nr_elts */
				break;
			}

			e->level = level;
			l_add_tail(q->es, l, e);
		}

		/*
		 * Push some entries up.
		 */
		l_above = q->qs + level + 1u;
		while (l->nr_elts > target) {
			e = l_pop_tail(q->es, l);

			if (!e)
				/* bug in nr_elts */
				break;

			e->level = level + 1u;
			l_add_tail(q->es, l_above, e);
		}
	}
}

static inline void q_requeue(struct queue *q, struct entry *e, unsigned extra_levels,
		      struct entry *s1, struct entry *s2)
{
	struct entry *de;
	unsigned sentinels_passed = 0;
	unsigned new_level = min(q->nr_levels - 1u, e->level + extra_levels);

	/* try and find an entry to swap with */
	if (extra_levels && (e->level < q->nr_levels - 1u)) {
		for (de = l_head(q->es, q->qs + new_level); de && de->sentinel; de = l_next(q->es, de))
			sentinels_passed++;

		if (de) {
			q_del(q, de);
			de->level = e->level;
			if (s1) {
				switch (sentinels_passed) {
				case 0:
					q_push_before(q, s1, de);
					break;

				case 1:
					q_push_before(q, s2, de);
					break;

				default:
					q_push(q, de);
				}
			} else
				q_push(q, de);
		}
	}

	q_del(q, e);
	e->level = new_level;
	q_push(q, e);
}

/*----------------------------------------------------------------*/

#define FP_SHIFT 8
#define SIXTEENTH (1u << (FP_SHIFT - 4u))
#define EIGHTH (1u << (FP_SHIFT - 3u))

struct stats {
	unsigned hit_threshold;
	unsigned hits;
	unsigned misses;
};

enum performance {
	Q_POOR,
	Q_FAIR,
	Q_WELL
};

static inline void stats_init(struct stats *s, unsigned nr_levels)
{
	s->hit_threshold = (nr_levels * 3u) / 4u;
	s->hits = 0u;
	s->misses = 0u;
}

static inline void stats_reset(struct stats *s)
{
	s->hits = s->misses = 0u;
}

static inline void stats_level_accessed(struct stats *s, unsigned level)
{
	if (level >= s->hit_threshold)
		s->hits++;
	else
		s->misses++;
}

static inline void stats_miss(struct stats *s)
{
	s->misses++;
}

/*
 * There are times when we don't have any confidence in the hotspot queue.
 * Such as when a fresh cache is created and the blocks have been spread
 * out across the levels, or if an io load changes.  We detect this by
 * seeing how often a lookup is in the top levels of the hotspot queue.
 */
static inline enum performance stats_assess(struct stats *s)
{
	unsigned confidence = safe_div(s->hits << FP_SHIFT, s->hits + s->misses);

	if (confidence < SIXTEENTH)
		return Q_POOR;

	else if (confidence < EIGHTH)
		return Q_FAIR;

	else
		return Q_WELL;
}

/*----------------------------------------------------------------*/

struct smq_hash_table {
	struct entry_space *es;
	unsigned long long hash_bits;
	unsigned *buckets;
};

/*
 * All cache entries are stored in a chained hash table.  To save space we
 * use indexing again, and only store indexes to the next entry.
 */
static inline int h_init(struct smq_hash_table *ht, struct entry_space *es, unsigned nr_entries)
{
	unsigned i, nr_buckets;

	ht->es = es;
	nr_buckets = roundup_pow_of_two(max(nr_entries / 4u, 16u));
	ht->hash_bits = __ffs(nr_buckets);

	ht->buckets = vmalloc(array_size(nr_buckets, sizeof(*ht->buckets)));
	if (!ht->buckets)
		return -ENOMEM;

	for (i = 0; i < nr_buckets; i++)
		ht->buckets[i] = INDEXER_NULL;

	return 0;
}

static inline void h_exit(struct smq_hash_table *ht)
{
	vfree(ht->buckets);
}

static inline struct entry *h_head(struct smq_hash_table *ht, unsigned bucket)
{
	return to_entry(ht->es, ht->buckets[bucket]);
}

static inline struct entry *h_next(struct smq_hash_table *ht, struct entry *e)
{
	return to_entry(ht->es, e->hash_next);
}

static inline void __h_insert(struct smq_hash_table *ht, unsigned bucket, struct entry *e)
{
	e->hash_next = ht->buckets[bucket];
	ht->buckets[bucket] = to_index(ht->es, e);
}

static inline void h_insert(struct smq_hash_table *ht, struct entry *e)
{
	unsigned h = hash_64(from_oblock(e->oblock), ht->hash_bits);
	__h_insert(ht, h, e);
}

static inline struct entry *__h_lookup(struct smq_hash_table *ht, unsigned h, oblock_t oblock,
				struct entry **prev)
{
	struct entry *e;

	*prev = NULL;
	for (e = h_head(ht, h); e; e = h_next(ht, e)) {
		if (e->oblock == oblock)
			return e;

		*prev = e;
	}

	return NULL;
}

static inline void __h_unlink(struct smq_hash_table *ht, unsigned h,
		       struct entry *e, struct entry *prev)
{
	if (prev)
		prev->hash_next = e->hash_next;
	else
		ht->buckets[h] = e->hash_next;
}

/*
 * Also moves each entry to the front of the bucket.
 */
static inline struct entry *h_lookup(struct smq_hash_table *ht, oblock_t oblock)
{
	struct entry *e, *prev;
	unsigned h = hash_64(from_oblock(oblock), ht->hash_bits);

	e = __h_lookup(ht, h, oblock, &prev);
	if (e && prev) {
		/*
		 * Move to the front because this entry is likely
		 * to be hit again.
		 */
		__h_unlink(ht, h, e, prev);
		__h_insert(ht, h, e);
	}

	return e;
}

static inline void h_remove(struct smq_hash_table *ht, struct entry *e)
{
	unsigned h = hash_64(from_oblock(e->oblock), ht->hash_bits);
	struct entry *prev;

	/*
	 * The down side of using a singly linked list is we have to
	 * iterate the bucket to remove an item.
	 */
	e = __h_lookup(ht, h, e->oblock, &prev);
	if (e)
		__h_unlink(ht, h, e, prev);
}

/*----------------------------------------------------------------*/

struct entry_alloc {
	struct entry_space *es;
	unsigned begin;

	unsigned nr_allocated;
	struct ilist free;
};

static inline void init_allocator(struct entry_alloc *ea, struct entry_space *es,
			   unsigned begin, unsigned end)
{
	unsigned i;

	ea->es = es;
	ea->nr_allocated = 0u;
	ea->begin = begin;

	l_init(&ea->free);
	for (i = begin; i != end; i++)
		l_add_tail(ea->es, &ea->free, __get_entry(ea->es, i));
}

static inline void init_entry(struct entry *e)
{
	/*
	 * We can't memset because that would clear the hotspot and
	 * sentinel bits which remain constant.
	 */
	e->hash_next = INDEXER_NULL;
	e->next = INDEXER_NULL;
	e->prev = INDEXER_NULL;
	e->level = 0u;
	e->dirty = true;	/* FIXME: audit */
	e->allocated = true;
	e->sentinel = false;
	e->pending_work = false;
}

static inline struct entry *alloc_entry(struct entry_alloc *ea)
{
	struct entry *e;

	if (l_empty(&ea->free))
		return NULL;

	e = l_pop_head(ea->es, &ea->free);
	init_entry(e);
	ea->nr_allocated++;

	return e;
}

/*
 * This assumes the cblock hasn't already been allocated.
 */
static inline struct entry *alloc_particular_entry(struct entry_alloc *ea, unsigned i)
{
	struct entry *e = __get_entry(ea->es, ea->begin + i);

	BUG_ON(e->allocated);

	l_del(ea->es, &ea->free, e);
	init_entry(e);
	ea->nr_allocated++;

	return e;
}

static inline void free_entry(struct entry_alloc *ea, struct entry *e)
{
	BUG_ON(!ea->nr_allocated);
	BUG_ON(!e->allocated);

	ea->nr_allocated--;
	e->allocated = false;
	l_add_tail(ea->es, &ea->free, e);
}

static inline bool allocator_empty(struct entry_alloc *ea)
{
	return l_empty(&ea->free);
}

static inline unsigned get_index(struct entry_alloc *ea, struct entry *e)
{
	return to_index(ea->es, e) - ea->begin;
}

static inline struct entry *get_entry(struct entry_alloc *ea, unsigned index)
{
	return __get_entry(ea->es, ea->begin + index);
}

#endif /* _PX_LIB_H_ */
