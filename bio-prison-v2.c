/*
 * Copyright (C) 2012-2017 Red Hat, Inc.
 *
 * This file is released under the GPL.
 * Original file: dm-bio-prison-v2.c
 */

#include "bio-prison-v2.h"
#include "pxtgt.h"

#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

/*----------------------------------------------------------------*/

#define MIN_CELLS 1024

struct bio_prison_v2 {
  struct workqueue_struct *wq;

  spinlock_t lock;
  struct rb_root cells;
  mempool_t cell_pool;
};

static struct kmem_cache *_cell_cache;

/*----------------------------------------------------------------*/

/*
 * @nr_cells should be the number of cells you want in use _concurrently_.
 * Don't confuse it with the number of distinct keys.
 */
struct bio_prison_v2 *bio_prison_create_v2(struct workqueue_struct *wq) {
  struct bio_prison_v2 *prison = kzalloc(sizeof(*prison), GFP_KERNEL);
  int ret;

  if (!prison) return NULL;

  prison->wq = wq;
  spin_lock_init(&prison->lock);

  if (!_cell_cache) {
    if (bio_prison_init_v2()) {
      return NULL;
    }
  }

  ret = mempool_init_slab_pool(&prison->cell_pool, MIN_CELLS, _cell_cache);
  if (ret) {
    kfree(prison);
    return NULL;
  }

  prison->cells = RB_ROOT;

  return prison;
}
// EXPORT_SYMBOL_GPL(bio_prison_create_v2);

void bio_prison_destroy_v2(struct bio_prison_v2 *prison) {
  mempool_exit(&prison->cell_pool);
  kfree(prison);
}
// EXPORT_SYMBOL_GPL(bio_prison_destroy_v2);

struct bio_prison_cell_v2 *bio_prison_alloc_cell_v2(
    struct bio_prison_v2 *prison, gfp_t gfp) {
  return mempool_alloc(&prison->cell_pool, gfp);
}
// EXPORT_SYMBOL_GPL(bio_prison_alloc_cell_v2);

void bio_prison_free_cell_v2(struct bio_prison_v2 *prison,
                             struct bio_prison_cell_v2 *cell) {
  mempool_free(cell, &prison->cell_pool);
}
// EXPORT_SYMBOL_GPL(bio_prison_free_cell_v2);

static void __setup_new_cell(struct cell_key_v2 *key,
                             struct bio_prison_cell_v2 *cell) {
  memset(cell, 0, sizeof(*cell));
  memcpy(&cell->key, key, sizeof(cell->key));
  bio_list_init(&cell->bios);
}

static int cmp_keys(struct cell_key_v2 *lhs, struct cell_key_v2 *rhs) {
  if (lhs->virtual < rhs->virtual) return -1;

  if (lhs->virtual > rhs->virtual) return 1;

  if (lhs->dev < rhs->dev) return -1;

  if (lhs->dev > rhs->dev) return 1;

  if (lhs->block_end <= rhs->block_begin) return -1;

  if (lhs->block_begin >= rhs->block_end) return 1;

  return 0;
}

/*
 * Returns true if node found, otherwise it inserts a new one.
 */
static bool __find_or_insert(struct bio_prison_v2 *prison,
                             struct cell_key_v2 *key,
                             struct bio_prison_cell_v2 *cell_prealloc,
                             struct bio_prison_cell_v2 **result) {
  int r;
  struct rb_node **new = &prison->cells.rb_node, *parent = NULL;

  while (*new) {
    struct bio_prison_cell_v2 *cell =
        rb_entry(*new, struct bio_prison_cell_v2, node);

    r = cmp_keys(key, &cell->key);

    parent = *new;
    if (r < 0)
      new = &((*new)->rb_left);

    else if (r > 0)
      new = &((*new)->rb_right);

    else {
      *result = cell;
      return true;
    }
  }

  __setup_new_cell(key, cell_prealloc);
  *result = cell_prealloc;
  rb_link_node(&cell_prealloc->node, parent, new);
  rb_insert_color(&cell_prealloc->node, &prison->cells);

  return false;
}

static bool __get(struct bio_prison_v2 *prison, struct cell_key_v2 *key,
                  unsigned lock_level, struct bio *inmate,
                  struct bio_prison_cell_v2 *cell_prealloc,
                  struct bio_prison_cell_v2 **cell) {
  if (__find_or_insert(prison, key, cell_prealloc, cell)) {
    if ((*cell)->exclusive_lock) {
      if (lock_level <= (*cell)->exclusive_level) {
        bio_list_add(&(*cell)->bios, inmate);
        return false;
      }
    }

    (*cell)->shared_count++;

  } else
    (*cell)->shared_count = 1;

  return true;
}

bool cell_get_v2(struct bio_prison_v2 *prison, struct cell_key_v2 *key,
                 unsigned lock_level, struct bio *inmate,
                 struct bio_prison_cell_v2 *cell_prealloc,
                 struct bio_prison_cell_v2 **cell_result) {
  int r;
  unsigned long flags;

  spin_lock_irqsave(&prison->lock, flags);
  r = __get(prison, key, lock_level, inmate, cell_prealloc, cell_result);
  spin_unlock_irqrestore(&prison->lock, flags);

  return r;
}
// EXPORT_SYMBOL_GPL(cell_get_v2);

static bool __put(struct bio_prison_v2 *prison,
                  struct bio_prison_cell_v2 *cell) {
  BUG_ON(!cell->shared_count);
  cell->shared_count--;

  // FIXME: shared locks granted above the lock level could starve this
  if (!cell->shared_count) {
    if (cell->exclusive_lock) {
      if (cell->quiesce_continuation) {
        queue_work(prison->wq, cell->quiesce_continuation);
        cell->quiesce_continuation = NULL;
      }
    } else {
      rb_erase(&cell->node, &prison->cells);
      return true;
    }
  }

  return false;
}

bool cell_put_v2(struct bio_prison_v2 *prison,
                 struct bio_prison_cell_v2 *cell) {
  bool r;
  unsigned long flags;

  spin_lock_irqsave(&prison->lock, flags);
  r = __put(prison, cell);
  spin_unlock_irqrestore(&prison->lock, flags);

  return r;
}
// EXPORT_SYMBOL_GPL(cell_put_v2);

static int __lock(struct bio_prison_v2 *prison, struct cell_key_v2 *key,
                  unsigned lock_level, struct bio_prison_cell_v2 *cell_prealloc,
                  struct bio_prison_cell_v2 **cell_result) {
  struct bio_prison_cell_v2 *cell;

  if (__find_or_insert(prison, key, cell_prealloc, &cell)) {
    if (cell->exclusive_lock) return -EBUSY;

    cell->exclusive_lock = true;
    cell->exclusive_level = lock_level;
    *cell_result = cell;

    // FIXME: we don't yet know what level these shared locks
    // were taken at, so have to quiesce them all.
    return cell->shared_count > 0;

  } else {
    cell = cell_prealloc;
    cell->shared_count = 0;
    cell->exclusive_lock = true;
    cell->exclusive_level = lock_level;
    *cell_result = cell;
  }

  return 0;
}

int cell_lock_v2(struct bio_prison_v2 *prison, struct cell_key_v2 *key,
                 unsigned lock_level, struct bio_prison_cell_v2 *cell_prealloc,
                 struct bio_prison_cell_v2 **cell_result) {
  int r;
  unsigned long flags;

  spin_lock_irqsave(&prison->lock, flags);
  r = __lock(prison, key, lock_level, cell_prealloc, cell_result);
  spin_unlock_irqrestore(&prison->lock, flags);

  return r;
}
// EXPORT_SYMBOL_GPL(cell_lock_v2);

static void __quiesce(struct bio_prison_v2 *prison,
                      struct bio_prison_cell_v2 *cell,
                      struct work_struct *continuation) {
  if (!cell->shared_count)
    queue_work(prison->wq, continuation);
  else
    cell->quiesce_continuation = continuation;
}

void cell_quiesce_v2(struct bio_prison_v2 *prison,
                     struct bio_prison_cell_v2 *cell,
                     struct work_struct *continuation) {
  unsigned long flags;

  spin_lock_irqsave(&prison->lock, flags);
  __quiesce(prison, cell, continuation);
  spin_unlock_irqrestore(&prison->lock, flags);
}
// EXPORT_SYMBOL_GPL(cell_quiesce_v2);

static int __promote(struct bio_prison_v2 *prison,
                     struct bio_prison_cell_v2 *cell, unsigned new_lock_level) {
  if (!cell->exclusive_lock) return -EINVAL;

  cell->exclusive_level = new_lock_level;
  return cell->shared_count > 0;
}

int cell_lock_promote_v2(struct bio_prison_v2 *prison,
                         struct bio_prison_cell_v2 *cell,
                         unsigned new_lock_level) {
  int r;
  unsigned long flags;

  spin_lock_irqsave(&prison->lock, flags);
  r = __promote(prison, cell, new_lock_level);
  spin_unlock_irqrestore(&prison->lock, flags);

  return r;
}
// EXPORT_SYMBOL_GPL(cell_lock_promote_v2);

static bool __unlock(struct bio_prison_v2 *prison,
                     struct bio_prison_cell_v2 *cell, struct bio_list *bios) {
  BUG_ON(!cell->exclusive_lock);

  bio_list_merge(bios, &cell->bios);
  bio_list_init(&cell->bios);

  if (cell->shared_count) {
    cell->exclusive_lock = 0;
    return false;
  }

  rb_erase(&cell->node, &prison->cells);
  return true;
}

bool cell_unlock_v2(struct bio_prison_v2 *prison,
                    struct bio_prison_cell_v2 *cell, struct bio_list *bios) {
  bool r;
  unsigned long flags;

  spin_lock_irqsave(&prison->lock, flags);
  r = __unlock(prison, cell, bios);
  spin_unlock_irqrestore(&prison->lock, flags);

  return r;
}
// EXPORT_SYMBOL_GPL(cell_unlock_v2);

/*----------------------------------------------------------------*/

int bio_prison_init_v2(void) {
  _cell_cache = KMEM_CACHE(bio_prison_cell_v2, 0);
  if (!_cell_cache) return -ENOMEM;

  return 0;
}

void bio_prison_exit_v2(void) {
  kmem_cache_destroy(_cell_cache);
  _cell_cache = NULL;
}
