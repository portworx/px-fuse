#ifndef _PXTGT_ACCT_H_
#define _PXTGT_ACCT_H_

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)

#ifdef RHEL_RELEASE_CODE

#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 6)
static inline void _generic_end_io_acct(struct request_queue *q, int rw,
                                        struct hd_struct *part,
                                        unsigned long start_time) {
  unsigned long duration = jiffies - start_time;
  int cpu = part_stat_lock();

  part_stat_add(cpu, part, ticks[rw], duration);
  part_round_stats(q, cpu, part);
  part_dec_in_flight(q, part, rw);

  part_stat_unlock();
}

static inline void _generic_start_io_acct(struct request_queue *q, int rw,
                                          unsigned long sectors,
                                          struct hd_struct *part) {
  int cpu = part_stat_lock();

  part_round_stats(q, cpu, part);
  part_stat_inc(cpu, part, ios[rw]);
  part_stat_add(cpu, part, sectors[rw], sectors);
  part_inc_in_flight(q, part, rw);

  part_stat_unlock();
}
#else
static inline void _generic_end_io_acct(struct request_queue *q, int rw,
                                        struct hd_struct *part,
                                        unsigned long start_time) {
  unsigned long duration = jiffies - start_time;
  int cpu = part_stat_lock();

  part_stat_add(cpu, part, ticks[rw], duration);
  part_round_stats(cpu, part);
  part_dec_in_flight(part, rw);

  part_stat_unlock();
}

static inline void _generic_start_io_acct(struct request_queue *q, int rw,
                                          unsigned long sectors,
                                          struct hd_struct *part) {
  int cpu = part_stat_lock();

  part_round_stats(cpu, part);
  part_stat_inc(cpu, part, ios[rw]);
  part_stat_add(cpu, part, sectors[rw], sectors);
  part_inc_in_flight(part, rw);

  part_stat_unlock();
}
#endif

#else
// non RHEL distro
// based on unpatched pristine kernel release
static inline void _generic_end_io_acct(struct request_queue *q, int rw,
                                        struct hd_struct *part,
                                        unsigned long start_time) {
  unsigned long duration = jiffies - start_time;
  int cpu = part_stat_lock();

  part_stat_add(cpu, part, ticks[rw], duration);
  part_round_stats(cpu, part);
  part_dec_in_flight(part, rw);

  part_stat_unlock();
}

static inline void _generic_start_io_acct(struct request_queue *q, int rw,
                                          unsigned long sectors,
                                          struct hd_struct *part) {
  int cpu = part_stat_lock();

  part_round_stats(cpu, part);
  part_stat_inc(cpu, part, ios[rw]);
  part_stat_add(cpu, part, sectors[rw], sectors);
  part_inc_in_flight(part, rw);

  part_stat_unlock();
}

#endif
#endif

#endif /* _PXTGT_ACCT_H_ */
