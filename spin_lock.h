#ifndef PXFUSE_SPIN_LOCK_H
#define PXFUSE_SPIN_LOCK_H

/*
 * Userspace spin-lock wrapper used inside the shared fuse_queue_cb layout
 * (fuse_i.h, userspace branch). Lives in px-fuse so that px-fuse compiles
 * standalone: px-storage (and any other consumer of fuse_i.h) depends on
 * px-fuse, not the other way around.
 *
 * Layout-compatible with a raw pthread_spinlock_t: sizeof(px::spinlock) ==
 * sizeof(pthread_spinlock_t), no vtable. This is required because the same
 * bytes also overlay the kernel-side fuse_queue_reader { need_wake_up; pad; }
 * slot. Kernel and userspace share the mmap'd queue verbatim.
 *
 * This header is C++ only. The kernel module never includes it: fuse_i.h
 * gates the userspace block on __KERNEL__, and __KERNEL__ is defined for
 * the kernel build (see Makefile.in: KBUILD_CPPFLAGS := -D__KERNEL__).
 * The guard below catches accidental inclusion from C translation units.
 */

#ifndef __cplusplus
#error "spin_lock.h is C++ only; include from a C++ TU or guard with #ifdef __cplusplus"
#endif

#include <pthread.h>

namespace px {

class spinlock {
public:
	spinlock() = default;

	spinlock(const spinlock &other) = delete;
	spinlock(spinlock &&other) = delete;

	spinlock &operator=(const spinlock &other) = delete;
	spinlock &operator=(spinlock &&other) = delete;

	void lock() { (void)pthread_spin_lock(&lock_); }

	void unlock() { (void)pthread_spin_unlock(&lock_); }

	bool try_lock() { return pthread_spin_trylock(&lock_) == 0; }

	bool locked() const { return lock_ != 1; }

private:
	pthread_spinlock_t lock_ = 1;
};

} // namespace px

#endif // PXFUSE_SPIN_LOCK_H
