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
 * slot — kernel and userspace share the mmap'd queue verbatim.
 */

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
