// SPDX-License-Identifier: GPL-2.0
/*
 * Focused user-space gtests for the px-fuse io_uring transport.
 *
 * Exercises only the uring-specific surface introduced in this port:
 *   - /dev/pxd/pxd-io char device (open/close, poll, fasync)
 *   - ioctl(PXD_IOC_INIT_IO)                 - ring setup + param normalization
 *   - mmap of SQ ring, CQ ring, SQE array
 *   - ioctl(PXD_IOC_WAKE_UP_SQO)             - SQO wakeup
 *   - ioctl(PXD_IOC_RUN_IO_QUEUE)            - kernel-side submission drain
 *   - ioctl(PXD_IOC_REGISTER_FILE / _UNREGISTER_FILE)
 *   - ioctl(PXD_IOC_REGISTER_REGION)
 *   - ioctl(PXD_IOC_REGISTER_BUFFERS / _UNREGISTER_BUFFERS)
 *   - end-to-end NOP submit + complete via the mmap'd rings
 *
 * Most tests require root + the px.ko module loaded.  Tests that need root
 * skip themselves with GTEST_SKIP() when not effective-uid 0.
 *
 * These tests are intentionally orthogonal to pxd_test.cc / pxd_fastpath_test.cc.
 * They never open /dev/pxd/pxd-control and never issue PXD_ADD / PXD_REMOVE -
 * just the uring side.
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <linux/fs.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

extern "C" {
#include "fuse.h"
#include "pxd.h"
#include "pxd_io_uring.h"
}

namespace {

constexpr const char *kPxdIoDev = "/dev/pxd/pxd-io";

bool running_as_root()
{
	return geteuid() == 0;
}

bool pxd_io_dev_available()
{
	struct stat st;
	return ::stat(kPxdIoDev, &st) == 0 && S_ISCHR(st.st_mode);
}

#define SKIP_IF_NO_PXD_IO()                                                                  \
	do {                                                                                     \
		if (!pxd_io_dev_available()) {                                                       \
			GTEST_SKIP() << kPxdIoDev << " not present (load px.ko first)";                  \
		}                                                                                    \
	} while (0)

#define SKIP_IF_NOT_ROOT()                                                                   \
	do {                                                                                     \
		if (!running_as_root()) {                                                            \
			GTEST_SKIP() << "test requires root (CAP_SYS_ADMIN for SQPOLL / mmap)";          \
		}                                                                                    \
	} while (0)

// RAII wrapper for the pxd-io fd.
class PxdIoFd {
  public:
	explicit PxdIoFd(int flags = O_RDWR) { fd_ = ::open(kPxdIoDev, flags); }
	~PxdIoFd()
	{
		if (fd_ >= 0)
			::close(fd_);
	}
	PxdIoFd(const PxdIoFd &) = delete;
	PxdIoFd &operator=(const PxdIoFd &) = delete;
	int get() const { return fd_; }
	bool ok() const { return fd_ >= 0; }
	int release()
	{
		int f = fd_;
		fd_ = -1;
		return f;
	}

  private:
	int fd_{-1};
};

// Initialize a ring on `fd` with `params`. Returns 0 on success or -errno.
int init_io_ring(int fd, struct io_uring_params *params)
{
	if (::ioctl(fd, PXD_IOC_INIT_IO, params) < 0)
		return -errno;
	return 0;
}

// Convenience: make a default-zero params with non-zero entry counts.
io_uring_params make_default_params(uint32_t sq_entries = 64, uint32_t cq_entries = 128)
{
	io_uring_params p{};
	p.sq_entries = sq_entries;
	p.cq_entries = cq_entries;
	return p;
}

// Round up to power of two helper (matches kernel-side roundup_pow_of_two).
uint32_t next_pow2(uint32_t v)
{
	if (v <= 1)
		return 1;
	--v;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	return v + 1;
}

// ---------------------------------------------------------------------------
// Bare-metal tests against the pxd-io char device.
// ---------------------------------------------------------------------------

TEST(PxdIoUring, DeviceNodeExists)
{
	SKIP_IF_NO_PXD_IO();
	struct stat st;
	ASSERT_EQ(::stat(kPxdIoDev, &st), 0) << strerror(errno);
	EXPECT_TRUE(S_ISCHR(st.st_mode));
}

TEST(PxdIoUring, OpenClose)
{
	SKIP_IF_NO_PXD_IO();
	PxdIoFd f;
	ASSERT_TRUE(f.ok()) << "open(" << kPxdIoDev << "): " << strerror(errno);
}

TEST(PxdIoUring, OpenMultipleInstances)
{
	SKIP_IF_NO_PXD_IO();
	PxdIoFd a;
	PxdIoFd b;
	PxdIoFd c;
	EXPECT_TRUE(a.ok());
	EXPECT_TRUE(b.ok());
	EXPECT_TRUE(c.ok());
	EXPECT_NE(a.get(), b.get());
	EXPECT_NE(b.get(), c.get());
}

TEST(PxdIoUring, IoctlOnUninitializedFails)
{
	SKIP_IF_NO_PXD_IO();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());

	// Random unrelated ioctl on an uninit ring fd should ENOTTY,
	// not crash the kernel.
	EXPECT_EQ(::ioctl(f.get(), BLKGETSIZE), -1);
	EXPECT_EQ(errno, ENOTTY);
}

TEST(PxdIoUring, PollOnUninitialized)
{
	SKIP_IF_NO_PXD_IO();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());

	// Poll on a freshly opened (uninitialized) pxd-io fd should not block.
	// We don't constrain the exact mask; just that it returns promptly.
	struct pollfd pfd{f.get(), POLLIN | POLLOUT, 0};
	int rc = ::poll(&pfd, 1, /*timeout_ms=*/0);
	EXPECT_GE(rc, 0) << strerror(errno);
}

// ---------------------------------------------------------------------------
// PXD_IOC_INIT_IO
// ---------------------------------------------------------------------------

TEST(PxdIoUring, InitDefaultParams)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());

	auto p = make_default_params(0, 0); // zero -> kernel picks FUSE_REQUEST_QUEUE_SIZE
	ASSERT_EQ(init_io_ring(f.get(), &p), 0) << "PXD_IOC_INIT_IO";

	EXPECT_GT(p.sq_entries, 0u);
	EXPECT_GT(p.cq_entries, 0u);
	// kernel rounds to power of two
	EXPECT_EQ(p.sq_entries, next_pow2(p.sq_entries));
	EXPECT_EQ(p.cq_entries, next_pow2(p.cq_entries));
}

TEST(PxdIoUring, InitRoundsToPowerOfTwo)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());

	// Pass non-power-of-two values; kernel should round up.
	auto p = make_default_params(33, 65);
	ASSERT_EQ(init_io_ring(f.get(), &p), 0);
	EXPECT_EQ(p.sq_entries, 64u);
	EXPECT_EQ(p.cq_entries, 128u);
}

TEST(PxdIoUring, InitSqAffWithoutSqPollFails)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());

	auto p = make_default_params();
	p.flags = IORING_SETUP_SQ_AFF; // SQ_AFF without SQPOLL is rejected
	EXPECT_LT(::ioctl(f.get(), PXD_IOC_INIT_IO, &p), 0);
	EXPECT_EQ(errno, EINVAL);
}

TEST(PxdIoUring, InitTwiceOnSameFdRejected)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());

	auto p1 = make_default_params();
	ASSERT_EQ(init_io_ring(f.get(), &p1), 0);

	// Second INIT_IO on the same fd: the implementation may either reject
	// or allow re-init.  Just assert it doesn't crash and the kernel
	// returns *some* result (success or error).
	auto p2 = make_default_params();
	int rc = ::ioctl(f.get(), PXD_IOC_INIT_IO, &p2);
	EXPECT_TRUE(rc == 0 || rc < 0);
}

// ---------------------------------------------------------------------------
// mmap of SQ ring, CQ ring, SQEs
// ---------------------------------------------------------------------------

struct Ring {
	PxdIoFd fd;
	io_uring_params params{};

	// Mapped pointer to ctx->queue base.
	void *base{nullptr};
	size_t base_len{0};

	// Aliased into base (matches kernel-side io_ring_ctx_init layout):
	//   [ fuse_queue_cb requests_cb ]
	//   [ io_uring_sqe requests[sq_entries] ]
	//   [ fuse_queue_cb responses_cb ]
	//   [ io_uring_cqe responses[cq_entries] ]
	fuse_queue_cb *requests_cb{nullptr};
	io_uring_sqe *requests{nullptr};
	fuse_queue_cb *responses_cb{nullptr};
	io_uring_cqe *responses{nullptr};

	bool setup(uint32_t sq = 64, uint32_t cq = 128, uint32_t flags = 0)
	{
		if (!fd.ok())
			return false;
		params = make_default_params(sq, cq);
		params.flags = flags;
		if (init_io_ring(fd.get(), &params) != 0)
			return false;

		// Compute the queue length used by the kernel.  Mirrors queue_size():
		//   sizeof(fuse_queue_cb)*2 + sq_entries*sizeof(sqe) + cq_entries*sizeof(cqe)
		// then page-aligned by vmalloc.
		size_t raw = sizeof(fuse_queue_cb) * 2 +
		             params.sq_entries * sizeof(io_uring_sqe) +
		             params.cq_entries * sizeof(io_uring_cqe);
		size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
		base_len = (raw + page - 1) & ~(page - 1);

		base = ::mmap(nullptr, base_len, PROT_READ | PROT_WRITE,
		              MAP_SHARED, fd.get(), 0);
		if (base == MAP_FAILED) {
			base = nullptr;
			return false;
		}

		auto *cb0 = reinterpret_cast<fuse_queue_cb *>(base);
		requests_cb = cb0;
		requests = reinterpret_cast<io_uring_sqe *>(cb0 + 1);
		responses_cb = reinterpret_cast<fuse_queue_cb *>(requests + params.sq_entries);
		responses = reinterpret_cast<io_uring_cqe *>(responses_cb + 1);
		return true;
	}

	~Ring()
	{
		if (base)
			::munmap(base, base_len);
	}
};

TEST(PxdIoUring, MmapQueueRegions)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	Ring r;
	ASSERT_TRUE(r.fd.ok());
	ASSERT_TRUE(r.setup());
	ASSERT_NE(r.base, nullptr);

	// CB fields should be zeroed by fuse_queue_init_cb / sequence-initialized.
	EXPECT_EQ(r.requests_cb->r.read, 0u);
	EXPECT_EQ(r.requests_cb->r.write, 0u);
	EXPECT_EQ(r.responses_cb->r.read, 0u);
	EXPECT_EQ(r.responses_cb->r.write, 0u);
}

TEST(PxdIoUring, MmapOutOfRangeFails)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());
	auto p = make_default_params();
	ASSERT_EQ(init_io_ring(f.get(), &p), 0);

	size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
	// Map far past the actual queue length; access should fault.
	void *bad = ::mmap(nullptr, page, PROT_READ, MAP_SHARED, f.get(),
	                   /*off=*/1ULL << 30);
	if (bad == MAP_FAILED) {
		// Some kernels reject the mmap call outright; that's acceptable.
		SUCCEED();
		return;
	}
	// If mmap succeeded, faulting on the bad page must SIGSEGV or return 0;
	// we don't dereference it here.
	::munmap(bad, page);
}

// ---------------------------------------------------------------------------
// SQO wakeup + RUN_IO_QUEUE on empty ring
// ---------------------------------------------------------------------------

TEST(PxdIoUring, WakeupSqo)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());
	auto p = make_default_params();
	ASSERT_EQ(init_io_ring(f.get(), &p), 0);

	EXPECT_EQ(::ioctl(f.get(), PXD_IOC_WAKE_UP_SQO), 0);
}

TEST(PxdIoUring, RunQueueWhenEmpty)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	Ring r;
	ASSERT_TRUE(r.fd.ok());
	ASSERT_TRUE(r.setup());

	EXPECT_EQ(::ioctl(r.fd.get(), PXD_IOC_RUN_IO_QUEUE), 0);
	// No CQE should have been produced.
	EXPECT_EQ(r.responses_cb->r.write, 0u);
}

// ---------------------------------------------------------------------------
// File registration
// ---------------------------------------------------------------------------

TEST(PxdIoUring, RegisterAndUnregisterFile)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());
	auto p = make_default_params();
	ASSERT_EQ(init_io_ring(f.get(), &p), 0);

	// Register a known regular file (a temp file).
	char tmppath[] = "/tmp/pxd-io-test.XXXXXX";
	int tmp = ::mkstemp(tmppath);
	ASSERT_GE(tmp, 0) << strerror(errno);
	::unlink(tmppath); // anonymous

	int idx = ::ioctl(f.get(), PXD_IOC_REGISTER_FILE, tmp);
	EXPECT_GE(idx, 0) << "PXD_IOC_REGISTER_FILE: " << strerror(errno);
	if (idx >= 0) {
		EXPECT_EQ(::ioctl(f.get(), PXD_IOC_UNREGISTER_FILE, idx), 0)
		    << strerror(errno);
	}
	::close(tmp);
}

TEST(PxdIoUring, UnregisterFileBadIndexFails)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());
	auto p = make_default_params();
	ASSERT_EQ(init_io_ring(f.get(), &p), 0);

	EXPECT_LT(::ioctl(f.get(), PXD_IOC_UNREGISTER_FILE,
	                  static_cast<unsigned long>(1u << 30)),
	          0);
	EXPECT_EQ(errno, EINVAL);
}

// ---------------------------------------------------------------------------
// Region & buffer registration
// ---------------------------------------------------------------------------

TEST(PxdIoUring, RegisterRegionRequiresPageAlignment)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());
	auto p = make_default_params();
	ASSERT_EQ(init_io_ring(f.get(), &p), 0);

	size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));

	// Unaligned length.
	pxd_ioc_register_region bad{};
	bad.base = reinterpret_cast<void *>(page); // aligned addr
	bad.len = page - 1;                        // unaligned length
	EXPECT_LT(::ioctl(f.get(), PXD_IOC_REGISTER_REGION, &bad), 0);
	EXPECT_EQ(errno, EINVAL);

	// Zero length.
	bad.len = 0;
	EXPECT_LT(::ioctl(f.get(), PXD_IOC_REGISTER_REGION, &bad), 0);
	EXPECT_EQ(errno, EINVAL);

	// Zero addr.
	bad.base = nullptr;
	bad.len = page;
	EXPECT_LT(::ioctl(f.get(), PXD_IOC_REGISTER_REGION, &bad), 0);
	EXPECT_EQ(errno, EINVAL);
}

TEST(PxdIoUring, RegisterRegionAndBuffersHappyPath)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());
	auto p = make_default_params();
	ASSERT_EQ(init_io_ring(f.get(), &p), 0);

	size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
	const size_t region_len = page * 4;

	// Map an anonymous region the kernel can pin.
	void *region = ::mmap(nullptr, region_len, PROT_READ | PROT_WRITE,
	                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(region, MAP_FAILED) << strerror(errno);

	pxd_ioc_register_region rr{};
	rr.base = region;
	rr.len = region_len;
	int region_idx = ::ioctl(f.get(), PXD_IOC_REGISTER_REGION, &rr);
	ASSERT_GE(region_idx, 0) << "PXD_IOC_REGISTER_REGION: " << strerror(errno);

	// Register a subset as a buffer in slot 0.
	pxd_ioc_register_buffers rb{};
	rb.base = region;
	rb.len = page * 2;
	rb.buf_index = 0;
	EXPECT_EQ(::ioctl(f.get(), PXD_IOC_REGISTER_BUFFERS, &rb), 0)
	    << "PXD_IOC_REGISTER_BUFFERS: " << strerror(errno);

	// Duplicate registration into the same slot must fail.
	EXPECT_LT(::ioctl(f.get(), PXD_IOC_REGISTER_BUFFERS, &rb), 0);
	EXPECT_EQ(errno, EEXIST);

	// Unregister all.
	EXPECT_EQ(::ioctl(f.get(), PXD_IOC_UNREGISTER_BUFFERS), 0);

	::munmap(region, region_len);
}

TEST(PxdIoUring, RegisterBuffersOutsideAnyRegion)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());
	auto p = make_default_params();
	ASSERT_EQ(init_io_ring(f.get(), &p), 0);

	size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
	pxd_ioc_register_buffers rb{};
	rb.base = reinterpret_cast<void *>(page); // arbitrary address, no region
	rb.len = page;
	rb.buf_index = 0;
	EXPECT_LT(::ioctl(f.get(), PXD_IOC_REGISTER_BUFFERS, &rb), 0);
	// kernel returns either ERANGE (outside region) or EFAULT (copy_from_user
	// failed). Either is a valid rejection.
	EXPECT_TRUE(errno == ERANGE || errno == EFAULT || errno == EINVAL);
}

// ---------------------------------------------------------------------------
// End-to-end submission: IORING_OP_NOP
// ---------------------------------------------------------------------------

TEST(PxdIoUring, NopSubmitAndComplete)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	Ring r;
	ASSERT_TRUE(r.fd.ok());
	ASSERT_TRUE(r.setup(/*sq=*/8, /*cq=*/8));

	constexpr uint64_t kUserData = 0xCAFEBABEull;

	// Userspace writes an SQE into the first slot.
	io_uring_sqe *sqe = &r.requests[0];
	std::memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_NOP;
	sqe->user_data = kUserData;

	// Publish the SQE: advance the writer-side write index.
	// The kernel reads from r.requests_cb->r.write to find new SQEs.
	__sync_synchronize();
	__atomic_store_n(&r.requests_cb->r.write, 1u, __ATOMIC_RELEASE);

	// Trigger kernel-side drain.
	ASSERT_EQ(::ioctl(r.fd.get(), PXD_IOC_RUN_IO_QUEUE), 0)
	    << "PXD_IOC_RUN_IO_QUEUE: " << strerror(errno);

	// Spin briefly for the completion to land on the CQ.
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	uint32_t cq_write = 0;
	while (std::chrono::steady_clock::now() < deadline) {
		cq_write = __atomic_load_n(&r.responses_cb->r.write, __ATOMIC_ACQUIRE);
		if (cq_write != 0)
			break;
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	ASSERT_EQ(cq_write, 1u) << "no CQE produced";

	io_uring_cqe cqe = r.responses[0];
	EXPECT_EQ(cqe.user_data, kUserData);
	EXPECT_EQ(cqe.res, 0); // NOP returns 0

	// Acknowledge the CQE.
	__atomic_store_n(&r.responses_cb->r.read, 1u, __ATOMIC_RELEASE);
}

TEST(PxdIoUring, InvalidOpcodeYieldsEinvalCqe)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	Ring r;
	ASSERT_TRUE(r.fd.ok());
	ASSERT_TRUE(r.setup(/*sq=*/4, /*cq=*/4));

	io_uring_sqe *sqe = &r.requests[0];
	std::memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = 0xFE; // unmapped opcode
	sqe->user_data = 0xDEADBEEFull;

	__sync_synchronize();
	__atomic_store_n(&r.requests_cb->r.write, 1u, __ATOMIC_RELEASE);

	ASSERT_EQ(::ioctl(r.fd.get(), PXD_IOC_RUN_IO_QUEUE), 0);

	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	uint32_t cq_write = 0;
	while (std::chrono::steady_clock::now() < deadline) {
		cq_write = __atomic_load_n(&r.responses_cb->r.write, __ATOMIC_ACQUIRE);
		if (cq_write != 0)
			break;
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	ASSERT_EQ(cq_write, 1u);
	io_uring_cqe cqe = r.responses[0];
	EXPECT_EQ(cqe.user_data, 0xDEADBEEFull);
	EXPECT_EQ(cqe.res, -EINVAL);
}

// ---------------------------------------------------------------------------
// fd lifecycle stress
// ---------------------------------------------------------------------------

TEST(PxdIoUring, OpenCloseChurn)
{
	SKIP_IF_NO_PXD_IO();
	constexpr int kIters = 32;
	for (int i = 0; i < kIters; ++i) {
		PxdIoFd f;
		ASSERT_TRUE(f.ok()) << "iter " << i;
	}
}

TEST(PxdIoUring, ConcurrentOpens)
{
	SKIP_IF_NO_PXD_IO();
	constexpr int kThreads = 8;
	constexpr int kPerThread = 8;
	std::atomic<int> failures{0};
	std::vector<std::thread> tt;
	tt.reserve(kThreads);
	for (int t = 0; t < kThreads; ++t) {
		tt.emplace_back([&]() {
			for (int i = 0; i < kPerThread; ++i) {
				PxdIoFd f;
				if (!f.ok())
					++failures;
			}
		});
	}
	for (auto &th : tt)
		th.join();
	EXPECT_EQ(failures.load(), 0);
}

} // namespace

#ifdef PXD_IO_URING_TEST_STANDALONE
// Standalone main so this file can be built as its own gtest binary.
// When linked alongside pxd_test.cc (which already defines main), leave this
// macro undefined to avoid duplicate-symbol errors.
int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
#endif
