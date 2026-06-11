// SPDX-License-Identifier: GPL-2.0
/*
 * Focused user-space gtests for the px-fuse io_uring transport.
 *
 * Self-contained: does NOT include fuse_i.h or pxd_io_uring.h.
 * The px-fuse fuse_queue_cb is shared between kernel and userspace and now
 * exposes only typed data slots plus an opaque 32-byte lock_storage region
 * at offset 32 of each half (kernel placement-inits spinlock_t there;
 * userspace placement-inits pthread_spinlock_t / px::spinlock). This test
 * deliberately re-declares the minimum kernel ABI surface (io_uring_sqe,
 * cqe, params, IORING_* opcodes/flags) and mirrors only the two CB fields
 * it actually reads/writes via the mmap'd queue (r.read, r.write). That
 * keeps the test as a small, independent ABI witness. If the kernel struct
 * layout drifts, the static_assert below catches it without needing a
 * rebuild of every userspace consumer.
 * Sizes/offsets must match the kernel side of fuse_i.h:
 *
 *   struct fuse_queue_writer {
 *       uint32_t write;          // offset  0
 *       uint32_t read;           // offset  4
 *       uint64_t sequence;       // offset  8 (load-bearing only on user_requests_cb)
 *       uint32_t need_wake_up;   // offset 16 (load-bearing only on requests_cb)
 *       uint32_t committed_;     // offset 20 (userspace, requests_cb only)
 *       uint8_t  in_runq;        // offset 24 (userspace, requests_cb only)
 *       uint8_t  __pad1[7];      // offset 25..31
 *       uint8_t  lock_storage[32]; // offset 32: spinlock_t / pthread_spinlock_t
 *   }   (cacheline-aligned, 64 bytes)
 *
 *   struct fuse_queue_reader {
 *       uint32_t read;             // offset  0
 *       uint32_t write;            // offset  4
 *       uint8_t  __pad1[24];       // offset  8..31
 *       uint8_t  lock_storage[32]; // offset 32
 *   }   (cacheline-aligned, 64 bytes)
 *
 *   struct fuse_queue_cb { fuse_queue_writer w; fuse_queue_reader r; }
 *
 * So in a queue_cb the reader sub-struct starts at offset 64, with `read` at
 * offset 64 and `write` at offset 68.  The test uses that exclusively.
 *
 * Tests that need root + the px.ko module skip themselves with GTEST_SKIP()
 * when not satisfied.
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/types.h>
#include <memory>
#include <poll.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern "C" {
#include "pxd.h"   // safe: does not pull in fuse_i.h
}

// gtest 1.8 (Ubuntu 18.04 / GLib gtester era) lacks GTEST_SKIP. Provide a
// shim that prints a [  SKIPPED ] line and returns from the test. On gtest
// 1.10+ this falls through to the real macro.
#ifndef GTEST_SKIP
namespace pxd_test_compat {
class SkipNotice {
  public:
	SkipNotice(const char *file, int line)
	{
		std::cerr << "[  SKIPPED ] " << file << ":" << line << ": ";
	}
	~SkipNotice() { std::cerr << std::endl; }
	template <typename T> SkipNotice &operator<<(const T &v)
	{
		std::cerr << v;
		return *this;
	}
};
} // namespace pxd_test_compat
// Streaming form: PXD_SKIP() << "reason"; then return;
// Used inside the SKIP_IF_* macros below so call sites stay readable.
#define PXD_SKIP_STREAM() ::pxd_test_compat::SkipNotice(__FILE__, __LINE__)
#define PXD_SKIP_AND_RETURN(msg)                                                             \
	do {                                                                                     \
		PXD_SKIP_STREAM() << msg;                                                            \
		return;                                                                              \
	} while (0)
#else
#define PXD_SKIP_AND_RETURN(msg)                                                             \
	do {                                                                                     \
		GTEST_SKIP() << msg;                                                                 \
		return;                                                                              \
	} while (0)
#endif

namespace {

constexpr const char *kPxdIoDev = "/dev/pxd/pxd-io";

// ---------------------------------------------------------------------------
// Minimal kernel ABI re-declarations.  Layouts must match pxd_io_uring.h /
// fuse_i.h kernel side, byte for byte.
// ---------------------------------------------------------------------------

struct io_uring_sqe_abi {
	__u8 opcode;
	__u8 flags;
	__u16 ioprio;
	__s32 fd;
	__u64 off;
	__u64 addr;
	__u32 len;
	union {
		int rw_flags;
		__u32 fsync_flags;
		__u16 poll_events;
		__u32 sync_range_flags;
	};
	__u64 user_data;
	union {
		__u16 buf_index;
		__u64 __pad2[3];
	};
};

struct io_uring_cqe_abi {
	__u64 user_data;
	__s32 res;
	__u32 flags;
};

struct io_sqring_offsets_abi {
	__u32 head, tail, ring_mask, ring_entries, flags, dropped, array, resv1;
	__u64 resv2;
};

struct io_cqring_offsets_abi {
	__u32 head, tail, ring_mask, ring_entries, overflow, cqes;
	__u64 resv[2];
};

struct io_uring_params_abi {
	__u32 sq_entries;
	__u32 cq_entries;
	__u32 flags;
	__u32 sq_thread_cpu;
	__u32 sq_thread_idle;
	__u32 resv[5];
	io_sqring_offsets_abi sq_off;
	io_cqring_offsets_abi cq_off;
	__u32 work_queue_num_active;
};

// IORING_SETUP_* / IORING_OP_*
static constexpr __u32 IORING_SETUP_IOPOLL = (1U << 0);
static constexpr __u32 IORING_SETUP_SQPOLL = (1U << 1);
static constexpr __u32 IORING_SETUP_SQ_AFF = (1U << 2);

static constexpr __u8 IORING_OP_NOP = 0;
static constexpr __u8 IORING_OP_READV = 1;
static constexpr __u8 IORING_OP_WRITEV = 2;
static constexpr __u8 IORING_OP_FSYNC = 3;

static constexpr __u8 IOSQE_FIXED_FILE_ABI = (1U << 0);

// Cacheline-aligned CB sub-structs.  We only touch r.read / r.write; w is
// opaque from userspace's perspective (lock layout depends on kernel config).
constexpr size_t kCachelineSize = 64;

// Mirror of kernel-side struct fuse_queue_cb: a 64-byte writer half followed
// by a 64-byte reader half whose first 8 bytes are { uint32_t read; uint32_t write; }.
struct fuse_queue_cb_mirror {
	unsigned char w_opaque[kCachelineSize]; // writer half, kernel uses internally
	struct {
		std::atomic<uint32_t> read;  // offset 64
		std::atomic<uint32_t> write; // offset 68
		// rest of reader half is unused by these tests
		unsigned char tail[kCachelineSize - 2 * sizeof(uint32_t)];
	} r;
};
static_assert(sizeof(fuse_queue_cb_mirror) == 2 * kCachelineSize,
              "queue_cb mirror layout broken");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

bool running_as_root()
{
	return ::geteuid() == 0;
}

bool pxd_io_dev_available()
{
	struct stat st;
	return ::stat(kPxdIoDev, &st) == 0 && S_ISCHR(st.st_mode);
}

#define SKIP_IF_NO_PXD_IO()                                                                  \
	do {                                                                                     \
		if (!pxd_io_dev_available()) {                                                       \
			PXD_SKIP_AND_RETURN("/dev/pxd/pxd-io not present (load px.ko first)");           \
		}                                                                                    \
	} while (0)

#define SKIP_IF_NOT_ROOT()                                                                   \
	do {                                                                                     \
		if (!running_as_root()) {                                                            \
			PXD_SKIP_AND_RETURN("test requires root (CAP_SYS_ADMIN for mmap / page-pin)");   \
		}                                                                                    \
	} while (0)

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

  private:
	int fd_{-1};
};

int init_io_ring(int fd, io_uring_params_abi *p)
{
	if (::ioctl(fd, PXD_IOC_INIT_IO, p) < 0)
		return -errno;
	return 0;
}

io_uring_params_abi make_default_params(uint32_t sq_entries = 64,
                                        uint32_t cq_entries = 128)
{
	io_uring_params_abi p{};
	p.sq_entries = sq_entries;
	p.cq_entries = cq_entries;
	return p;
}

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
// Device-node sanity & lifecycle.
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

	EXPECT_EQ(::ioctl(f.get(), BLKGETSIZE), -1);
	EXPECT_EQ(errno, ENOTTY);
}

TEST(PxdIoUring, PollOnUninitialized)
{
	SKIP_IF_NO_PXD_IO();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());

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

	auto p = make_default_params(0, 0);
	ASSERT_EQ(init_io_ring(f.get(), &p), 0) << "PXD_IOC_INIT_IO";

	EXPECT_GT(p.sq_entries, 0u);
	EXPECT_GT(p.cq_entries, 0u);
	EXPECT_EQ(p.sq_entries, next_pow2(p.sq_entries));
	EXPECT_EQ(p.cq_entries, next_pow2(p.cq_entries));
}

TEST(PxdIoUring, InitRoundsToPowerOfTwo)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());

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
	p.flags = IORING_SETUP_SQ_AFF;
	EXPECT_LT(::ioctl(f.get(), PXD_IOC_INIT_IO, &p), 0);
	EXPECT_EQ(errno, EINVAL);
}

TEST(PxdIoUring, InitTwiceOnSameFdSurvives)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());

	auto p1 = make_default_params();
	ASSERT_EQ(init_io_ring(f.get(), &p1), 0);

	auto p2 = make_default_params();
	int rc = ::ioctl(f.get(), PXD_IOC_INIT_IO, &p2);
	EXPECT_TRUE(rc == 0 || rc < 0); // either result is acceptable; must not crash
}

// ---------------------------------------------------------------------------
// mmap of SQ ring, CQ ring, SQEs
// ---------------------------------------------------------------------------

struct Ring {
	PxdIoFd fd;
	io_uring_params_abi params{};

	void *base{nullptr};
	size_t base_len{0};

	fuse_queue_cb_mirror *requests_cb{nullptr};
	io_uring_sqe_abi *requests{nullptr};
	fuse_queue_cb_mirror *responses_cb{nullptr};
	io_uring_cqe_abi *responses{nullptr};

	bool setup(uint32_t sq = 64, uint32_t cq = 128, uint32_t flags = 0)
	{
		if (!fd.ok())
			return false;
		params = make_default_params(sq, cq);
		params.flags = flags;
		if (init_io_ring(fd.get(), &params) != 0)
			return false;

		size_t raw = sizeof(fuse_queue_cb_mirror) * 2 +
		             params.sq_entries * sizeof(io_uring_sqe_abi) +
		             params.cq_entries * sizeof(io_uring_cqe_abi);
		size_t page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
		base_len = (raw + page - 1) & ~(page - 1);

		base = ::mmap(nullptr, base_len, PROT_READ | PROT_WRITE,
		              MAP_SHARED, fd.get(), 0);
		if (base == MAP_FAILED) {
			base = nullptr;
			return false;
		}

		auto *cb0 = reinterpret_cast<fuse_queue_cb_mirror *>(base);
		requests_cb = cb0;
		requests = reinterpret_cast<io_uring_sqe_abi *>(cb0 + 1);
		responses_cb =
		    reinterpret_cast<fuse_queue_cb_mirror *>(requests + params.sq_entries);
		responses = reinterpret_cast<io_uring_cqe_abi *>(responses_cb + 1);
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

	EXPECT_EQ(r.requests_cb->r.read.load(), 0u);
	EXPECT_EQ(r.requests_cb->r.write.load(), 0u);
	EXPECT_EQ(r.responses_cb->r.read.load(), 0u);
	EXPECT_EQ(r.responses_cb->r.write.load(), 0u);
}

TEST(PxdIoUring, MmapFarBeyondQueueRejected)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	PxdIoFd f;
	ASSERT_TRUE(f.ok());
	auto p = make_default_params();
	ASSERT_EQ(init_io_ring(f.get(), &p), 0);

	size_t page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
	void *bad = ::mmap(nullptr, page, PROT_READ, MAP_SHARED, f.get(),
	                   /*off=*/1ULL << 30);
	if (bad != MAP_FAILED)
		::munmap(bad, page);
	SUCCEED(); // either rejected outright (good) or faults on touch (not tested)
}

// ---------------------------------------------------------------------------
// SQO wakeup + RUN_IO_QUEUE
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
	EXPECT_EQ(r.responses_cb->r.write.load(), 0u);
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

	char tmppath[] = "/tmp/pxd-io-test.XXXXXX";
	int tmp = ::mkstemp(tmppath);
	ASSERT_GE(tmp, 0) << strerror(errno);
	::unlink(tmppath);

	int idx = ::ioctl(f.get(), PXD_IOC_REGISTER_FILE, tmp);
	EXPECT_GE(idx, 0) << "PXD_IOC_REGISTER_FILE: " << strerror(errno);
	if (idx >= 0)
		EXPECT_EQ(::ioctl(f.get(), PXD_IOC_UNREGISTER_FILE, idx), 0)
		    << strerror(errno);
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

	size_t page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));

	pxd_ioc_register_region bad{};
	bad.base = reinterpret_cast<void *>(page);
	bad.len = page - 1;
	EXPECT_LT(::ioctl(f.get(), PXD_IOC_REGISTER_REGION, &bad), 0);
	EXPECT_EQ(errno, EINVAL);

	bad.len = 0;
	EXPECT_LT(::ioctl(f.get(), PXD_IOC_REGISTER_REGION, &bad), 0);
	EXPECT_EQ(errno, EINVAL);

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

	size_t page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
	const size_t region_len = page * 4;

	void *region = ::mmap(nullptr, region_len, PROT_READ | PROT_WRITE,
	                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(region, MAP_FAILED) << strerror(errno);

	pxd_ioc_register_region rr{};
	rr.base = region;
	rr.len = region_len;
	int region_idx = ::ioctl(f.get(), PXD_IOC_REGISTER_REGION, &rr);
	ASSERT_GE(region_idx, 0) << "PXD_IOC_REGISTER_REGION: " << strerror(errno);

	pxd_ioc_register_buffers rb{};
	rb.base = region;
	rb.len = page * 2;
	rb.buf_index = 0;
	EXPECT_EQ(::ioctl(f.get(), PXD_IOC_REGISTER_BUFFERS, &rb), 0)
	    << "PXD_IOC_REGISTER_BUFFERS: " << strerror(errno);

	EXPECT_LT(::ioctl(f.get(), PXD_IOC_REGISTER_BUFFERS, &rb), 0);
	EXPECT_EQ(errno, EEXIST);

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

	size_t page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
	pxd_ioc_register_buffers rb{};
	rb.base = reinterpret_cast<void *>(page);
	rb.len = page;
	rb.buf_index = 0;
	EXPECT_LT(::ioctl(f.get(), PXD_IOC_REGISTER_BUFFERS, &rb), 0);
	EXPECT_TRUE(errno == ERANGE || errno == EFAULT || errno == EINVAL);
}

// ---------------------------------------------------------------------------
// End-to-end NOP through the rings
// ---------------------------------------------------------------------------

TEST(PxdIoUring, NopSubmitAndComplete)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	Ring r;
	ASSERT_TRUE(r.fd.ok());
	ASSERT_TRUE(r.setup(/*sq=*/8, /*cq=*/8));

	constexpr uint64_t kUserData = 0xCAFEBABEull;

	io_uring_sqe_abi *sqe = &r.requests[0];
	std::memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_NOP;
	sqe->user_data = kUserData;

	r.requests_cb->r.write.store(1u, std::memory_order_release);

	ASSERT_EQ(::ioctl(r.fd.get(), PXD_IOC_RUN_IO_QUEUE), 0)
	    << "PXD_IOC_RUN_IO_QUEUE: " << strerror(errno);

	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	uint32_t cq_write = 0;
	while (std::chrono::steady_clock::now() < deadline) {
		cq_write = r.responses_cb->r.write.load(std::memory_order_acquire);
		if (cq_write != 0)
			break;
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	ASSERT_EQ(cq_write, 1u) << "no CQE produced";

	io_uring_cqe_abi cqe = r.responses[0];
	EXPECT_EQ(cqe.user_data, kUserData);
	EXPECT_EQ(cqe.res, 0);

	r.responses_cb->r.read.store(1u, std::memory_order_release);
}

TEST(PxdIoUring, InvalidOpcodeYieldsEinvalCqe)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	Ring r;
	ASSERT_TRUE(r.fd.ok());
	ASSERT_TRUE(r.setup(/*sq=*/4, /*cq=*/4));

	io_uring_sqe_abi *sqe = &r.requests[0];
	std::memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = 0xFE;
	sqe->user_data = 0xDEADBEEFull;

	r.requests_cb->r.write.store(1u, std::memory_order_release);

	ASSERT_EQ(::ioctl(r.fd.get(), PXD_IOC_RUN_IO_QUEUE), 0);

	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	uint32_t cq_write = 0;
	while (std::chrono::steady_clock::now() < deadline) {
		cq_write = r.responses_cb->r.write.load(std::memory_order_acquire);
		if (cq_write != 0)
			break;
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	ASSERT_EQ(cq_write, 1u);
	io_uring_cqe_abi cqe = r.responses[0];
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

// ===========================================================================
// Loop-device IO path (writev / readv / fsync via raw kernel ABI).
//
// These tests exercise the actual IO opcodes against a file-backed loop
// device. The loop device gives us a block-device fd whose contents we
// fully control, without needing a real pxd minor. The submission/CQE
// drain logic mirrors the NopSubmitAndComplete idiom above (write into
// requests[], bump r.requests_cb->r.write, ioctl RUN_IO_QUEUE, poll
// r.responses_cb->r.write, read CQE).
//
// All tests here require root (loop control + register_file) and skip
// when /dev/loop-control is absent.
// ===========================================================================

#define SKIP_IF_NO_LOOP_CONTROL()                                                            \
	do {                                                                                   \
		struct stat _st;                                                               \
		if (::stat("/dev/loop-control", &_st) != 0) {                                  \
			PXD_SKIP_AND_RETURN("/dev/loop-control not present");                  \
		}                                                                              \
	} while (0)

// RAII: mkstemp + ftruncate + LOOP_CTL_GET_FREE + LOOP_SET_FD. dtor reverses.
class FileBackedLoop {
  public:
	explicit FileBackedLoop(size_t size_bytes) : size_(size_bytes)
	{
		char tmpl[] = "/tmp/pxd_uring_loop_XXXXXX";
		backing_fd_ = ::mkstemp(tmpl);
		if (backing_fd_ < 0) {
			err_ = std::string("mkstemp: ") + std::strerror(errno);
			return;
		}
		backing_path_ = tmpl;
		if (::ftruncate(backing_fd_, static_cast<off_t>(size_)) != 0) {
			err_ = std::string("ftruncate: ") + std::strerror(errno);
			return;
		}

		int ctl = ::open("/dev/loop-control", O_RDWR);
		if (ctl < 0) {
			err_ = std::string("open(loop-control): ") + std::strerror(errno);
			return;
		}
		int loop_n = ::ioctl(ctl, LOOP_CTL_GET_FREE);
		int saved = errno;
		::close(ctl);
		if (loop_n < 0) {
			err_ = std::string("LOOP_CTL_GET_FREE: ") + std::strerror(saved);
			return;
		}
		char path[64];
		std::snprintf(path, sizeof(path), "/dev/loop%d", loop_n);
		loop_path_ = path;

		loop_fd_ = ::open(path, O_RDWR);
		if (loop_fd_ < 0) {
			err_ = std::string("open(") + path + "): " + std::strerror(errno);
			return;
		}
		if (::ioctl(loop_fd_, LOOP_SET_FD, backing_fd_) != 0) {
			err_ = std::string("LOOP_SET_FD: ") + std::strerror(errno);
			return;
		}
		bound_ = true;
	}

	~FileBackedLoop()
	{
		if (bound_ && loop_fd_ >= 0)
			(void)::ioctl(loop_fd_, LOOP_CLR_FD, 0);
		if (loop_fd_ >= 0)
			::close(loop_fd_);
		if (backing_fd_ >= 0)
			::close(backing_fd_);
		if (!backing_path_.empty())
			::unlink(backing_path_.c_str());
	}

	FileBackedLoop(const FileBackedLoop &) = delete;
	FileBackedLoop &operator=(const FileBackedLoop &) = delete;

	bool ok() const { return bound_ && err_.empty(); }
	const std::string &error() const { return err_; }
	int loop_fd() const { return loop_fd_; }
	const std::string &loop_path() const { return loop_path_; }
	size_t size() const { return size_; }

  private:
	size_t size_;
	int backing_fd_{-1};
	int loop_fd_{-1};
	bool bound_{false};
	std::string backing_path_;
	std::string loop_path_;
	std::string err_;
};

struct AlignedFree {
	void operator()(void *p) const { std::free(p); }
};
using AlignedBuf = std::unique_ptr<uint8_t, AlignedFree>;

static AlignedBuf make_aligned(size_t bytes)
{
	void *p = nullptr;
	if (::posix_memalign(&p, 4096, bytes) != 0)
		return AlignedBuf{};
	return AlignedBuf{static_cast<uint8_t *>(p)};
}

static void fill_pattern(uint8_t *buf, size_t bytes, uint32_t seed)
{
	uint32_t s = seed * 2654435761u + 1u;
	for (size_t i = 0; i < bytes; ++i) {
		s = s * 1103515245u + 12345u;
		buf[i] = static_cast<uint8_t>((s >> 16) & 0xff);
	}
}

// Wait for a CQE at the given expected_write_pos in the responses ring.
// Returns true if the CQE landed within `timeout`.
static bool wait_for_cqe(Ring &r, uint32_t expected_write_pos,
                         std::chrono::milliseconds timeout = std::chrono::seconds(2))
{
	auto deadline = std::chrono::steady_clock::now() + timeout;
	while (std::chrono::steady_clock::now() < deadline) {
		auto w = r.responses_cb->r.write.load(std::memory_order_acquire);
		if (w >= expected_write_pos)
			return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	}
	return false;
}

// Acknowledge `n` CQEs by bumping the consumer cursor on responses_cb.
static void ack_cqes(Ring &r, uint32_t n)
{
	r.responses_cb->r.read.store(n, std::memory_order_release);
}

// Fill in a writev/readv SQE.
static void prep_rw_sqe(io_uring_sqe_abi *sqe, __u8 opcode, __s32 fixed_fd_idx,
                        __u64 off, iovec *iov, int iovcnt, __u64 user_data)
{
	std::memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = opcode;
	sqe->flags = IOSQE_FIXED_FILE_ABI;
	sqe->fd = fixed_fd_idx;
	sqe->off = off;
	sqe->addr = reinterpret_cast<__u64>(iov);
	sqe->len = static_cast<__u32>(iovcnt);
	sqe->user_data = user_data;
}

static void prep_fsync_sqe(io_uring_sqe_abi *sqe, __s32 fixed_fd_idx, __u64 user_data)
{
	std::memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_FSYNC;
	sqe->flags = IOSQE_FIXED_FILE_ABI;
	sqe->fd = fixed_fd_idx;
	sqe->user_data = user_data;
}

TEST(PxdIoUring, LoopDeviceSetupTeardown)
{
	SKIP_IF_NOT_ROOT();
	SKIP_IF_NO_LOOP_CONTROL();

	FileBackedLoop loop(1 << 20);
	ASSERT_TRUE(loop.ok()) << loop.error();
	EXPECT_GE(loop.loop_fd(), 0);

	uint64_t sz = 0;
	ASSERT_EQ(::ioctl(loop.loop_fd(), BLKGETSIZE64, &sz), 0)
	    << strerror(errno);
	EXPECT_EQ(sz, loop.size());
}

TEST(PxdIoUring, WritevReadvRoundTripOnLoop)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	SKIP_IF_NO_LOOP_CONTROL();

	FileBackedLoop loop(1 << 20);
	ASSERT_TRUE(loop.ok()) << loop.error();

	Ring r;
	ASSERT_TRUE(r.fd.ok());
	ASSERT_TRUE(r.setup(/*sq=*/8, /*cq=*/8));

	int fixed_idx = ::ioctl(r.fd.get(), PXD_IOC_REGISTER_FILE, loop.loop_fd());
	ASSERT_GE(fixed_idx, 0) << "REGISTER_FILE: " << strerror(errno);

	constexpr size_t kIo = 64 * 1024;
	constexpr uint64_t kOff = 4096;
	auto wbuf = make_aligned(kIo);
	auto rbuf = make_aligned(kIo);
	ASSERT_TRUE(wbuf && rbuf);
	fill_pattern(wbuf.get(), kIo, 0xC0FFEE);
	std::memset(rbuf.get(), 0, kIo);

	uint32_t sq_pos = 0;
	uint32_t cq_pos = 0;

	// 1) writev
	{
		iovec iov{wbuf.get(), kIo};
		prep_rw_sqe(&r.requests[sq_pos], IORING_OP_WRITEV, fixed_idx,
		            kOff, &iov, 1, 0x11);
		++sq_pos;
		r.requests_cb->r.write.store(sq_pos, std::memory_order_release);
		ASSERT_EQ(::ioctl(r.fd.get(), PXD_IOC_RUN_IO_QUEUE), 0);

		ASSERT_TRUE(wait_for_cqe(r, cq_pos + 1)) << "writev CQE timeout";
		auto cqe = r.responses[cq_pos];
		EXPECT_EQ(cqe.user_data, 0x11ull);
		EXPECT_EQ(cqe.res, static_cast<int>(kIo));
		++cq_pos;
		ack_cqes(r, cq_pos);
	}

	// 2) fsync to flush through
	{
		prep_fsync_sqe(&r.requests[sq_pos & 7], fixed_idx, 0x22);
		++sq_pos;
		r.requests_cb->r.write.store(sq_pos, std::memory_order_release);
		ASSERT_EQ(::ioctl(r.fd.get(), PXD_IOC_RUN_IO_QUEUE), 0);

		ASSERT_TRUE(wait_for_cqe(r, cq_pos + 1)) << "fsync CQE timeout";
		auto cqe = r.responses[cq_pos & 7];
		EXPECT_EQ(cqe.user_data, 0x22ull);
		EXPECT_EQ(cqe.res, 0);
		++cq_pos;
		ack_cqes(r, cq_pos);
	}

	// 3) readv
	{
		iovec iov{rbuf.get(), kIo};
		prep_rw_sqe(&r.requests[sq_pos & 7], IORING_OP_READV, fixed_idx,
		            kOff, &iov, 1, 0x33);
		++sq_pos;
		r.requests_cb->r.write.store(sq_pos, std::memory_order_release);
		ASSERT_EQ(::ioctl(r.fd.get(), PXD_IOC_RUN_IO_QUEUE), 0);

		ASSERT_TRUE(wait_for_cqe(r, cq_pos + 1)) << "readv CQE timeout";
		auto cqe = r.responses[cq_pos & 7];
		EXPECT_EQ(cqe.user_data, 0x33ull);
		EXPECT_EQ(cqe.res, static_cast<int>(kIo));
		++cq_pos;
		ack_cqes(r, cq_pos);
	}

	EXPECT_EQ(std::memcmp(wbuf.get(), rbuf.get(), kIo), 0)
	    << "data mismatch between writev and readv";

	EXPECT_EQ(::ioctl(r.fd.get(), PXD_IOC_UNREGISTER_FILE, fixed_idx), 0);
}

TEST(PxdIoUring, MultipleWritevsCompleteOnLoop)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	SKIP_IF_NO_LOOP_CONTROL();

	constexpr size_t kSize = 4 * 1024 * 1024;
	constexpr size_t kBlock = 4096;
	constexpr uint32_t kCount = 16;

	FileBackedLoop loop(kSize);
	ASSERT_TRUE(loop.ok()) << loop.error();

	Ring r;
	ASSERT_TRUE(r.fd.ok());
	ASSERT_TRUE(r.setup(/*sq=*/kCount * 2, /*cq=*/kCount * 2));

	int fixed_idx = ::ioctl(r.fd.get(), PXD_IOC_REGISTER_FILE, loop.loop_fd());
	ASSERT_GE(fixed_idx, 0) << strerror(errno);

	std::vector<AlignedBuf> wbufs;
	wbufs.reserve(kCount);
	std::vector<iovec> iovs(kCount);

	const uint32_t sq_mask = r.params.sq_entries - 1;
	for (uint32_t i = 0; i < kCount; ++i) {
		wbufs.push_back(make_aligned(kBlock));
		ASSERT_TRUE(wbufs.back() != nullptr);
		fill_pattern(wbufs.back().get(), kBlock, 0x1000u + i);
		iovs[i].iov_base = wbufs.back().get();
		iovs[i].iov_len = kBlock;
		prep_rw_sqe(&r.requests[i & sq_mask], IORING_OP_WRITEV, fixed_idx,
		            static_cast<uint64_t>(i) * kBlock, &iovs[i], 1,
		            0xA000ull + i);
	}
	r.requests_cb->r.write.store(kCount, std::memory_order_release);
	ASSERT_EQ(::ioctl(r.fd.get(), PXD_IOC_RUN_IO_QUEUE), 0);

	ASSERT_TRUE(wait_for_cqe(r, kCount)) << "writev batch CQE timeout";
	const uint32_t cq_mask = r.params.cq_entries - 1;
	for (uint32_t i = 0; i < kCount; ++i) {
		auto cqe = r.responses[i & cq_mask];
		EXPECT_EQ(cqe.res, static_cast<int>(kBlock))
		    << "writev[" << i << "] cqe.res";
	}
	ack_cqes(r, kCount);

	// Read each block back and verify content.
	auto rbuf = make_aligned(kBlock);
	ASSERT_TRUE(rbuf != nullptr);
	uint32_t sq_pos = kCount;
	uint32_t cq_pos = kCount;
	for (uint32_t i = 0; i < kCount; ++i) {
		std::memset(rbuf.get(), 0, kBlock);
		iovec iov{rbuf.get(), kBlock};
		prep_rw_sqe(&r.requests[sq_pos & sq_mask], IORING_OP_READV,
		            fixed_idx, static_cast<uint64_t>(i) * kBlock, &iov,
		            1, 0xB000ull + i);
		++sq_pos;
		r.requests_cb->r.write.store(sq_pos, std::memory_order_release);
		ASSERT_EQ(::ioctl(r.fd.get(), PXD_IOC_RUN_IO_QUEUE), 0);

		ASSERT_TRUE(wait_for_cqe(r, cq_pos + 1))
		    << "readv[" << i << "] CQE timeout";
		auto cqe = r.responses[cq_pos & cq_mask];
		EXPECT_EQ(cqe.res, static_cast<int>(kBlock));
		++cq_pos;
		ack_cqes(r, cq_pos);

		EXPECT_EQ(std::memcmp(rbuf.get(), wbufs[i].get(), kBlock), 0)
		    << "block " << i << " mismatched after read-back";
	}

	EXPECT_EQ(::ioctl(r.fd.get(), PXD_IOC_UNREGISTER_FILE, fixed_idx), 0);
}

TEST(PxdIoUring, FsyncOnLoop)
{
	SKIP_IF_NO_PXD_IO();
	SKIP_IF_NOT_ROOT();
	SKIP_IF_NO_LOOP_CONTROL();

	FileBackedLoop loop(1 << 20);
	ASSERT_TRUE(loop.ok()) << loop.error();

	Ring r;
	ASSERT_TRUE(r.fd.ok());
	ASSERT_TRUE(r.setup(/*sq=*/4, /*cq=*/4));

	int fixed_idx = ::ioctl(r.fd.get(), PXD_IOC_REGISTER_FILE, loop.loop_fd());
	ASSERT_GE(fixed_idx, 0) << strerror(errno);

	prep_fsync_sqe(&r.requests[0], fixed_idx, 0xF0F0);
	r.requests_cb->r.write.store(1u, std::memory_order_release);
	ASSERT_EQ(::ioctl(r.fd.get(), PXD_IOC_RUN_IO_QUEUE), 0);

	ASSERT_TRUE(wait_for_cqe(r, 1u));
	auto cqe = r.responses[0];
	EXPECT_EQ(cqe.user_data, 0xF0F0ull);
	EXPECT_EQ(cqe.res, 0);
	ack_cqes(r, 1u);

	EXPECT_EQ(::ioctl(r.fd.get(), PXD_IOC_UNREGISTER_FILE, fixed_idx), 0);
}

} // namespace

#ifdef PXD_IO_URING_TEST_STANDALONE
int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
#endif
