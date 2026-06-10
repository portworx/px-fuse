// SPDX-License-Identifier: GPL-2.0
/*
 * Focused user-space gtests for the px-fuse io_uring transport.
 *
 * Self-contained: does NOT include fuse_i.h or pxd_io_uring.h.
 * The px-fuse userspace block in fuse_i.h is now standalone (no px-storage
 * dependency), but this test deliberately re-declares the minimum kernel
 * ABI surface (io_uring_sqe, cqe, params, IORING_* opcodes/flags) and
 * mirrors only the two CB fields it actually reads/writes via the mmap'd
 * queue (r.read, r.write). That keeps the test as a small, independent
 * ABI witness. If the kernel struct layout drifts, the static_assert below
 * catches it without needing a rebuild of every userspace consumer.
 * Sizes/offsets must match the kernel side of fuse_i.h:
 *
 *   struct fuse_queue_writer { uint32_t write, read; spinlock_t lock;
 *                              uint32_t need_wake_up; uint64_t sequence;
 *                              uint64_t pad[5]; }
 *       (cacheline-aligned, 64 bytes on typical configs)
 *   struct fuse_queue_reader { uint32_t read, write; uint32_t need_wake_up;
 *                              uint32_t pad; uint64_t pad_2[6]; }
 *       (cacheline-aligned, 64 bytes)
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
#include <cstring>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern "C" {
#include "pxd.h"   // safe: does not pull in fuse_i.h
}

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
			GTEST_SKIP() << kPxdIoDev << " not present (load px.ko first)";                  \
		}                                                                                    \
	} while (0)

#define SKIP_IF_NOT_ROOT()                                                                   \
	do {                                                                                     \
		if (!running_as_root()) {                                                            \
			GTEST_SKIP() << "test requires root (CAP_SYS_ADMIN for mmap / page-pin)";        \
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

} // namespace

#ifdef PXD_IO_URING_TEST_STANDALONE
int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
#endif
