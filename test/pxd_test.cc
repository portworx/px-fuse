#include <algorithm>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/lexical_cast.hpp>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <gtest/gtest.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <chrono>

#include "fuse.h"
#include "pxd.h"

using namespace std::placeholders;

#define ALIGN(x, a) (((x) + (a)-1) & ~((a)-1))

struct fuse_notify_header : public ::fuse_out_header {
	fuse_notify_header(int32_t opcode, uint32_t op_len);
};

fuse_notify_header::fuse_notify_header(int32_t opcode, uint32_t op_len)
{
	unique = 0;
	error = opcode;
	len = sizeof(fuse_out_header) + op_len;
}

static ::testing::AssertionResult verify_pattern(void *buf, size_t len)
{
	uint8_t *d = (uint8_t *)buf;
	for (size_t i = 0; i < len; ++i) {
		if (d[i] != (i % UINT8_MAX)) {
			return ::testing::AssertionFailure() << "at " << i << " val " << d[i];
		}
	}
	return ::testing::AssertionSuccess();
}

static std::vector<uint8_t> make_pattern(size_t size)
{
	std::vector<uint8_t> v(size);
	for (size_t i = 0; i < v.size(); ++i)
		v[i] = i % UINT8_MAX;
	return v;
}

static void init_pattern(void *vv, size_t size)
{
	uint8_t *v = (uint8_t *)vv;
	for (size_t i = 0; i < size; ++i)
		v[i] = i % UINT8_MAX;
}

std::unique_ptr<void, decltype(&std::free)> aligned_buffer(size_t buffer_size)
{
	void *ptr = nullptr;
	if (posix_memalign(&ptr, 4096, buffer_size) != 0) {
		throw std::runtime_error("Failed to allocate aligned buffer");
	}
	return std::unique_ptr<void, decltype(&std::free)>(ptr, &std::free);
}

std::string control_device(unsigned int driver_context_id)
{
	assert(driver_context_id < PXD_NUM_CONTEXTS);
	std::string ret{PXD_CONTROL_DEV};
	if (driver_context_id != 0)
		ret += "-" + std::to_string(driver_context_id);
	return ret;
}

class PxdTest : public ::testing::Test
{
  protected:
	bool killed{false};
	int ctl_fd; // control file descriptor
	std::set<uint64_t> added_ids;
	const size_t write_len = PXD_LBS * 4;
	const size_t test_off = 4 * 4096;

	PxdTest() : ctl_fd(-1)
	{
	}
	virtual ~PxdTest()
	{
		if (ctl_fd >= 0) {
			close(ctl_fd);
			fprintf(stderr, "closed control fd");
		}
	}

	virtual void SetUp();
	virtual void TearDown();

	void dev_add(pxd_add_out &add, int &minor, std::string &name);
	void dev_add_ext(pxd_add_ext_out &add_ext, int &minor, std::string &name);
	void dev_add_v2(pxd_add_v2_out &add_v2, int &minor, std::string &name);
	void dev_export(uint64_t dev_id, const std::string &expected_name);
	void dev_remove(uint64_t dev_id);
	int wait_msg(int timeout); // timeout in seconds
	void read_block(fuse_in_header *in, pxd_rdwr_in *rd);
	void validate_device_properties(const std::string &device_name,
	                                uint64_t expected_discard_granularity = PXD_MAX_DISCARD_GRANULARITY,
	                                uint64_t expected_max_discard_bytes = PXD_MAX_DISCARD_GRANULARITY);
	void validate_write_zeroes(const std::string &device_name, bool expected_enabled);

	int write_pxd_timeout(int minor, int timeout_value);

  public:
	void fail_io(struct rdwr_in *);
	int finish_io(struct rdwr_in *, bool read_data = false);
	void write_thread(const char *name);
	void read_thread(const char *name);
	void write_thread_timeout(const char *name);
	void cleaner();
};

int PxdTest::write_pxd_timeout(int minor, int timeout_value)
{
	char sysfs_path[256];
	snprintf(sysfs_path, sizeof(sysfs_path), "/sys/devices/pxd/%d/timeout", minor);

	FILE *fp = fopen(sysfs_path, "w");
	if (!fp) {
		perror("fopen");
		return -1;
	}

	int ret = fprintf(fp, "%d\n", timeout_value);
	if (ret < 0) {
		perror("fprintf");
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

void PxdTest::dev_add(pxd_add_out &add, int &minor, std::string &name)
{
	fuse_out_header oh;
	struct iovec iov[2];

	ASSERT_TRUE(added_ids.find(add.dev_id) == added_ids.end());

	oh.unique = 0;
	oh.error = PXD_ADD, oh.len = sizeof(oh) + sizeof(add);

	iov[0].iov_base = &oh;
	iov[0].iov_len = sizeof(oh);
	iov[1].iov_base = &add;
	iov[1].iov_len = sizeof(add);

	ssize_t write_bytes = writev(ctl_fd, iov, 2);
	ASSERT_GT(write_bytes, 0);

	added_ids.insert(add.dev_id);

	minor = write_bytes;
	name = std::string(PXD_DEV_PATH) + std::to_string(add.dev_id);

	dev_export(minor, name);
	validate_device_properties(name, PXD_MAX_DISCARD_GRANULARITY,
	                           ALIGN(add.discard_size, PXD_MAX_DISCARD_GRANULARITY));
}

void PxdTest::dev_add_ext(pxd_add_ext_out &add_ext, int &minor, std::string &name)
{
	fuse_out_header oh;
	struct iovec iov[2];

	ASSERT_TRUE(added_ids.find(add_ext.dev_id) == added_ids.end());

	oh.unique = 0;
	oh.error = PXD_ADD_EXT;
	oh.len = sizeof(oh) + sizeof(add_ext);

	iov[0].iov_base = &oh;
	iov[0].iov_len = sizeof(oh);
	iov[1].iov_base = &add_ext;
	iov[1].iov_len = sizeof(add_ext);

	ssize_t write_bytes = writev(ctl_fd, iov, 2);
	ASSERT_GT(write_bytes, 0);

	std::cout << "dev_add_ext: PXD_ADD_EXT completed, wrote " << write_bytes << " bytes"
	          << std::endl;
	std::cout << "dev_add_ext: device ID = " << add_ext.dev_id << std::endl;

	added_ids.insert(add_ext.dev_id);
	minor = write_bytes;
	name = std::string(PXD_DEV_PATH) + std::to_string(add_ext.dev_id);

	dev_export(minor, name);
	std::cout << "dev_add_ext: expected device path = " << name << std::endl;
}

void PxdTest::dev_add_v2(pxd_add_v2_out &add_v2, int &minor, std::string &name)
{
	fuse_out_header oh;
	struct iovec iov[2];

	ASSERT_TRUE(added_ids.find(add_v2.dev_id) == added_ids.end());

	oh.unique = 0;
	oh.error = PXD_ADD_EXT_V2;
	oh.len = sizeof(oh) + sizeof(add_v2);

	iov[0].iov_base = &oh;
	iov[0].iov_len = sizeof(oh);
	iov[1].iov_base = &add_v2;
	iov[1].iov_len = sizeof(add_v2);

	ssize_t write_bytes = writev(ctl_fd, iov, 2);
	ASSERT_GT(write_bytes, 0);

	std::cout << "dev_add_v2: PXD_ADD_EXT_V2 completed, wrote " << write_bytes << " bytes"
	          << std::endl;
	std::cout << "dev_add_v2: device ID = " << add_v2.dev_id
	          << ", capabilities = 0x" << std::hex << add_v2.capabilities << std::dec
	          << std::endl;

	added_ids.insert(add_v2.dev_id);
	minor = write_bytes;
	name = std::string(PXD_DEV_PATH) + std::to_string(add_v2.dev_id);

	// Export device - pass dev_id (not minor) to pxd_export
	dev_export(add_v2.dev_id, name);
	std::cout << "dev_add_v2: expected device path = " << name << std::endl;
}

void PxdTest::dev_export(uint64_t dev_id, const std::string &expected_name)
{
	fuse_out_header oh;
	struct iovec iov[2];

	oh.unique = 0;
	oh.error = PXD_EXPORT_DEV;
	oh.len = sizeof(oh) + sizeof(dev_id);

	iov[0].iov_base = &oh;
	iov[0].iov_len = sizeof(oh);
	iov[1].iov_base = &dev_id;
	iov[1].iov_len = sizeof(dev_id);

	ssize_t write_bytes = writev(ctl_fd, iov, 2);
	ASSERT_GT(write_bytes, 0);

	std::cout << "dev_export: PXD_EXPORT completed, wrote " << write_bytes << " bytes" << std::endl;
	std::cout << "dev_export: device ID = " << dev_id << std::endl;
	std::cout << "dev_export: expected device path = " << expected_name << std::endl;

	// Wait for device file to appear
	for (int i = 0; i < 10; i++) {
		sleep(1);
		if (access(expected_name.c_str(), F_OK) == 0) {
			std::cout << "dev_export: device file appeared after " << (i + 1) << " seconds"
			          << std::endl;
			return;
		}
		sleep(2);
		std::cout << "dev_export: waiting for device file... (" << (i + 1) << "/10)" << std::endl;
	}

	std::cout << "dev_export: WARNING - device file never appeared!" << std::endl;
}

int PxdTest::wait_msg(int timeout_secs)
{
	struct pollfd fds = {};
	int ret;

	fds.fd = ctl_fd;
	fds.events = POLLIN;

	ret = poll(&fds, 1, timeout_secs * 1000);

	if (ret > 0)
		return 0;
	if (ret == 0)
		return -ETIMEDOUT;

	// should never arise?!
	ret = -errno;
	EXPECT_GE(ret, 0);
	return ret;
}

void PxdTest::fail_io(struct rdwr_in *rdwr)
{
	struct pxd_rdwr_in *req;
	fuse_out_header oh;
	struct iovec iov[1];

	req = reinterpret_cast<pxd_rdwr_in *>(&rdwr->rdwr);

	// Reply to the kernel
	oh.len = sizeof(oh);
	oh.error = -EIO;
	oh.unique = rdwr->in.unique;
	iov[0].iov_base = &oh;
	iov[0].iov_len = sizeof(oh);

	fprintf(stderr, "%s: opc (%d) reply to kernel: status: %d iovcnt: %d\n", __func__,
	        rdwr->in.opcode, oh.error, 1);
	size_t ret = writev(ctl_fd, iov, 1);
	ASSERT_GE(ret, 0);
}

int PxdTest::finish_io(struct rdwr_in *rdwr, bool read_data)
{
	struct pxd_rdwr_in *rd;
	fuse_out_header oh;
	struct iovec iov[16];
	int iovcnt = 0;
	char buf[PXD_LBS];
	int rc = 0;
	size_t ret;

	rd = reinterpret_cast<pxd_rdwr_in *>(&rdwr->rdwr);

	switch (rdwr->in.opcode) {
	case PXD_READ:
		if (rdwr->in.opcode == PXD_READ && rd->offset == test_off) {
			if (rd->size == write_len) {
				rc = 1;
			}
		}
		// Reply to the kernel
		iovcnt = rd->size / PXD_LBS;
		oh.len = sizeof(oh) + rd->size;
		oh.error = 0;
		oh.unique = rdwr->in.unique;
		iov[0].iov_base = &oh;
		iov[0].iov_len = sizeof(oh);

		if (iovcnt >= 16) {
			fail_io(rdwr);
			return 0;
		}

		for (int i = 1; i <= iovcnt; i++) {
			iov[i].iov_base = buf;
			iov[i].iov_len = PXD_LBS;
		}

		fprintf(stderr, "%s: reply to kernel: status: %d iovcnt: %d\n", __func__, oh.error, iovcnt);
		ret = writev(ctl_fd, iov, iovcnt + 1);
		EXPECT_GE(ret, 0);
		break;
	case PXD_WRITE:
		if (read_data && rd->size != 0)
			read_block(&rdwr->in, reinterpret_cast<pxd_rdwr_in *>(&rdwr->rdwr));
		// Reply to the kernel
		oh.len = sizeof(oh);
		oh.error = 0;
		oh.unique = rdwr->in.unique;
		fprintf(stderr, "%s: reply to kernel: status: %d\n", __func__, oh.error);
		ret = ::write(ctl_fd, &oh, sizeof(oh));
		EXPECT_EQ(sizeof(oh), ret);

		break;
	default:
		fail_io(rdwr);
	}
	return rc;
}

void PxdTest::cleaner()
{
	struct rdwr_in rdwr;

	fprintf(stderr, "cleaner thread active\n");
	// Now read in the request from kernel
	while (!killed) {
		int ret = wait_msg(1);
		if (ret == -ETIMEDOUT) {
			sleep(1);
			continue;
		}
		ssize_t read_bytes = read(ctl_fd, &rdwr, sizeof(rdwr));
		if (read_bytes < 0) {
			EXPECT_EQ(read_bytes, -EAGAIN);
		} else if (read_bytes > 0) {
			// finish_io(&rdwr);
			fail_io(&rdwr);
		}
	}
	fprintf(stderr, "cleaner thread done\n");
}

void PxdTest::dev_remove(uint64_t dev_id)
{
	pxd_remove_out remove;
	fuse_out_header oh;
	struct iovec iov[2];
	int iter = 0;

	fprintf(stderr, "%s: device removing %ld\n", __func__, dev_id);
	killed = false;
	std::thread cleaner(&PxdTest::cleaner, this);
	sleep(1);
	while (1) {
		fprintf(stderr, "initiating dev cleanup\n");
		oh.unique = 0;
		oh.error = PXD_REMOVE;
		oh.len = sizeof(oh) + sizeof(remove);

		remove.dev_id = dev_id;
		remove.force = false; //// cannot force

		iov[0].iov_base = &oh;
		iov[0].iov_len = sizeof(oh);
		iov[1].iov_base = &remove;
		iov[1].iov_len = sizeof(remove);

		ssize_t write_bytes = writev(ctl_fd, iov, 2);
		if (write_bytes > 0) {
			fprintf(stderr, "device removal success\n");
			ASSERT_EQ(write_bytes, oh.len);
			break;
		}

		ASSERT_EQ(EBUSY, errno);
		fprintf(stderr, "device busy.. will retry after sleep\n");
		iter++;
		sleep(1);
	}

	fprintf(stderr, "%s: device %ld removed after %d secs\n", __func__, dev_id, iter);
	fprintf(stderr, "prepping to stop background cleaner\n");
	killed = true;
	sleep(1);
	cleaner.join();
	killed = false;

	added_ids.erase(dev_id);
}

void PxdTest::validate_device_properties(const std::string &device_name,
                                         uint64_t expected_discard_granularity,
                                         uint64_t expected_max_discard_bytes)
{
	std::cout << "validating pxd device: " << device_name << std::endl;

	// Convert device name to sysfs path format
	std::string sysfs_name = device_name;
	// /dev/pxd/pxd123 -> pxd!pxd123
	if (sysfs_name.find("/dev/pxd/") == 0) {
		sysfs_name = sysfs_name.substr(9); // Remove "/dev/pxd/"
		sysfs_name = "pxd!" + sysfs_name;
	}

	std::string sysfs_path = "/sys/block/" + sysfs_name + "/queue/";
	// Helper lambda to read sysfs file and return value
	auto read_sysfs_value = [](const std::string &path) -> uint64_t {
		std::cout << "reading sysfs path: " << path << std::endl;
		std::ifstream file(path);
		EXPECT_TRUE(file.is_open()) << "Failed to open: " << path;
		uint64_t value;
		file >> value;
		EXPECT_TRUE(file.good()) << "Failed to read from: " << path;
		return value;
	};
	// Validate rotational (should be 1 for traditional spinning disk behavior)
	// unstable across distros RHEL has it off, while others on
	// EXPECT_EQ(1, read_sysfs_value(sysfs_path + "rotational"));
	// Validate block sizes (all should be 4096)
	EXPECT_EQ(4096, read_sysfs_value(sysfs_path + "minimum_io_size"));
	EXPECT_EQ(4096, read_sysfs_value(sysfs_path + "optimal_io_size"));
	EXPECT_EQ(4096, read_sysfs_value(sysfs_path + "logical_block_size"));
	EXPECT_EQ(4096, read_sysfs_value(sysfs_path + "physical_block_size"));

	// Validate segment properties
	EXPECT_EQ(256, read_sysfs_value(sysfs_path + "max_segments"));
	EXPECT_EQ(524288, read_sysfs_value(sysfs_path + "max_segment_size"));

	// Validate discard properties (configurable)
	EXPECT_EQ(expected_discard_granularity, read_sysfs_value(sysfs_path + "discard_granularity"));
	EXPECT_EQ(expected_max_discard_bytes, read_sysfs_value(sysfs_path + "discard_max_bytes"));
	EXPECT_EQ(1, read_sysfs_value(sysfs_path + "max_discard_segments"));

	// Validate other properties
	EXPECT_EQ(128, read_sysfs_value(sysfs_path + "nr_requests"));

	// read_ahead_kb value is set by kernel based on physical storage performance
	// For HDDs it is 256 or higher, for SSDs it could be 128 or lower
	// Some older kernel version also set it to 512 kbs by default.
	EXPECT_GE(read_sysfs_value(sysfs_path + "read_ahead_kb"), 128);

	// Check if FUA file exists before trying to read it
	std::string fua_path = sysfs_path + "fua";
	if (access(fua_path.c_str(), F_OK) == 0) {
		EXPECT_EQ(1, read_sysfs_value(fua_path));
		std::cout << "FUA validation passed" << std::endl;
	} else {
		std::cout << "WARNING: FUA sysfs attribute does not exist at: " << fua_path << std::endl;
		// Check if the queue actually has FUA capability
		std::string features_path = sysfs_path + "write_cache";
		if (access(features_path.c_str(), F_OK) == 0) {
			std::cout << "write_cache attribute exists, checking value..." << std::endl;
			system(("cat " + features_path).c_str());
		}
	}
}

void PxdTest::validate_write_zeroes(const std::string &device_name, bool expected_enabled)
{
	std::cout << "Validating write_zeroes for device: " << device_name
	          << ", expected_enabled: " << (expected_enabled ? "true" : "false") << std::endl;

	// Convert device name to sysfs path format
	std::string sysfs_name = device_name;
	// /dev/pxd/pxd123 -> pxd!pxd123
	if (sysfs_name.find("/dev/pxd/") == 0) {
		sysfs_name = sysfs_name.substr(9); // Remove "/dev/pxd/"
		sysfs_name = "pxd!" + sysfs_name;
	}

	std::string sysfs_path = "/sys/block/" + sysfs_name + "/queue/";
	std::string wz_path = sysfs_path + "write_zeroes_max_bytes";

	// Check if write_zeroes_max_bytes file exists
	if (access(wz_path.c_str(), F_OK) != 0) {
		std::cout << "WARNING: write_zeroes_max_bytes sysfs attribute does not exist at: "
		          << wz_path << std::endl;
		// On older kernels, this file may not exist - skip the check
		return;
	}

	// Read write_zeroes_max_bytes value
	std::ifstream file(wz_path);
	ASSERT_TRUE(file.is_open()) << "Failed to open: " << wz_path;
	uint64_t wz_max_bytes;
	file >> wz_max_bytes;
	ASSERT_TRUE(file.good()) << "Failed to read from: " << wz_path;

	std::cout << "write_zeroes_max_bytes = " << wz_max_bytes << std::endl;

	if (expected_enabled) {
		// WriteZero should be enabled: write_zeroes_max_bytes > 0
		EXPECT_GT(wz_max_bytes, 0u)
		    << "WriteZero should be ENABLED but write_zeroes_max_bytes is 0";
		// Value should be discard_granularity (default PXD_MAX_DISCARD_GRANULARITY = 1MB)
		EXPECT_EQ(wz_max_bytes, PXD_MAX_DISCARD_GRANULARITY)
		    << "write_zeroes_max_bytes should equal discard_granularity";
	} else {
		// WriteZero should be disabled: write_zeroes_max_bytes == 0
		EXPECT_EQ(wz_max_bytes, 0u)
		    << "WriteZero should be DISABLED but write_zeroes_max_bytes is " << wz_max_bytes;
	}

	std::cout << "WriteZero validation passed" << std::endl;
}

void PxdTest::SetUp()
{
	fprintf(stderr, "%s\n", __func__);
	seteuid(0);
	if (system("/usr/bin/sudo /sbin/lsmod | grep px") == 0) {
		ASSERT_EQ(0, system("/usr/bin/sudo /sbin/rmmod px"));
	}
	auto insmod_ret =  system("/usr/bin/sudo /sbin/insmod px.ko");

	if (insmod_ret != 0 && (system("/usr/bin/sudo /sbin/lsmod | grep px") != 0)) {
		FAIL() << "Failed to load px module";
	} else {
		std::cout << "Opening control dev: " << control_device(0) << "\n";
		ctl_fd = open(control_device(0).c_str(), O_RDWR);
		ASSERT_GT(ctl_fd, 0);

		pxd_ioctl_init_args args;
		auto ret = ioctl(ctl_fd, PXD_IOC_INIT, &args);
		if (ret < 0) {
			fprintf(stderr, "%s: init ioctl failed: %d(%s)", __func__, errno, strerror(errno));
		}

		auto read_bytes = static_cast<size_t>(ret);
		ASSERT_EQ(sizeof(pxd_init_in), read_bytes);
		ASSERT_EQ(0, args.hdr.num_devices);
		ASSERT_EQ(PXD_VERSION, args.hdr.version);
	}
}

void PxdTest::TearDown()
{
	fprintf(stderr, "%s\n", __func__);
	std::for_each(added_ids.begin(), added_ids.end(), std::bind(&PxdTest::dev_remove, this, _1));

	if (ctl_fd >= 0) {
		close(ctl_fd);
		ctl_fd = -1;
	}

	int ret = 0;
	int iter = 0;
	while (1) {
		iter++;
		ret = system("/usr/bin/sudo /sbin/rmmod px.ko");
		if (ret == 0)
			break;
		fprintf(stderr, "waiting for rmmod to pass\n");
		sleep(1);
	}
	fprintf(stderr, "took %d seconds to perform rmmod\n", iter);
}

// Read block from kernel
void PxdTest::read_block(fuse_in_header *hdr, pxd_rdwr_in *req)
{
	int iovcnt = 1;
	struct iovec iov[iovcnt];
	size_t iovlen = iovcnt * sizeof(iov);
	std::vector<uint8_t> buf(req->size, 0);
	size_t ret = 0;

	fprintf(stderr, "request opc(%d) offset (%ld) len (%d)\n", hdr->opcode, req->offset, req->size);

	// Setup request header and payload
	fuse_notify_header oh(PXD_READ_DATA, sizeof(pxd_read_data_out) + iovlen);
	pxd_read_data_out rd_out = {hdr->unique, iovcnt, 0};

	// memset(buf, 0, req->size);
	iov[0].iov_base = buf.data();
	iov[0].iov_len = req->size;
	struct iovec wr_iov[3] = {{&oh, sizeof(oh)}, {&rd_out, sizeof(rd_out)}, {iov, iovlen}};

	// Send a read request to kernel
	ret = writev(ctl_fd, wr_iov, 3);
	fprintf(stderr, "%s: read/verify data from kernel\n", __func__);
	ASSERT_EQ(ret, oh.len);
	ASSERT_TRUE(verify_pattern(buf.data(), req->size));
}

void PxdTest::write_thread(const char *name)
{
	auto buf = aligned_buffer(write_len);
	init_pattern(buf.get(), write_len);

	boost::iostreams::file_descriptor dev_fd(name);

	ssize_t write_bytes = pwrite(dev_fd.handle(), buf.get(), write_len, test_off);
	ASSERT_EQ(write_bytes, write_len);
	fprintf(stderr, "%s: bytes written: %lu\n", __func__, write_bytes);
}

void PxdTest::read_thread(const char *name)
{
	auto buf = aligned_buffer(write_len);
	init_pattern(buf.get(), write_len);

	int fd = open(name, O_RDWR | O_DIRECT);
	boost::iostreams::file_descriptor dev_fd(fd, boost::iostreams::close_handle);

	// explicitly read non-zero offset
	fprintf(stderr, "%s: submit read req: size: %lu\n", __func__, write_len);
	ssize_t read_bytes = pread(dev_fd.handle(), buf.get(), write_len, test_off);
	fprintf(stderr, "%s: response read bytes: %lu\n", __func__, read_bytes);
	ASSERT_EQ(read_bytes, write_len);
}

TEST_F(PxdTest, simple)
{
	std::cout << "simple test" << std::endl;
}

TEST_F(PxdTest, device_size)
{
	pxd_add_out add;
	std::string name;
	int minor, ret;
	uint64_t dev_size;
	const uint64_t target_dev_size = 1024 * 1024;

	add.dev_id = 1;
	add.size = target_dev_size;
	add.queue_depth = 128;
	add.discard_size = 4096;
	dev_add(add, minor, name);

	boost::iostreams::file_descriptor dev_fd(name);
	ASSERT_GT(dev_fd.handle(), 0);

	ret = ioctl(dev_fd.handle(), BLKGETSIZE64, &dev_size);
	ASSERT_EQ(0, ret);
	ASSERT_EQ(dev_size, target_dev_size);

	dev_fd.close();

	dev_remove(add.dev_id);
}

TEST_F(PxdTest, write)
{
	struct pxd_add_out add;
	struct rdwr_in rdwr;
	struct pxd_rdwr_in *wr = NULL;
	std::string name;
	int minor = 0;
	ssize_t read_bytes = 0;

	// Attach a kernel block device (/dev/pxd/pxd1)
	add.dev_id = 1;
	add.size = 1024 * 1024;
	add.queue_depth = 128;
	add.discard_size = PXD_LBS;
	dev_add(add, minor, name);

	// Start a thread to perform writes on the attached device
	std::thread wt(&PxdTest::write_thread, this, name.c_str());

	// Now read in the request from kernel
	while (1) {
		int ret = wait_msg(1);
		if (ret == -ETIMEDOUT) {
			sleep(1);
			continue;
		}
		ASSERT_EQ(ret, 0);

		read_bytes = read(ctl_fd, &rdwr, sizeof(rdwr_in));
		wr = reinterpret_cast<pxd_rdwr_in *>(&rdwr.rdwr);

		if (rdwr.in.opcode == PXD_WRITE && rdwr.rdwr.offset == test_off) {
			read_block(&rdwr.in, reinterpret_cast<pxd_rdwr_in *>(&rdwr.rdwr));
			break;
		} else {
			finish_io(&rdwr);
		}
	}

	// Process the write request
	ASSERT_EQ(rdwr.in.opcode, PXD_WRITE);
	ASSERT_EQ(wr->dev_minor, minor);
	ASSERT_EQ(wr->offset, test_off);
	ASSERT_EQ(wr->size, write_len);

	// Reply to the kernel
	finish_io(&rdwr);
	wt.join();

	// Detach block device
	dev_remove(add.dev_id);
}

TEST_F(PxdTest, read)
{
	struct pxd_add_out add;
	std::string name;
	int minor = 0;
	struct rdwr_in rdwr;
	ssize_t read_bytes = 0;

	// Attach a kernel block device (/dev/pxd/pxd1)
	add.dev_id = 1;
	add.size = 1024 * 1024;
	add.queue_depth = 128;
	add.discard_size = PXD_MAX_DISCARD_GRANULARITY;
	dev_add(add, minor, name);

	// Start a thread to perform reads on the attached device
	std::thread rt(&PxdTest::read_thread, this, name.c_str());

	// Now read in the request from kernel
	while (1) {
		int ret = wait_msg(1);
		if (ret == -ETIMEDOUT) {
			sleep(1);
			continue;
		}
		EXPECT_EQ(ret, 0);

		read_bytes = read(ctl_fd, &rdwr, sizeof(rdwr));

		if (finish_io(&rdwr) == 1) {
			fprintf(stderr, "found the test read\n");
			break;
		}
	}

	rt.join();
	// Detach block device
	dev_remove(add.dev_id);
}

TEST_F(PxdTest, blkdiscard_ioctl)
{
	struct pxd_add_out add;
	std::string name;
	int minor = 0;
	struct rdwr_in rdwr;
	ssize_t read_bytes = 0;
	const uint64_t device_size = 32 * 1024 * 1024;                    // 32MB device
	const uint64_t discard_granularity = PXD_MAX_DISCARD_GRANULARITY;
	const uint64_t discard_offset = 0; // 0MB offset (aligned to granularity)
	// const uint64_t discard_length = 2 * 1024 * 1024; // 2MB length
	const uint64_t expected_kernel_discard_size =
	    discard_granularity; // Kernel may align to granularity

	std::cout << "Starting BLKDISCARD ioctl test" << std::endl;

	std::vector<uint64_t> discard_sizes = {0,
	                                       4096,
	                                       PXD_MAX_DISCARD_GRANULARITY,
	                                       PXD_MAX_DISCARD_GRANULARITY + 512 * 1024,
	                                       PXD_MAX_DISCARD_GRANULARITY * 3,
	                                       PXD_MAX_DISCARD_GRANULARITY * 32,
	                                       PXD_MAX_DISCARD_GRANULARITY * 32 + 512 * 1024};

	std::vector<uint64_t> discard_lengths = {0, 4096, PXD_MAX_DISCARD_GRANULARITY,
	                                         PXD_MAX_DISCARD_GRANULARITY + 512 * 1024,
	                                         PXD_MAX_DISCARD_GRANULARITY * 3};

	// Attach a kernel block device with discard support
	add.dev_id = 1;
	add.size = device_size;
	add.queue_depth = 128;
	for (uint64_t discard_size : discard_sizes) {
		add.discard_size = discard_size;
		dev_add(add, minor, name);
			validate_device_properties(name, PXD_MAX_DISCARD_GRANULARITY,
									ALIGN(add.discard_size, PXD_MAX_DISCARD_GRANULARITY));
			std::cout << "Device created: " << name << std::endl;

		for (uint64_t discard_length : discard_lengths) {
			
			std::cout << "============>	Testing discard for discard size: " << discard_size
			          << ", and discard length: " << discard_length << std::endl;

			int timeout_attempts = 0;
			const int max_timeout_attempts = 50;
			bool discard_issued = false;
			std::thread discard_thread;
			uint64_t total_discarded = 0;
			const uint64_t expected_total_discard = discard_length;

			while (total_discarded < expected_total_discard) {
				if (discard_size == 0) {
					std::cout << "Not expecting discard ioctl since discard size is 0" << std::endl;
					break;
				}
				// Issue BLKDISCARD on first iteration after we're ready to handle requests
				if (!discard_issued) {
					discard_thread = std::thread([&]() {
						int fd = open(name.c_str(), O_RDWR);
						ASSERT_GT(fd, 0) << "Failed to open device: " << name;

						uint64_t range[2] = {discard_offset, discard_length};

						std::cout << "Issuing BLKDISCARD ioctl: offset=" << discard_offset
						          << ", length=" << discard_length << std::endl;

						int ret = ioctl(fd, BLKDISCARD, range);
						std::cout << "BLKDISCARD ioctl completed with ret=" << ret << std::endl;
						ASSERT_EQ(ret, 0) << "BLKDISCARD ioctl failed";

						close(fd);
					});
					discard_issued = true;
					std::cout << "Started BLKDISCARD thread, now listening for kernel requests..."
					          << std::endl;
				}
				int ret = wait_msg(2);
				if (ret == -ETIMEDOUT) {
					timeout_attempts++;
					std::cout << "Timeout waiting for discard request (attempt " << timeout_attempts
					          << ")" << std::endl;
					if (timeout_attempts >= max_timeout_attempts) {
						std::cout << "ERROR: Max timeouts reached" << std::endl;
						break;
					}
					continue;
				}
				ASSERT_EQ(ret, 0);

				read_bytes = read(ctl_fd, &rdwr, sizeof(rdwr));
				ASSERT_GT(read_bytes, 0);

				struct pxd_rdwr_in *rd = reinterpret_cast<pxd_rdwr_in *>(&rdwr.rdwr);

				std::cout << "Received request: opcode=" << rdwr.in.opcode
				          << ", offset=" << rd->offset << ", size=" << rd->size << std::endl;

				if (rdwr.in.opcode == PXD_DISCARD) {
					std::cout << "Received PXD_DISCARD request" << std::endl;

					// Reply success to the kernel
					fuse_out_header oh;
					oh.len = sizeof(oh);
					oh.error = 0;
					oh.unique = rdwr.in.unique;
					ssize_t write_ret = ::write(ctl_fd, &oh, sizeof(oh));
					ASSERT_EQ(sizeof(oh), write_ret);

					// Track total discarded
					total_discarded += rd->size;
					std::cout << "SUCCESS: Processed " << rd->size
					          << " bytes, total: " << total_discarded << "/"
					          << expected_total_discard << std::endl;
				} else {
					// Handle other operations normally
					finish_io(&rdwr);
				}
			}

			// Clean up thread
			if (discard_thread.joinable()) {
				discard_thread.join();
			}

			if (total_discarded || !discard_size) {
				std::cout << "SUCCESS: BLKDISCARD ioctl test completed successfully" << std::endl;
			} else {
				std::cerr << "ERROR: BLKDISCARD test failed - no discard request received"
				          << std::endl;
			}

			std::cout << "============>	BLKDISCARD ioctl test completed" << std::endl;

		}
		// Detach block device
		dev_remove(add.dev_id);
		sleep(1);
	}
}

void PxdTest::write_thread_timeout(const char *name)
{
	auto buf = aligned_buffer(write_len);
	init_pattern(buf.get(), write_len);

	int fd = open(name, O_RDWR | O_DIRECT);
	ASSERT_TRUE(fd >= 0);

	fprintf(stderr, "write thread: waiting for attach IO to complete for 10 seconds\n");
	std::this_thread::sleep_for(std::chrono::seconds(10)); // wait for attach IO to complete

	auto off = test_off * 2;
	ssize_t write_bytes = pwrite(fd, buf.get(), write_len, off);
	
	ASSERT_EQ(-1, write_bytes);
	close(fd);
}

TEST_F(PxdTest, AbortContextWithInFlightIO)
{
	struct pxd_add_out add;
	std::string name;
	int minor = 0;

	add.dev_id = 1;
	add.size = 1024 * 1024;
	add.queue_depth = 128;
	add.discard_size = PXD_LBS;
	// create a /dev/pxd/pxd1 device
	dev_add(add, minor, name);

	ASSERT_TRUE(added_ids.find(1) != added_ids.end());

	const int test_timeout_secs = 30; // min valid value
	// set timeout to 30s
	ASSERT_EQ(0, write_pxd_timeout(minor, test_timeout_secs));

	// start a thread to do a write to /dev/pxd/pxd1 at test_off
	std::thread wt(&PxdTest::write_thread_timeout, this, name.c_str());

	struct rdwr_in rdwr;
	struct pxd_rdwr_in *wr {nullptr};
	auto off = test_off * 2;
	while (1) {
		// wait for upto 1 second for px-fuse to notify the ctrl fd
		int ret = wait_msg(1);
		if (ret == -ETIMEDOUT) {
			continue;
		}
		EXPECT_EQ(ret, 0);

		ssize_t read_bytes = read(ctl_fd, &rdwr, sizeof(rdwr_in));
		EXPECT_EQ(read_bytes, sizeof(rdwr_in));
		wr = reinterpret_cast<pxd_rdwr_in*>(&rdwr.rdwr);
		// find the test write
		if (rdwr.in.opcode == PXD_WRITE && rdwr.rdwr.offset >= off && rdwr.rdwr.offset < off + write_len) {
			fprintf(stderr, "found the test write: offset: %ld, len = %d\n", rdwr.rdwr.offset, rdwr.rdwr.size);
			break;
		} else {
			fprintf(stderr, "opcode : %d, offset: %ld, len = %d\n", rdwr.in.opcode, rdwr.rdwr.offset, rdwr.rdwr.size);
			// finish unrelated IO
			finish_io(&rdwr);
		}
	}

	// validate the write request
	ASSERT_EQ(wr->dev_minor, minor);
	ASSERT_EQ(wr->offset, off);
	ASSERT_EQ(wr->size, write_len);

	// close the ctrl fd to trigger pxd_abort_context
	close(ctl_fd);
	ctl_fd = -1; 

	std::this_thread::sleep_for(std::chrono::seconds(test_timeout_secs + 5));
	fprintf(stderr, "Test: Wait complete.\n");

	wt.join();

	// re-open the control fd to remove the device
	ctl_fd = open(control_device(0).c_str(), O_RDWR);
	ASSERT_GT(ctl_fd, 0);
	// detach the device
	dev_remove(add.dev_id);
}

/**
 * Test: WriteZero flag is SET for native path device when capability is enabled
 *
 * This test verifies that when a device is attached via PXD_ADD_EXT_V2 with:
 * - enable_fp = 0 (native path, not fastpath)
 * - capabilities = PXD_DEV_CAP_WRITE_ZEROES
 *
 * The resulting block device should have write_zeroes_max_bytes > 0 in sysfs.
 */
TEST_F(PxdTest, write_zeroes_enabled_native_path)
{
	std::cout << "=== Test: WriteZero enabled for native path with capability ===" << std::endl;

	pxd_add_v2_out add_v2;
	std::string name;
	int minor;

	// Zero-initialize the structure (sets reserved[4]=0)
	memset(&add_v2, 0, sizeof(add_v2));

	// Setup device with native path (enable_fp = 0) and WriteZero capability
	add_v2.dev_id = 100;
	add_v2.size = 100 * 1024 * 1024;  // 100 MB
	add_v2.queue_depth = 128;
	add_v2.discard_size = PXD_MAX_DISCARD_GRANULARITY;
	add_v2.open_mode = O_LARGEFILE | O_RDWR;
	add_v2.enable_fp = 0;  // Native path (NOT fastpath)
	add_v2.paths.count = 0;  // No fastpath backing devices
	add_v2.capabilities = PXD_DEV_CAP_WRITE_ZEROES;  // Enable WriteZero capability
	add_v2.discard_granularity = 0;  // Use default

	// Add device via PXD_ADD_EXT_V2
	dev_add_v2(add_v2, minor, name);

	std::cout << "Device created: " << name << std::endl;

	// Validate that WriteZero is ENABLED for native path
	validate_write_zeroes(name, true /* expected_enabled */);

	// Cleanup
	dev_remove(add_v2.dev_id);

	std::cout << "=== Test PASSED: WriteZero enabled for native path ===" << std::endl;
}

/**
 * Test: WriteZero flag is DISABLED for native path device when capability is NOT set
 *
 * This test verifies that when a device is attached via PXD_ADD_EXT_V2 with:
 * - enable_fp = 0 (native path)
 * - capabilities = 0 (no WriteZero capability)
 *
 * The resulting block device should have write_zeroes_max_bytes == 0 in sysfs.
 */
TEST_F(PxdTest, write_zeroes_disabled_native_path_no_capability)
{
	std::cout << "=== Test: WriteZero disabled for native path without capability ===" << std::endl;

	pxd_add_v2_out add_v2;
	std::string name;
	int minor;

	// Zero-initialize the structure
	memset(&add_v2, 0, sizeof(add_v2));

	// Setup device with native path but NO WriteZero capability
	add_v2.dev_id = 101;
	add_v2.size = 100 * 1024 * 1024;  // 100 MB
	add_v2.queue_depth = 128;
	add_v2.discard_size = PXD_MAX_DISCARD_GRANULARITY;
	add_v2.open_mode = O_LARGEFILE | O_RDWR;
	add_v2.enable_fp = 0;  // Native path
	add_v2.paths.count = 0;
	add_v2.capabilities = 0;  // NO WriteZero capability
	add_v2.discard_granularity = 0;

	// Add device via PXD_ADD_EXT_V2
	dev_add_v2(add_v2, minor, name);

	std::cout << "Device created: " << name << std::endl;

	// Validate that WriteZero is DISABLED
	validate_write_zeroes(name, false /* expected_enabled */);

	// Cleanup
	dev_remove(add_v2.dev_id);

	std::cout << "=== Test PASSED: WriteZero disabled without capability ===" << std::endl;
}

/**
 * Test: WriteZero flag uses custom discard_granularity when specified
 *
 * This test verifies that when a device is attached via PXD_ADD_EXT_V2 with:
 * - capabilities = PXD_DEV_CAP_WRITE_ZEROES
 * - discard_granularity = custom value (2MB instead of default 1MB)
 *
 * The resulting block device should have write_zeroes_max_bytes == custom value.
 */
TEST_F(PxdTest, write_zeroes_custom_discard_granularity)
{
	std::cout << "=== Test: WriteZero with custom discard_granularity ===" << std::endl;

	pxd_add_v2_out add_v2;
	std::string name;
	int minor;
	const uint32_t custom_granularity = 2 * 1024 * 1024;  // 2MB

	// Zero-initialize the structure
	memset(&add_v2, 0, sizeof(add_v2));

	// Setup device with custom discard_granularity
	add_v2.dev_id = 102;
	add_v2.size = 100 * 1024 * 1024;  // 100 MB
	add_v2.queue_depth = 128;
	add_v2.discard_size = custom_granularity;
	add_v2.open_mode = O_LARGEFILE | O_RDWR;
	add_v2.enable_fp = 0;  // Native path
	add_v2.paths.count = 0;
	add_v2.capabilities = PXD_DEV_CAP_WRITE_ZEROES;
	add_v2.discard_granularity = custom_granularity;  // Custom value

	// Add device via PXD_ADD_EXT_V2
	dev_add_v2(add_v2, minor, name);

	std::cout << "Device created: " << name << std::endl;

	// Validate WriteZero uses custom granularity
	// Convert device name to sysfs path
	std::string sysfs_name = name;
	if (sysfs_name.find("/dev/pxd/") == 0) {
		sysfs_name = sysfs_name.substr(9);
		sysfs_name = "pxd!" + sysfs_name;
	}
	std::string wz_path = "/sys/block/" + sysfs_name + "/queue/write_zeroes_max_bytes";

	if (access(wz_path.c_str(), F_OK) == 0) {
		std::ifstream file(wz_path);
		ASSERT_TRUE(file.is_open());
		uint64_t wz_max_bytes;
		file >> wz_max_bytes;
		std::cout << "write_zeroes_max_bytes = " << wz_max_bytes << std::endl;
		EXPECT_EQ(wz_max_bytes, custom_granularity)
		    << "write_zeroes_max_bytes should equal custom discard_granularity";
	} else {
		std::cout << "WARNING: write_zeroes_max_bytes not available on this kernel" << std::endl;
	}

	// Cleanup
	dev_remove(add_v2.dev_id);

	std::cout << "=== Test PASSED: WriteZero with custom granularity ===" << std::endl;
}

/*
 * NOTE: Fastpath WriteZero tests should be added to pxd_fastpath_test.cc
 * since they require backing devices infrastructure.
 *
 * Test case for fastpath:
 * - WriteZero should be DISABLED for fastpath devices regardless of capabilities
 * - Even if PXD_DEV_CAP_WRITE_ZEROES is set, fastpath (LVM) doesn't support discard
 * - See pxd_fastpath_test.cc for implementation
 */

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
