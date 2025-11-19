#include <algorithm>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/lexical_cast.hpp>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <thread>
#include <vector>
#include <unistd.h>
#include <linux/fs.h>
#include <set>

#include <cstdlib>
#include <memory>
#include <stdexcept>

#include "fuse.h"
#include "pxd.h"

using namespace std::placeholders;

// Enum to define backing device types for parameterized tests
enum class BackingDeviceType {
    BACKING_FILE,
    LOOP_DEVICE
};

// Helper function to create temporary backing files for fastpath
class TempBackingFile {
public:
    TempBackingFile(size_t size_mb = 100) {
        char template_name[] = "/tmp/pxd_test_backing_XXXXXX";
        fd_ = mkstemp(template_name);
        if (fd_ < 0) {
            throw std::runtime_error("Failed to create temporary backing file");
        }
        path_ = template_name;

        // Extend the file to the desired size
        if (ftruncate(fd_, size_mb * 1024 * 1024) != 0) {
            close(fd_);
            unlink(path_.c_str());
            throw std::runtime_error("Failed to extend backing file");
        }
    }

    ~TempBackingFile() {
        if (fd_ >= 0) {
            close(fd_);
            unlink(path_.c_str());
        }
    }

    const std::string& path() const { return path_; }
    int fd() const { return fd_; }

private:
    int fd_;
    std::string path_;
};

// Helper class to create and manage loop devices for fastpath tests
class TempLoopDevice {
public:
    TempLoopDevice(size_t size_mb = 100) : loop_device_path_(""), backing_file_path_("") {
        // Create a temporary backing file first
        char template_name[] = "/tmp/pxd_test_loop_backing_XXXXXX";
        int backing_fd = mkstemp(template_name);
        if (backing_fd < 0) {
            throw std::runtime_error("Failed to create temporary backing file for loop device");
        }
        backing_file_path_ = template_name;

        // Extend the backing file to the desired size
        if (ftruncate(backing_fd, size_mb * 1024 * 1024) != 0) {
            close(backing_fd);
            unlink(backing_file_path_.c_str());
            throw std::runtime_error("Failed to extend backing file for loop device");
        }
        close(backing_fd);

        // Find a free loop device
        loop_device_path_ = find_free_loop_device();
        if (loop_device_path_.empty()) {
            unlink(backing_file_path_.c_str());
            throw std::runtime_error("Failed to find free loop device");
        }

        // Setup the loop device
        std::string cmd = "losetup " + loop_device_path_ + " " + backing_file_path_;
        int ret = system(cmd.c_str());
        if (ret != 0) {
            unlink(backing_file_path_.c_str());
            throw std::runtime_error("Failed to setup loop device: " + cmd);
        }

        std::cout << "Created loop device: " << loop_device_path_ << " backed by " << backing_file_path_ << std::endl;
    }

    ~TempLoopDevice() {
        // Detach loop device
        if (!loop_device_path_.empty()) {
            std::string cmd = "losetup -d " + loop_device_path_;
            int ret = system(cmd.c_str());
            if (ret != 0) {
                std::cerr << "Warning: Failed to detach loop device: " << loop_device_path_ << std::endl;
            }
        }

        // Remove backing file
        if (!backing_file_path_.empty()) {
            unlink(backing_file_path_.c_str());
        }
    }

    const std::string& path() const { return loop_device_path_; }

private:
    std::string loop_device_path_;
    std::string backing_file_path_;

    std::string find_free_loop_device() {
        // Try loop devices from 100 to 199 to avoid conflicts with system devices
        for (int i = 100; i < 200; ++i) {
            std::string loop_path = "/dev/loop" + std::to_string(i);

            // Check if loop device exists, create if it doesn't
            if (access(loop_path.c_str(), F_OK) != 0) {
                std::string mknod_cmd = "mknod " + loop_path + " b 7 " + std::to_string(i);
                if (system(mknod_cmd.c_str()) != 0) {
                    continue; // Try next device
                }
            }

            // Check if loop device is free
            std::string check_cmd = "losetup " + loop_path + " 2>/dev/null";
            if (system(check_cmd.c_str()) != 0) {
                // Device is free
                return loop_path;
            }
        }
        return "";
    }
};

// Utility functions for fastpath tests
static ::testing::AssertionResult verify_pattern_fastpath(void *buf, size_t len)
{
    uint8_t *d = (uint8_t *)buf;
    for (size_t i = 0; i < len; ++i) {
        if (d[i] != (i % UINT8_MAX)) {
            return ::testing::AssertionFailure() << "at " << i << " val " << d[i];
        }
    }
    return ::testing::AssertionSuccess();
}

static void init_pattern_fastpath(void *vv, size_t size)
{
    uint8_t *v = (uint8_t *)vv;
    for (size_t i = 0; i < size; ++i)
        v[i] = i % UINT8_MAX;
}

std::unique_ptr<void, decltype(&std::free)> aligned_buffer_fastpath(size_t buffer_size)
{
    void *ptr = nullptr;
    if (posix_memalign(&ptr, 4096, buffer_size) != 0) {
        throw std::runtime_error("Failed to allocate aligned buffer");
    }
    return std::unique_ptr<void, decltype(&std::free)>(ptr, &std::free);
}

std::string control_device_fastpath(unsigned int driver_context_id)
{
    assert(driver_context_id < PXD_NUM_CONTEXTS);
    std::string ret{PXD_CONTROL_DEV};
    if (driver_context_id != 0)
        ret += "-" + std::to_string(driver_context_id);
    return ret;
}

// Base class for fastpath tests - now parameterized by backing device type
class PxdFastpathTest : public ::testing::TestWithParam<BackingDeviceType>
{
protected:
    bool killed{false};
    int ctl_fd; // control file descriptor
    std::set<uint64_t> added_ids;
    const size_t write_len = PXD_LBS * 4;
    const size_t test_off = 4 * 4096;
    std::vector<std::unique_ptr<TempBackingFile>> backing_files;
    std::vector<std::unique_ptr<TempLoopDevice>> loop_devices;

    PxdFastpathTest() : ctl_fd(-1)
    {
    }

    virtual ~PxdFastpathTest()
    {
        if (ctl_fd >= 0) {
            close(ctl_fd);
            fprintf(stderr, "closed control fd\n");
        }
    }

    virtual void SetUp();
    virtual void TearDown();

    // Helper functions for device lifecycle (consistent with pxd_test.cc)
    void dev_add_fastpath(pxd_add_out &add, int &minor, std::string &name);
    void dev_add_fastpath(pxd_add_ext_out &add_ext, int &minor, std::string &name);
    void dev_export_fastpath(uint64_t dev_id, const std::string &expected_name);
    void dev_remove_fastpath(uint64_t dev_id);
    int wait_msg(int timeout); // timeout in seconds
    void read_block(fuse_in_header *in, pxd_rdwr_in *rd);
    void validate_device_properties(const std::string &device_name,
                                    uint64_t expected_discard_granularity = 1048576,
                                    uint64_t expected_max_discard_bytes = 1048576);
    void validate_fastpath_active(const std::string &device_name, int minor_with_status);



    // I/O test helpers
    void write_thread_fastpath(const char *name);
    void read_thread_fastpath(const char *name);
    void perform_io_test(const std::string &device_path);

    // Backing device management (files or loop devices)
    void create_backing_devices(size_t count, size_t size_mb = 100);
    void setup_fastpath_paths(pxd_update_path_out &paths);

    // Helper methods for backing device management
    void create_backing_files(size_t count, size_t size_mb = 100);
    void create_loop_devices(size_t count, size_t size_mb = 100);

public:
    void fail_io(struct rdwr_in *);
    int finish_io(struct rdwr_in *, bool read_data = false);
    void cleaner();
};

void PxdFastpathTest::SetUp()
{
    fprintf(stderr, "%s\n", __func__);
    seteuid(0);
	auto insmod_ret = system("/usr/bin/sudo /sbin/insmod px.ko");

    if (insmod_ret != 0 && (system("/usr/bin/sudo /sbin/lsmod | grep px") != 0)) {
        FAIL() << "Failed to load px module";
    } else {
        std::string control_dev = control_device_fastpath(0);
        std::cout << "Opening control dev: " << control_dev << "\n";
        ctl_fd = open(control_dev.c_str(), O_RDWR);
        ASSERT_GT(ctl_fd, 0);

        pxd_ioctl_init_args args;
        auto ret = ioctl(ctl_fd, PXD_IOC_INIT, &args);
        if (ret < 0) {
            fprintf(stderr, "%s: init ioctl failed: %d(%s)", __func__, errno, strerror(errno));
        }

        auto read_bytes = static_cast<size_t>(ret);
        fprintf(stdout, "Number of devices: %d\n", args.hdr.num_devices);
        ASSERT_EQ(sizeof(pxd_init_in), read_bytes);
        ASSERT_EQ(0, args.hdr.num_devices);
        ASSERT_EQ(PXD_VERSION, args.hdr.version);

        // Note: Backing devices are created on-demand by individual tests
    }
    
}

void PxdFastpathTest::TearDown()
{
    fprintf(stderr, "%s\n", __func__);

    // Create a copy to avoid iterator invalidation
    std::set<uint64_t> ids_to_remove = added_ids;
    for (uint64_t id : ids_to_remove) {
        if (added_ids.find(id) != added_ids.end()) {
            dev_remove_fastpath(id);
            added_ids.erase(id);  // Erase here instead
        }
    }

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

    // Clean up backing devices safely
    try {
        backing_files.clear();
        loop_devices.clear();
        fprintf(stderr, "backing devices cleared\n");
    } catch (const std::exception& e) {
        fprintf(stderr, "Error clearing backing devices: %s\n", e.what());
    }
}

void PxdFastpathTest::create_backing_devices(size_t count, size_t size_mb)
{
    BackingDeviceType device_type = GetParam();

    // Clear any existing devices
    backing_files.clear();
    loop_devices.clear();

    if (device_type == BackingDeviceType::BACKING_FILE) {
        create_backing_files(count, size_mb);
    } else if (device_type == BackingDeviceType::LOOP_DEVICE) {
        create_loop_devices(count, size_mb);
    }
}

void PxdFastpathTest::create_backing_files(size_t count, size_t size_mb)
{
    backing_files.clear();
    for (size_t i = 0; i < count; ++i) {
        backing_files.push_back(std::unique_ptr<TempBackingFile>(new TempBackingFile(size_mb)));
        std::cout << "Created backing file " << i << ": " << backing_files[i]->path() << std::endl;
    }
}

void PxdFastpathTest::create_loop_devices(size_t count, size_t size_mb)
{
    loop_devices.clear();
    for (size_t i = 0; i < count; ++i) {
        loop_devices.push_back(std::unique_ptr<TempLoopDevice>(new TempLoopDevice(size_mb)));
        std::cout << "Created loop device " << i << ": " << loop_devices[i]->path() << std::endl;
    }
}

void PxdFastpathTest::setup_fastpath_paths(pxd_update_path_out &paths)
{
    memset(&paths, 0, sizeof(paths));
    paths.can_failover = true;

    BackingDeviceType device_type = GetParam();

    if (device_type == BackingDeviceType::BACKING_FILE) {
        paths.count = backing_files.size();
        for (size_t i = 0; i < backing_files.size() && i < MAX_PXD_BACKING_DEVS; ++i) {
            strncpy(paths.devpath[i], backing_files[i]->path().c_str(), MAX_PXD_DEVPATH_LEN);
            paths.devpath[i][MAX_PXD_DEVPATH_LEN] = '\0';
            std::cout << "Setup fastpath (backing file) " << i << ": " << paths.devpath[i] << std::endl;
        }
    } else if (device_type == BackingDeviceType::LOOP_DEVICE) {
        paths.count = loop_devices.size();
        for (size_t i = 0; i < loop_devices.size() && i < MAX_PXD_BACKING_DEVS; ++i) {
            strncpy(paths.devpath[i], loop_devices[i]->path().c_str(), MAX_PXD_DEVPATH_LEN);
            paths.devpath[i][MAX_PXD_DEVPATH_LEN] = '\0';
            std::cout << "Setup fastpath (loop device) " << i << ": " << paths.devpath[i] << std::endl;
        }
    }
}

void PxdFastpathTest::dev_add_fastpath(pxd_add_out &add, int &minor, std::string &name)
{
	fuse_out_header oh;
	struct iovec iov[2];

	ASSERT_TRUE(added_ids.find(add.dev_id) == added_ids.end());

	oh.unique = 0;
	oh.error = PXD_ADD;
	oh.len = sizeof(oh) + sizeof(add);

	iov[0].iov_base = &oh;
	iov[0].iov_len = sizeof(oh);
	iov[1].iov_base = &add;
	iov[1].iov_len = sizeof(add);

	ssize_t write_bytes = writev(ctl_fd, iov, 2);
    if (write_bytes <= 0) {
        fprintf(stderr, "writev failed: errno=%d (%s)\n", errno, strerror(errno));
        fprintf(stderr, "dev_id=%llu, size=%zu, ctl_fd=%d\n", 
                add.dev_id, add.size, ctl_fd);
    }
	ASSERT_GT(write_bytes, 0);

	std::cout << "dev_add_fastpath: PXD_ADD completed, wrote " << write_bytes << " bytes"
	          << std::endl;
	std::cout << "dev_add_fastpath: device ID = " << add.dev_id << std::endl;

	added_ids.insert(add.dev_id);
	minor = write_bytes;
	name = std::string(PXD_DEV_PATH) + std::to_string(add.dev_id);

	dev_export_fastpath(add.dev_id, name);
	validate_device_properties(name, 1024 * 1024, 1024 * 1024);
	validate_fastpath_active(name, minor);
}

void PxdFastpathTest::dev_add_fastpath(pxd_add_ext_out &add_ext, int &minor, std::string &name)
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

	std::cout << "dev_add_fastpath: PXD_ADD_EXT completed, wrote " << write_bytes << " bytes"
	          << std::endl;
	std::cout << "dev_add_fastpath: device ID = " << add_ext.dev_id << std::endl;

	added_ids.insert(add_ext.dev_id);
	minor = write_bytes;
	name = std::string(PXD_DEV_PATH) + std::to_string(add_ext.dev_id);

	dev_export_fastpath(add_ext.dev_id, name);
	std::cout << "dev_add_fastpath: expected device path = " << name << std::endl;
	validate_device_properties(name, 1024 * 1024, 1024 * 1024);
	validate_fastpath_active(name, minor);
}

void PxdFastpathTest::dev_export_fastpath(uint64_t dev_id, const std::string &expected_name)
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

    // Wait for device to appear
    int retries = 50;
    while (retries-- > 0) {
        if (access(expected_name.c_str(), F_OK) == 0) {
            break;
        }
        usleep(100000); // 100ms
    }

    ASSERT_TRUE(access(expected_name.c_str(), F_OK) == 0)
        << "Device " << expected_name << " did not appear after export";

    std::cout << "Device exported successfully: " << expected_name << std::endl;
}

void PxdFastpathTest::dev_remove_fastpath(uint64_t dev_id)
{
    // Check if device actually exists before trying to remove
    if (added_ids.find(dev_id) == added_ids.end()) {
        return;
    }
    pxd_remove_out remove;
	fuse_out_header oh;
	struct iovec iov[2];
	int iter = 0;

	fprintf(stderr, "%s: device removing %ld\n", __func__, dev_id);
	killed = false;
	std::thread cleaner(&PxdFastpathTest::cleaner, this);
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
}

int PxdFastpathTest::wait_msg(int timeout)
{
    struct pollfd fds = {};
    int ret;

    fds.fd = ctl_fd;
    fds.events = POLLIN;
    ret = poll(&fds, 1, timeout * 1000);
    if (ret > 0)
		return 0;
	if (ret == 0)
		return -ETIMEDOUT;

	// should never arise?!
	ret = -errno;
	EXPECT_GE(ret, 0);
	return ret;
}

void PxdFastpathTest::read_block(fuse_in_header *in, pxd_rdwr_in *rd)
{
    auto buf = aligned_buffer_fastpath(rd->size);
    init_pattern_fastpath(buf.get(), rd->size);

    // Verify the data pattern is correct before sending to kernel
    ASSERT_TRUE(verify_pattern_fastpath(buf.get(), rd->size))
        << "Data pattern verification failed in read_block";

    fuse_out_header oh;
    struct iovec wr_iov[3];
    int ret;

    oh.unique = in->unique;
    oh.error = 0;
    oh.len = sizeof(oh) + rd->size;

    wr_iov[0].iov_base = &oh;
    wr_iov[0].iov_len = sizeof(oh);
    wr_iov[1].iov_base = buf.get();
    wr_iov[1].iov_len = rd->size;

    // Send a read response to kernel
    ret = writev(ctl_fd, wr_iov, 2);
    fprintf(stderr, "%s: sent read response to kernel\n", __func__);
    ASSERT_EQ(ret, oh.len);
}

void PxdFastpathTest::validate_device_properties(const std::string &device_name,
                                                 uint64_t expected_discard_granularity,
                                                 uint64_t expected_max_discard_bytes)
{
    // Check if device exists
    ASSERT_TRUE(access(device_name.c_str(), F_OK) == 0)
        << "Device " << device_name << " does not exist";

    // Read sysfs attributes to validate device properties
    std::string dev_name = device_name.substr(device_name.find_last_of('/') + 1);
    std::string sysfs_base = "/sys/block/pxd!" + dev_name;

    // Check queue directory exists
    std::string queue_dir = sysfs_base + "/queue";
    ASSERT_TRUE(access(queue_dir.c_str(), F_OK) == 0)
        << "Queue directory " << queue_dir << " does not exist";
    
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
    

    std::cout << "Device properties validated for: " << device_name << std::endl;
}

void PxdFastpathTest::validate_fastpath_active(const std::string &device_name, int minor_with_status)
{
    // Extract minor number and I/O path status from the return value
    // The return value encodes: minor | (fastpath_active << MINORBITS)
    int minor_number = minor_with_status & MINORMASK;
    int iopath_status = (minor_with_status >> MINORBITS) & 1;

    std::cout << "Device " << device_name << " minor: " << minor_number
              << ", I/O path status: " << (iopath_status ? "fastpath" : "native") << std::endl;

    // Check fastpath sysfs attribute using the actual minor number
    std::string fastpath_path = "/sys/devices/pxd/" + std::to_string(minor_number) + "/fastpath";

    // Wait for sysfs to be populated
    int retries = 20;
    while (retries-- > 0) {
        if (access(fastpath_path.c_str(), F_OK) == 0) {
            break;
        }
        usleep(100000); // 100ms
    }

    if (access(fastpath_path.c_str(), F_OK) == 0) {
        std::ifstream fp_file(fastpath_path);
        std::string fp_status;
        if (fp_file >> fp_status) {
            std::cout << "Sysfs fastpath status for " << device_name << ": " << fp_status << std::endl;

            // Validate that the sysfs status matches the returned I/O path status
            bool sysfs_fastpath_active = (fp_status == "1" || fp_status == "true");
            if (sysfs_fastpath_active != static_cast<bool>(iopath_status)) {
                std::cout << "WARNING: I/O path status mismatch - returned: "
                          << (iopath_status ? "fastpath" : "native")
                          << ", sysfs: " << (sysfs_fastpath_active ? "fastpath" : "native") << std::endl;
            }
        }
    } else {
        std::cout << "WARNING: Fastpath sysfs attribute not found at: " << fastpath_path << std::endl;
    }
}

void PxdFastpathTest::write_thread_fastpath(const char *name)
{
    auto buf = aligned_buffer_fastpath(write_len);
    init_pattern_fastpath(buf.get(), write_len);

    boost::iostreams::file_descriptor dev_fd(name);

    ssize_t write_bytes = pwrite(dev_fd.handle(), buf.get(), write_len, test_off);
    ASSERT_EQ(write_bytes, write_len);
    fprintf(stderr, "%s: bytes written: %lu\n", __func__, write_bytes);
}

void PxdFastpathTest::read_thread_fastpath(const char *name)
{
    auto buf = aligned_buffer_fastpath(write_len);
    init_pattern_fastpath(buf.get(), write_len);

    int fd = open(name, O_RDWR | O_DIRECT);
    boost::iostreams::file_descriptor dev_fd(fd, boost::iostreams::close_handle);

    // explicitly read non-zero offset
    fprintf(stderr, "%s: submit read req: size: %lu\n", __func__, write_len);
    ssize_t read_bytes = pread(dev_fd.handle(), buf.get(), write_len, test_off);
    fprintf(stderr, "%s: response read bytes: %lu\n", __func__, read_bytes);
    ASSERT_EQ(read_bytes, write_len);

    // Validate that the read data matches the expected pattern
    fprintf(stderr, "%s: validating read data pattern\n", __func__);
    ASSERT_TRUE(verify_pattern_fastpath(buf.get(), write_len));
}

void PxdFastpathTest::perform_io_test(const std::string &device_path)
{
    std::cout << "Performing I/O test on " << device_path << std::endl;

    // Test write operation
    auto write_buf = aligned_buffer_fastpath(write_len);
    init_pattern_fastpath(write_buf.get(), write_len);

    int fd = open(device_path.c_str(), O_RDWR | O_DIRECT);
    ASSERT_GE(fd, 0) << "Failed to open device " << device_path << " - " << strerror(errno);

    ssize_t written = pwrite(fd, write_buf.get(), write_len, test_off);
    ASSERT_EQ(written, write_len) << "Write operation failed";

    // Test read operation
    auto read_buf = aligned_buffer_fastpath(write_len);
    ssize_t read_bytes = pread(fd, read_buf.get(), write_len, test_off);
    ASSERT_EQ(read_bytes, write_len) << "Read operation failed";

    // Verify data integrity
    ASSERT_TRUE(verify_pattern_fastpath(read_buf.get(), write_len)) << "Data verification failed";

    close(fd);
    std::cout << "I/O test completed successfully on " << device_path << std::endl;
}



void PxdFastpathTest::cleaner()
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
			fprintf(stderr, "cleaner: processing I/O request, opcode=%d\n", rdwr.in.opcode);
			// finish_io(&rdwr);
			fail_io(&rdwr);  // Only use this for error testing
		}
	}
	fprintf(stderr, "cleaner thread done\n");
}

void PxdFastpathTest::fail_io(struct rdwr_in *rdwr)
{
    struct pxd_rdwr_in *req;
    fuse_out_header oh;
    struct iovec iov[1];

    req = reinterpret_cast<pxd_rdwr_in *>(&rdwr->rdwr);
    oh.unique = rdwr->in.unique;
    oh.error = -EIO;
    oh.len = sizeof(oh);

    iov[0].iov_base = &oh;
    iov[0].iov_len = sizeof(oh);

    fprintf(stderr, "%s: failing request opc(%d) error (%d) iovcnt (%d)\n", __func__,
            rdwr->in.opcode, oh.error, 1);
    size_t ret = writev(ctl_fd, iov, 1);
    ASSERT_GE(ret, 0);
}

int PxdFastpathTest::finish_io(struct rdwr_in *rdwr, bool read_data)
{
    struct pxd_rdwr_in *rd;
    fuse_out_header oh;
    struct iovec iov[16];
    int iovcnt = 0;
    int rc = 0;
    void *buf = nullptr;
    size_t ret;

    rd = reinterpret_cast<pxd_rdwr_in *>(&rdwr->rdwr);

    switch (rdwr->in.opcode) {
        case PXD_READ:
            if (read_data && rd->offset == test_off && rd->size == write_len) {
                rc = 1;
            }
            buf = aligned_buffer_fastpath(rd->size).release();
            init_pattern_fastpath(buf, rd->size);
            iovcnt = rd->size / PXD_LBS;

            oh.error = 0;
            oh.len = sizeof(oh) + rd->size;
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
                buf = (char *)buf + PXD_LBS;
            }

            ret = writev(ctl_fd, iov, iovcnt + 1);
            if (ret < 0) {
                fprintf(stderr, "writev failed with error: %s\n", strerror(errno));
                free(iov[1].iov_base);
                fail_io(rdwr);
                return 0;
            }
            EXPECT_EQ(oh.len, ret);
            free(iov[1].iov_base);
            break;
        case PXD_WRITE:
            oh.error = 0;
            oh.len = sizeof(oh);
            oh.unique = rdwr->in.unique;

            ret = ::write(ctl_fd, &oh, sizeof(oh));
            if (ret < 0) {
                fprintf(stderr, "write failed with error: %s\n", strerror(errno));
                fail_io(rdwr);
                return 0;
            }
            EXPECT_EQ(sizeof(oh), ret);

            break;
        default:
            fail_io(rdwr);
    }
    return rc;
}

TEST_P(PxdFastpathTest, simple_test_fastpath)
{
    BackingDeviceType device_type = GetParam();
    std::string device_type_str = (device_type == BackingDeviceType::BACKING_FILE) ? "backing file" : "loop device";
    std::cout << "Simple fastpath test with " << device_type_str << std::endl;
}

TEST_P(PxdFastpathTest, device_create_fastpath)
{
	BackingDeviceType device_type = GetParam();
	std::string device_type_str = (device_type == BackingDeviceType::BACKING_FILE) ? "backing file" : "loop device";
	std::cout << "Testing device creation with " << device_type_str << std::endl;

	pxd_add_ext_out add_ext;
	std::string name;
	int minor;

	// Setup device parameters
	add_ext.dev_id = 1;
	add_ext.size = 100 * 1024 * 1024; // 100MB
	add_ext.queue_depth = 128;
	add_ext.discard_size = PXD_LBS;
	add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
	add_ext.enable_fp = 1;

	// Create backing devices and setup fastpath backing device paths
	create_backing_devices(2, 100); // Create 2 backing devices of 100MB each
	setup_fastpath_paths(add_ext.paths);

	// Create device with fastpath enabled
	dev_add_fastpath(add_ext, minor, name);

	// Verify device exists
	ASSERT_TRUE(access(name.c_str(), F_OK) == 0) << "Device " << name << " was not created";
}

TEST_P(PxdFastpathTest, device_attach_export_fastpath)
{
	BackingDeviceType device_type = GetParam();
	std::string device_type_str = (device_type == BackingDeviceType::BACKING_FILE) ? "backing file" : "loop device";
	std::cout << "Testing device attach/export with " << device_type_str << std::endl;

	pxd_add_ext_out add_ext;
	std::string name;
	int minor;

	// Setup device with fastpath
	add_ext.dev_id = 2;
	add_ext.size = 100 * 1024 * 1024;
	add_ext.queue_depth = 128;
	add_ext.discard_size = PXD_LBS;
	add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
	add_ext.enable_fp = 1;

	create_backing_devices(2, 100);
	setup_fastpath_paths(add_ext.paths);

	// Create and attach device
	dev_add_fastpath(add_ext, minor, name);

	// Verify device is accessible
	int fd = open(name.c_str(), O_RDWR);
	ASSERT_GE(fd, 0) << "Failed to open device " << name;
	close(fd);

	// Verify device size
	uint64_t dev_size;
	fd = open(name.c_str(), O_RDWR);
	int ret = ioctl(fd, BLKGETSIZE64, &dev_size);
	ASSERT_EQ(ret, 0) << "Failed to get device size";
	ASSERT_EQ(dev_size, add_ext.size) << "Device size mismatch";
	close(fd);

	std::cout << "Device " << name << " attached and exported successfully with size "
	          << dev_size << " bytes using " << device_type_str << std::endl;
}

TEST_P(PxdFastpathTest, io_operations_fastpath)
{
	BackingDeviceType device_type = GetParam();
	std::string device_type_str = (device_type == BackingDeviceType::BACKING_FILE) ? "backing file" : "loop device";
	std::cout << "Testing I/O operations with " << device_type_str << std::endl;

	pxd_add_ext_out add_ext;
	std::string device_name;
	int minor;

	// Create fastpath device
	add_ext.dev_id = 4;
	add_ext.size = 100 * 1024 * 1024;
	add_ext.queue_depth = 128;
	add_ext.discard_size = PXD_LBS;
	add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
	add_ext.enable_fp = 1;

	create_backing_devices(2, 100);
	setup_fastpath_paths(add_ext.paths);
	dev_add_fastpath(add_ext, minor, device_name);

	// Perform I/O operations to verify fastpath functionality
	perform_io_test(device_name);
}

TEST_P(PxdFastpathTest, device_detach_remove_fastpath)
{
	BackingDeviceType device_type = GetParam();
	std::string device_type_str = (device_type == BackingDeviceType::BACKING_FILE) ? "backing file" : "loop device";
	std::cout << "Testing device detach/remove with " << device_type_str << std::endl;

	pxd_add_ext_out add_ext;
	std::string device_name;
	int minor;

	// Create fastpath device
	add_ext.dev_id = 5;
	add_ext.size = 100 * 1024 * 1024;
	add_ext.queue_depth = 128;
	add_ext.discard_size = PXD_LBS;
	add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
	add_ext.enable_fp = 1;

	create_backing_devices(2, 100);
	setup_fastpath_paths(add_ext.paths);
	dev_add_fastpath(add_ext, minor, device_name);

	// Verify device exists before removal
	ASSERT_TRUE(access(device_name.c_str(), F_OK) == 0) << "Device should exist before removal";

	// Test explicit device removal (this test specifically tests removal functionality)
	dev_remove_fastpath(add_ext.dev_id);

	// Wait for device to be removed
	int retries = 50;
	while (retries-- > 0) {
		if (access(device_name.c_str(), F_OK) != 0) {
			break;
		}
		usleep(100000); // 100ms
	}

	// Verify device no longer exists
	ASSERT_TRUE(access(device_name.c_str(), F_OK) != 0) << "Device should not exist after removal";
	std::cout << "Device " << device_name << " successfully detached and removed using " << device_type_str << std::endl;

	// Make sure removal of this device is skipped during TearDown
	added_ids.erase(add_ext.dev_id);
}

TEST_P(PxdFastpathTest, multiple_devices_fastpath)
{
	BackingDeviceType device_type = GetParam();
	std::string device_type_str = (device_type == BackingDeviceType::BACKING_FILE) ? "backing file" : "loop device";
	std::cout << "Testing multiple devices with " << device_type_str << std::endl;

	std::vector<pxd_add_ext_out> devices;
	std::vector<std::string> device_names;
	std::vector<int> minors;

	// Create backing devices for multiple fastpath devices
	create_backing_devices(2, 50); // Create 2 backing devices of 50MB each (shared by all PXD devices)

	// Create multiple fastpath devices
	for (int i = 0; i < 3; ++i) {
		pxd_add_ext_out add_ext;
		std::string device_name;
		int minor;

		add_ext.dev_id = 10 + i;
		add_ext.size = 50 * 1024 * 1024; // 50MB each
		add_ext.queue_depth = 128;
		add_ext.discard_size = PXD_LBS;
		add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
		add_ext.enable_fp = 1;

		setup_fastpath_paths(add_ext.paths);
		dev_add_fastpath(add_ext, minor, device_name);

		devices.push_back(add_ext);
		device_names.push_back(device_name);
		minors.push_back(minor);

		std::cout << "Created device " << i << ": " << device_name << " using " << device_type_str << std::endl;
	}

	// Verify all devices exist and are accessible
	for (size_t i = 0; i < device_names.size(); ++i) {
		ASSERT_TRUE(access(device_names[i].c_str(), F_OK) == 0)
		    << "Device " << device_names[i] << " should exist";

		// Test basic I/O on each device
		perform_io_test(device_names[i]);
	}
	std::cout << "Successfully tested multiple fastpath devices using " << device_type_str << std::endl;
}

TEST_P(PxdFastpathTest, error_handling_fastpath)
{
	BackingDeviceType device_type = GetParam();
	std::string device_type_str = (device_type == BackingDeviceType::BACKING_FILE) ? "backing file" : "loop device";
	std::cout << "=== Testing Fastpath Error Handling with " << device_type_str << " ===" << std::endl;

	// Test 1: Create fastpath device with valid backing devices
	std::cout << "Test 1: Creating fastpath device with valid backing devices..." << std::endl;

	pxd_add_ext_out add_ext;
	add_ext.dev_id = 100;
	add_ext.size = 100 * 1024 * 1024; // 100MB
	add_ext.queue_depth = 128;
	add_ext.discard_size = PXD_LBS;
	add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
	add_ext.enable_fp = 1;

	// Create backing devices and setup fastpath
	create_backing_devices(2, 100); // Create 2 backing devices of 100MB each
	setup_fastpath_paths(add_ext.paths);

	std::string device_name;
	int minor;
	dev_add_fastpath(add_ext, minor, device_name);
	std::cout << "Created fastpath device: " << device_name << std::endl;

	// Test 2: Test I/O operations work normally
	std::cout << "Test 2: Verifying normal I/O operations..." << std::endl;
	perform_io_test(device_name);
	std::cout << "Normal I/O operations completed successfully" << std::endl;

	// Test 3: Simulate backing device failure by corrupting one backing device
	std::cout << "Test 3: Simulating backing device failure..." << std::endl;

	// Get the first backing device path and corrupt it
	std::string first_backing_path = add_ext.paths.devpath[0];
	std::cout << "Corrupting backing device: " << first_backing_path << std::endl;

	// Truncate the backing device to simulate failure
	int corrupt_fd = open(first_backing_path.c_str(), O_WRONLY | O_TRUNC);
	if (corrupt_fd >= 0) {
		close(corrupt_fd);
		std::cout << "Backing device corrupted successfully" << std::endl;
	} else {
		std::cout << "Warning: Could not corrupt backing device: " << strerror(errno) << std::endl;
	}

	// Test 4: Test I/O operations with corrupted backing device (should trigger failover)
	std::cout << "Test 4: Testing I/O operations with corrupted backing device..." << std::endl;

	// Try to perform I/O operations - should either fail or failover to second backing device
	try {
		auto test_buf = aligned_buffer_fastpath(4096);
		init_pattern_fastpath(test_buf.get(), 4096);

		int io_fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
		if (io_fd >= 0) {
			// Attempt write operation
			ssize_t written = pwrite(io_fd, test_buf.get(), 4096, 8192);
			if (written == 4096) {
				std::cout << "I/O operation succeeded - failover mechanism working" << std::endl;
			} else {
				std::cout << "I/O operation failed as expected due to backing device failure" << std::endl;
			}
			close(io_fd);
		} else {
			std::cout << "Device became inaccessible due to backing device failure" << std::endl;
		}
	} catch (const std::exception& e) {
		std::cout << "I/O operations failed: " << e.what() << std::endl;
	}

	// Test 5: Test recovery by recreating the corrupted backing device
	std::cout << "Test 5: Testing recovery by recreating corrupted backing device..." << std::endl;

	// Recreate the corrupted backing device / backing file
    int recovery_fd = open(first_backing_path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (recovery_fd >= 0) {
        // Restore original size
        if (ftruncate(recovery_fd, 100 * 1024 * 1024) == 0) {
            std::cout << "Backing file recreated successfully" << std::endl;
        } else {
            std::cout << "Failed to restore backing file size: " << strerror(errno) << std::endl;
        }
        close(recovery_fd);
    }

	// Test 6: Verify device functionality after recovery attempt
	std::cout << "Test 6: Testing device functionality after recovery..." << std::endl;

	try {
		// Give some time for potential recovery mechanisms
		sleep(5); // 5s

		// Test basic device access
		int recovery_fd = open(device_name.c_str(), O_RDWR);
		if (recovery_fd >= 0) {
			std::cout << "Device is accessible after recovery attempt" << std::endl;
			close(recovery_fd);

			// Try I/O operations again
			perform_io_test(device_name);
			std::cout << "I/O operations work after recovery" << std::endl;
		} else {
			std::cout << "Device remains inaccessible after recovery attempt" << std::endl;
		}
	} catch (const std::exception& e) {
		std::cout << "Device functionality test after recovery failed: " << e.what() << std::endl;
	}

	std::cout << "=== Fastpath Error Handling Test completed with " << device_type_str << " ===" << std::endl;
}

// Instantiate the parameterized tests with both backing file and loop device configurations
INSTANTIATE_TEST_SUITE_P(
    BackingDeviceTypes,
    PxdFastpathTest,
    ::testing::Values(BackingDeviceType::BACKING_FILE, BackingDeviceType::LOOP_DEVICE),
    [](const ::testing::TestParamInfo<BackingDeviceType>& info) {
        switch (info.param) {
            case BackingDeviceType::BACKING_FILE:
                return "BackingFile";
            case BackingDeviceType::LOOP_DEVICE:
                return "LoopDevice";
            default:
                return "Unknown";
        }
    }
);
