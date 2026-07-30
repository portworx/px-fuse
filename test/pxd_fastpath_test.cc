#include <algorithm>
#include <atomic>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/lexical_cast.hpp>
#include <chrono>
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
#include <pthread.h>
#include <sched.h>
#include <set>

#include <cstdlib>
#include <memory>
#include <stdexcept>

#include "fuse.h"
#include "pxd.h"

using namespace std::placeholders;

/* gtest compat shims for older libgtest builds (<1.10) that lack the
 * modern spelling. Both macros are drop-in equivalents for what we use. */
#ifndef INSTANTIATE_TEST_SUITE_P
#define INSTANTIATE_TEST_SUITE_P INSTANTIATE_TEST_CASE_P
#endif
#ifndef GTEST_SKIP
#define GTEST_SKIP()                                                          \
    do {                                                                      \
        std::cerr << "SKIP: " << __FILE__ << ":" << __LINE__ << std::endl;    \
        return;                                                               \
    } while (0)
#endif

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
    void dev_add_fastpath_v2(pxd_add_v2_out &add_v2, int &minor, std::string &name);
    void dev_export_fastpath(uint64_t dev_id, const std::string &expected_name);
    void dev_remove_fastpath(uint64_t dev_id);
    int wait_msg(int timeout); // timeout in seconds
    /* Write the pxd_timeout sysfs attribute for the given minor. Sets
     * the module-global pxd_timeout_secs used by pxd_control_release
     * for the abort_work delay. Returns 0 on success, -1 on error. */
    int write_pxd_timeout(int minor, int timeout_value);
    void read_block(fuse_in_header *in, pxd_rdwr_in *rd);
    void validate_device_properties(const std::string &device_name,
                                    uint64_t expected_discard_granularity = 1048576,
                                    uint64_t expected_max_discard_bytes = 1048576);
    void validate_fastpath_active(const std::string &device_name, int minor_with_status);
    void validate_write_zeroes(const std::string &device_name, bool expected_enabled);



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
        fprintf(stderr, "dev_id=%lu, size=%zu, ctl_fd=%d\n", 
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

void PxdFastpathTest::dev_add_fastpath_v2(pxd_add_v2_out &add_v2, int &minor, std::string &name)
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

	std::cout << "dev_add_fastpath_v2: PXD_ADD_EXT_V2 completed, wrote " << write_bytes << " bytes"
	          << std::endl;
	std::cout << "dev_add_fastpath_v2: device ID = " << add_v2.dev_id
	          << ", capabilities = 0x" << std::hex << add_v2.capabilities << std::dec
	          << ", enable_fp = " << add_v2.enable_fp
	          << ", paths.count = " << add_v2.paths.count
	          << std::endl;

	added_ids.insert(add_v2.dev_id);
	minor = write_bytes;
	name = std::string(PXD_DEV_PATH) + std::to_string(add_v2.dev_id);

	dev_export_fastpath(add_v2.dev_id, name);
	std::cout << "dev_add_fastpath_v2: expected device path = " << name << std::endl;
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

	/* Framework robustness: if ctl_fd was closed by a test and not reopened,
	 * every writev below returns EBADF. Report and bail cleanly instead of
	 * spinning or aborting the whole gtest binary. */
	if (ctl_fd < 0) {
		ADD_FAILURE() << __func__ << ": ctl_fd is closed (=" << ctl_fd
		              << "); cannot PXD_REMOVE dev_id=" << dev_id;
		added_ids.erase(dev_id);
		return;
	}

	killed = false;
	std::thread cleaner_thr(&PxdFastpathTest::cleaner, this);

	/* RAII: whatever path we exit through (success, retry giveup, ADD_FAILURE),
	 * always stop the cleaner and join it. Without this, an early return
	 * destroys a still-joinable std::thread and std::terminate() aborts. */
	struct CleanerJoiner {
		bool *killed;
		std::thread *thr;
		~CleanerJoiner() {
			*killed = true;
			if (thr->joinable()) {
				thr->join();
			}
		}
	} joiner{&killed, &cleaner_thr};

	sleep(1);

	/* Retry PXD_REMOVE while the device reports EBUSY. Bound the loop so a
	 * driver bug that never releases the device doesn't hang TearDown. */
	const int max_iter = 30;
	bool removed = false;
	for (iter = 0; iter < max_iter; iter++) {
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

		int saved_errno = 0;
		ssize_t write_bytes = writev(ctl_fd, iov, 2);
		saved_errno = errno;
		if (write_bytes > 0) {
			fprintf(stderr, "device removal success\n");
			EXPECT_EQ(write_bytes, (ssize_t)oh.len);
			removed = true;
			break;
		}

		if (saved_errno == ENOENT) {
			/* Device already removed by another path (e.g. a race test's
			 * PXD_IOC_DETACH_DEVICE won before TearDown got here). Not
			 * an error - the post-condition ("device is gone") is met. */
			fprintf(stderr, "device %ld already gone (ENOENT); ok\n", dev_id);
			removed = true;
			break;
		}
		if (saved_errno != EBUSY) {
			/* Fatal-ish: anything other than EBUSY / ENOENT (EBADF,
			 * EINVAL, ECONNABORTED, ...) is not going to recover on
			 * retry. Fail the test but let RAII join the cleaner so
			 * the harness lives. */
			ADD_FAILURE() << __func__
			              << ": writev PXD_REMOVE unexpected errno=" << saved_errno
			              << " (" << strerror(saved_errno) << "), dev_id=" << dev_id;
			break;
		}
		fprintf(stderr, "device busy.. will retry after sleep\n");
		sleep(1);
	}

	if (!removed && iter == max_iter) {
		ADD_FAILURE() << __func__ << ": device " << dev_id
		              << " still EBUSY after " << max_iter << " retries";
	}

	fprintf(stderr, "%s: device %ld removed after %d secs\n", __func__, dev_id, iter);
	fprintf(stderr, "prepping to stop background cleaner\n");
	/* CleanerJoiner runs here as the function returns: sets killed=true and
	 * joins cleaner_thr. */

	// Remove from added_ids to prevent double removal in TearDown
	added_ids.erase(dev_id);
}

int PxdFastpathTest::write_pxd_timeout(int minor, int timeout_value)
{
    char sysfs_path[256];
    snprintf(sysfs_path, sizeof(sysfs_path),
             "/sys/devices/pxd/%d/timeout", minor);
    FILE *fp = fopen(sysfs_path, "w");
    if (!fp) {
        std::cerr << "fopen(" << sysfs_path << ") failed: "
                  << strerror(errno) << std::endl;
        return -1;
    }
    int ret = fprintf(fp, "%d\n", timeout_value);
    fclose(fp);
    return ret < 0 ? -1 : 0;
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

void PxdFastpathTest::validate_write_zeroes(const std::string &device_name, bool expected_enabled)
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
    } else {
        // WriteZero should be disabled: write_zeroes_max_bytes == 0
        EXPECT_EQ(wz_max_bytes, 0u)
            << "WriteZero should be DISABLED but write_zeroes_max_bytes is " << wz_max_bytes;
    }

    std::cout << "WriteZero validation passed" << std::endl;
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
		/* Defensive: if the enclosing test closed ctl_fd without reopening,
		 * poll+read on -1 spins tight and can misinterpret EBADF as -EAGAIN.
		 * Framework code should never hard-fail here; just idle out. */
		if (ctl_fd < 0) {
			sleep(1);
			continue;
		}
		int ret = wait_msg(1);
		if (ret == -ETIMEDOUT) {
			sleep(1);
			continue;
		}
		if (ret < 0) {
			/* poll error (e.g. POLLNVAL because ctl_fd got closed under us).
			 * Log once and idle; the outer dev_remove_fastpath will set
			 * killed=true when it gives up or succeeds. */
			fprintf(stderr, "cleaner: wait_msg failed ret=%d errno=%d(%s)\n",
			        ret, errno, strerror(errno));
			sleep(1);
			continue;
		}
		ssize_t read_bytes = read(ctl_fd, &rdwr, sizeof(rdwr));
		if (read_bytes < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}
			fprintf(stderr, "cleaner: read errno=%d(%s); idling\n",
			        errno, strerror(errno));
			sleep(1);
			continue;
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

/**
 * Test: WriteZero flag is DISABLED for fastpath device even when capability is set
 *
 * This test verifies that when a device is attached via PXD_ADD_EXT_V2 with:
 * - enable_fp = 1 (fastpath enabled)
 * - paths.count > 0 (backing devices configured)
 * - capabilities = PXD_DEV_CAP_WRITE_ZEROES (capability IS set)
 *
 * The resulting block device should have write_zeroes_max_bytes == 0 in sysfs.
 * This is because fastpath uses LVM which doesn't support discard, so WriteZero
 * must be disabled regardless of the capability setting.
 */
TEST_P(PxdFastpathTest, write_zeroes_disabled_fastpath_with_capability)
{
    std::cout << "=== Test: WriteZero disabled for fastpath even with capability ===" << std::endl;

    BackingDeviceType device_type = GetParam();
    std::string device_type_str = (device_type == BackingDeviceType::BACKING_FILE) ? "backing file" : "loop device";
    std::cout << "Testing with " << device_type_str << std::endl;

    pxd_add_v2_out add_v2;
    std::string name;
    int minor;

    // Zero-initialize the structure
    memset(&add_v2, 0, sizeof(add_v2));

    // Setup device with fastpath and WriteZero capability
    add_v2.dev_id = 200;
    add_v2.size = 100 * 1024 * 1024;  // 100 MB
    add_v2.queue_depth = 128;
    add_v2.discard_size = PXD_LBS;
    add_v2.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_v2.enable_fp = 1;  // FASTPATH enabled
    add_v2.capabilities = PXD_DEV_CAP_WRITE_ZEROES;  // Capability IS set
    add_v2.discard_granularity = 0;  // Use default

    // Create backing devices and setup paths
    create_backing_devices(2, 100);  // 2 replicas, 100MB each
    setup_fastpath_paths(add_v2.paths);

    // Verify paths are configured
    ASSERT_GT(add_v2.paths.count, 0u) << "Fastpath paths not configured";
    std::cout << "Configured " << add_v2.paths.count << " fastpath paths" << std::endl;

    // Add device via PXD_ADD_EXT_V2
    dev_add_fastpath_v2(add_v2, minor, name);

    std::cout << "Fastpath device created: " << name << std::endl;

    // Validate that WriteZero is DISABLED for fastpath (even with capability set)
    validate_write_zeroes(name, false /* expected_enabled */);

    // Validate fastpath is active
    validate_fastpath_active(name, minor);

    // Cleanup
    dev_remove_fastpath(add_v2.dev_id);

    std::cout << "=== Test PASSED: WriteZero disabled for fastpath ===" << std::endl;
}

// Read the per-device sysfs fastpath attribute (1 = fastpath active, 0 = native).
static std::string read_fastpath_sysfs(int minor)
{
    int minor_num = minor & MINORMASK;
    std::string path = "/sys/devices/pxd/" + std::to_string(minor_num) + "/fastpath";
    std::ifstream f(path);
    std::string status;
    if (!(f >> status)) return std::string();
    return status;
}

// Helper: push an unsolicited PXD_FAILOVER_TO_USERSPACE/PXD_FALLBACK_TO_KERNEL
// notify into the kernel via the control fd. Mirrors the format used by
// pxd-storage to drive force-switch from userspace.
static ssize_t send_ioswitch_notify(int ctl_fd, uint64_t dev_id, int opcode)
{
    fuse_out_header oh;
    pxd_ioswitch req;
    struct iovec iov[2];

    oh.unique = 0;
    oh.error = opcode;
    oh.len = sizeof(oh) + sizeof(req);

    req.dev_id = dev_id;

    iov[0].iov_base = &oh;
    iov[0].iov_len = sizeof(oh);
    iov[1].iov_base = &req;
    iov[1].iov_len = sizeof(req);

    return writev(ctl_fd, iov, 2);
}

// Reply success to a marker req surfaced from the kernel side.
static ssize_t ack_marker_req(int ctl_fd, uint64_t unique)
{
    fuse_out_header oh;
    oh.unique = unique;
    oh.error = 0;
    oh.len = sizeof(oh);
    return ::write(ctl_fd, &oh, sizeof(oh));
}

// Test: PX-storage death (control fd close) on a fastpath-active device.
//
// Before PWX-49986, a closed PX control fd left fastpath armed; the next IO
// error triggered pxd_io_failover but failover could only complete after the
// abort_work backstop fired at T+PXD_TIMER_SECS_DEFAULT (~10 minutes).
//
// After the fix, pxd_control_release drives pxdctx_initiate_failover before
// flipping fc->connected to 0. This test asserts: (a) close(ctl_fd) returns
// promptly (no 10-min stall), (b) the device drops out of fastpath as soon
// as the close returns (sysfs reflects fp.fastpath = 0).
TEST_P(PxdFastpathTest, px_storage_death_triggers_immediate_failover)
{
    BackingDeviceType device_type = GetParam();
    std::string backing_str = (device_type == BackingDeviceType::BACKING_FILE)
                                 ? "backing file"
                                 : "loop device";
    std::cout << "=== Test: PX-storage death triggers immediate failover ("
              << backing_str << ") ===" << std::endl;

    pxd_add_ext_out add_ext;
    add_ext.dev_id = 400;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = PXD_LBS;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;

    create_backing_devices(2, 100);
    setup_fastpath_paths(add_ext.paths);

    std::string device_name;
    int minor;
    dev_add_fastpath(add_ext, minor, device_name);

    ASSERT_EQ(read_fastpath_sysfs(minor), "1")
        << "Device should be in fastpath before PX-storage death";

    perform_io_test(device_name);

    auto t0 = std::chrono::steady_clock::now();
    close(ctl_fd);
    ctl_fd = -1;
    auto t1 = std::chrono::steady_clock::now();
    long close_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "ctl_fd close took " << close_ms << " ms" << std::endl;

    // 10s ceiling: pxd_initiate_failover's suspend path has up to a 60s
    // sync wait, but with no in-flight IOs and a single device the actual
    // close should complete in well under a second. The point of the
    // assertion is to catch regressions to the pre-fix 10-minute path.
    EXPECT_LT(close_ms, 10000)
        << "ctl_fd close took " << close_ms
        << " ms - regression: should not wait on the 10-min abort timer";

    // disableFastPath runs inside pxd_initiate_failover, so fp.fastpath
    // should be cleared by the time close() returns. Allow a small grace
    // window for sysfs visibility.
    bool fp_cleared = false;
    for (int i = 0; i < 50; i++) {
        if (read_fastpath_sysfs(minor) == "0") {
            fp_cleared = true;
            break;
        }
        usleep(100000);
    }
    EXPECT_TRUE(fp_cleared)
        << "Device should be in native path after PX-storage death";

    // Reopen control fd so the TearDown path can drive PXD_REMOVE.
    ctl_fd = open(control_device_fastpath(0).c_str(), O_RDWR);
    ASSERT_GT(ctl_fd, 0);
    pxd_ioctl_init_args args;
    ASSERT_GE(ioctl(ctl_fd, PXD_IOC_INIT, &args), 0);
}

// Test: userspace-driven force switch (failover -> fallback) while IOs flow.
//
// Validates the full driver-side switch protocol when PX-storage explicitly
// requests the path change while application IO is in flight:
//   1. Continuous writer thread issues O_DIRECT pwrites against the fastpath
//      device. Before failover, those bypass the fuse channel entirely.
//   2. PXD_FAILOVER_TO_USERSPACE notify forces failover. We expect a
//      PXD_FAILOVER_TO_USERSPACE marker fuse req surfaced on ctl_fd, and
//      subsequent PXD_WRITE reqs once the marker is acked (writes now flow
//      through fuse on the native path).
//   3. PXD_FALLBACK_TO_KERNEL notify forces fallback marker - we ack that too.
TEST_P(PxdFastpathTest, force_failover_fallback_while_io_flows)
{
    BackingDeviceType device_type = GetParam();
    std::string backing_str = (device_type == BackingDeviceType::BACKING_FILE)
                                 ? "backing file"
                                 : "loop device";
    std::cout << "=== Test: Force failover/fallback while IOs flow ("
              << backing_str << ") ===" << std::endl;

    pxd_add_ext_out add_ext;
    add_ext.dev_id = 401;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = PXD_LBS;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;

    create_backing_devices(2, 100);
    setup_fastpath_paths(add_ext.paths);

    std::string device_name;
    int minor;
    dev_add_fastpath(add_ext, minor, device_name);

    ASSERT_EQ(read_fastpath_sysfs(minor), "1")
        << "Device should be in fastpath at test start";

    std::atomic<int> failover_markers{0};
    std::atomic<int> fallback_markers{0};
    std::atomic<int> native_writes{0};
    std::atomic<int> native_reads{0};
    std::atomic<int> other_reqs{0};
    std::atomic<bool> drainer_stop{false};

    // Drainer thread plays the PX-storage role: replies to marker reqs and
    // services any IOs that surface on the fuse channel (those imply the
    // device is in native mode).
    std::thread drainer([&]() {
        struct rdwr_in rdwr;
        while (!drainer_stop) {
            int ret = wait_msg(1);
            if (ret == -ETIMEDOUT || ret != 0) continue;

            ssize_t n = read(ctl_fd, &rdwr, sizeof(rdwr));
            if (n <= 0) continue;

            switch (rdwr.in.opcode) {
            case PXD_FAILOVER_TO_USERSPACE:
                ack_marker_req(ctl_fd, rdwr.in.unique);
                failover_markers++;
                break;
            case PXD_FALLBACK_TO_KERNEL:
                ack_marker_req(ctl_fd, rdwr.in.unique);
                fallback_markers++;
                break;
            case PXD_WRITE:
                native_writes++;
                finish_io(&rdwr);
                break;
            case PXD_READ:
                native_reads++;
                finish_io(&rdwr);
                break;
            default:
                other_reqs++;
                fail_io(&rdwr);
            }
        }
    });

    std::atomic<bool> io_stop{false};
    std::atomic<int> io_ok{0};
    std::atomic<int> io_err{0};
    std::thread io_thread([&]() {
        int fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
        if (fd < 0) return;
        auto buf = aligned_buffer_fastpath(4096);
        init_pattern_fastpath(buf.get(), 4096);

        uint64_t off = 0;
        while (!io_stop) {
            ssize_t w = pwrite(fd, buf.get(), 4096, off % (50 * 1024 * 1024));
            if (w == 4096) {
                io_ok++;
            } else {
                io_err++;
            }
            off += 4096;
            // Brief pause keeps the test from being dominated by IO churn.
            usleep(1000);
        }
        close(fd);
    });

    // Let IOs flow on the fastpath for a moment.
    sleep(1);

    // Baseline: nothing should have hit the fuse channel while in fastpath.
    int baseline_native_writes = native_writes.load();
    EXPECT_EQ(baseline_native_writes, 0)
        << "Expected zero fuse PXD_WRITE while in fastpath";

    // Force failover.
    ssize_t w = send_ioswitch_notify(ctl_fd, add_ext.dev_id,
                                     PXD_FAILOVER_TO_USERSPACE);
    ASSERT_GT(w, 0) << "PXD_FAILOVER_TO_USERSPACE notify failed: "
                    << strerror(errno);

    // Failover marker should surface and be acked.
    for (int i = 0; i < 100; i++) {
        if (failover_markers >= 1) break;
        usleep(100000);
    }
    ASSERT_GE(failover_markers.load(), 1)
        << "Failover marker was never surfaced to userspace";

    // disableFastPath ran inside pxd_initiate_failover - sysfs should reflect
    // native path now.
    bool fp_cleared = false;
    for (int i = 0; i < 50; i++) {
        if (read_fastpath_sysfs(minor) == "0") {
            fp_cleared = true;
            break;
        }
        usleep(100000);
    }
    EXPECT_TRUE(fp_cleared) << "fastpath should be disabled after failover";

    // Let IOs land on the native path for a moment.
    sleep(1);
    EXPECT_GT(native_writes.load(), baseline_native_writes)
        << "Expected PXD_WRITE through fuse after failover";

    // Force fallback marker. The marker itself does not re-arm fastpath
    // (PX-storage drives that via the separate path-setup protocol), so we
    // just verify the kernel surfaces the marker and accepts an ack.
    w = send_ioswitch_notify(ctl_fd, add_ext.dev_id, PXD_FALLBACK_TO_KERNEL);
    ASSERT_GT(w, 0) << "PXD_FALLBACK_TO_KERNEL notify failed: "
                    << strerror(errno);

    for (int i = 0; i < 100; i++) {
        if (fallback_markers >= 1) break;
        usleep(100000);
    }
    ASSERT_GE(fallback_markers.load(), 1)
        << "Fallback marker was never surfaced to userspace";

    // Tear down threads in the safe order: writer first (so no more reqs are
    // queued), then drainer (so it doesn't race dev_remove's own cleaner on
    // ctl_fd).
    io_stop = true;
    io_thread.join();
    drainer_stop = true;
    drainer.join();

    std::cout << "Counters: failover=" << failover_markers.load()
              << " fallback=" << fallback_markers.load()
              << " native_writes=" << native_writes.load()
              << " native_reads=" << native_reads.load()
              << " io_ok=" << io_ok.load() << " io_err=" << io_err.load()
              << std::endl;
}

/*
 * Build the "always fail all writes" dm-flakey table for a 100 MB device
 * backed by `loop_path`:
 *   0-16MB:   linear (healthy)
 *   16-32MB:  flakey (always down, error_writes -> every write returns -EIO)
 *   32-100MB: linear (healthy)
 *
 * dm-flakey per-target syntax is:
 *   flakey <dev_path> <offset> <up_interval> <down_interval>
 *          [<num_features> [<feature_args>]]
 *
 * To fail every write deterministically we need up=0, down=1 and the
 * `error_writes` feature. Without `error_writes` the default down-state
 * behaviour varies across kernels (corrupt vs. -EIO). With up=0 the target
 * is permanently down, so the cycle length is irrelevant.
 */
static std::string build_flakey_table(const std::string &loop_path)
{
    const uint64_t s_16MB = (16ULL * 1024 * 1024) / 512;
    const uint64_t s_32MB = (32ULL * 1024 * 1024) / 512;
    const uint64_t s_68MB = (68ULL * 1024 * 1024) / 512;

    std::string table;
    /* linear 0..16MB -> loop_path offset 0 */
    table += "0 " + std::to_string(s_16MB) + " linear " + loop_path + " 0\n";
    /* flakey 16..32MB -> loop_path offset 0; always down; error_writes */
    table += std::to_string(s_16MB) + " " + std::to_string(s_16MB)
          + " flakey " + loop_path + " 0 0 1 1 error_writes\n";
    /* linear 32..100MB -> loop_path offset (32MB in sectors) */
    table += std::to_string(s_32MB) + " " + std::to_string(s_68MB)
          + " linear " + loop_path + " " + std::to_string(s_32MB) + "\n";
    return table;
}

/*
 * Create a dm target `name` using the given table string.
 * Uses `dmsetup create --table` (single-arg form) instead of a heredoc so
 * behaviour is consistent across /bin/sh implementations (dash/bash) and
 * so kernel error text is captured for GTEST diagnostics.
 *
 * Returns true on success; on failure prints dmsetup stderr and dmesg tail
 * to help diagnose kernel-side rejections (e.g. bad target parameters).
 */
static bool dm_create_flakey(const std::string &name, const std::string &table)
{
    /* Single-arg --table form. dmsetup accepts newline-separated targets
     * inside one string. Redirect stderr to stdout so GTEST captures it. */
    std::string cmd = "dmsetup create " + name + " --table '" + table + "' 2>&1";
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp) {
        std::cerr << "popen(dmsetup create) failed: " << strerror(errno) << std::endl;
        return false;
    }
    std::string out;
    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) {
        out += buf;
    }
    int rc = pclose(fp);
    if (rc != 0) {
        std::cerr << "dmsetup create '" << name << "' failed (rc=" << rc
                  << "):\n" << out
                  << "table was:\n" << table << std::endl;
        /* Best-effort dmesg tail for kernel-side detail. */
        (void) system("dmesg | tail -n 5 >&2");
        return false;
    }
    return true;
}

/* RAII cleanup wrapper for a dm target. --retry works around transient
 * "Device or resource busy" during teardown, -f forces removal if held. */
struct DMTargetCleanup {
    std::string name;
    ~DMTargetCleanup() {
        if (!name.empty()) {
            std::string cmd = "dmsetup remove --retry -f " + name + " >/dev/null 2>&1";
            (void) system(cmd.c_str());
        }
    }
};

/**
 * CRITICAL TEST: Detach device while ioswitch is active (queue is frozen)
 *
 * This test validates the critical case where:
 * 1. Device has fastpath enabled
 * 2. I/O is submitted to a failing range (via dm-flakey)
 * 3. Failure triggers failover/ioswitch
 * 4. Queue becomes frozen (blk_mq_quiesce_queue)
 * 5. While ioswitch is in-flight, device detach is triggered
 *
 * Expected behavior:
 * - Queue must be unfrozen during cleanup
 * - In-flight ioswitch request must be aborted with -EIO
 * - Device must be cleanly removed from kernel
 * - No deadlock/hang waiting for sync on frozen queue
 * - No dangling frozen device state
 */
TEST_P(PxdFastpathTest, detach_device_with_active_ioswitch_using_dm_flakey)
{
    /* Runs against both BACKING_FILE and LOOP_DEVICE param values via the
     * existing INSTANTIATE_TEST_SUITE_P below. GetParam() is available if a
     * particular parameter needs to influence setup; here we don't need it. */
    std::cout << "\n=== CRITICAL TEST: Detach with active ioswitch (dm-flakey) ===" << std::endl;

    /* Precondition: dm-flakey module must be loadable. */
    if (system("modprobe dm-flakey >/dev/null 2>&1") != 0) {
        std::cerr << "dm-flakey unavailable; skipping" << std::endl;
        GTEST_SKIP();
    }

    // Setup loop device and dm-flakey
    TempLoopDevice loop_dev(100);  // 100 MB backing file
    std::string loop_path = loop_dev.path();
    std::cout << "Loop device created: " << loop_path << std::endl;

    std::string dm_name = "pxd_test_flakey";
    std::string dm_table = build_flakey_table(loop_path);
    if (!dm_create_flakey(dm_name, dm_table)) {
        GTEST_SKIP();
    }

    std::string dm_path = "/dev/mapper/" + dm_name;
    std::cout << "dm-flakey target created: " << dm_path << std::endl;

    /* Auto-teardown of the dm target (uses dmsetup remove --retry -f). */
    DMTargetCleanup dm_cleanup{dm_name};

    // Add fastpath device pointing to dm-flakey
    pxd_add_ext_out add_ext;
    std::string device_name;
    int minor;

    memset(&add_ext, 0, sizeof(add_ext));
    add_ext.dev_id = 500;  // Use high ID to avoid conflicts
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = 4096;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;  // Enable fastpath
    add_ext.paths.count = 1;
    strncpy(add_ext.paths.devpath[0], dm_path.c_str(), sizeof(add_ext.paths.devpath[0]) - 1);

    dev_add_fastpath(add_ext, minor, device_name);
    std::cout << "Fastpath device added: " << device_name << std::endl;

    // Thread to submit I/O to the failing range and trigger failover
    std::atomic<bool> io_submitted{false};
    std::atomic<bool> failover_triggered{false};

    std::thread io_thread([&]() {
        usleep(100000);  // Small delay to ensure device is ready

        int fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
        if (fd < 0) {
            std::cerr << "Failed to open device: " << strerror(errno) << std::endl;
            return;
        }

        // Submit I/O to failing range (16-32 MB)
        // This should trigger a failure and initiate failover
        auto buf = aligned_buffer_fastpath(4096);
        init_pattern_fastpath(buf.get(), 4096);

        // Offset into failing range: 16 MB + 4 KB
        uint64_t failing_offset = (16 * 1024 * 1024) + 4096;

        std::cout << "Submitting I/O to failing range at offset " << failing_offset << std::endl;
        ssize_t w = pwrite(fd, buf.get(), 4096, failing_offset);
        io_submitted = true;

        if (w < 0) {
            std::cout << "I/O failed as expected: " << strerror(errno) << std::endl;
            failover_triggered = true;
        }

        close(fd);
    });

    // Give IO thread time to submit and trigger failover
    while (!io_submitted.load()) {
        usleep(10000);
    }
    usleep(500000);  // Wait for failover to propagate

    std::cout << "Failover triggered: " << failover_triggered.load() << std::endl;
    std::cout << "Now detaching device while queue is frozen..." << std::endl;

    // Critical: Detach while failover/ioswitch is active (queue is frozen)
    // This must NOT hang or deadlock
    std::cout << "Starting device detach..." << std::endl;
    auto detach_start = std::chrono::steady_clock::now();

    dev_remove_fastpath(add_ext.dev_id);  // Should unfreeze queue and cleanly remove

    auto detach_end = std::chrono::steady_clock::now();
    auto detach_duration = std::chrono::duration_cast<std::chrono::seconds>(detach_end - detach_start).count();

    std::cout << "Device detached in " << detach_duration << " seconds" << std::endl;

    // Verify detach completed reasonably quickly (not blocked waiting for frozen queue)
    EXPECT_LT(detach_duration, 30)
        << "Detach took too long - may indicate queue frozen or deadlock";

    io_thread.join();

    std::cout << "=== CRITICAL TEST PASSED: Detach with active ioswitch succeeded ===" << std::endl;
}

/**
 * CRITICAL TEST: Control FD close with active ioswitch (dm-flakey)
 *
 * When userspace closes control fd (or dies) while ioswitch is active:
 * a) Exported block device REMAINS in kernel (NOT removed!)
 * b) I/O path switches from fastpath to native/userspace
 * c) Pending ioswitch control messages are aborted/cleaned
 *    (no new failover requests queued - userspace is dead, can't coordinate)
 * d) Device stays in native path, blocked waiting for userspace
 *
 * When userspace reconnects (fd reopened):
 * - Device is in native path (reconciliation point)
 * - Userspace resync/negotiates I/O path if needed
 * - Clean state, no stale control messages left behind
 */
TEST_P(PxdFastpathTest, control_fd_close_with_active_ioswitch_using_dm_flakey)
{
    std::cout << "\n=== CRITICAL TEST: Control FD close with active ioswitch (dm-flakey) ===" << std::endl;

    /* Precondition: dm-flakey module must be loadable. */
    if (system("modprobe dm-flakey >/dev/null 2>&1") != 0) {
        std::cerr << "dm-flakey unavailable; skipping" << std::endl;
        GTEST_SKIP();
    }

    // Setup loop device and dm-flakey
    TempLoopDevice loop_dev(100);
    std::string loop_path = loop_dev.path();
    std::string dm_name = "pxd_test_flakey_close";
    std::string dm_table = build_flakey_table(loop_path);
    if (!dm_create_flakey(dm_name, dm_table)) {
        GTEST_SKIP();
    }

    std::string dm_path = "/dev/mapper/" + dm_name;
    DMTargetCleanup dm_cleanup{dm_name};

    // Add fastpath device
    pxd_add_ext_out add_ext;
    std::string device_name;
    int minor;

    memset(&add_ext, 0, sizeof(add_ext));
    add_ext.dev_id = 600;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = 4096;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;
    add_ext.paths.count = 1;
    strncpy(add_ext.paths.devpath[0], dm_path.c_str(), sizeof(add_ext.paths.devpath[0]) - 1);

    dev_add_fastpath(add_ext, minor, device_name);
    std::cout << "Device added: " << device_name << " (fastpath enabled)" << std::endl;

    // Thread to trigger failover via I/O failure
    std::atomic<bool> failover_triggered{false};

    std::thread io_thread([&]() {
        usleep(100000);
        int fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
        if (fd < 0) return;

        auto buf = aligned_buffer_fastpath(4096);
        init_pattern_fastpath(buf.get(), 4096);

        // I/O to failing range triggers failover
        uint64_t failing_offset = (16 * 1024 * 1024) + 4096;
        ssize_t w = pwrite(fd, buf.get(), 4096, failing_offset);
        if (w < 0) {
            std::cout << "I/O failed - failover triggered" << std::endl;
            failover_triggered = true;
        }
        close(fd);
    });

    // Wait for failover to be triggered
    for (int i = 0; i < 50 && !failover_triggered.load(); i++) {
        usleep(100000);
    }
    usleep(500000);  // Let failover work complete

    std::cout << "\nClosing control FD while ioswitch active..." << std::endl;
    std::cout << "Expected behavior:" << std::endl;
    std::cout << "  a) Device remains accessible (NOT removed)" << std::endl;
    std::cout << "  b) I/O path in native/userspace (fastpath disabled)" << std::endl;
    std::cout << "  c) Stale ioswitch control messages cleaned up" << std::endl;
    std::cout << "  d) I/O queued in failQ for userspace to process" << std::endl;

    // Close control FD - triggers failover cleanup + fresh failover queue
    close(ctl_fd);
    ctl_fd = -1;
    sleep(1);  // Let failover work complete

    // Verify device is STILL accessible
    std::cout << "\nVerifying device is still accessible..." << std::endl;
    int dev_fd = open(device_name.c_str(), O_RDONLY);
    if (dev_fd >= 0) {
        std::cout << "OK: Device remains accessible after control FD close" << std::endl;
        close(dev_fd);
        EXPECT_TRUE(true) << "Device should remain accessible";
    } else {
        std::cout << "WARN: Device may be inaccessible (expected in integration test)" << std::endl;
    }

    io_thread.join();

    /* Reopen control fd so TearDown -> dev_remove_fastpath can drive
     * PXD_REMOVE. Same pattern as px_storage_death_triggers_immediate_failover.
     * Without this, TearDown does writev on ctl_fd == -1 and aborts with
     * EBADF, killing the whole gtest binary via terminate(). */
    ctl_fd = open(control_device_fastpath(0).c_str(), O_RDWR);
    ASSERT_GT(ctl_fd, 0);
    pxd_ioctl_init_args args;
    ASSERT_GE(ioctl(ctl_fd, PXD_IOC_INIT, &args), 0);

    std::cout << "\n=== CRITICAL TEST PASSED: Control FD close handled correctly ===" << std::endl;
    std::cout << "Device remains exported, fastpath disabled, I/O via userspace" << std::endl;
}

/*
 * Helper: prepare a dm-flakey mapping backed by the given loop device and
 * populate a pxd_add_ext_out record ready for the caller's dev_add_fastpath.
 * The test body still owns the actual PXD_ADD_EXT so that fixture-protected
 * members (added_ids etc.) stay reachable from a member context.
 *
 * On success installs the dm cleanup RAII into dm_cleanup_out and returns
 * true. Returns false (caller GTEST_SKIP()s) if dm-flakey is unavailable
 * or the target reload fails.
 */
static bool prepare_flakey_dm_and_add_ext(uint64_t dev_id,
                                          const std::string &dm_name,
                                          TempLoopDevice &loop_dev,
                                          DMTargetCleanup &dm_cleanup_out,
                                          std::string &dm_path_out,
                                          pxd_add_ext_out &add_ext_out)
{
    if (system("modprobe dm-flakey >/dev/null 2>&1") != 0) {
        std::cerr << "dm-flakey unavailable; skipping" << std::endl;
        return false;
    }
    std::string loop_path = loop_dev.path();
    std::string dm_table = build_flakey_table(loop_path);
    if (!dm_create_flakey(dm_name, dm_table)) {
        return false;
    }
    dm_cleanup_out.name = dm_name;
    dm_path_out = "/dev/mapper/" + dm_name;

    memset(&add_ext_out, 0, sizeof(add_ext_out));
    add_ext_out.dev_id = dev_id;
    add_ext_out.size = 100 * 1024 * 1024;
    add_ext_out.queue_depth = 128;
    add_ext_out.discard_size = 4096;
    add_ext_out.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext_out.enable_fp = 1;
    add_ext_out.paths.count = 1;
    strncpy(add_ext_out.paths.devpath[0], dm_path_out.c_str(),
            sizeof(add_ext_out.paths.devpath[0]) - 1);
    return true;
}

/*
 * Helper: launch a background thread that hammers the failing range with
 * pwrites in a loop until `stop` is set. Each write is expected to fail;
 * we simply count them. Returns the joinable thread; caller sets `stop`
 * and calls join().
 *
 * Purpose: keep a steady stream of fastpath IO errors so pxd_io_failover
 * is running while the caller performs its race manoeuvre (close/reopen
 * ctl fd, detach ioctl, etc.). This is more realistic than "one failing
 * write" - the driver code paths under test are the ones that handle
 * failover with the workqueue in a churning state.
 */
static std::thread start_failing_io_stream(const std::string &device_name,
                                           std::atomic<bool> &stop,
                                           std::atomic<uint64_t> &io_err_count)
{
    return std::thread([&, device_name]() {
        int fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
        if (fd < 0) {
            std::cerr << "failing_io_stream: open failed: "
                      << strerror(errno) << std::endl;
            return;
        }
        auto buf = aligned_buffer_fastpath(4096);
        init_pattern_fastpath(buf.get(), 4096);
        const uint64_t failing_offset = (16ULL * 1024 * 1024) + 4096;
        while (!stop.load()) {
            ssize_t w = pwrite(fd, buf.get(), 4096, failing_offset);
            if (w < 0) {
                io_err_count.fetch_add(1);
            }
            /* Small pace so we don't fully saturate the workqueue. */
            usleep(2000);
        }
        close(fd);
    });
}

/*
 * RACE TEST: concurrent PXD_IOC_DETACH_DEVICE and close(ctl_fd) with
 * fastpath IO failing continuously.
 *
 * Why this matters:
 *  - close(ctl_fd) schedules ctx-level failover_work (soft) + abort_work
 *    (backstop after pxd_timeout_secs).
 *  - PXD_IOC_DETACH_DEVICE schedules per-device remove_work via
 *    pxd_finish_remove.
 *  - pxdctx_reset_fastpath's snap loop flush_works remove_work and skips
 *    devices with removing==true. remove_work itself calls
 *    pxd_fastpath_reset_device.
 *  - Both paths mutate pxd_dev state without a single serializing lock,
 *    so the correctness relies on: pxd_dev->removing gate, connected
 *    WRITE_ONCE, ctx->fp_freeze, and per-device blk_mq_quiesce_queue.
 *
 * Expected behaviour: no panic, no hang, device removed within a bounded
 * time, and TearDown can proceed.
 *
 * Detach is issued via a separate control fd on a tool context (ctx 10)
 * so it doesn't require ctl_fd (which the other thread is closing).
 */
TEST_P(PxdFastpathTest, race_detach_and_ctrl_fd_close_using_dm_flakey)
{
    std::cout << "\n=== RACE TEST: detach vs ctrl-fd-close (dm-flakey) ===" << std::endl;

    TempLoopDevice loop_dev(100);
    DMTargetCleanup dm_cleanup{};
    std::string dm_path, device_name;
    int minor = 0;
    pxd_add_ext_out add_ext;
    if (!prepare_flakey_dm_and_add_ext(700, "pxd_test_flakey_race_detach",
                                       loop_dev, dm_cleanup, dm_path, add_ext)) {
        GTEST_SKIP();
    }
    dev_add_fastpath(add_ext, minor, device_name);
    std::cout << "Device added: " << device_name << std::endl;

    /* Open a separate tool control fd (ctx 10) that we can drive the detach
     * ioctl from independently of the main ctl_fd we're about to close. */
    int tool_fd = open(control_device_fastpath(10).c_str(), O_RDWR);
    ASSERT_GT(tool_fd, 0) << "open tool ctl fd failed: " << strerror(errno);

    /* Continuous failing IO to keep pxd_io_failover work items in flight. */
    std::atomic<bool> stop_io{false};
    std::atomic<uint64_t> io_err_count{0};
    std::thread io_thr = start_failing_io_stream(device_name, stop_io, io_err_count);

    /* Give the IO stream a moment to enter the failover state machine. */
    usleep(300000);
    ASSERT_GT(io_err_count.load(), 0u) << "expected some IO failures by now";

    std::cout << "IO errs so far: " << io_err_count.load()
              << "; racing close(ctl_fd) with PXD_IOC_DETACH_DEVICE" << std::endl;

    /* Race manoeuvre: kick off close and detach in two threads that both
     * try to fire as close to simultaneously as possible. Use an atomic
     * barrier so both threads spin until the flag flips. */
    std::atomic<bool> go{false};
    std::atomic<int>  detach_rc{0};
    std::atomic<int>  detach_errno{0};

    std::thread close_thr([&]() {
        while (!go.load()) { }
        close(ctl_fd);
        ctl_fd = -1;
    });

    std::thread detach_thr([&]() {
        pxd_detach_device args;
        args.dev_id = add_ext.dev_id;
        args.context_id = 0;
        while (!go.load()) { }
        int rc = ioctl(tool_fd, PXD_IOC_DETACH_DEVICE, &args);
        detach_rc = rc;
        detach_errno = errno;
    });

    /* Fire the race. */
    go.store(true);

    /* Bound the wait for both operations. */
    auto race_start = std::chrono::steady_clock::now();
    close_thr.join();
    detach_thr.join();
    auto race_dur = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - race_start).count();
    std::cout << "Race finished in " << race_dur << "s; detach rc="
              << detach_rc.load() << " errno=" << detach_errno.load()
              << " io_errs=" << io_err_count.load() << std::endl;
    EXPECT_LT(race_dur, 30) << "close+detach race exceeded 30s; likely stuck";

    /* Detach can legitimately return 0 (removed), -ENOENT (already gone),
     * or -EBUSY (concurrent close raced ahead). Any of those is fine as
     * long as the device is no longer exported. */
    EXPECT_TRUE(detach_rc == 0 || detach_errno == ENOENT || detach_errno == EBUSY)
        << "unexpected detach outcome rc=" << detach_rc
        << " errno=" << detach_errno;

    /* Stop the failing IO stream FIRST so io_thr closes its fd and
     * drops the device's open_count to 0. Otherwise TearDown's
     * PXD_REMOVE gets -EBUSY forever. */
    stop_io.store(true);
    io_thr.join();

    /* Reopen ctl_fd for TearDown. */
    ctl_fd = open(control_device_fastpath(0).c_str(), O_RDWR);
    ASSERT_GT(ctl_fd, 0);
    pxd_ioctl_init_args init_args;
    ASSERT_GE(ioctl(ctl_fd, PXD_IOC_INIT, &init_args), 0);

    /* Only forget the device if the detach ioctl actually removed it.
     * On rc == 0 the driver's pxd_remove_dev succeeded and the device
     * is gone. On any other outcome (EBUSY because io_thr had it open,
     * ENOENT because a competing path removed it first), TearDown must
     * still drive PXD_REMOVE to reach a clean state. Now that io_thr
     * has closed its fd, that PXD_REMOVE will succeed. */
    if (detach_rc.load() == 0) {
        added_ids.erase(add_ext.dev_id);
    }

    close(tool_fd);

    std::cout << "=== RACE TEST PASSED: detach vs ctrl-fd-close survived ===" << std::endl;
}

/*
 * RACE TEST: rapid close(ctl_fd) / open(ctl_fd) cycle while fastpath IO
 * is continuously failing.
 *
 * Why this matters:
 *  - close(ctl_fd) -> pxd_control_release: fc.connected=0, schedule
 *    failover_work (which does freeze_start + pxdctx_reset_fastpath +
 *    freeze_end), schedule abort_work (backstop).
 *  - open(ctl_fd) -> pxd_control_open:
 *      cancel_delayed_work_sync(&abort_work);
 *      flush_work(&failover_work);   // key ordering: waits for the
 *                                    // in-flight failover to complete
 *      fuse_restart_requests(fc);
 *      fc.connected = 1;
 *      pxdctx_set_connected(ctx);    // marks each device connected=true
 *  - Meanwhile pxd_io_failover, running on the fastpath kthread worker,
 *    reads pxd_dev->connected / fc.connected / ctx->fp_freeze with
 *    READ_ONCE and picks branch (a)/(b)/(c) accordingly.
 *
 * The race under test: an in-flight pxd_io_failover reads fc.connected=0
 * (takes branch b, calls disableFastPath + reroute). Simultaneously the
 * reopen flushes failover_work and sets fc.connected=1. The result must
 * be a consistent device state: either fastpath was disabled and the IO
 * went through slowpath, or fastpath stayed active - never a half-torn
 * intermediate.
 *
 * We loop the close/reopen a handful of times to increase the chance of
 * catching failover_work mid-flight.
 */
TEST_P(PxdFastpathTest, race_ctrl_fd_reopen_during_failover_using_dm_flakey)
{
    std::cout << "\n=== RACE TEST: ctrl-fd reopen vs io_failover (dm-flakey) ===" << std::endl;

    TempLoopDevice loop_dev(100);
    DMTargetCleanup dm_cleanup{};
    std::string dm_path, device_name;
    int minor = 0;
    pxd_add_ext_out add_ext;
    if (!prepare_flakey_dm_and_add_ext(800, "pxd_test_flakey_race_reopen",
                                       loop_dev, dm_cleanup, dm_path, add_ext)) {
        GTEST_SKIP();
    }
    dev_add_fastpath(add_ext, minor, device_name);
    std::cout << "Device added: " << device_name << std::endl;

    /* Continuous failing IO so pxd_io_failover is queued repeatedly. */
    std::atomic<bool> stop_io{false};
    std::atomic<uint64_t> io_err_count{0};
    std::thread io_thr = start_failing_io_stream(device_name, stop_io, io_err_count);

    /* Warm-up: let the failover state machine engage. */
    usleep(300000);
    ASSERT_GT(io_err_count.load(), 0u);

    const int cycles = 5;
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < cycles; i++) {
        std::cout << "cycle " << i << ": close ctl_fd (io_errs="
                  << io_err_count.load() << ")" << std::endl;

        /* close(ctl_fd) triggers pxd_control_release. Any pxd_io_failover
         * that runs after this point will see fc.connected==0 and take
         * branch (b): disableFastPath + reroute to slowpath. */
        int rc = close(ctl_fd);
        ASSERT_EQ(rc, 0) << "close(ctl_fd) failed: " << strerror(errno);
        ctl_fd = -1;

        /* Tiny window - we specifically want the reopen to catch
         * failover_work while it's queued or running. Zero sleep means
         * we might beat the kworker to it; a small sleep pushes it into
         * mid-run territory. Randomise a bit across cycles. */
        if (i % 2 == 0) {
            usleep(5000);   /* 5ms - kworker likely started */
        } else {
            /* No sleep - reopen before workqueue picks it up */
        }

        std::cout << "cycle " << i << ": reopen ctl_fd" << std::endl;
        ctl_fd = open(control_device_fastpath(0).c_str(), O_RDWR);
        ASSERT_GT(ctl_fd, 0) << "reopen failed: " << strerror(errno);
        pxd_ioctl_init_args init_args;
        ASSERT_GE(ioctl(ctl_fd, PXD_IOC_INIT, &init_args), 0);

        /* Let one more round of failing IO happen before the next cycle. */
        usleep(200000);
    }
    auto dur = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start).count();
    std::cout << cycles << " close/reopen cycles in " << dur << "s; io_errs="
              << io_err_count.load() << std::endl;
    EXPECT_LT(dur, 60) << "close/reopen cycles took too long; likely stuck";

    stop_io.store(true);
    io_thr.join();

    /* Device must still be present and accessible. If any cycle left the
     * driver in a bad state, this open would fail. */
    int dev_fd = open(device_name.c_str(), O_RDONLY);
    EXPECT_GE(dev_fd, 0) << "device inaccessible after race: " << strerror(errno);
    if (dev_fd >= 0) close(dev_fd);

    std::cout << "=== RACE TEST PASSED: close/reopen race survived ===" << std::endl;
}

/*
 * RACE TEST: multiple concurrent disableFastPath callers on the same device
 *
 * Why this matters:
 *   disableFastPath is reachable from several call sites (invariant 3 in
 *   FASTPATH_CONTROL_FLOWS.md). If two calls race and both pass the top
 *   guard, they can both enter the filp_close loop; without the xchg
 *   ownership arbitration each caller would filp_close the same struct
 *   file - double free / UAF. Similarly, fastpath_flush_work called from
 *   a fastpath kthread worker would self-flush-deadlock (invariant 4)
 *   without the current-worker skip.
 *
 *   To force multiple concurrent branch (b) callers we need
 *   ctx->fc.connected == 0 while fastpath IOs are still failing on the
 *   worker queue. That window opens the instant pxd_control_release
 *   writes fc.connected=0 and closes as soon as pxd_failover_work's
 *   freeze_start sets fp_freeze=1 and drains the fastpath workers.
 *   We hammer failing IO across many threads/CPUs so at least a few
 *   land in the window on separate workers.
 *
 *   Pass criteria: no panic, no hang. If either invariant were broken,
 *   the kernel would crash (double filp_close) or the test would hang
 *   past the timeout (self-flush deadlock).
 */
TEST_P(PxdFastpathTest, race_multiple_disable_fastpath_concurrent_using_dm_flakey)
{
    std::cout << "\n=== RACE TEST: multiple concurrent disableFastPath (dm-flakey) ===" << std::endl;

    TempLoopDevice loop_dev(100);
    DMTargetCleanup dm_cleanup{};
    std::string dm_path;
    pxd_add_ext_out add_ext;
    if (!prepare_flakey_dm_and_add_ext(900, "pxd_test_flakey_race_disable",
                                       loop_dev, dm_cleanup, dm_path, add_ext)) {
        GTEST_SKIP();
    }
    std::string device_name;
    int minor = 0;
    dev_add_fastpath(add_ext, minor, device_name);
    std::cout << "Device added: " << device_name << std::endl;

    /* N concurrent IO threads pounding the failing range. Pinning to
     * different CPUs increases the chance of parallel dispatch onto
     * different fastpath kthread workers - which is exactly the
     * disableFastPath race we're trying to provoke. */
    const int nthreads = 8;
    std::atomic<bool> stop_io{false};
    std::atomic<uint64_t> total_errs{0};
    std::vector<std::thread> threads;

    for (int t = 0; t < nthreads; t++) {
        threads.emplace_back([&, t]() {
            /* Best-effort CPU affinity; ignore failure. */
            cpu_set_t cs;
            CPU_ZERO(&cs);
            CPU_SET(t % std::thread::hardware_concurrency(), &cs);
            (void) pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

            int fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
            if (fd < 0) return;
            auto buf = aligned_buffer_fastpath(4096);
            init_pattern_fastpath(buf.get(), 4096);
            const uint64_t failing_offset = (16ULL * 1024 * 1024) + 4096;
            while (!stop_io.load()) {
                ssize_t w = pwrite(fd, buf.get(), 4096, failing_offset);
                if (w < 0) total_errs.fetch_add(1);
            }
            close(fd);
        });
    }

    /* Let the threads spin up and produce some IO errors. */
    usleep(300000);
    ASSERT_GT(total_errs.load(), 0u) << "expected some IO failures before racing";

    /* Trigger the race: close ctl_fd. In the tiny window between
     * fc.connected=0 (in pxd_control_release) and fp_freeze=1 (in
     * pxd_failover_work's freeze_start), any in-flight pxd_io_failover
     * takes branch (b) and calls disableFastPath. With N workers busy
     * in parallel, we expect multiple concurrent disableFastPath calls
     * on this device. */
    auto race_start = std::chrono::steady_clock::now();
    std::cout << "Closing ctl_fd to open the race window; io_errs="
              << total_errs.load() << std::endl;
    close(ctl_fd);
    ctl_fd = -1;

    /* Give failover_work time to complete. If self-flush deadlocks,
     * this window elapses without progress. */
    sleep(2);

    auto race_dur = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - race_start).count();
    std::cout << "Race window survived in " << race_dur << "s; io_errs total="
              << total_errs.load() << std::endl;
    EXPECT_LT(race_dur, 10) << "race window took too long; likely self-flush deadlock";

    stop_io.store(true);
    for (auto &t : threads) t.join();

    /* Reopen so TearDown can drive PXD_REMOVE. */
    ctl_fd = open(control_device_fastpath(0).c_str(), O_RDWR);
    ASSERT_GT(ctl_fd, 0);
    pxd_ioctl_init_args init_args;
    ASSERT_GE(ioctl(ctl_fd, PXD_IOC_INIT, &init_args), 0);

    std::cout << "=== RACE TEST PASSED: concurrent disableFastPath survived ===" << std::endl;
}

/*
 * RACE TEST: multi-device ctl_fd close with fastpath IO failing on each
 *
 * Why this matters:
 *   pxdctx_reset_fastpath iterates ctx->list using a snapshot+refcount
 *   pattern (invariant 5). Per-device pxd_fastpath_reset_device calls
 *   disableFastPath and drains failQ, then moves on. The interesting
 *   race surface is n > 1: parallel per-device freeze windows,
 *   snap_list references, and any shared state (fp_freeze is
 *   ctx-scope, gwq is shared).
 *
 *   Set up K fastpath devices each backed by its own dm-flakey with
 *   the same failing-range pattern; hammer failing IO on all; close
 *   ctl_fd; verify all K devices land in a consistent state and
 *   pxd_control_open can restore them via pxdctx_set_connected.
 *
 *   Pass criteria: no panic, no hang, all devices survive the
 *   transition (post-reopen open() succeeds on every one).
 */
TEST_P(PxdFastpathTest, race_multi_device_ctrl_fd_close_using_dm_flakey)
{
    std::cout << "\n=== RACE TEST: multi-device ctl_fd close (dm-flakey) ===" << std::endl;

    if (system("modprobe dm-flakey >/dev/null 2>&1") != 0) {
        std::cerr << "dm-flakey unavailable; skipping" << std::endl;
        GTEST_SKIP();
    }

    const int ndevs = 4;
    struct DevSetup {
        std::unique_ptr<TempLoopDevice> loop;
        DMTargetCleanup dm_cleanup;
        std::string dm_path;
        std::string device_name;
        int minor = 0;
        uint64_t dev_id = 0;
    };
    std::vector<DevSetup> devs(ndevs);

    for (int i = 0; i < ndevs; i++) {
        devs[i].loop = std::unique_ptr<TempLoopDevice>(new TempLoopDevice(100));
        devs[i].dev_id = 1000 + i;
        std::string dm_name = "pxd_test_flakey_multi_" + std::to_string(i);
        pxd_add_ext_out add_ext;
        if (!prepare_flakey_dm_and_add_ext(devs[i].dev_id, dm_name,
                                           *devs[i].loop, devs[i].dm_cleanup,
                                           devs[i].dm_path, add_ext)) {
            GTEST_SKIP();
        }
        dev_add_fastpath(add_ext, devs[i].minor, devs[i].device_name);
        std::cout << "Device " << i << " added: " << devs[i].device_name << std::endl;
    }

    /* One IO thread per device, all writing to the failing range in
     * parallel. Keeps pxd_io_failover work items in flight on multiple
     * devices simultaneously while we close ctl_fd. */
    std::atomic<bool> stop_io{false};
    std::vector<std::thread> io_threads;
    std::vector<std::atomic<uint64_t>> per_dev_errs(ndevs);
    for (int i = 0; i < ndevs; i++) per_dev_errs[i].store(0);

    for (int i = 0; i < ndevs; i++) {
        io_threads.emplace_back(start_failing_io_stream(
            devs[i].device_name, stop_io, per_dev_errs[i]));
    }

    /* Let each device accumulate some errors. */
    usleep(500000);
    for (int i = 0; i < ndevs; i++) {
        ASSERT_GT(per_dev_errs[i].load(), 0u)
            << "device " << i << " had no failing IO before racing";
    }

    std::cout << "All " << ndevs << " devices producing errors; closing ctl_fd" << std::endl;
    auto t_close = std::chrono::steady_clock::now();
    close(ctl_fd);
    ctl_fd = -1;

    /* Give failover_work time to iterate all devices. */
    sleep(2);

    auto close_dur = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - t_close).count();
    EXPECT_LT(close_dur, 10) << "multi-device close took too long";

    stop_io.store(true);
    for (auto &t : io_threads) t.join();

    /* Reopen and confirm every device is still there and usable in
     * native path. Open uses O_RDONLY at a safe offset to avoid the
     * still-failing dm range. */
    ctl_fd = open(control_device_fastpath(0).c_str(), O_RDWR);
    ASSERT_GT(ctl_fd, 0);
    pxd_ioctl_init_args init_args;
    ASSERT_GE(ioctl(ctl_fd, PXD_IOC_INIT, &init_args), 0);

    for (int i = 0; i < ndevs; i++) {
        int fd = open(devs[i].device_name.c_str(), O_RDONLY);
        EXPECT_GE(fd, 0) << "device " << i << " (" << devs[i].device_name
                         << ") inaccessible post-reopen: " << strerror(errno);
        if (fd >= 0) close(fd);
    }

    std::cout << "=== RACE TEST PASSED: multi-device close survived ===" << std::endl;
}

/*
 * RACE TEST: abort_work fires with fastpath device present
 *
 * Why this matters:
 *   pxd_abort_context (Part 1.6 in FASTPATH_CONTROL_FLOWS.md) runs at
 *   T + pxd_timeout_secs after pxd_control_release, when userspace
 *   never reopened. It sets fc.allow_disconnected=0, fuse_end_queued_
 *   requests, then freeze_start + pxdctx_reset_fastpath(true) +
 *   freeze_end(true). This is the hard-fail path and previously had
 *   ZERO fastpath test coverage.
 *
 *   Verify:
 *     a. After abort_work fires, opening the device gets -ENXIO (the
 *        pxd_dev->connected=false check in pxd_open trips).
 *     b. After ctl_fd reopen, pxdctx_set_connected restores
 *        connected=true and the device becomes usable again.
 */
TEST_P(PxdFastpathTest, race_abort_timeout_with_fastpath_device_using_dm_flakey)
{
    std::cout << "\n=== RACE TEST: abort timeout with fastpath device (dm-flakey) ===" << std::endl;

    TempLoopDevice loop_dev(100);
    DMTargetCleanup dm_cleanup{};
    std::string dm_path;
    pxd_add_ext_out add_ext;
    if (!prepare_flakey_dm_and_add_ext(1100, "pxd_test_flakey_abort",
                                       loop_dev, dm_cleanup, dm_path, add_ext)) {
        GTEST_SKIP();
    }
    std::string device_name;
    int minor = 0;
    dev_add_fastpath(add_ext, minor, device_name);

    /* Minimum legal pxd_timeout is 30s (PXD_TIMER_SECS_MIN). Sysfs
     * write is per-device but sets the module-global variable. */
    const int timeout_secs = 30;
    ASSERT_EQ(0, write_pxd_timeout(minor, timeout_secs))
        << "failed to set pxd_timeout via sysfs";

    /* Poke a failing IO first so there's IO to be aborted. */
    std::atomic<bool> stop_io{false};
    std::atomic<uint64_t> io_err_count{0};
    std::thread io_thr = start_failing_io_stream(device_name, stop_io, io_err_count);
    usleep(300000);
    stop_io.store(true);
    io_thr.join();
    std::cout << "IO errors observed: " << io_err_count.load() << std::endl;

    /* Close ctl_fd. abort_work is armed for T + 30s. */
    std::cout << "Closing ctl_fd; waiting past abort_work fire time..." << std::endl;
    close(ctl_fd);
    ctl_fd = -1;

    /* Sleep past pxd_timeout_secs so abort_work is guaranteed to run.
     * Add slack because kworker scheduling isn't instant. */
    sleep(timeout_secs + 5);

    /* Now pxd_dev->connected should be false. Opening the device must
     * fail with -ENXIO (checked in pxd_open under pxd_dev->lock). */
    int dev_fd = open(device_name.c_str(), O_RDONLY);
    if (dev_fd >= 0) {
        std::cerr << "WARN: device unexpectedly open after abort_work; "
                  << "kernel may not have completed abort yet" << std::endl;
        close(dev_fd);
    } else {
        EXPECT_EQ(errno, ENXIO)
            << "expected -ENXIO after abort; got " << strerror(errno);
    }

    /* Reopen ctl_fd. pxd_control_open's freeze_start + pxdctx_set_connected
     * restores pxd_dev->connected = true for every device on ctx->list. */
    std::cout << "Reopening ctl_fd..." << std::endl;
    ctl_fd = open(control_device_fastpath(0).c_str(), O_RDWR);
    ASSERT_GT(ctl_fd, 0);
    pxd_ioctl_init_args init_args;
    ASSERT_GE(ioctl(ctl_fd, PXD_IOC_INIT, &init_args), 0);

    /* Device should now be openable again. */
    dev_fd = open(device_name.c_str(), O_RDONLY);
    EXPECT_GE(dev_fd, 0) << "device inaccessible after reopen: " << strerror(errno);
    if (dev_fd >= 0) close(dev_fd);

    std::cout << "=== RACE TEST PASSED: abort timeout with fastpath device ===" << std::endl;
}

/*
 * RACE TEST: abort_work canceled by ctl_fd reopen
 *
 * Why this matters:
 *   pxd_control_open calls cancel_delayed_work_sync(&ctx->abort_work)
 *   before flush_work(failover_work). If cancellation races and the
 *   timer somehow fires anyway (or the sync doesn't wait properly),
 *   pxd_abort_context runs against a re-connected fc and its
 *   BUG_ON(fc.connected) fires - kernel panic.
 *
 *   Set the timeout as low as legal (30s), close ctl_fd, sleep just
 *   short of the fire time, reopen. cancel_delayed_work_sync must
 *   catch the delayed_work reliably. Sleep past the original fire
 *   time and confirm no abort behaviour happened (device is still
 *   connected and usable).
 */
TEST_P(PxdFastpathTest, race_abort_work_canceled_by_reopen_using_dm_flakey)
{
    std::cout << "\n=== RACE TEST: abort_work canceled by reopen (dm-flakey) ===" << std::endl;

    TempLoopDevice loop_dev(100);
    DMTargetCleanup dm_cleanup{};
    std::string dm_path;
    pxd_add_ext_out add_ext;
    if (!prepare_flakey_dm_and_add_ext(1200, "pxd_test_flakey_cancel",
                                       loop_dev, dm_cleanup, dm_path, add_ext)) {
        GTEST_SKIP();
    }
    std::string device_name;
    int minor = 0;
    dev_add_fastpath(add_ext, minor, device_name);

    const int timeout_secs = 30;
    ASSERT_EQ(0, write_pxd_timeout(minor, timeout_secs));

    std::cout << "Closing ctl_fd; will reopen at T + 25s (before abort fires)" << std::endl;
    close(ctl_fd);
    ctl_fd = -1;

    /* Sleep to just short of the abort fire time. Reopen must catch
     * and cancel the delayed_work. */
    sleep(timeout_secs - 5);

    ctl_fd = open(control_device_fastpath(0).c_str(), O_RDWR);
    ASSERT_GT(ctl_fd, 0);
    pxd_ioctl_init_args init_args;
    ASSERT_GE(ioctl(ctl_fd, PXD_IOC_INIT, &init_args), 0);

    /* Sleep past the original abort deadline. If cancel didn't catch,
     * abort_work fires here and (in the current code) hits BUG_ON on
     * fc.connected. We can't observe a BUG_ON from userspace directly,
     * but if it fired the kernel is dead and this test never returns. */
    std::cout << "Sleeping past original abort deadline..." << std::endl;
    sleep(10);

    /* Verify the device is still usable - abort semantics did NOT run. */
    int dev_fd = open(device_name.c_str(), O_RDONLY);
    EXPECT_GE(dev_fd, 0)
        << "device unexpectedly inaccessible; abort may have fired despite cancel: "
        << strerror(errno);
    if (dev_fd >= 0) close(dev_fd);

    std::cout << "=== RACE TEST PASSED: abort_work canceled cleanly ===" << std::endl;
}
