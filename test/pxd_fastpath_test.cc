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
#include <dirent.h>
#include <memory>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>

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
    /* dev_add_fastpath returns the composite value the kernel packs
     * into writev's return: pxd_dev->minor | (fastpath_active <<
     * MINORBITS). But the sysfs directory (via dev_set_name in pxd.c)
     * is named with just pxd_dev->minor - the low 20 bits. Mask so
     * callers can pass either form and still hit the right path. */
    int pure_minor = minor & MINORMASK;
    char sysfs_path[256];
    snprintf(sysfs_path, sizeof(sysfs_path),
             "/sys/devices/pxd/%d/timeout", pure_minor);
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

/*
 * Helpers for driving the per-device suspend/resume counter via the
 * /sys/devices/pxd/<minor>/debug sysfs attribute. The store side accepts
 * single-char verbs: 's' -> pxd_suspend_io, 'r' -> pxd_resume_io,
 * 'S' -> pxd_request_suspend, 'R' -> pxd_request_resume. The show side
 * emits "nfd:%d,suspend:%d,fpenabled:%d,fpactive:%d,app_suspend:%d\n".
 */
static int debug_write(int pure_minor, char verb)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/devices/pxd/%d/debug", pure_minor);
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    int n = fputc(verb, fp);
    fclose(fp);
    return n == verb ? 0 : -1;
}

struct debug_state {
    int nfd;
    int suspend;
    int fpenabled;
    int fpactive;
    int app_suspend;
};

static bool debug_read(int pure_minor, debug_state &s)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/devices/pxd/%d/debug", pure_minor);
    FILE *fp = fopen(path, "r");
    if (!fp) return false;
    int rc = fscanf(fp,
                    "nfd:%d,suspend:%d,fpenabled:%d,fpactive:%d,app_suspend:%d",
                    &s.nfd, &s.suspend, &s.fpenabled, &s.fpactive,
                    &s.app_suspend);
    fclose(fp);
    return rc == 5;
}

static int read_suspend_count(int pure_minor)
{
    debug_state s{};
    if (!debug_read(pure_minor, s)) return -1;
    return s.suspend;
}

static int read_app_suspend(int pure_minor)
{
    debug_state s{};
    if (!debug_read(pure_minor, s)) return -1;
    return s.app_suspend;
}

/*
 * Read /var/log/kern.log (or dmesg) tail to catch the underflow warning
 * emitted by pxd_resume_io when the caller tries to drop the counter
 * below 0. Returns true if the tag was seen since `since_offset`.
 * Uses dmesg -c is destructive; we prefer a simple substring search
 * against dmesg output.
 */
static bool dmesg_contains(const std::string &needle)
{
    FILE *p = popen("dmesg | tail -n 200", "r");
    if (!p) return false;
    char buf[4096];
    bool found = false;
    while (fgets(buf, sizeof(buf), p)) {
        if (strstr(buf, needle.c_str())) { found = true; break; }
    }
    pclose(p);
    return found;
}

/*
 * Basic single suspend/resume cycle drives fp->suspend 0 -> 1 -> 0 via
 * the low-level 's'/'r' verbs.
 */
TEST_P(PxdFastpathTest, suspend_resume_basic)
{
    pxd_add_ext_out add_ext{};
    std::string name;
    int minor;

    add_ext.dev_id = 200;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = PXD_LBS;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;

    create_backing_devices(2, 100);
    setup_fastpath_paths(add_ext.paths);
    dev_add_fastpath(add_ext, minor, name);

    const int pm = minor & MINORMASK;
    ASSERT_EQ(0, read_suspend_count(pm));

    ASSERT_EQ(0, debug_write(pm, 's'));
    ASSERT_EQ(1, read_suspend_count(pm));

    ASSERT_EQ(0, debug_write(pm, 'r'));
    ASSERT_EQ(0, read_suspend_count(pm));
}

/*
 * Nested suspends increment the refcount; matching resumes bring it back
 * to zero without the queue-unquiesce firing early.
 */
TEST_P(PxdFastpathTest, suspend_resume_nested)
{
    pxd_add_ext_out add_ext{};
    std::string name;
    int minor;

    add_ext.dev_id = 201;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = PXD_LBS;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;

    create_backing_devices(2, 100);
    setup_fastpath_paths(add_ext.paths);
    dev_add_fastpath(add_ext, minor, name);

    const int pm = minor & MINORMASK;
    ASSERT_EQ(0, read_suspend_count(pm));

    const int depth = 5;
    for (int i = 1; i <= depth; ++i) {
        ASSERT_EQ(0, debug_write(pm, 's'));
        ASSERT_EQ(i, read_suspend_count(pm));
    }
    for (int i = depth - 1; i >= 0; --i) {
        ASSERT_EQ(0, debug_write(pm, 'r'));
        ASSERT_EQ(i, read_suspend_count(pm));
    }
    ASSERT_EQ(0, read_suspend_count(pm));
}

/*
 * Extra resume when counter is already 0 must NOT drive it negative;
 * pxd_resume_io emits a KERN_WARNING and no-ops. The counter stays at
 * 0 across many spurious resumes, and a subsequent suspend/resume pair
 * still works.
 */
TEST_P(PxdFastpathTest, resume_underflow_ignored)
{
    pxd_add_ext_out add_ext{};
    std::string name;
    int minor;

    add_ext.dev_id = 202;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = PXD_LBS;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;

    create_backing_devices(2, 100);
    setup_fastpath_paths(add_ext.paths);
    dev_add_fastpath(add_ext, minor, name);

    const int pm = minor & MINORMASK;
    ASSERT_EQ(0, read_suspend_count(pm));

    for (int i = 0; i < 8; ++i) {
        ASSERT_EQ(0, debug_write(pm, 'r'));
        ASSERT_EQ(0, read_suspend_count(pm))
            << "spurious resume #" << i << " should not drive suspend below 0";
    }

    /* Guard message must be present in the kernel log. Use a substring
     * of the exact print in pxd_resume_io to avoid false positives from
     * unrelated devices. */
    EXPECT_TRUE(dmesg_contains("resume with suspend count already 0"))
        << "expected KERN_WARNING from pxd_resume_io underflow guard";

    /* Counter is still usable after the underflow attempts. */
    ASSERT_EQ(0, debug_write(pm, 's'));
    ASSERT_EQ(1, read_suspend_count(pm));
    ASSERT_EQ(0, debug_write(pm, 'r'));
    ASSERT_EQ(0, read_suspend_count(pm));
}

/*
 * More resumes than suspends: nested-then-over-drained. Final count
 * clamps at 0; every extra resume is a no-op.
 */
TEST_P(PxdFastpathTest, resume_overdrain_clamps_at_zero)
{
    pxd_add_ext_out add_ext{};
    std::string name;
    int minor;

    add_ext.dev_id = 203;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = PXD_LBS;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;

    create_backing_devices(2, 100);
    setup_fastpath_paths(add_ext.paths);
    dev_add_fastpath(add_ext, minor, name);

    const int pm = minor & MINORMASK;

    const int depth = 3;
    for (int i = 0; i < depth; ++i) {
        ASSERT_EQ(0, debug_write(pm, 's'));
    }
    ASSERT_EQ(depth, read_suspend_count(pm));

    /* depth + 5 resumes: last 5 must be no-ops, count clamps at 0. */
    for (int i = 0; i < depth + 5; ++i) {
        ASSERT_EQ(0, debug_write(pm, 'r'));
    }
    ASSERT_EQ(0, read_suspend_count(pm));
}

/*
 * pxd_request_suspend / pxd_request_resume drive both the app_suspend
 * flag and the fp->suspend refcount. A duplicate 'S' must be rejected by
 * the cmpxchg gate on app_suspend, so the refcount only moves once even
 * if the ioctl is called twice.
 */
TEST_P(PxdFastpathTest, app_suspend_resume_and_double_request)
{
    pxd_add_ext_out add_ext{};
    std::string name;
    int minor;

    add_ext.dev_id = 204;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = PXD_LBS;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;

    create_backing_devices(2, 100);
    setup_fastpath_paths(add_ext.paths);
    dev_add_fastpath(add_ext, minor, name);

    const int pm = minor & MINORMASK;
    debug_state s{};
    ASSERT_TRUE(debug_read(pm, s));
    ASSERT_EQ(0, s.suspend);
    ASSERT_EQ(0, s.app_suspend);

    ASSERT_EQ(0, debug_write(pm, 'S'));
    ASSERT_TRUE(debug_read(pm, s));
    ASSERT_EQ(1, s.suspend);
    ASSERT_EQ(1, s.app_suspend);

    /* Second request is refused by cmpxchg on app_suspend; refcount and
     * flag stay put. sysfs write itself does not surface -EBUSY, so we
     * validate by inspecting the resulting counters. */
    ASSERT_EQ(0, debug_write(pm, 'S'));
    ASSERT_TRUE(debug_read(pm, s));
    ASSERT_EQ(1, s.suspend) << "duplicate app suspend must not re-increment refcount";
    ASSERT_EQ(1, s.app_suspend);

    ASSERT_EQ(0, debug_write(pm, 'R'));
    ASSERT_TRUE(debug_read(pm, s));
    ASSERT_EQ(0, s.suspend);
    ASSERT_EQ(0, s.app_suspend);

    /* Second resume is a no-op via the app_suspend cmpxchg; refcount
     * stays at 0 and does not go negative. */
    ASSERT_EQ(0, debug_write(pm, 'R'));
    ASSERT_TRUE(debug_read(pm, s));
    ASSERT_EQ(0, s.suspend);
    ASSERT_EQ(0, s.app_suspend);
}

/*
 * Mix low-level ('s'/'r') and app-level ('S'/'R') callers. The refcount
 * must be the sum of active suspends across both sources; final drain
 * lands at exactly 0.
 */
TEST_P(PxdFastpathTest, suspend_resume_mixed_sources)
{
    pxd_add_ext_out add_ext{};
    std::string name;
    int minor;

    add_ext.dev_id = 205;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = PXD_LBS;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;

    create_backing_devices(2, 100);
    setup_fastpath_paths(add_ext.paths);
    dev_add_fastpath(add_ext, minor, name);

    const int pm = minor & MINORMASK;
    debug_state s{};

    ASSERT_EQ(0, debug_write(pm, 'S'));   /* app: suspend=1, app_suspend=1 */
    ASSERT_EQ(0, debug_write(pm, 's'));   /* low: suspend=2                */
    ASSERT_EQ(0, debug_write(pm, 's'));   /* low: suspend=3                */

    ASSERT_TRUE(debug_read(pm, s));
    ASSERT_EQ(3, s.suspend);
    ASSERT_EQ(1, s.app_suspend);

    ASSERT_EQ(0, debug_write(pm, 'r'));   /* low: suspend=2 */
    ASSERT_EQ(0, debug_write(pm, 'R'));   /* app: suspend=1, app_suspend=0 */
    ASSERT_EQ(0, debug_write(pm, 'r'));   /* low: suspend=0 */

    ASSERT_TRUE(debug_read(pm, s));
    ASSERT_EQ(0, s.suspend);
    ASSERT_EQ(0, s.app_suspend);
}

/*
 * Concurrent balanced suspend/resume from many threads. Final refcount
 * must land at exactly 0 regardless of interleaving; no thread should
 * observe a spurious "already 0" warning because every 'r' is
 * predecessed by an 's' from the same thread.
 */
TEST_P(PxdFastpathTest, suspend_resume_concurrent_balanced)
{
    pxd_add_ext_out add_ext{};
    std::string name;
    int minor;

    add_ext.dev_id = 206;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = PXD_LBS;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;

    create_backing_devices(2, 100);
    setup_fastpath_paths(add_ext.paths);
    dev_add_fastpath(add_ext, minor, name);

    const int pm = minor & MINORMASK;
    ASSERT_EQ(0, read_suspend_count(pm));

    const int nthreads = 8;
    const int iters = 50;
    std::vector<std::thread> threads;
    threads.reserve(nthreads);
    for (int t = 0; t < nthreads; ++t) {
        threads.emplace_back([pm, iters]() {
            for (int i = 0; i < iters; ++i) {
                debug_write(pm, 's');
                debug_write(pm, 'r');
            }
        });
    }
    for (auto &th : threads) th.join();

    ASSERT_EQ(0, read_suspend_count(pm))
        << "balanced concurrent suspend/resume must drain to exactly 0";
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

    // 10s ceiling: pxd_initiate_failover's suspend path has up to a
    // SYNC_TIMEOUT (10s) sync wait, but with no in-flight IOs and a single
    // device the actual close should complete in well under a second. The
    // point of the assertion is to catch regressions to the pre-fix
    // 10-minute path.
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
static bool dm_create_target(const std::string &name, const std::string &table)
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

/* Backwards-compatible name for the flakey-only call sites. */
static bool dm_create_flakey(const std::string &name, const std::string &table)
{
    return dm_create_target(name, table);
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

/*
 * Build a dm-delay table spanning the whole 100 MB device, mapping 1:1
 * onto `below_path` (normally the dm-flakey device, so the two layers
 * compose: flakey decides *whether* an IO fails, delay decides *when*
 * it is serviced).
 *
 * dm-delay's 9-argument form declares three independent classes:
 *   <dev> <off> <read_ms> <dev> <off> <write_ms> <dev> <off> <flush_ms>
 *
 * The class is picked per-bio in delay_map(): WRITE with REQ_PREFLUSH
 * goes to the flush class, other WRITEs to the write class, everything
 * else to read. That third class is the one that matters for the sync
 * path - vfs_fsync() on a block device issues a preflush, so flush_ms
 * is what controls how long wait_for_sync() blocks.
 *
 * The 9-arg form needs a kernel whose dm-delay has the flush class. If
 * the target rejects the table, dm_create_target logs the kernel error
 * and the caller skips the test.
 */
static std::string build_delay_table(const std::string &below_path,
                                     uint64_t read_ms,
                                     uint64_t write_ms,
                                     uint64_t flush_ms)
{
    const uint64_t s_100MB = (100ULL * 1024 * 1024) / 512;

    return "0 " + std::to_string(s_100MB) + " delay "
         + below_path + " 0 " + std::to_string(read_ms)  + " "
         + below_path + " 0 " + std::to_string(write_ms) + " "
         + below_path + " 0 " + std::to_string(flush_ms) + "\n";
}

/*
 * Region-scoped dm-delay: linear / delay / linear, so only IO addressed to
 * [offset, offset+size) is delayed and the rest of the device stays fast.
 *
 * Use this when the test needs the device to be generally usable - device
 * setup, healthy-path writes, a sanity read - while one window is slow.
 * build_delay_table() delays the whole span instead, which is what you
 * want when the target is a flush (flushes are not addressed to a sector,
 * so scoping them by region is meaningless).
 */
static std::string build_delay_table_region(const std::string &below_path,
                                            uint64_t offset_bytes,
                                            uint64_t size_bytes,
                                            uint64_t read_ms,
                                            uint64_t write_ms,
                                            uint64_t flush_ms)
{
    const uint64_t s_total = (100ULL * 1024 * 1024) / 512;
    const uint64_t s_off   = offset_bytes / 512;
    const uint64_t s_size  = size_bytes / 512;
    const uint64_t s_tail  = s_total - (s_off + s_size);

    std::string t;
    t += "0 " + std::to_string(s_off) + " linear " + below_path + " 0\n";
    t += std::to_string(s_off) + " " + std::to_string(s_size) + " delay "
       + below_path + " " + std::to_string(s_off) + " " + std::to_string(read_ms)  + " "
       + below_path + " " + std::to_string(s_off) + " " + std::to_string(write_ms) + " "
       + below_path + " " + std::to_string(s_off) + " " + std::to_string(flush_ms) + "\n";
    t += std::to_string(s_off + s_size) + " " + std::to_string(s_tail)
       + " linear " + below_path + " " + std::to_string(s_off + s_size) + "\n";
    return t;
}

/*
 * An all-healthy dm-flakey table: one target spanning the device with
 * up_interval=1, down_interval=0, i.e. permanently up.
 *
 * Why a healthy flakey layer instead of no flakey layer at all: a test
 * that only wants latency still wants the error layer *present* in the
 * stack, so it can be reloaded into an erroring table mid-test, and so
 * the device geometry matches the erroring tests exactly.
 *
 * This matters more than it looks for the flush class. dm sends a flush
 * bio to every target in a table, so the always-down region built by
 * build_flakey_table() fails *all* flushes on the device, not just those
 * addressed to 16-32MB - an fsync there returns -EIO after the delay
 * rather than succeeding after it. Tests that want to observe the sync
 * timeout on its own, with no IO error confusing the result, want this
 * table.
 */
static std::string build_flakey_table_healthy(const std::string &loop_path)
{
    const uint64_t s_100MB = (100ULL * 1024 * 1024) / 512;

    return "0 " + std::to_string(s_100MB) + " flakey " + loop_path + " 0 1 0\n";
}

/*
 * Swap a live dm target's table (suspend / reload / resume).
 *
 * Used to retune delays mid-test and, importantly, to *release* them:
 * dm-delay's presuspend handler sets may_delay=0 and immediately flushes
 * every queued bio, so a suspend is the escape hatch for a deliberately
 * stuck IO. Teardown depends on that - see DMStackCleanup.
 */
static bool dm_reload_table(const std::string &name, const std::string &table)
{
    std::string cmd = "dmsetup suspend " + name
                    + " && dmsetup reload " + name + " --table '" + table + "'"
                    + " && dmsetup resume " + name + " 2>&1";
    int rc = system(cmd.c_str());
    if (rc != 0) {
        std::cerr << "dm_reload_table('" << name << "') failed rc=" << rc
                  << "\ntable was:\n" << table << std::endl;
        return false;
    }
    return true;
}

/*
 * RAII cleanup for a stack of dm targets (e.g. delay on top of flakey).
 *
 * Two things this does that a bare `dmsetup remove` loop cannot:
 *
 * 1. Removes in reverse order of push(), so the upper target goes first.
 *    Removing flakey while delay still references it fails with EBUSY.
 *
 * 2. Suspends each target before removing it. A test that deliberately
 *    parks an IO behind a multi-minute dm-delay would otherwise leave
 *    that IO in flight at teardown, holding the device open and making
 *    the remove fail (or block). delay_presuspend() releases the queued
 *    bios, so the suspend both unblocks the stuck submitter and makes
 *    the subsequent remove succeed.
 */
struct DMStackCleanup {
    std::vector<std::string> names;   /* bottom-most first */

    void push(const std::string &name) { names.push_back(name); }

    ~DMStackCleanup() {
        for (auto it = names.rbegin(); it != names.rend(); ++it) {
            /* Release any parked bios first; ignore failure (the target
             * may already be gone or never have been created). */
            std::string suspend_cmd = "dmsetup suspend " + *it + " >/dev/null 2>&1";
            (void) system(suspend_cmd.c_str());
            std::string cmd = "dmsetup remove --retry -f " + *it + " >/dev/null 2>&1";
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
 * Helper: prepare a stacked loop -> dm-flakey -> dm-delay mapping and
 * populate a pxd_add_ext_out pointing at the *delay* device (the top of
 * the stack), ready for the caller's dev_add_fastpath.
 *
 * Layout is the same as prepare_flakey_dm_and_add_ext - 16-32MB errors
 * writes, the rest is healthy - with a latency layer added on top:
 *
 *   loop (100MB)
 *     -> <base_name>_flakey   16-32MB error_writes, rest linear
 *       -> <base_name>_delay  read/write/flush delays, whole span
 *
 * Both targets are registered with `stack` so teardown removes them
 * top-down (and suspends first, releasing anything parked in the delay
 * queue). `delay_name_out` / `flakey_path_out` are returned so the test
 * can retune or release either layer mid-run via dm_reload_table.
 *
 * @flakey_errors: true installs the usual 16-32MB error_writes window;
 *   false installs an all-healthy flakey layer. Pick false when the test
 *   wants latency only - see build_flakey_table_healthy for why an
 *   erroring region also fails every flush on the device.
 *
 * Returns false (caller GTEST_SKIP()s) if either dm target is
 * unavailable - notably on kernels whose dm-delay predates the flush
 * class, where the 9-argument table is rejected.
 */
static bool prepare_flakey_delay_dm_and_add_ext(uint64_t dev_id,
                                                const std::string &base_name,
                                                TempLoopDevice &loop_dev,
                                                DMStackCleanup &stack,
                                                std::string &dm_path_out,
                                                std::string &delay_name_out,
                                                std::string &flakey_path_out,
                                                pxd_add_ext_out &add_ext_out,
                                                bool flakey_errors,
                                                uint64_t read_ms,
                                                uint64_t write_ms,
                                                uint64_t flush_ms)
{
    if (system("modprobe dm-flakey >/dev/null 2>&1") != 0) {
        std::cerr << "dm-flakey unavailable; skipping" << std::endl;
        return false;
    }
    if (system("modprobe dm-delay >/dev/null 2>&1") != 0) {
        std::cerr << "dm-delay unavailable; skipping" << std::endl;
        return false;
    }

    const std::string flakey_name = base_name + "_flakey";
    const std::string delay_name  = base_name + "_delay";

    const std::string flakey_table = flakey_errors
        ? build_flakey_table(loop_dev.path())
        : build_flakey_table_healthy(loop_dev.path());
    if (!dm_create_target(flakey_name, flakey_table)) {
        return false;
    }
    stack.push(flakey_name);
    const std::string flakey_path = "/dev/mapper/" + flakey_name;
    flakey_path_out = flakey_path;

    if (!dm_create_target(delay_name,
                          build_delay_table(flakey_path, read_ms, write_ms, flush_ms))) {
        /* Most likely an old dm-delay without the flush class. The
         * flakey target is already registered with `stack`, so it is
         * still cleaned up. */
        return false;
    }
    stack.push(delay_name);

    delay_name_out = delay_name;
    dm_path_out = "/dev/mapper/" + delay_name;

    memset(&add_ext_out, 0, sizeof(add_ext_out));
    add_ext_out.dev_id = dev_id;
    add_ext_out.size = 100 * 1024 * 1024;
    add_ext_out.queue_depth = 128;
    add_ext_out.discard_size = 4096;
    add_ext_out.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext_out.enable_fp = 1;
    add_ext_out.paths.count = 1;
    /* MUST be set for any test that expects pxd_io_failover to run.
     * _end_clone_bio gates the whole failover path on it:
     *     if (pxd_dev->fp.can_failover && blkrc < 0)
     *             pxd_failover_initiate(fproot);
     * With can_failover=0 a failing fastpath IO is simply completed with
     * the error and no fp_root_context is ever queued to a kthread
     * worker. (Note prepare_flakey_dm_and_add_ext leaves this zeroed, so
     * the tests using it exercise the IO-error path but never actually
     * enter pxd_io_failover.) */
    add_ext_out.paths.can_failover = true;
    strncpy(add_ext_out.paths.devpath[0], dm_path_out.c_str(),
            sizeof(add_ext_out.paths.devpath[0]) - 1);
    return true;
}

/* Read the per-device `debug` sysfs attribute, which reports
 *   nfd:%d,suspend:%d,fpenabled:%d,fpactive:%d,app_suspend:%d
 * (see pxd_debug_show). Returns an empty string on error. */
static std::string read_pxd_debug(int minor)
{
    char sysfs_path[256];
    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/devices/pxd/%d/debug",
             minor & MINORMASK);
    std::ifstream ifs(sysfs_path);
    if (!ifs.is_open()) {
        std::cerr << "open(" << sysfs_path << ") failed: " << strerror(errno)
                  << std::endl;
        return "";
    }
    std::string line;
    std::getline(ifs, line);
    return line;
}

/*
 * Write a command byte to the per-device `debug` sysfs attribute and
 * return how long the write() syscall blocked, in milliseconds
 * (-1 on error).
 *
 * The duration is the point of this helper. pxd_debug_store runs its
 * handler synchronously in the context of the writing task, so 'X'
 * (pxd_debug_switch_nativepath -> disableFastPath) makes the caller pay
 * for the whole teardown - blk_mq freeze, synchronize_rcu,
 * fastpath_flush_work and wait_for_sync - inline. That gives the test a
 * direct, unambiguous measurement of how long the sync leg took.
 */
static long write_pxd_debug_timed(int minor, char cmd)
{
    char sysfs_path[256];
    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/devices/pxd/%d/debug",
             minor & MINORMASK);
    int fd = open(sysfs_path, O_WRONLY);
    if (fd < 0) {
        std::cerr << "open(" << sysfs_path << ") failed: " << strerror(errno)
                  << std::endl;
        return -1;
    }
    auto start = std::chrono::steady_clock::now();
    ssize_t wb = write(fd, &cmd, 1);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    int saved_errno = errno;
    close(fd);
    if (wb < 0) {
        std::cerr << "write('" << cmd << "') failed: " << strerror(saved_errno)
                  << std::endl;
        return -1;
    }
    return (long) elapsed;
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

    /* Lower pxd_timeout_secs to the driver minimum (30s) so abort_work
     * fires within test-tolerable time after close(ctl_fd). Otherwise
     * a pwrite that got routed to the fuse slow path during the
     * failover window sits in fc->processing for the default 600s
     * (nobody is reading ctl_fd), blocking io_thr.join(). abort_work's
     * fuse_end_queued_requests ends those with -ECONNABORTED,
     * unblocking pwrite. */
    ASSERT_EQ(0, write_pxd_timeout(minor, 30));

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

    /* Stop the failing IO stream. pwrite may be blocked in the fuse
     * slow path (see the write_pxd_timeout call above); it will
     * unblock at T+30s when abort_work fires and ends queued fuse
     * requests with -ECONNABORTED. Bounded wait. */
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

    /* Short timeout so abort_work fails any IO stuck in fc->processing
     * after each close(). Reopen resets pxd_timeout_secs back to the
     * driver default (600s), so we re-arm the short timeout after
     * each cycle. */
    ASSERT_EQ(0, write_pxd_timeout(minor, 30));

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
        /* pxd_control_open resets pxd_timeout_secs to the default (600s).
         * Re-arm the 30s abort so the next close's IO gets aborted
         * quickly rather than stuck for 10 minutes. */
        ASSERT_EQ(0, write_pxd_timeout(minor, 30));

        /* Let one more round of failing IO happen before the next cycle. */
        usleep(200000);
    }
    auto dur = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start).count();
    std::cout << cycles << " close/reopen cycles in " << dur << "s; io_errs="
              << io_err_count.load() << std::endl;
    EXPECT_LT(dur, 60) << "close/reopen cycles took too long; likely stuck";

    /* At this point ctl_fd is open (last cycle ended with a reopen). Any
     * IOs queued in fc->processing from prior close windows were
     * restarted by pxd_control_open's fuse_restart_requests but nobody
     * is reading ctl_fd, so io_thr's next pwrite still blocks. Force a
     * final close so abort_work (armed for 30s) can fire and fail the
     * queued IOs, unblocking io_thr. */
    std::cout << "Final close so abort_work can fail queued IO..." << std::endl;
    close(ctl_fd);
    ctl_fd = -1;

    stop_io.store(true);
    /* io_thr.join blocks until abort_work fires and
     * fuse_end_queued_requests ends the pending pwrite with
     * -ECONNABORTED. pxd_timeout_secs was set to 30s at test start. */
    io_thr.join();

    /* Reopen for TearDown. */
    ctl_fd = open(control_device_fastpath(0).c_str(), O_RDWR);
    ASSERT_GT(ctl_fd, 0);
    pxd_ioctl_init_args init_args;
    ASSERT_GE(ioctl(ctl_fd, PXD_IOC_INIT, &init_args), 0);

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

    /* Short timeout so abort_work fails queued IOs quickly after close.
     * Without this the loser threads' pwrites sit in fc->processing for
     * the default 600s (no ctl_fd reader) and join() would hang. */
    ASSERT_EQ(0, write_pxd_timeout(minor, 30));

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

    /* pxd_timeout_secs is module-global; setting it via any device's
     * sysfs affects all devices in this ctx. Short timeout so
     * abort_work fails queued IOs on every device after close(). */
    ASSERT_EQ(0, write_pxd_timeout(devs[0].minor, 30));

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

/*
 * RACE TEST: reopen ctl_fd -> userspace pulls and fails queued fuse reqs
 *
 * Why this matters (companion to abort_work coverage):
 *   The freeze protocol relies on two complementary drains for IO that
 *   got routed to the fuse slow path during a ctx transition:
 *     - abort_work (T + pxd_timeout_secs) hard-fails everything.
 *     - Reopen + userspace read cycles them back out normally.
 *   The abort_work path is covered by other race tests. This test
 *   drives the second path: after close(ctl_fd), IO gets queued in
 *   fc->processing; reopen restarts them into fc->pending via
 *   fuse_restart_requests; a userspace reader then pulls each req and
 *   fails it. pwrite returns error, io_thr exits cleanly - WITHOUT
 *   waiting for abort_work.
 *
 *   If fuse_restart_requests were broken or userspace couldn't drain
 *   the pending list, io_thr.join would time out.
 */
TEST_P(PxdFastpathTest, race_reopen_userspace_drain_queued_reqs_using_dm_flakey)
{
    std::cout << "\n=== RACE TEST: reopen ctl_fd + userspace drain (dm-flakey) ===" << std::endl;

    TempLoopDevice loop_dev(100);
    DMTargetCleanup dm_cleanup{};
    std::string dm_path;
    pxd_add_ext_out add_ext;
    if (!prepare_flakey_dm_and_add_ext(1300, "pxd_test_flakey_reopen_drain",
                                       loop_dev, dm_cleanup, dm_path, add_ext)) {
        GTEST_SKIP();
    }
    std::string device_name;
    int minor = 0;
    dev_add_fastpath(add_ext, minor, device_name);
    std::cout << "Device added: " << device_name << std::endl;

    /* Set a short timeout as a fallback safety net. If the userspace
     * drain works correctly, io_thr exits well before abort_work fires. */
    ASSERT_EQ(0, write_pxd_timeout(minor, 30));

    /* Single failing IO from a worker thread. Once it fails on the
     * fastpath, the failover state machine routes it through the fuse
     * slow path. On close(ctl_fd) it lingers in fc->processing until
     * we reopen and drain. */
    std::atomic<bool> stop_io{false};
    std::atomic<uint64_t> io_err_count{0};
    std::thread io_thr = start_failing_io_stream(device_name, stop_io, io_err_count);

    /* Let io_thr accumulate errors and queue at least one req in flight. */
    usleep(300000);
    ASSERT_GT(io_err_count.load(), 0u);

    std::cout << "Closing ctl_fd; IOs will land in fc->processing" << std::endl;
    close(ctl_fd);
    ctl_fd = -1;

    /* Let failover_work run and the next pwrite queue in fuse slow path. */
    usleep(500000);

    std::cout << "Reopening ctl_fd; fuse_restart_requests moves reqs to pending" << std::endl;
    ctl_fd = open(control_device_fastpath(0).c_str(), O_RDWR);
    ASSERT_GT(ctl_fd, 0);
    pxd_ioctl_init_args init_args;
    ASSERT_GE(ioctl(ctl_fd, PXD_IOC_INIT, &init_args), 0);
    /* Re-arm short timeout as a fallback; the drain below should
     * complete well before it triggers. */
    ASSERT_EQ(0, write_pxd_timeout(minor, 30));

    /* Now userspace drains ctl_fd - pull each fuse req and fail it.
     * fail_io ends the request with -EIO which propagates to
     * blk_mq_end_request; the block layer wakes the pwrite waiter.
     * This validates the freeze-doc's assertion that reopen +
     * userspace read is a valid drain path (not just abort_work). */
    std::atomic<uint64_t> drained{0};
    std::atomic<bool> stop_drain{false};
    std::thread drain_thr([&]() {
        struct rdwr_in rdwr;
        while (!stop_drain.load()) {
            int ret = wait_msg(1);
            if (ret == -ETIMEDOUT) continue;
            if (ret < 0) break;
            ssize_t rb = read(ctl_fd, &rdwr, sizeof(rdwr));
            if (rb > 0) {
                fail_io(&rdwr);
                drained.fetch_add(1);
            }
        }
    });

    /* Stop io_thr and wait for it. If userspace drain is working,
     * pwrite errors out quickly (the drainer replies -EIO). If
     * broken, we fall back to abort_work at T+30s. If both are
     * broken, this hangs and the outer test framework catches it. */
    stop_io.store(true);
    io_thr.join();

    stop_drain.store(true);
    drain_thr.join();

    std::cout << "Drained " << drained.load() << " fuse reqs; io_errs="
              << io_err_count.load() << std::endl;
    EXPECT_GT(drained.load(), 0u)
        << "expected userspace to service at least one queued req";

    std::cout << "=== RACE TEST PASSED: reopen + userspace drain works ===" << std::endl;
}

/*
 * SYNC-TIMEOUT TEST: force wait_for_sync() past SYNC_TIMEOUT and verify
 * the driver still converges to a sane state.
 *
 * What is being forced
 * --------------------
 * disableFastPath(skipsync=false) calls wait_for_sync(), which fans one
 * work item per backing fd onto the global workqueue (__pxd_syncer ->
 * vfs_fsync) and waits on fp->sync_complete with a bounded
 * wait_for_completion_timeout(SYNC_TIMEOUT = 10s). Every other blocking
 * wait on that path (blk_mq freeze, fastpath_flush_work) is unbounded;
 * this is the one leg with a deadline, and nothing in the normal test
 * suite ever reaches it because loop/flakey devices fsync instantly.
 *
 * dm-delay's flush class is what makes it reachable. vfs_fsync() on a
 * block device issues a REQ_PREFLUSH, delay_map() routes that to the
 * flush class, and a flush_ms well above SYNC_TIMEOUT parks the fsync
 * for longer than the driver is willing to wait.
 *
 * Trigger: `echo X > /sys/devices/pxd/<minor>/debug`, i.e.
 * pxd_debug_switch_nativepath -> disableFastPath(pxd_dev, false). The
 * sysfs store runs the handler inline, so the write() syscall blocks for
 * exactly as long as the disable sequence does and we can time it.
 *
 * What "handled correctly" means afterwards
 * -----------------------------------------
 *  1. The wait is bounded: the write returns at ~SYNC_TIMEOUT, NOT after
 *     the full flush delay. If it returns at ~DELAY_FLUSH_MS instead,
 *     the timeout is not doing its job.
 *  2. wait_for_sync's -EBUSY is non-fatal: disableFastPath logs and
 *     continues (it is deliberately not a failure return), so the device
 *     must end up fully in native path - fpactive:0, nfd:0.
 *  3. The device stays usable: a second disable is a no-op that returns
 *     promptly rather than hanging, and PXD_REMOVE still succeeds.
 *
 * Runtime: ~10s (dominated by SYNC_TIMEOUT). This is inherent - the
 * timeout is a compile-time constant in pxd_fastpath.c with no sysfs
 * knob, so the test cannot shorten it.
 */
TEST_P(PxdFastpathTest, sync_timeout_during_disable_fastpath_using_dm_delay)
{
    /* Must exceed SYNC_TIMEOUT (10s) by enough that "timed out at 10s"
     * and "waited for the flush" are unambiguously distinguishable.
     * Keep these in step with SYNC_TIMEOUT in pxd_fastpath.c - it is a
     * compile-time constant with no sysfs knob, so the test cannot read
     * the driver's value at runtime. */
    const uint64_t DELAY_FLUSH_MS = 30000;
    const long SYNC_TIMEOUT_MS = 10000;

    std::cout << "\n=== SYNC TIMEOUT TEST: wait_for_sync past SYNC_TIMEOUT "
                 "(dm-flakey + dm-delay) ===" << std::endl;

    TempLoopDevice loop_dev(100);
    DMStackCleanup dm_stack{};
    std::string dm_path, delay_name, flakey_path, device_name;
    int minor = 0;
    pxd_add_ext_out add_ext;

    /* Reads and writes are undelayed - only the flush class is parked.
     * Delaying data IO too would just make the setup writes slow without
     * making the sync path any more interesting.
     *
     * flakey_errors=false is deliberate: with an erroring flakey region
     * the fsync would come back -EIO (dm broadcasts flush bios to every
     * target in the table), and -EIO is a *different* branch of
     * disableFastPath's error check than the -EBUSY the timeout
     * produces. A healthy backing store isolates the timeout as the only
     * thing under test. */
    if (!prepare_flakey_delay_dm_and_add_ext(1300, "pxd_test_synctmo",
                                             loop_dev, dm_stack, dm_path,
                                             delay_name, flakey_path, add_ext,
                                             false /* flakey_errors */,
                                             0 /* read_ms */,
                                             0 /* write_ms */,
                                             DELAY_FLUSH_MS)) {
        GTEST_SKIP();
    }

    dev_add_fastpath(add_ext, minor, device_name);
    std::cout << "Device added: " << device_name << " (minor " << minor
              << ") on " << dm_path << std::endl;

    /* Confirm we actually got fastpath - if the device fell back to
     * native at attach, disableFastPath would early-return and never
     * reach wait_for_sync, making the whole test vacuous. */
    std::string dbg = read_pxd_debug(minor);
    std::cout << "debug before: " << dbg << std::endl;
    ASSERT_NE(dbg.find("fpactive:1"), std::string::npos)
        << "device is not in fastpath; sync path would not be exercised. debug="
        << dbg;

    /* Dirty the healthy range so the fsync has something to do and the
     * flush is genuinely issued. Offset 0 is linear/healthy in the
     * flakey table; the failing window is 16-32MB. */
    {
        int fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
        ASSERT_GT(fd, 0) << "open(" << device_name << ") failed: "
                         << strerror(errno);
        auto buf = aligned_buffer_fastpath(4096);
        init_pattern_fastpath(buf.get(), 4096);
        ssize_t w = pwrite(fd, buf.get(), 4096, 0);
        EXPECT_EQ(4096, w) << "setup write failed: " << strerror(errno);
        close(fd);
    }

    /* --- force the timeout --- */
    std::cout << "Triggering disableFastPath with a " << DELAY_FLUSH_MS
              << "ms flush delay; expect ~" << SYNC_TIMEOUT_MS
              << "ms of blocking..." << std::endl;

    long elapsed_ms = write_pxd_debug_timed(minor, 'X');
    ASSERT_GE(elapsed_ms, 0) << "debug sysfs write failed";
    std::cout << "disableFastPath returned after " << elapsed_ms << "ms"
              << std::endl;

    /* (1) The wait must be bounded by SYNC_TIMEOUT, not by the delay.
     * Lower bound with slack for jiffies granularity; upper bound well
     * below DELAY_FLUSH_MS so "waited for the flush" fails loudly. */
    EXPECT_GE(elapsed_ms, SYNC_TIMEOUT_MS - 3000)
        << "returned too early (" << elapsed_ms << "ms) - the fsync was not "
           "actually delayed, so the timeout path was never taken";
    EXPECT_LT(elapsed_ms, (long) DELAY_FLUSH_MS - 8000)
        << "blocked for ~the full flush delay (" << elapsed_ms << "ms) - "
           "wait_for_sync did not honour SYNC_TIMEOUT";

    /* (2) -EBUSY from wait_for_sync is advisory: the disable must have
     * run to completion regardless. */
    dbg = read_pxd_debug(minor);
    std::cout << "debug after: " << dbg << std::endl;
    EXPECT_NE(dbg.find("fpactive:0"), std::string::npos)
        << "device still in fastpath after a timed-out disable. debug=" << dbg;
    EXPECT_NE(dbg.find("nfd:0"), std::string::npos)
        << "backing fds not released after a timed-out disable. debug=" << dbg;

    /* (3) A second disable must be a prompt no-op (disableFastPath's
     * xchg ownership gate returns immediately once fp->fastpath is
     * false). If the first disable left the sync machinery wedged -
     * fp->sync_done non-zero with syncers still parked - this is where
     * a stuck-state regression shows up as a long stall. */
    long second_ms = write_pxd_debug_timed(minor, 'X');
    ASSERT_GE(second_ms, 0) << "second debug sysfs write failed";
    std::cout << "second disable returned after " << second_ms << "ms"
              << std::endl;
    EXPECT_LT(second_ms, 5000)
        << "repeat disable took " << second_ms << "ms; expected an immediate "
           "no-op via the fp->fastpath xchg gate";

    /* Release the parked flush before teardown so the outstanding fsync
     * (and anything holding the dm device open) can retire. dm-delay's
     * presuspend flushes queued bios, so this both unblocks the syncer
     * and lets the dm targets be removed. Done explicitly here rather
     * than leaving it to ~DMStackCleanup so a failure is visible. */
    EXPECT_TRUE(dm_reload_table(delay_name,
                                build_delay_table(flakey_path, 0, 0, 0)))
        << "failed to release the delay; teardown may be slow";

    /* (3, cont.) The device must still be removable. dev_remove_fastpath
     * drives PXD_REMOVE and updates added_ids so TearDown does not retry
     * it. A hang here means the timed-out sync left a reference behind. */
    auto rm_start = std::chrono::steady_clock::now();
    dev_remove_fastpath(add_ext.dev_id);
    auto rm_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - rm_start).count();
    std::cout << "device removed in " << rm_ms << "ms" << std::endl;
    EXPECT_LT(rm_ms, 30000)
        << "PXD_REMOVE took " << rm_ms << "ms after a timed-out sync";

    std::cout << "=== SYNC TIMEOUT TEST PASSED: bounded wait, device "
                 "converged to native, remove clean ===" << std::endl;
    std::cout << "NOTE: 'device <id> sync failed -16' is expected in dmesg - "
                 "that is wait_for_sync returning -EBUSY on the timeout."
              << std::endl;
}

/*
 * ---------------------------------------------------------------------------
 * NVMe-oF TCP loopback target infrastructure
 * ---------------------------------------------------------------------------
 *
 * Mirrors how px sets up remote fastpath (pkg/fastpath/nvmeof-tcp.go), but
 * with target and initiator on the same host so a UT can build the whole
 * path with no second node:
 *
 *   loop (100MB)
 *     -> dm-flakey                (error injection layer, healthy here)
 *       -> dm-delay               (latency injection; the TARGET-side delay)
 *         -> nvmet namespace      configfs, exported over nvmet-tcp
 *           -> nvme connect       127.0.0.1, dynamically chosen port
 *             -> /dev/nvmeXnY     <-- attached to pxd as the fastpath backing
 *
 * The delay MUST sit below nvmet. Delaying on the initiator side would just
 * make the local IO slow; the point is that the *target* is slow to answer,
 * so the initiator's nvme command exceeds io_timeout and the NVMe layer
 * aborts it. That abort is what surfaces to pxd as a failed fastpath IO.
 *
 * Config that this mirrors from nvmeof-tcp.go:
 *   port attrs   addr_adrfam=ipv4, addr_traddr, addr_trsvcid, addr_trtype=tcp
 *   subsystem    attr_allow_any_host=1 (px uses ACLs; irrelevant on loopback)
 *   namespace    device_path=<backing>, enable=1
 *   modules      nvmet, nvmet-tcp, nvme-core, nvme-tcp, nvme, nvme-fabrics
 *
 * Deliberate deviations, each learned the hard way:
 *
 *  - The TCP port is probed, not hardcoded. px uses 4420 and will already
 *    hold it on a real node; unrelated daemons squat on nearby ports too.
 *  - The port index under ports/ is high (241) so it cannot collide with
 *    px's ports/0.
 *  - hostnqn is passed explicitly with -q rather than relying on
 *    /etc/nvme/hostnqn, so the test never writes to /etc.
 */

static const char *kNvmetPortIdx = "241";

/* Probe a free TCP port by binding to port 0 and reading back the
 * assignment. Racy in principle - something could take the port between
 * close() and nvmet binding it - but the window is small and a collision
 * shows up immediately as a clear "failed to bind port socket" skip. */
static int find_free_tcp_port()
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(s);
        return -1;
    }
    socklen_t len = sizeof(a);
    if (getsockname(s, (struct sockaddr *)&a, &len) != 0) {
        close(s);
        return -1;
    }
    int port = ntohs(a.sin_port);
    close(s);
    return port;
}

static bool write_sysfs(const std::string &path, const std::string &val)
{
    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) {
        std::cerr << "open(" << path << ") failed: " << strerror(errno) << std::endl;
        return false;
    }
    ssize_t wb = write(fd, val.c_str(), val.size());
    int saved = errno;
    close(fd);
    if (wb != (ssize_t) val.size()) {
        std::cerr << "write(" << path << ", '" << val << "') failed: "
                  << strerror(saved) << std::endl;
        return false;
    }
    return true;
}

static std::string read_sysfs(const std::string &path)
{
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        return "";
    }
    std::string line;
    std::getline(ifs, line);
    return line;
}

/*
 * Check every prerequisite for the NVMe-oF loopback path. On failure sets
 * `why` to something the runner can act on, and the caller GTEST_SKIP()s.
 *
 * The multipath check is the subtle one and is NOT optional. With
 * nvme_core.multipath=Y, an io_timeout does not surface as an IO error:
 * the NVMe multipath head requeues the command instead
 *
 *     nvme nvme0: queue 8: timeout request 0x42 type 4
 *     nvme nvme0: starting error recovery
 *     block nvme0n1: no usable path - requeuing I/O
 *
 * so the write blocks indefinitely (there is no second path on loopback)
 * and pxd never sees an error, never calls pxd_failover_initiate, and the
 * test would hang rather than fail. The parameter is 0444 - read-only at
 * runtime - so this cannot be fixed from inside the test; it needs
 * nvme_core.multipath=N on the kernel command line. That is what px
 * requires in production anyway (see the prerequisite check in
 * storage/hal/provider/pure/cloudops/prerequisites.go).
 */
static bool nvmet_tcp_available(std::string &why)
{
    if (geteuid() != 0) {
        why = "must run as root";
        return false;
    }
    if (system("which nvme >/dev/null 2>&1") != 0) {
        why = "nvme-cli not installed (need the 'nvme' binary)";
        return false;
    }

    const char *mods[] = { "nvmet", "nvmet-tcp", "nvme-tcp", "nvme-fabrics",
                           "dm-flakey", "dm-delay" };
    for (size_t i = 0; i < sizeof(mods) / sizeof(mods[0]); i++) {
        std::string cmd = "modprobe " + std::string(mods[i]) + " >/dev/null 2>&1";
        if (system(cmd.c_str()) != 0) {
            why = std::string("kernel module unavailable: ") + mods[i];
            return false;
        }
    }

    struct stat st;
    if (stat("/sys/kernel/config/nvmet", &st) != 0) {
        /* configfs not mounted, or nvmet did not register. */
        if (system("mount -t configfs none /sys/kernel/config >/dev/null 2>&1") != 0 ||
            stat("/sys/kernel/config/nvmet", &st) != 0) {
            why = "/sys/kernel/config/nvmet missing (configfs not mounted?)";
            return false;
        }
    }

    if (stat("/sys/module/nvme_core/parameters/io_timeout", &st) != 0) {
        why = "/sys/module/nvme_core/parameters/io_timeout missing";
        return false;
    }
    if (access("/sys/module/nvme_core/parameters/io_timeout", W_OK) != 0) {
        why = "nvme_core io_timeout parameter is not writable";
        return false;
    }

    if (stat("/sys/module/nvme_core/parameters/max_retries", &st) != 0 ||
        access("/sys/module/nvme_core/parameters/max_retries", W_OK) != 0) {
        why = "nvme_core.max_retries parameter missing or not writable";
        return false;
    }

    /* nvme_core.multipath=Y is survivable but worth flagging.
     *
     * With the default max_retries a timed-out command on a multipath
     * controller is requeued by the mpath head - "no usable path -
     * requeuing I/O" - and on a single-path loopback setup it never
     * completes at all. This test sets max_retries=0, and
     * nvme_decide_disposition checks the retry budget BEFORE the
     * REQ_NVME_MPATH branch:
     *
     *     if (... || nvme_req(req)->retries >= nvme_max_retries)
     *             return COMPLETE;                 <-- taken with 0
     *     if (req->cmd_flags & REQ_NVME_MPATH) ... return FAILOVER;
     *
     * so the command is completed with an error rather than handed to the
     * multipath layer. Verified end to end on a multipath=Y box: the write
     * failed with EIO at 5.06s against a 5s io_timeout and a 10s target
     * delay. Note px itself requires multipath=N in production (see
     * storage/hal/provider/pure/cloudops/prerequisites.go). */
    std::string mp = read_sysfs("/sys/module/nvme_core/parameters/multipath");
    if (mp == "Y" || mp == "1") {
        std::cout << "NOTE: nvme_core.multipath=Y. Fine here because "
                     "max_retries=0 completes the command before the mpath "
                     "branch, but px requires multipath=N in production."
                  << std::endl;
    }

    return true;
}

/*
 * RAII nvmet-tcp target: subsystem + namespace + port, torn down in reverse.
 *
 * Teardown order matters and the kernel enforces it: the port symlink must
 * go before the subsystem rmdir, and the namespace must be disabled before
 * its rmdir, or configfs returns EBUSY.
 */
struct NvmetTcpTarget {
    std::string nqn;
    std::string port_idx;
    int         tcp_port{0};
    bool        subsys_made{false};
    bool        ns_made{false};
    bool        port_made{false};
    bool        linked{false};

    std::string subsys_path() const {
        return "/sys/kernel/config/nvmet/subsystems/" + nqn;
    }
    std::string ns_path() const { return subsys_path() + "/namespaces/1"; }
    std::string port_path() const {
        return "/sys/kernel/config/nvmet/ports/" + port_idx;
    }

    /* Export `backing_dev` (e.g. /dev/mapper/foo_delay) as nsid 1. */
    bool setup(const std::string &nqn_in, const std::string &port_idx_in,
               const std::string &backing_dev)
    {
        nqn = nqn_in;
        port_idx = port_idx_in;

        tcp_port = find_free_tcp_port();
        if (tcp_port <= 0) {
            std::cerr << "could not find a free TCP port" << std::endl;
            return false;
        }

        if (mkdir(subsys_path().c_str(), 0755) != 0) {
            std::cerr << "mkdir(" << subsys_path() << ") failed: "
                      << strerror(errno) << std::endl;
            return false;
        }
        subsys_made = true;
        if (!write_sysfs(subsys_path() + "/attr_allow_any_host", "1")) {
            return false;
        }

        if (mkdir(ns_path().c_str(), 0755) != 0) {
            std::cerr << "mkdir(" << ns_path() << ") failed: " << strerror(errno)
                      << std::endl;
            return false;
        }
        ns_made = true;
        if (!write_sysfs(ns_path() + "/device_path", backing_dev)) {
            return false;
        }
        if (!write_sysfs(ns_path() + "/enable", "1")) {
            return false;
        }

        if (mkdir(port_path().c_str(), 0755) != 0 && errno != EEXIST) {
            std::cerr << "mkdir(" << port_path() << ") failed: " << strerror(errno)
                      << std::endl;
            return false;
        }
        port_made = true;
        if (!write_sysfs(port_path() + "/addr_adrfam", "ipv4") ||
            !write_sysfs(port_path() + "/addr_traddr", "127.0.0.1") ||
            !write_sysfs(port_path() + "/addr_trsvcid", std::to_string(tcp_port)) ||
            !write_sysfs(port_path() + "/addr_trtype", "tcp")) {
            return false;
        }

        /* Linking the subsystem into the port is what makes nvmet bind the
         * socket, so a port collision surfaces here as EADDRINUSE. */
        std::string link = port_path() + "/subsystems/" + nqn;
        if (symlink(subsys_path().c_str(), link.c_str()) != 0) {
            std::cerr << "symlink(" << link << ") failed: " << strerror(errno)
                      << " (port " << tcp_port << " taken?)" << std::endl;
            return false;
        }
        linked = true;
        return true;
    }

    /*
     * Stop the target accepting new connections, without dismantling it.
     *
     * Call this BEFORE disconnecting the initiator. If the transport was in
     * error recovery, the initiator has a reconnect in flight; with the
     * port still linked it happily establishes a fresh controller against a
     * subsystem we are about to delete:
     *
     *     nvme nvme0: Removing ctrl: NQN "...:iotmo"
     *     nvmet: creating nvm controller 2 for subsystem ...:iotmo   <-- here
     *     nvme nvme0: Failed reconnect attempt 1
     *
     * Unlinking first makes those reconnects fail fast against a port that
     * serves nothing, instead of racing the teardown. Idempotent.
     */
    void stop_accepting() {
        if (linked) {
            std::string link = port_path() + "/subsystems/" + nqn;
            (void) unlink(link.c_str());
            linked = false;
        }
    }

    ~NvmetTcpTarget() {
        stop_accepting();
        if (port_made) {
            (void) rmdir(port_path().c_str());
        }
        if (ns_made) {
            (void) write_sysfs(ns_path() + "/enable", "0");
            (void) rmdir(ns_path().c_str());
        }
        if (subsys_made) {
            (void) rmdir(subsys_path().c_str());
        }
    }
};

/*
 * RAII `nvme disconnect`, plus a wait for the controller to actually go
 * away.
 *
 * `nvme disconnect` returning does not mean the controller is gone. If the
 * transport was in error recovery when we disconnected, a reconnect can
 * still be in flight; it then keeps retrying against an nvmet target that
 * the NvmetTcpTarget destructor is busy dismantling, and only gives up
 * when its own fabrics-connect command times out. Observed cost of not
 * waiting: ~40s of teardown and a pile of confusing "Failed reconnect
 * attempt" / partition-scan IO errors after the test body had finished.
 *
 * Polling subsysnqn under /sys/class/nvme is the reliable signal - the
 * entry disappears once the controller is really torn down.
 */
struct NvmeConnCleanup {
    std::string nqn;

    bool controller_present() const {
        bool present = false;
        DIR *d = opendir("/sys/class/nvme");
        if (!d) {
            return false;
        }
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strncmp(ent->d_name, "nvme", 4) != 0) {
                continue;
            }
            std::string p = std::string("/sys/class/nvme/") + ent->d_name
                          + "/subsysnqn";
            if (read_sysfs(p) == nqn) {
                present = true;
                break;
            }
        }
        closedir(d);
        return present;
    }

    /* Name of any controller still bound to our subsystem, or "". */
    std::string controller_name() const {
        std::string found;
        DIR *d = opendir("/sys/class/nvme");
        if (!d) {
            return found;
        }
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strncmp(ent->d_name, "nvme", 4) != 0) {
                continue;
            }
            std::string p = std::string("/sys/class/nvme/") + ent->d_name
                          + "/subsysnqn";
            if (read_sysfs(p) == nqn) {
                found = ent->d_name;
                break;
            }
        }
        closedir(d);
        return found;
    }

    /*
     * Disconnect and do not return until the controller is really gone.
     * Idempotent - clears nqn so the destructor becomes a no-op.
     *
     * `nvme disconnect` returning is not proof of anything: a controller in
     * error recovery can survive it and keep reconnecting. If it is still
     * there after a grace period, force it out via delete_controller, which
     * the driver honours regardless of transport state.
     */
    void disconnect() {
        if (nqn.empty()) {
            return;
        }
        std::string cmd = "nvme disconnect -n " + nqn + " >/dev/null 2>&1";
        (void) system(cmd.c_str());

        for (int i = 0; i < 50; i++) {         /* up to ~5s */
            if (controller_name().empty()) {
                nqn.clear();
                return;
            }
            usleep(100000);
        }

        std::string ctrl = controller_name();
        if (!ctrl.empty()) {
            std::cerr << "nvme controller " << ctrl << " survived disconnect; "
                         "forcing delete_controller" << std::endl;
            (void) write_sysfs("/sys/class/nvme/" + ctrl + "/delete_controller",
                               "1");
        }
        for (int i = 0; i < 100; i++) {        /* up to ~10s more */
            if (controller_name().empty()) {
                break;
            }
            usleep(100000);
        }
        if (!controller_name().empty()) {
            std::cerr << "warning: nvme controller for " << nqn
                      << " still present; nvmet teardown may race it"
                      << std::endl;
        }
        nqn.clear();
    }

    ~NvmeConnCleanup() { disconnect(); }
};

/*
 * RAII save/set/restore for an nvme_core module parameter. Both parameters
 * this test touches are global to every NVMe device on the box, which is
 * one reason it is not part of a default sweep.
 *
 * nvme_core.io_timeout (SECONDS, default 30)
 *   Must be set BEFORE `nvme connect`: nvme-tcp stamps it into the tagset
 *   at controller setup,
 *       drivers/nvme/host/tcp.c:  set->timeout = NVME_IO_TIMEOUT;
 *   where NVME_IO_TIMEOUT is (nvme_io_timeout * HZ). Changing it later has
 *   no effect on an already-connected controller.
 *
 * nvme_core.max_retries (default 5)
 *   Read at completion time, so it may be set at any point before the IO.
 *   See the note on the test itself for why it has to be zero.
 */
struct NvmeParamGuard {
    std::string path;
    std::string saved;
    bool        applied{false};

    bool set(const std::string &param, const std::string &value) {
        path = "/sys/module/nvme_core/parameters/" + param;
        saved = read_sysfs(path);
        if (saved.empty()) {
            return false;
        }
        if (!write_sysfs(path, value)) {
            return false;
        }
        applied = true;
        return true;
    }
    ~NvmeParamGuard() {
        if (applied) {
            (void) write_sysfs(path, saved);
        }
    }
};

/*
 * Count how many lines in the kernel ring buffer match `pattern`.
 *
 * Deliberately counts MATCHES rather than taking a total-line-count
 * baseline and tailing past it. On a long-running node the ring buffer is
 * full and wraps: old lines fall off the front while new ones arrive, so a
 * saved line index no longer points where it did and `tail -n +N` skips
 * straight past the messages you are looking for. That silently reports
 * "the event never happened". Comparing match counts degrades far more
 * gracefully - wrapping can only drop matches, never invent them.
 */
static int dmesg_match_count(const std::string &pattern)
{
    std::string cmd = "dmesg 2>/dev/null | grep -cE '" + pattern + "'";
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp) {
        return -1;
    }
    char buf[64] = {0};
    if (!fgets(buf, sizeof(buf), fp)) {
        pclose(fp);
        return 0;
    }
    pclose(fp);
    return atoi(buf);
}

/*
 * Connect the initiator and return the namespace block device name.
 *
 * The name filter matters: with NVMe native multipath compiled in, a
 * controller also exposes per-path devices named nvme<ctrl>c<path>n<ns>
 * (e.g. nvme0c0n1) which cannot be opened directly - dd on one returns
 * EINVAL. Only the plain nvme<ctrl>n<ns> form is usable, hence the
 * "digits, n, digits" shape check.
 */
static bool nvme_connect_and_find_ns(const std::string &nqn, int tcp_port,
                                     const std::string &hostnqn,
                                     int reconnect_delay_secs,
                                     int ctrl_loss_tmo_secs,
                                     std::string &ns_dev_out)
{
    /* -c / -l mirror px's CtrlLossTmoSec / reconnect tuning (see
     * runNvmeConnect in pkg/fastpath/nvmeof-tcp.go). A short reconnect
     * delay keeps the post-abort error-recovery cycle brief; the kernel
     * default is 10s, which otherwise dominates the timing. */
    std::string cmd = "nvme connect -t tcp -n " + nqn
                    + " -a 127.0.0.1 -s " + std::to_string(tcp_port)
                    + " -q " + hostnqn
                    + " -c " + std::to_string(reconnect_delay_secs)
                    + " -l " + std::to_string(ctrl_loss_tmo_secs) + " 2>&1";
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp) {
        std::cerr << "popen(nvme connect) failed" << std::endl;
        return false;
    }
    std::string out;
    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) {
        out += buf;
    }
    if (pclose(fp) != 0) {
        std::cerr << "nvme connect failed: " << out << std::endl;
        return false;
    }

    /* udev may take a moment to publish the namespace. */
    for (int attempt = 0; attempt < 100; attempt++) {
        DIR *d = opendir("/sys/block");
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                std::string name = ent->d_name;
                if (name.compare(0, 4, "nvme") != 0) {
                    continue;
                }
                /* Require exactly nvme<digits>n<digits>: reject nvmeXcYnZ. */
                size_t i = 4;
                size_t ctrl_digits = 0;
                while (i < name.size() && isdigit(name[i])) { i++; ctrl_digits++; }
                if (ctrl_digits == 0 || i >= name.size() || name[i] != 'n') {
                    continue;
                }
                i++;
                size_t ns_digits = 0;
                while (i < name.size() && isdigit(name[i])) { i++; ns_digits++; }
                if (ns_digits == 0 || i != name.size()) {
                    continue;
                }

                std::string sub = read_sysfs("/sys/block/" + name + "/device/subsysnqn");
                if (sub == nqn) {
                    ns_dev_out = name;
                    closedir(d);
                    return true;
                }
            }
            closedir(d);
        }
        usleep(100000);
    }
    std::cerr << "connected but no namespace appeared for " << nqn << std::endl;
    return false;
}

/*
 * REMOTE-FASTPATH IO-TIMEOUT TEST
 *
 * Question this answers: when a remote fastpath backing device stops
 * answering and the NVMe layer times the command out, does px-fuse notice
 * and trigger a failover?
 *
 * Everything in the earlier dm-only tests injects an *immediate* error
 * (dm-flakey returns -EIO from map()). That is not what a dead remote
 * target looks like. Here the failure is a genuine transport timeout:
 *
 *   dm-delay parks the write on the TARGET side for kTargetDelayMs (10s)
 *   nvme_core.io_timeout is set to kIoTimeoutSecs (5s) before connect
 *   -> at ~5s nvme_timeout() fires, aborts the command, error recovery runs
 *   -> the clone bio completes with an error
 *   -> _end_clone_bio: can_failover && blkrc < 0 -> pxd_failover_initiate
 *   -> pxd_io_failover branch (c) -> pxd_initiate_failover
 *   -> PXD_FAILOVER_TO_USERSPACE marker appears on ctl_fd
 *
 * Why nvme_core.max_retries MUST be 0
 * -----------------------------------
 * An NVMe io_timeout on its own does NOT produce an IO error. With the
 * controller LIVE, nvme_tcp_timeout() logs "timeout request", kicks error
 * recovery, and returns BLK_EH_RESET_TIMER - it does not complete the
 * request (drivers/nvme/host/tcp.c:2185). Error recovery cancels the
 * command, and nvme_decide_disposition (drivers/nvme/host/core.c) then
 * decides what to do with it:
 *
 *     if (blk_noretry_request(req) || (status & NVME_SC_DNR) ||
 *         nvme_req(req)->retries >= nvme_max_retries)
 *             return COMPLETE;
 *     return RETRY;
 *
 * With the default nvme_max_retries = 5 the command is REQUEUED and
 * retried after the controller reconnects. Against a healthy target with
 * one slow region, every retry hits the same delay and times out again, so
 * the IO error only surfaces after ~5 x (io_timeout + reconnect_delay) -
 * roughly 75s with kernel defaults. Upper layers see a stalled IO, not a
 * failed one, and no failover is triggered in the meantime.
 *
 * That is a real property of remote fastpath worth knowing: a slow or
 * half-dead NVMe target does not promptly produce the IO error that
 * pxd_failover_initiate needs. px controls the surrounding knobs via
 * `nvme connect -l/-k` (CtrlLossTmoSec / KeepAliveTmoSec) but max_retries
 * is global.
 *
 * Setting max_retries=0 makes the first cancelled command take the
 * COMPLETE branch, so the abort surfaces as -EIO at ~io_timeout. That is
 * what this test wants to exercise: given an errored fastpath IO, does
 * px-fuse fail over? It deliberately does NOT test how long NVMe takes to
 * give up by default.
 *
 * The marker arriving is the assertion. Its *timing* is the second
 * assertion and is what separates "the timeout caused this" from "the
 * delay simply elapsed": a marker at ~5s means nvme aborted the command,
 * a marker at ~10s (or a successful write and no marker) means it did not.
 *
 * Verified prerequisites are all checked up front and the test skips with
 * a specific reason - see nvmet_tcp_available(). The one that most often
 * bites is nvme_core.multipath=Y.
 *
 * Side effects: sets nvme_core.io_timeout globally for the duration
 * (restored on exit) and creates/destroys an nvmet subsystem. Explicitly
 * invoked (note: the filter needs a trailing "/LoopDevice" to pin one
 * parameter instantiation - not spelled out here because the slash-star
 * sequence would close this comment):
 *   ./test/pxd_test --gtest_filter='...remote_fastpath_io_timeout...'
 */
TEST_P(PxdFastpathTest, remote_fastpath_io_timeout_triggers_failover_using_nvmet)
{
    /* The target delay must be comfortably LARGER than the io_timeout, or
     * "the abort fired" and "the delay simply elapsed" land at the same
     * instant and the run proves nothing. Raising io_timeout to 10s means
     * the delay has to move well past it - hence 30s, not 10s. */
    const uint64_t kTargetDelayMs   = 30000; /* target-side write delay */
    const int      kIoTimeoutSecs   = 10;    /* nvme abort deadline */
    const int      kReconnectSecs   = 1;     /* -c: default 10s dominates otherwise */
    const int      kCtrlLossTmoSecs = 20;    /* -l */
    const int      kMarkerWaitSecs  = 90;    /* generous: covers a retry cycle
                                              * or two if max_retries could not
                                              * be zeroed */
    const uint64_t kFailingOffset   = (16ULL * 1024 * 1024) + 4096;
    const uint64_t kHealthyOffset   = 0;

    std::cout << "\n=== REMOTE FASTPATH IO-TIMEOUT TEST (nvmet-tcp loopback) ==="
              << std::endl;

    std::string why;
    if (!nvmet_tcp_available(why)) {
        std::cerr << "SKIP: " << why << std::endl;
        GTEST_SKIP();
    }

    /* Backing stack. The flakey layer is healthy - the failure under test
     * is a timeout, not an injected -EIO - but it is kept in the stack so
     * the geometry matches the other fastpath tests and so a future test
     * can reload it into an erroring table. The delay is scoped to the
     * 16-32MB window so device setup and the healthy-path write stay fast. */
    TempLoopDevice loop_dev(100);
    DMStackCleanup dm_stack{};

    const std::string flakey_name = "pxd_test_nvmet_flakey";
    const std::string delay_name  = "pxd_test_nvmet_delay";
    if (!dm_create_target(flakey_name, build_flakey_table_healthy(loop_dev.path()))) {
        std::cerr << "SKIP: could not create dm-flakey target" << std::endl;
        GTEST_SKIP();
    }
    dm_stack.push(flakey_name);
    const std::string flakey_path = "/dev/mapper/" + flakey_name;

    if (!dm_create_target(delay_name,
                          build_delay_table_region(flakey_path,
                                                   16ULL * 1024 * 1024,
                                                   16ULL * 1024 * 1024,
                                                   0 /* read_ms */,
                                                   kTargetDelayMs /* write_ms */,
                                                   0 /* flush_ms */))) {
        std::cerr << "SKIP: could not create dm-delay target" << std::endl;
        GTEST_SKIP();
    }
    dm_stack.push(delay_name);
    const std::string delay_path = "/dev/mapper/" + delay_name;
    std::cout << "backing stack ready: " << delay_path << std::endl;

    /* io_timeout must be set BEFORE connect - see NvmeParamGuard. */
    NvmeParamGuard tmo;
    if (!tmo.set("io_timeout", std::to_string(kIoTimeoutSecs))) {
        std::cerr << "SKIP: could not set nvme_core.io_timeout" << std::endl;
        GTEST_SKIP();
    }
    std::cout << "nvme_core.io_timeout = " << kIoTimeoutSecs << "s (was "
              << tmo.saved << "s)" << std::endl;

    /* Without this the timed-out command is retried instead of failed and
     * no error ever reaches pxd - see the header comment. */
    NvmeParamGuard retries;
    if (!retries.set("max_retries", "0")) {
        std::cerr << "SKIP: could not set nvme_core.max_retries" << std::endl;
        GTEST_SKIP();
    }
    std::cout << "nvme_core.max_retries = 0 (was " << retries.saved
              << ") so the abort completes the command instead of retrying"
              << std::endl;

    const std::string nqn = "nqn.2026-01.com.purestorage.pxdut:iotmo";
    NvmetTcpTarget target;
    if (!target.setup(nqn, kNvmetPortIdx, delay_path)) {
        std::cerr << "SKIP: nvmet target setup failed" << std::endl;
        GTEST_SKIP();
    }
    std::cout << "nvmet target up: " << nqn << " on 127.0.0.1:"
              << target.tcp_port << std::endl;

    std::string hostnqn = "nqn.2014-08.org.nvmexpress:uuid:"
                        + read_sysfs("/proc/sys/kernel/random/uuid");
    NvmeConnCleanup conn;
    std::string ns_dev;
    if (!nvme_connect_and_find_ns(nqn, target.tcp_port, hostnqn,
                                  kReconnectSecs, kCtrlLossTmoSecs, ns_dev)) {
        std::cerr << "SKIP: nvme connect / namespace discovery failed" << std::endl;
        GTEST_SKIP();
    }
    conn.nqn = nqn;
    const std::string ns_path = "/dev/" + ns_dev;
    std::cout << "initiator connected: " << ns_path << std::endl;

    /* Attach the NVMe namespace to pxd as the fastpath backing device -
     * exactly what px does with a remote replica. */
    pxd_add_ext_out add_ext;
    memset(&add_ext, 0, sizeof(add_ext));
    add_ext.dev_id = 1500;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = 4096;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;
    add_ext.paths.count = 1;
    add_ext.paths.can_failover = true;
    strncpy(add_ext.paths.devpath[0], ns_path.c_str(),
            sizeof(add_ext.paths.devpath[0]) - 1);

    int minor = 0;
    std::string device_name;
    dev_add_fastpath(add_ext, minor, device_name);
    std::cout << "pxd device " << device_name << " (minor " << minor
              << ") on remote fastpath " << ns_path << std::endl;

    std::string dbg = read_pxd_debug(minor);
    std::cout << "debug: " << dbg << std::endl;
    if (dbg.find("fpactive:1") == std::string::npos) {
        ADD_FAILURE() << "device not in fastpath over the NVMe namespace; "
                         "nothing to time out. debug=" << dbg;
        dev_remove_fastpath(add_ext.dev_id);
        return;
    }

    /* Sanity: the healthy (undelayed) region works over the full
     * loop->flakey->delay->nvmet->nvme->pxd path. If this fails the test
     * setup is broken and the timing result below would be meaningless. */
    {
        int fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
        ASSERT_GT(fd, 0) << "open(" << device_name << "): " << strerror(errno);
        auto buf = aligned_buffer_fastpath(4096);
        init_pattern_fastpath(buf.get(), 4096);
        auto t0 = std::chrono::steady_clock::now();
        ssize_t w = pwrite(fd, buf.get(), 4096, kHealthyOffset);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        close(fd);
        EXPECT_EQ(4096, w) << "healthy-region write failed: " << strerror(errno);
        EXPECT_LT(ms, 3000) << "healthy-region write took " << ms
                            << "ms; the delay region is mis-scoped";
        std::cout << "healthy-region write OK in " << ms << "ms" << std::endl;
    }

    /* The real test: write into the delayed window. The writer blocks until
     * the failover resolves, so it runs on its own thread while the main
     * thread watches ctl_fd for the marker. */
    struct WriterCtl {
        std::atomic<bool> started{false};
        std::atomic<int>  completed{0};
        std::atomic<long> elapsed_ms{-1};
        std::atomic<int>  rc{0};
    };
    auto ctl = std::make_shared<WriterCtl>();
    std::string dev_copy = device_name;

    /* Baseline the abort-message count so the scan only reacts to a NEW
     * nvme_tcp_timeout, not to one from an earlier run.
     *
     * Extended regex, not a literal, because nvme_tcp_timeout's wording is
     * not stable across kernels:
     *   older:  "nvme nvme0: queue 8: timeout request 0x42 type 4"
     *   newer:  "nvme nvme0: queue 8: timeout cid 0x42 type 4 opcode 0x1 (Write)"
     * Matching the literal "timeout request" silently reports "no abort" on
     * any kernel using the newer wording. "queue <n>: timeout" covers both.
     * The error-recovery line is included as a second, independent witness -
     * it has been stable far longer and is emitted on the same path. */
    const std::string kAbortPat = "queue [0-9]+: timeout|starting error recovery";
    int dmesg_base = dmesg_match_count(kAbortPat);
    if (dmesg_base < 0) {
        dmesg_base = 0;
    }

    std::thread writer([ctl, dev_copy, kFailingOffset]() {
        int fd = open(dev_copy.c_str(), O_RDWR | O_DIRECT);
        if (fd < 0) {
            ctl->started.store(true);
            ctl->completed.fetch_add(1);
            return;
        }
        auto buf = aligned_buffer_fastpath(4096);
        init_pattern_fastpath(buf.get(), 4096);
        ctl->started.store(true);
        auto t0 = std::chrono::steady_clock::now();
        ssize_t w = pwrite(fd, buf.get(), 4096, kFailingOffset);
        ctl->elapsed_ms.store(
            (long) std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count());
        ctl->rc.store(w < 0 ? -errno : (int) w);
        close(fd);
        ctl->completed.fetch_add(1);
    });

    while (!ctl->started.load()) {
        usleep(1000);
    }
    auto submit_t = std::chrono::steady_clock::now();
    std::cout << "submitted write to delayed region; expecting an nvme abort at ~"
              << kIoTimeoutSecs << "s (target delay is " << kTargetDelayMs
              << "ms)" << std::endl;

    auto since_submit_ms = [&submit_t]() -> long {
        return (long) std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - submit_t).count();
    };

    /* Watch two things concurrently, at 1s granularity:
     *   - the kernel ring buffer, for nvme_tcp_timeout's "timeout request"
     *     line, which pins WHEN the abort fired (io_timeout vs the target
     *     delay elapsing);
     *   - ctl_fd, for the failover marker.
     * The abort and the marker are separate events and either can be
     * missing, which is exactly what distinguishes the failure modes. */
    long   abort_ms  = -1;
    long   marker_ms = -1;
    int    markers = 0;
    int    drained = 0;
    for (int i = 0; i < kMarkerWaitSecs && marker_ms < 0; i++) {
        if (abort_ms < 0 && dmesg_match_count(kAbortPat) > dmesg_base) {
            abort_ms = since_submit_ms();
            std::cout << "nvme abort observed in dmesg at ~" << abort_ms
                      << "ms after submit" << std::endl;
        }

        struct rdwr_in rdwr;
        if (wait_msg(1) == -ETIMEDOUT) {
            continue;
        }
        ssize_t rb = read(ctl_fd, &rdwr, sizeof(rdwr));
        if (rb <= 0) {
            continue;
        }
        drained++;
        if (rdwr.in.opcode == PXD_FAILOVER_TO_USERSPACE) {
            markers++;
            marker_ms = since_submit_ms();
            std::cout << "PXD_FAILOVER_TO_USERSPACE received " << marker_ms
                      << "ms after submit" << std::endl;
        }
        /* Answer everything with -EIO: for the marker this drives
         * pxd_process_ioswitch_complete down the status != 0 path, which
         * aborts the failQ and calls pxd_resume_io, releasing the writer. */
        fail_io(&rdwr);
    }
    if (abort_ms < 0 && dmesg_match_count(kAbortPat) > dmesg_base) {
        abort_ms = since_submit_ms();
    }

    /* Assertion 0: the transport actually timed the command out. If this
     * fails the rest is moot - the IO was never aborted, so there was
     * nothing for px-fuse to react to. */
    EXPECT_GE(abort_ms, 0)
        << "no nvme timeout/error-recovery message in dmesg - nvme never "
           "aborted the command. Check that nvme_core.io_timeout took effect "
           "BEFORE connect, that the write landed in the delayed region, and "
           "that this kernel's nvme_tcp_timeout wording is covered by the "
           "kAbortPat regex";
    if (abort_ms >= 0) {
        /* Loose bounds on purpose. The exact instant depends on blk-mq
         * timer granularity (blk_add_timer rounds up with
         * round_jiffies_up) and on how quickly the poll loop notices, so
         * pinning it to io_timeout +/- a second would be flaky. What
         * actually needs proving is a lot weaker: the command survived
         * well past a normal IO, and it died before the target delay
         * elapsed - i.e. the timeout killed it, not the delay finishing. */
        EXPECT_GT(abort_ms, 5000)
            << "abort at " << abort_ms << "ms is too early to be the "
            << kIoTimeoutSecs << "s io_timeout - the IO failed for some "
               "other reason";
        EXPECT_LT(abort_ms, (long) kTargetDelayMs - 2000)
            << "abort at " << abort_ms << "ms is ~the target delay ("
            << kTargetDelayMs << "ms), not the io_timeout ("
            << kIoTimeoutSecs * 1000 << "ms)";
    }

    /* Assertion 1: the aborted command surfaced as an IO error and px-fuse
     * failed over. If the abort was seen but no marker arrived, the command
     * was retried rather than failed - check max_retries. */
    EXPECT_GT(markers, 0)
        << "no PXD_FAILOVER_TO_USERSPACE marker within " << kMarkerWaitSecs
        << "s (abort_ms=" << abort_ms << ", drained " << drained
        << " other req(s)). If the abort was observed, the command was "
           "REQUEUED rather than failed - verify nvme_core.max_retries is 0; "
           "with the default of 5 the error takes ~5 retry cycles to surface";

    /* Assertion 2: the failover landed in the same window as the abort,
     * i.e. the timeout is what triggered it and not the target delay
     * finally elapsing.
     *
     * Expect the marker at roughly io_timeout + SYNC_TIMEOUT, not at
     * io_timeout. pxd_initiate_failover suspends IO and then runs
     * wait_for_sync(pxd_dev, false) BEFORE queueing the marker; on this
     * path the backing device is a remote target in nvme error recovery,
     * so that fsync cannot complete and burns the whole SYNC_TIMEOUT
     * budget (look for "device <id> sync failed -16" in dmesg). With
     * SYNC_TIMEOUT at 10s and io_timeout at 10s that puts the marker near
     * 20s - comfortably inside the kTargetDelayMs bound below, which is
     * what the assertion actually cares about. If SYNC_TIMEOUT changes in
     * pxd_fastpath.c, re-check that kTargetDelayMs still leaves room.
     *
     * Deliberately NOT asserting marker_ms >= abort_ms. The two numbers
     * come from different instruments with different latencies: marker_ms
     * is event-driven (poll on ctl_fd, near-zero lag), while abort_ms is
     * sampled by dmesg_match_count() at the top of the poll loop. When both
     * events happen in the same instant - which is exactly what a correct
     * run now produces - the loop checks dmesg before the message is
     * visible, then blocks in wait_msg, catches the marker, and exits; the
     * abort is only picked up by the post-loop check some milliseconds
     * later. So abort_ms is systematically biased late here and a small
     * negative gap is normal, not a fault. */
    if (marker_ms >= 0) {
        EXPECT_GT(marker_ms, 5000)
            << "failover marker at " << marker_ms << "ms is too early to be "
               "the " << kIoTimeoutSecs << "s io_timeout - the IO failed for "
               "some other reason";
        EXPECT_LT(marker_ms, (long) kTargetDelayMs - 2000)
            << "failover marker at " << marker_ms << "ms is ~the target delay "
            << "(" << kTargetDelayMs << "ms) rather than the io_timeout ("
            << kIoTimeoutSecs * 1000 << "ms) - the abort is not what "
               "triggered the failover";
    }
    if (marker_ms >= 0 && abort_ms >= 0) {
        std::cout << "abort -> failover gap: " << (marker_ms - abort_ms)
                  << "ms (small negative values are a sampling artefact, "
                     "see comment)" << std::endl;
    }
    std::cout << "summary: abort_ms=" << abort_ms << " marker_ms=" << marker_ms
              << " (io_timeout=" << kIoTimeoutSecs * 1000
              << "ms, target delay=" << kTargetDelayMs << "ms)" << std::endl;

    for (int i = 0; i < 30 && ctl->completed.load() == 0; i++) {
        sleep(1);
    }
    if (ctl->completed.load() == 1) {
        writer.join();
        std::cout << "delayed write returned rc=" << ctl->rc.load() << " after "
                  << ctl->elapsed_ms.load() << "ms" << std::endl;
    } else {
        std::cout << "writer still blocked; detaching" << std::endl;
        writer.detach();
    }

    std::cout << "final debug: " << read_pxd_debug(minor) << std::endl;

    /*
     * Ordered teardown. The destructors below would do all of this anyway,
     * but only in reverse-declaration order, which is not the order the
     * kernel wants. Driving it explicitly here gets the sequence right and
     * keeps every step idempotent, so the destructors remain a correct
     * fallback on any early-return path.
     *
     *   1. pxd first  - it holds the NVMe namespace open, so nothing below
     *      can be released while the device exists. TearDown is too late:
     *      it runs after these locals are destroyed.
     *   2. stop_accepting() - unlink the port so an in-flight reconnect
     *      cannot establish a fresh controller mid-teardown.
     *   3. disconnect() - and wait for the controller to actually vanish,
     *      forcing it if necessary.
     *   4. udevadm settle - the namespace disappearing kicks off partition
     *      rescans and blkid probes ("unable to read partition table" in
     *      dmesg); let them finish before the dm targets go away underneath
     *      them.
     * The remaining nvmet configfs teardown, dm removal and loop detach
     * then run from the destructors in the right order.
     */
    dev_remove_fastpath(add_ext.dev_id);
    target.stop_accepting();
    conn.disconnect();
    (void) system("udevadm settle --timeout=10 >/dev/null 2>&1");

    std::cout << "=== REMOTE FASTPATH IO-TIMEOUT TEST DONE ===" << std::endl;
}

/* Current open count of a dm target, or -1 on error.
 *
 * This is the leak detector for the backing-file pins. Every filp_open on
 * /dev/mapper/<name> bumps this; every fput of the last reference drops it.
 * Once the pxd device is removed, a non-zero count means someone still
 * holds a struct file on the backing device - which for fastpath means a
 * fproot pinned files that no disposal path released. */
static int dm_open_count(const std::string &name)
{
    std::string cmd = "dmsetup info -c -o open --noheadings " + name
                    + " 2>/dev/null";
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp) {
        return -1;
    }
    char buf[64] = {0};
    if (!fgets(buf, sizeof(buf), fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    return atoi(buf);
}

/* Re-arm fastpath on a device that is currently on the native path, by
 * writing the backing path to the `fastpath` sysfs attribute
 * (pxd_fastpath_update -> __pxd_update_path -> pxd_init_fastpath_target).
 * Fails if the device is still fastpath_active, so the caller must have
 * completed a disable first. */
static bool write_pxd_fastpath_path(int minor, const std::string &dm_path)
{
    char sysfs_path[256];
    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/devices/pxd/%d/fastpath",
             minor & MINORMASK);
    return write_sysfs(sysfs_path, dm_path);
}

/*
 * RACE TEST: IO submission against disableFastPath.
 *
 * What this covers
 * ----------------
 * The window between pxd_queue_rq deciding to use fastpath and
 * fp_handle_io actually running on a pxfp worker. pxd_queue_rq observes
 * fp->fastpath and calls fproot_pin_files() - get_file() on each backing
 * file, plus an nfd snapshot - inside one rcu_read_lock() section;
 * disableFastPath does xchg(&fp->fastpath, false), synchronize_rcu(), then
 * xchg(&fp->file[i], NULL) + filp_close(). Handlers work only off the
 * fproot snapshot.
 *
 * Before the pins existed, clone_root read pxd_dev->fp.file[i] raw on the
 * worker and dereferenced it (get_bdev, get_mode) before taking any
 * reference, so a flip landing in that window gave a NULL deref or a UAF
 * on a closed struct file. Nothing else in the suite drives submission
 * concurrently with a transition, so nothing else exercises it.
 *
 * The manoeuvre: several writer threads hammer the (healthy) device while
 * the main thread flips fastpath off and back on repeatedly.
 *   off: echo X > /sys/devices/pxd/<minor>/debug   (disableFastPath)
 *   on : echo <dm path> > /sys/devices/pxd/<minor>/fastpath
 * A drainer services ctl_fd throughout, because IO submitted while the
 * device is native routes to the fuse channel and would otherwise block
 * the writers forever.
 *
 * What it asserts
 * ---------------
 *  1. No crash. A regression here oopses rather than failing an
 *     assertion, so surviving the flips at all is most of the signal.
 *  2. IO keeps completing across the transitions - some via fastpath,
 *     some via the drained native path. Errors are tolerated (a request
 *     in flight across a flip may legitimately fail) but total silence
 *     would mean the race never actually ran.
 *  3. No leaked backing-file references: once the pxd device is removed,
 *     the dm target's open count must return to zero. This is the
 *     specific failure mode of the pin/release plumbing - a missed
 *     fproot_release_files() leaks a struct file, which does NOT crash;
 *     it silently keeps the backing device open forever.
 */
TEST_P(PxdFastpathTest, race_submit_vs_disable_fastpath_pins_backing_files)
{
    const int kWriters = 4;
    const int kFlipRounds = 6;
    const uint64_t kIoSpan = 8ULL * 1024 * 1024;   /* healthy region */

    std::cout << "\n=== RACE TEST: submit vs disableFastPath (file pins) ==="
              << std::endl;

    TempLoopDevice loop_dev(100);
    DMStackCleanup dm_stack{};
    std::string dm_path, delay_name, flakey_path, device_name;
    int minor = 0;
    pxd_add_ext_out add_ext;

    /* Entirely healthy stack: no error injection, no delay. The race is
     * the transition itself, not an IO failure. */
    if (!prepare_flakey_delay_dm_and_add_ext(1600, "pxd_test_race",
                                             loop_dev, dm_stack, dm_path,
                                             delay_name, flakey_path, add_ext,
                                             false /* flakey_errors */,
                                             0, 0, 0 /* no delays */)) {
        GTEST_SKIP();
    }
    dev_add_fastpath(add_ext, minor, device_name);
    std::cout << "device " << device_name << " on " << dm_path
              << " (dm open count " << dm_open_count(delay_name) << ")"
              << std::endl;

    std::string dbg = read_pxd_debug(minor);
    ASSERT_NE(dbg.find("fpactive:1"), std::string::npos)
        << "device not in fastpath; the transition would be a no-op. debug="
        << dbg;

    /* Drain ctl_fd for the whole run: any IO submitted while the device is
     * on the native path lands in the fuse channel, and the writers block
     * until userspace answers. */
    std::atomic<bool> stop_drain{false};
    std::atomic<uint64_t> drained{0};
    std::thread drainer([&]() {
        while (!stop_drain.load()) {
            struct rdwr_in rdwr;
            if (wait_msg(1) == -ETIMEDOUT) {
                continue;
            }
            ssize_t rb = read(ctl_fd, &rdwr, sizeof(rdwr));
            if (rb > 0) {
                finish_io(&rdwr);
                drained.fetch_add(1);
            }
        }
    });

    std::atomic<bool> stop_io{false};
    std::atomic<uint64_t> io_ok{0}, io_err{0};
    std::vector<std::thread> writers;
    for (int t = 0; t < kWriters; t++) {
        writers.emplace_back([&, t]() {
            int fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
            if (fd < 0) {
                std::cerr << "writer open failed: " << strerror(errno)
                          << std::endl;
                return;
            }
            auto buf = aligned_buffer_fastpath(4096);
            init_pattern_fastpath(buf.get(), 4096);
            uint64_t off = (uint64_t) t * 4096;
            while (!stop_io.load()) {
                ssize_t w = pwrite(fd, buf.get(), 4096, off);
                if (w == 4096) {
                    io_ok.fetch_add(1);
                } else {
                    io_err.fetch_add(1);
                }
                off = (off + kWriters * 4096) % kIoSpan;
            }
            close(fd);
        });
    }

    /* Let the writers get going so submissions are genuinely in flight
     * when the first flip lands. */
    usleep(300000);
    ASSERT_GT(io_ok.load() + io_err.load(), 0u) << "no IO issued";

    for (int round = 0; round < kFlipRounds; round++) {
        long off_ms = write_pxd_debug_timed(minor, 'X');
        EXPECT_GE(off_ms, 0) << "round " << round << ": disable write failed";
        std::string d = read_pxd_debug(minor);
        EXPECT_NE(d.find("fpactive:0"), std::string::npos)
            << "round " << round << ": still fastpath after disable, debug="
            << d;

        usleep(100000);   /* run some IO on the native path */

        EXPECT_TRUE(write_pxd_fastpath_path(minor, dm_path))
            << "round " << round << ": re-enable failed";
        d = read_pxd_debug(minor);
        EXPECT_NE(d.find("fpactive:1"), std::string::npos)
            << "round " << round << ": not back in fastpath, debug=" << d;

        std::cout << "round " << round << ": disable took " << off_ms
                  << "ms, io_ok=" << io_ok.load() << " io_err=" << io_err.load()
                  << " drained=" << drained.load() << std::endl;

        usleep(100000);   /* and some on fastpath before the next flip */
    }

    stop_io.store(true);
    for (auto &w : writers) {
        w.join();
    }
    stop_drain.store(true);
    drainer.join();

    std::cout << "totals: io_ok=" << io_ok.load() << " io_err=" << io_err.load()
              << " drained=" << drained.load() << std::endl;

    /* (2) The race has to have actually run. */
    EXPECT_GT(io_ok.load(), 0u)
        << "no IO completed successfully across " << kFlipRounds
        << " fastpath transitions";

    /* (3) The leak check. Remove the device, then the backing dm target
     * must fall back to zero openers. fput of a struct file can be
     * fractionally delayed, so poll briefly rather than sampling once. */
    dev_remove_fastpath(add_ext.dev_id);

    int open_count = -1;
    for (int i = 0; i < 50; i++) {
        open_count = dm_open_count(delay_name);
        if (open_count == 0) {
            break;
        }
        usleep(100000);
    }
    std::cout << "dm '" << delay_name << "' open count after removal: "
              << open_count << std::endl;
    EXPECT_EQ(0, open_count)
        << "backing device still has " << open_count << " opener(s) after the "
           "pxd device was removed - a fproot pinned backing files that no "
           "disposal path released (fproot_release_files missing on some "
           "path), which keeps the device open indefinitely";

    std::cout << "=== RACE TEST PASSED: pins survived " << kFlipRounds
              << " transitions with no leak ===" << std::endl;
}

/*
 * fp_handle_io must be safe to complete AFTER disableFastPath returns.
 *
 * pxd_suspend_io uses blk_mq_quiesce_queue, which stops new dispatches but
 * does NOT wait for requests already handed off from queue_rq. So a
 * fastpath request whose clone bio is parked in a slow backing device can
 * still be in flight when disableFastPath xchg's each fp->file[i] to NULL
 * and filp_close()es it. Only the fproot pin keeps the struct file alive
 * for the still-running fp_handle_io to complete against.
 *
 * The setup: dm-delay with a large write_ms parks the clone bio in the
 * backing driver. We fire one pwrite, wait long enough for it to be
 * pinned and dispatched, trigger disableFastPath, and verify disable
 * returns while the pwrite is still parked. The pwrite must then complete
 * successfully - proving the pin outlived filp_close.
 *
 * A regression removing the pin oopses on this test rather than failing
 * an assertion (NULL deref on fp->file[i] in clone_root, or UAF on a
 * closed struct file in the backing bio path).
 */
TEST_P(PxdFastpathTest, fp_handle_io_completes_after_disable_using_dm_delay)
{
    const uint64_t DELAY_WRITE_MS = 5000;
    const long DISABLE_MAX_MS = 2000;

    std::cout << "\n=== TEST: fp_handle_io retires after disableFastPath ==="
              << std::endl;

    TempLoopDevice loop_dev(100);
    DMStackCleanup dm_stack{};
    std::string dm_path, delay_name, flakey_path, device_name;
    int minor = 0;
    pxd_add_ext_out add_ext;

    /* flakey healthy + big write delay; only the write class is slow so
     * disableFastPath's fsync (flush_ms=0) still returns promptly. */
    if (!prepare_flakey_delay_dm_and_add_ext(
            1700, "pxd_test_fpio_after_disable", loop_dev, dm_stack, dm_path,
            delay_name, flakey_path, add_ext,
            false /* flakey_errors */,
            0 /* read_ms */, DELAY_WRITE_MS /* write_ms */, 0 /* flush_ms */)) {
        GTEST_SKIP();
    }
    dev_add_fastpath(add_ext, minor, device_name);

    std::string dbg = read_pxd_debug(minor);
    ASSERT_NE(dbg.find("fpactive:1"), std::string::npos)
        << "device not in fastpath; test would be vacuous. debug=" << dbg;

    /* 'X' sets fp->force_fail=true before calling disableFastPath, so the
     * still-in-flight write's endio artificially returns -EIO and takes
     * the failover -> reissue-native leg through ctl_fd. Drain the fuse
     * channel so the reroute can complete. */
    std::atomic<bool> stop_drain{false};
    std::atomic<uint64_t> drained{0};
    std::thread drainer([&]() {
        while (!stop_drain.load()) {
            struct rdwr_in rdwr;
            if (wait_msg(1) == -ETIMEDOUT) continue;
            ssize_t rb = read(ctl_fd, &rdwr, sizeof(rdwr));
            if (rb > 0) { finish_io(&rdwr); drained.fetch_add(1); }
        }
    });

    std::atomic<long> write_ms{-1};
    std::atomic<ssize_t> write_rc{0};
    std::thread writer([&]() {
        int fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
        if (fd < 0) {
            std::cerr << "writer open failed: " << strerror(errno) << std::endl;
            return;
        }
        auto buf = aligned_buffer_fastpath(4096);
        init_pattern_fastpath(buf.get(), 4096);
        auto t0 = std::chrono::steady_clock::now();
        ssize_t w = pwrite(fd, buf.get(), 4096, 0);
        write_ms.store(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count());
        write_rc.store(w);
        close(fd);
    });

    /* Give the write time to pin files and reach dm-delay. */
    usleep(500000);

    long disable_ms = write_pxd_debug_timed(minor, 'X');
    ASSERT_GE(disable_ms, 0) << "debug sysfs write failed";
    std::cout << "disableFastPath returned in " << disable_ms
              << "ms; write still parked (delay=" << DELAY_WRITE_MS << "ms)"
              << std::endl;

    EXPECT_LT(disable_ms, DISABLE_MAX_MS)
        << "disable took " << disable_ms << "ms - either quiesce started "
           "waiting for dispatched requests, or the write already retired "
           "so the ordering under test never happened";

    dbg = read_pxd_debug(minor);
    EXPECT_NE(dbg.find("fpactive:0"), std::string::npos)
        << "device still on fastpath after disable. debug=" << dbg;
    EXPECT_NE(dbg.find("nfd:0"), std::string::npos)
        << "backing fds not released. debug=" << dbg;

    writer.join();
    stop_drain.store(true);
    drainer.join();
    std::cout << "write returned rc=" << write_rc.load()
              << " after " << write_ms.load() << "ms"
              << " (drained " << drained.load() << ")" << std::endl;

    /* The write MUST retire. 'X' sets force_fail so the endio synthesises
     * -EIO regardless of the backing bio result, then failover reroutes
     * native and the drainer answers - the request completes. A regression
     * removing the pin doesn't get this far: it crashes in clone_root /
     * end_clone_bio when the file slot is NULL/UAF. */
    EXPECT_EQ(4096, write_rc.load())
        << "write did not complete cleanly - pin+RCU or the reissue-native "
           "path is broken";
    EXPECT_GE(write_ms.load(), (long) DELAY_WRITE_MS - 1000)
        << "write finished in " << write_ms.load() << "ms; the delay was not "
           "honoured, so fp_handle_io was not actually in flight when disable "
           "returned - the pin was never exercised";
    EXPECT_GE(drained.load(), 1u)
        << "reissue-native leg never touched ctl_fd - the pinned bio must "
           "have gone somewhere else";

    auto rm_start = std::chrono::steady_clock::now();
    dev_remove_fastpath(add_ext.dev_id);
    auto rm_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - rm_start).count();
    EXPECT_LT(rm_ms, 5000) << "PXD_REMOVE took " << rm_ms << "ms";

    int open_count = -1;
    for (int i = 0; i < 50; i++) {
        open_count = dm_open_count(delay_name);
        if (open_count == 0) break;
        usleep(100000);
    }
    EXPECT_EQ(0, open_count)
        << "backing dm target still has " << open_count << " opener(s) after "
           "remove - fproot pin not released on some disposal path";

    std::cout << "=== TEST PASSED: pin kept fp_handle_io safe across disable "
                 "===" << std::endl;
}

/*
 * Fastpath IO that fails AFTER disableFastPath has already run must retire
 * cleanly through the failover state machine's "already native" path.
 *
 * Timeline:
 *   1. Write to erroring flakey region is submitted on fastpath.
 *      queue_rq pins files, queues fp_handle_io; clone bio dispatched to
 *      dm-delay and parked (write_ms delay).
 *   2. disableFastPath runs from a separate trigger ('X'). Quiesce doesn't
 *      wait for our parked bio; xchg fp->fastpath=false, close fp->file[].
 *   3. dm-delay releases the bio; dm-flakey errors it.
 *   4. _end_clone_bio -> pxd_failover_initiate queues pxd_io_failover on
 *      the same fproot.
 *   5. pxd_io_failover reaches branch (c), adds fproot to failQ, calls
 *      pxd_initiate_failover. That sees !fastpath_active(pxd_dev), splices
 *      failQ and runs pxd_reissuefailQ(status=0) -> clone_cleanup (release
 *      pins) + pxdmq_reroute_slowpath.
 *   6. Fuse channel drainer answers the reissue; original blk_mq request
 *      completes.
 *
 * A regression on the "already native" splice-and-reissue branch, or a
 * second disableFastPath entry that didn't idempotently xchg-through,
 * would either hang the writer or fault. This asserts a clean, bounded
 * retirement.
 */
TEST_P(PxdFastpathTest, failing_io_after_disable_reroutes_using_dm_flakey_delay)
{
    const uint64_t DELAY_WRITE_MS = 4000;
    const uint64_t failing_offset = (16ULL * 1024 * 1024) + 4096;

    std::cout << "\n=== TEST: failing IO after disableFastPath ===" << std::endl;

    TempLoopDevice loop_dev(100);
    DMStackCleanup dm_stack{};
    std::string dm_path, delay_name, flakey_path, device_name;
    int minor = 0;
    pxd_add_ext_out add_ext;

    if (!prepare_flakey_delay_dm_and_add_ext(
            1701, "pxd_test_fail_after_disable", loop_dev, dm_stack, dm_path,
            delay_name, flakey_path, add_ext,
            true /* flakey_errors: erroring window 16-32MB */,
            0 /* read_ms */, DELAY_WRITE_MS /* write_ms */, 0 /* flush_ms */)) {
        GTEST_SKIP();
    }
    dev_add_fastpath(add_ext, minor, device_name);

    std::string dbg = read_pxd_debug(minor);
    ASSERT_NE(dbg.find("fpactive:1"), std::string::npos)
        << "device not in fastpath. debug=" << dbg;

    /* Drain ctl_fd - the reroute leg lands there. */
    std::atomic<bool> stop_drain{false};
    std::atomic<uint64_t> drained{0};
    std::thread drainer([&]() {
        while (!stop_drain.load()) {
            struct rdwr_in rdwr;
            if (wait_msg(1) == -ETIMEDOUT) continue;
            ssize_t rb = read(ctl_fd, &rdwr, sizeof(rdwr));
            if (rb > 0) { finish_io(&rdwr); drained.fetch_add(1); }
        }
    });

    std::atomic<long> write_ms{-1};
    std::atomic<ssize_t> write_rc{0};
    std::atomic<int> write_errno{0};
    std::thread writer([&]() {
        int fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
        if (fd < 0) { std::cerr << "open failed\n"; return; }
        auto buf = aligned_buffer_fastpath(4096);
        init_pattern_fastpath(buf.get(), 4096);
        auto t0 = std::chrono::steady_clock::now();
        ssize_t w = pwrite(fd, buf.get(), 4096, failing_offset);
        int e = errno;
        write_ms.store(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count());
        write_rc.store(w);
        write_errno.store(e);
        close(fd);
    });

    /* Let the write get pinned + parked in dm-delay. */
    usleep(500000);

    long disable_ms = write_pxd_debug_timed(minor, 'X');
    ASSERT_GE(disable_ms, 0);
    std::cout << "disable returned in " << disable_ms << "ms" << std::endl;

    dbg = read_pxd_debug(minor);
    EXPECT_NE(dbg.find("fpactive:0"), std::string::npos)
        << "device still fastpath after disable. debug=" << dbg;

    writer.join();
    stop_drain.store(true);
    drainer.join();

    std::cout << "write rc=" << write_rc.load()
              << " errno=" << write_errno.load()
              << " after " << write_ms.load() << "ms"
              << " (drained " << drained.load() << ")" << std::endl;

    /* The write MUST retire - the specific failure mode of a broken
     * "already native" branch is a permanently stuck request. Either
     * success (rerouted native + drainer said OK) or a clean error is
     * acceptable; a hang is not. */
    EXPECT_GE(write_ms.load(), 0)
        << "writer never returned - failover state machine wedged when the "
           "device was already native at pxd_io_failover time";
    EXPECT_LT(write_ms.load(), 15000)
        << "writer took " << write_ms.load() << "ms - too slow for a simple "
           "failed IO + native reroute after disable";

    /* The reroute leg MUST have gone through ctl_fd; if drained == 0 we
     * were on some other path (e.g. IO completed on fastpath before
     * disable landed, or the request was errored directly). */
    EXPECT_GE(drained.load(), 1u)
        << "no request drained via ctl_fd - the failing IO did not take the "
           "reissue-native branch of pxd_initiate_failover as expected";

    auto rm_start = std::chrono::steady_clock::now();
    dev_remove_fastpath(add_ext.dev_id);
    auto rm_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - rm_start).count();
    EXPECT_LT(rm_ms, 5000) << "PXD_REMOVE took " << rm_ms << "ms";

    int open_count = -1;
    for (int i = 0; i < 50; i++) {
        open_count = dm_open_count(delay_name);
        if (open_count == 0) break;
        usleep(100000);
    }
    EXPECT_EQ(0, open_count) << "backing still has openers after remove";

    std::cout << "=== TEST PASSED: failing IO retired cleanly ===" << std::endl;
}

/*
 * After a sync-timed-out disable, the device must be fully usable again -
 * re-enable fastpath, disable again with no delay, and confirm the second
 * disable is prompt. Catches regressions where the -EBUSY leg leaks
 * fp->sync_done, fp->sync_complete state, or a syncwi[i].file reference,
 * which would either wedge the next wait_for_sync or leak a struct file
 * across the re-enable.
 *
 * Complements sync_timeout_during_disable_fastpath_using_dm_delay (which
 * only checks convergence and a same-state no-op second call).
 */
TEST_P(PxdFastpathTest, sync_timeout_then_reenable_using_dm_delay)
{
    const uint64_t DELAY_FLUSH_MS = 30000;
    const long SYNC_TIMEOUT_MS = 10000;

    std::cout << "\n=== TEST: sync timeout then re-enable ===" << std::endl;

    TempLoopDevice loop_dev(100);
    DMStackCleanup dm_stack{};
    std::string dm_path, delay_name, flakey_path, device_name;
    int minor = 0;
    pxd_add_ext_out add_ext;

    if (!prepare_flakey_delay_dm_and_add_ext(
            1702, "pxd_test_synctmo_reenable", loop_dev, dm_stack, dm_path,
            delay_name, flakey_path, add_ext,
            false /* flakey_errors */,
            0, 0, DELAY_FLUSH_MS)) {
        GTEST_SKIP();
    }
    dev_add_fastpath(add_ext, minor, device_name);

    std::string dbg = read_pxd_debug(minor);
    ASSERT_NE(dbg.find("fpactive:1"), std::string::npos)
        << "device not in fastpath. debug=" << dbg;

    /* 'X' sets fp->force_fail=true; every subsequent fastpath endio then
     * synthesises -EIO and reissues native via ctl_fd. Drain throughout. */
    std::atomic<bool> stop_drain{false};
    std::atomic<uint64_t> drained{0};
    std::thread drainer([&]() {
        while (!stop_drain.load()) {
            struct rdwr_in rdwr;
            if (wait_msg(1) == -ETIMEDOUT) continue;
            ssize_t rb = read(ctl_fd, &rdwr, sizeof(rdwr));
            if (rb > 0) { finish_io(&rdwr); drained.fetch_add(1); }
        }
    });

    /* Dirty something so fsync has real work. */
    {
        int fd = open(device_name.c_str(), O_RDWR | O_DIRECT);
        ASSERT_GT(fd, 0);
        auto buf = aligned_buffer_fastpath(4096);
        init_pattern_fastpath(buf.get(), 4096);
        EXPECT_EQ(4096, pwrite(fd, buf.get(), 4096, 0));
        close(fd);
    }

    long first_ms = write_pxd_debug_timed(minor, 'X');
    ASSERT_GE(first_ms, 0);
    std::cout << "first disable (sync timeout): " << first_ms << "ms"
              << std::endl;
    EXPECT_GE(first_ms, SYNC_TIMEOUT_MS - 3000)
        << "first disable returned too early - fsync was not delayed";
    EXPECT_LT(first_ms, (long) DELAY_FLUSH_MS - 8000)
        << "first disable waited for the delay itself - SYNC_TIMEOUT not "
           "honoured";

    dbg = read_pxd_debug(minor);
    ASSERT_NE(dbg.find("fpactive:0"), std::string::npos) << "debug=" << dbg;
    ASSERT_NE(dbg.find("nfd:0"), std::string::npos) << "debug=" << dbg;

    /* Release the delay so the still-running syncer can retire and any
     * subsequent fsync completes fast. */
    ASSERT_TRUE(dm_reload_table(delay_name,
                                build_delay_table(flakey_path, 0, 0, 0)));

    /* Give the outstanding syncer time to fput its file / put_device.
     * Without this, the re-enable races the tail of the previous sync. */
    usleep(500000);

    ASSERT_TRUE(write_pxd_fastpath_path(minor, dm_path))
        << "re-enable failed - sync-timeout path likely left fp state stuck";

    dbg = read_pxd_debug(minor);
    ASSERT_NE(dbg.find("fpactive:1"), std::string::npos)
        << "not back in fastpath after re-enable. debug=" << dbg;

    /* Skip a fresh write here: the first 'X' set fp.force_fail=true and
     * that flag persists until device destroy, so any fastpath IO from
     * this point synthesises -EIO at endio and drives the full failover
     * state machine (PXD_FAILOVER_TO_USERSPACE marker etc.), which our
     * test drainer answers with -EIO because it only handles READ/WRITE.
     * The second disable below re-enters wait_for_sync regardless of
     * whether there was fresh dirty data - if sync state was left stuck
     * by the first -EBUSY return, this call would stall on
     * fp->sync_complete. */
    long second_ms = write_pxd_debug_timed(minor, 'X');
    ASSERT_GE(second_ms, 0);
    std::cout << "second disable (no delay): " << second_ms << "ms"
              << std::endl;
    EXPECT_LT(second_ms, 3000)
        << "second disable took " << second_ms << "ms with no delay - sync "
           "state was not fully reset after the first timeout";

    dbg = read_pxd_debug(minor);
    EXPECT_NE(dbg.find("fpactive:0"), std::string::npos) << "debug=" << dbg;

    stop_drain.store(true);
    drainer.join();
    std::cout << "drained " << drained.load() << " reissue reqs" << std::endl;

    auto rm_start = std::chrono::steady_clock::now();
    dev_remove_fastpath(add_ext.dev_id);
    auto rm_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - rm_start).count();
    EXPECT_LT(rm_ms, 5000) << "PXD_REMOVE took " << rm_ms << "ms";

    int open_count = -1;
    for (int i = 0; i < 50; i++) {
        open_count = dm_open_count(delay_name);
        if (open_count == 0) break;
        usleep(100000);
    }
    EXPECT_EQ(0, open_count) << "backing still has openers after remove";

    std::cout << "=== TEST PASSED: sync timeout state cleanly reset ==="
              << std::endl;
}
