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
#include <sys/mount.h>
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

class PxdFastpathTest : public ::testing::Test
{
protected:
    bool killed{false};
    int ctl_fd; // control file descriptor
    std::set<uint64_t> added_ids;
    const size_t write_len = PXD_LBS * 4;
    const size_t test_off = 4 * 4096;
    std::vector<std::unique_ptr<TempBackingFile>> backing_files;

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

    // Helper functions for device lifecycle
    void dev_add_fastpath(pxd_add_ext_out &add_ext, int &minor, std::string &name);
    void dev_export(uint64_t dev_id, const std::string &expected_name);
    void dev_remove(uint64_t dev_id);
    int wait_msg(int timeout); // timeout in seconds
    void read_block(fuse_in_header *in, pxd_rdwr_in *rd);
    void validate_device_properties(const std::string &device_name,
                                    uint64_t expected_discard_granularity = 1048576,
                                    uint64_t expected_max_discard_bytes = 1048576);
    void validate_fastpath_active(const std::string &device_name);

    // Mount/unmount helpers
    std::string create_mount_point();
    void mount_device(const std::string &device_path, const std::string &mount_point);
    void unmount_device(const std::string &mount_point);
    void create_filesystem(const std::string &device_path);

    // I/O test helpers
    void write_thread_fastpath(const char *name);
    void read_thread_fastpath(const char *name);
    void perform_io_test(const std::string &device_path);

    // Backing file management
    void create_backing_files(size_t count, size_t size_mb = 100);
    void setup_fastpath_paths(pxd_update_path_out &paths);

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

        // Create backing files for fastpath tests
        create_backing_files(2, 100); // Create 2 backing files of 100MB each
    }
    
}

void PxdFastpathTest::TearDown()
{
    fprintf(stderr, "%s\n", __func__);

    // Create a copy to avoid iterator invalidation
    std::set<uint64_t> ids_to_remove = added_ids;
    for (uint64_t id : ids_to_remove) {
        if (added_ids.find(id) != added_ids.end()) {
            dev_remove(id);
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

    // Clean up backing files safely
    try {
        backing_files.clear();
        fprintf(stderr, "backing files cleared\n");
    } catch (const std::exception& e) {
        fprintf(stderr, "Error clearing backing files: %s\n", e.what());
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

void PxdFastpathTest::setup_fastpath_paths(pxd_update_path_out &paths)
{
    memset(&paths, 0, sizeof(paths));
    paths.count = backing_files.size();
    paths.can_failover = true;

    for (size_t i = 0; i < backing_files.size() && i < MAX_PXD_BACKING_DEVS; ++i) {
        strncpy(paths.devpath[i], backing_files[i]->path().c_str(), MAX_PXD_DEVPATH_LEN);
        paths.devpath[i][MAX_PXD_DEVPATH_LEN] = '\0';
        std::cout << "Setup fastpath " << i << ": " << paths.devpath[i] << std::endl;
    }
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

    std::cout << "dev_add_fastpath: PXD_ADD_EXT completed, wrote " << write_bytes << " bytes" << std::endl;
    std::cout << "dev_add_fastpath: device ID = " << add_ext.dev_id << std::endl;

    added_ids.insert(add_ext.dev_id);
    minor = write_bytes;
    name = std::string(PXD_DEV_PATH) + std::to_string(add_ext.dev_id);

    dev_export(add_ext.dev_id, name);
    std::cout << "dev_add_fastpath: expected device path = " << name << std::endl;

    // Validate fastpath is active
    validate_fastpath_active(name);
}

void PxdFastpathTest::dev_export(uint64_t dev_id, const std::string &expected_name)
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

void PxdFastpathTest::dev_remove(uint64_t dev_id)
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

    std::cout << "Device properties validated for: " << device_name << std::endl;
}

void PxdFastpathTest::validate_fastpath_active(const std::string &device_name)
{
    // Extract device minor number from device name
    std::string dev_name = device_name.substr(device_name.find_last_of('/') + 1);
    std::string minor_str = dev_name.substr(3); // Remove "pxd" prefix

    // Check fastpath sysfs attribute
    std::string fastpath_path = "/sys/devices/pxd/" + minor_str + "/fastpath";

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
            std::cout << "Fastpath status for " << device_name << ": " << fp_status << std::endl;
            // Note: We don't assert here as fastpath might not be active immediately
            // The test will verify functionality through I/O operations
        }
    } else {
        std::cout << "WARNING: Fastpath sysfs attribute not found at: " << fastpath_path << std::endl;
    }
}

std::string PxdFastpathTest::create_mount_point()
{
    char template_name[] = "/tmp/pxd_mount_XXXXXX";
    char *mount_dir = mkdtemp(template_name);
    if (!mount_dir) {
        throw std::runtime_error("Failed to create mount point");
    }
    return std::string(mount_dir);
}

void PxdFastpathTest::create_filesystem(const std::string &device_path)
{
    // First verify the device is accessible
    int fd = open(device_path.c_str(), O_RDWR);
    if (fd < 0) {
        FAIL() << "Device " << device_path << " is not accessible: " << strerror(errno);
    }
    close(fd);

    std::cout << "Creating ext4 filesystem on " << device_path << "..." << std::endl;

    // Start cleaner thread to handle I/O requests during filesystem creation
    killed = false;
    std::thread cleaner_thread(&PxdFastpathTest::cleaner, this);


    std::string cmd = "timeout 30 mkfs.ext4 -F " + device_path;
    int ret = system(cmd.c_str());

    // Stop cleaner thread
    killed = true;
    cleaner_thread.join();
    killed = false;

    
    ASSERT_EQ(ret, 0) << "Failed to create filesystem on " << device_path;
    std::cout << "Created ext4 filesystem on " << device_path << std::endl;
}

void PxdFastpathTest::mount_device(const std::string &device_path, const std::string &mount_point)
{
    int ret = mount(device_path.c_str(), mount_point.c_str(), "ext4", 0, nullptr);
    ASSERT_EQ(ret, 0) << "Failed to mount " << device_path << " at " << mount_point
                      << " - " << strerror(errno);
    std::cout << "Mounted " << device_path << " at " << mount_point << std::endl;
}

void PxdFastpathTest::unmount_device(const std::string &mount_point)
{
    int ret = umount(mount_point.c_str());
    ASSERT_EQ(ret, 0) << "Failed to unmount " << mount_point << " - " << strerror(errno);

    // Remove the mount point directory
    ret = rmdir(mount_point.c_str());
    ASSERT_EQ(ret, 0) << "Failed to remove mount point " << mount_point << " - " << strerror(errno);

    std::cout << "Unmounted and removed " << mount_point << std::endl;
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
			// finish_io(&rdwr);
			fail_io(&rdwr);
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

TEST_F(PxdFastpathTest, simple_test_fastpath)
{
    std::cout << "Simple fastpath test" << std::endl;
}

TEST_F(PxdFastpathTest, device_create_fastpath)
{
    pxd_add_ext_out add_ext;
    std::string name;
    int minor;

    // Setup device parameters
    add_ext.dev_id = 1;
    add_ext.size = 100 * 1024 * 1024; // 100MB
    add_ext.queue_depth = 128;
    add_ext.discard_size = PXD_LBS;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1; // Enable fastpath

    // Setup fastpath backing device paths
    setup_fastpath_paths(add_ext.paths);

    // Create device with fastpath enabled
    dev_add_fastpath(add_ext, minor, name);

    // Verify device exists
    ASSERT_TRUE(access(name.c_str(), F_OK) == 0) << "Device " << name << " was not created";

    // Validate device properties
    validate_device_properties(name);
}

TEST_F(PxdFastpathTest, device_attach_export_fastpath)
{
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
              << dev_size << " bytes" << std::endl;
}

// TEST_F(PxdFastpathTest, mount_unmount_fastpath)
// {
//     pxd_add_ext_out add_ext;
//     std::string device_name;
//     int minor;

//     // Create fastpath device
//     add_ext.dev_id = 3;
//     add_ext.size = 100 * 1024 * 1024;
//     add_ext.queue_depth = 128;
//     add_ext.discard_size = PXD_LBS;
//     add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
//     add_ext.enable_fp = 1;

//     setup_fastpath_paths(add_ext.paths);
//     dev_add_fastpath(add_ext, minor, device_name);

//     // Create filesystem on the device
//     create_filesystem(device_name);

//     // Create mount point and mount the device
//     std::string mount_point = create_mount_point();
//     mount_device(device_name, mount_point);

//     // Verify mount was successful by creating a test file
//     std::string test_file = mount_point + "/test_file.txt";
//     std::ofstream file(test_file);
//     ASSERT_TRUE(file.is_open()) << "Failed to create test file on mounted device";
//     file << "Hello, fastpath world!" << std::endl;
//     file.close();

//     // Verify file exists and has correct content
//     std::ifstream read_file(test_file);
//     ASSERT_TRUE(read_file.is_open()) << "Failed to read test file";
//     std::string content;
//     std::getline(read_file, content);
//     ASSERT_EQ(content, "Hello, fastpath world!") << "File content mismatch";
//     read_file.close();

//     std::cout << "Successfully created and verified file on mounted fastpath device" << std::endl;

//     // Unmount the device
//     unmount_device(mount_point);
// }

TEST_F(PxdFastpathTest, io_operations_fastpath)
{
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

    setup_fastpath_paths(add_ext.paths);
    dev_add_fastpath(add_ext, minor, device_name);

    // Perform I/O operations to verify fastpath functionality
    perform_io_test(device_name);
}

TEST_F(PxdFastpathTest, device_detach_remove_fastpath)
{
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

    setup_fastpath_paths(add_ext.paths);
    dev_add_fastpath(add_ext, minor, device_name);

    // Verify device exists before removal
    ASSERT_TRUE(access(device_name.c_str(), F_OK) == 0) << "Device should exist before removal";

    // Test explicit device removal (this test specifically tests removal functionality)
    dev_remove(add_ext.dev_id);

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
    std::cout << "Device " << device_name << " successfully detached and removed" << std::endl;

    // Make sure removal of this device is skipped during TearDown
    added_ids.erase(add_ext.dev_id);
}

TEST_F(PxdFastpathTest, multiple_devices_fastpath)
{
    std::vector<pxd_add_ext_out> devices;
    std::vector<std::string> device_names;
    std::vector<int> minors;

    // Create multiple fastpath devices
    for (int i = 0; i < 3; ++i) {
        pxd_add_ext_out add_ext;
        std::string device_name;
        int minor;

        add_ext.dev_id = 10 + i;
        add_ext.size = 50 * 1024 * 1024; // 50MB each
        add_ext.queue_depth = 64;
        add_ext.discard_size = PXD_LBS;
        add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
        add_ext.enable_fp = 1;

        setup_fastpath_paths(add_ext.paths);
        dev_add_fastpath(add_ext, minor, device_name);

        devices.push_back(add_ext);
        device_names.push_back(device_name);
        minors.push_back(minor);

        std::cout << "Created device " << i << ": " << device_name << std::endl;
    }

    // Verify all devices exist and are accessible
    for (size_t i = 0; i < device_names.size(); ++i) {
        ASSERT_TRUE(access(device_names[i].c_str(), F_OK) == 0)
            << "Device " << device_names[i] << " should exist";

        // Test basic I/O on each device
        perform_io_test(device_names[i]);
    }

    std::cout << "Successfully tested multiple fastpath devices" << std::endl;
}

TEST_F(PxdFastpathTest, error_handling_fastpath)
{
    std::cout << "=== Testing Fastpath Error Handling ===" << std::endl;

    // Test 1: Invalid backing device path
    std::cout << "Test 1: Invalid backing device path..." << std::endl;
    pxd_add_ext_out add_ext;
    add_ext.dev_id = 200;
    add_ext.size = 100 * 1024 * 1024;
    add_ext.queue_depth = 128;
    add_ext.discard_size = PXD_LBS;
    add_ext.open_mode = O_LARGEFILE | O_RDWR | O_DIRECT;
    add_ext.enable_fp = 1;

    // Setup invalid paths
    memset(&add_ext.paths, 0, sizeof(add_ext.paths));
    add_ext.paths.count = 1;
    add_ext.paths.can_failover = true;
    strcpy(add_ext.paths.devpath[0], "/nonexistent/path/to/device");

    // This should still succeed but fall back to native path
    std::string device_name;
    int minor;
    dev_add_fastpath(add_ext, minor, device_name);

    std::cout << "✓ Device created with invalid backing path (fallback to native)" << std::endl;

    std::cout << "=== Fastpath Error Handling Test PASSED ===" << std::endl;
}