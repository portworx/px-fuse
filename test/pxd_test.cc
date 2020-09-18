#include <stdlib.h>
#include <pxd.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fuse.h>
#include <sys/poll.h>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <sys/uio.h>
#include <string>
#include <boost/lexical_cast.hpp>
#include <functional>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <thread>
#include <vector>
#include "fuse.h"

using namespace std::placeholders;

const char *pxd_op_names[] = {
	"init",
	"write",
	"read",
	"discard",
	"flush",
	"add,"
	"pxd_remove",
};

std::string control_device(unsigned int driver_context_id)
{
	assert(driver_context_id < PXD_NUM_CONTEXTS);
	std::string ret{PXD_CONTROL_DEV};
	if (driver_context_id != 0)
		ret += "-" + std::to_string(driver_context_id);
	return ret;
}

const char *pxd_op_name(int opcode)
{
	if (opcode < PXD_INIT || opcode >= PXD_LAST) {
		return "unknown";
	} else {
		return pxd_op_names[opcode - PXD_INIT];
	}
}

class PxdTest : public ::testing::Test {
protected:
	int fd;		// control file descriptor
	std::set<uint64_t> added_ids;
	const size_t write_len = 4096;

	PxdTest() : fd(-1) {}
	virtual ~PxdTest() {
		if (fd >= 0)
			close(fd);
	}

	virtual void SetUp();
	virtual void TearDown();

	void dev_add(pxd_add_out &add, int &minor, std::string &name);
	void dev_remove(uint64_t dev_id);
	int wait_msg(int timeout); // timeout in seconds
	void read_block(fuse_in_header *in, pxd_rdwr_in *rd);
public:
	void write_thread(const char *name);
	void read_thread(const char *name);
};

void PxdTest::SetUp()
{
	seteuid(0);
	ASSERT_EQ(0, system("/usr/bin/sudo /sbin/insmod px.ko"));

	std::cout << "Opening... " << control_device(0) << "\n";
	fd = open(control_device(0).c_str(), O_RDWR);
	ASSERT_GT(fd, 0);

	pxd_ioctl_init_args args;
	auto ret = ioctl(fd, PXD_IOC_INIT, &args);
	if (ret < 0) {
		fprintf(stderr, "%s: init ioctl failed: %d(%s)", __func__, errno, strerror(errno));
	}

	auto read_bytes = static_cast<size_t>(ret);
}

void PxdTest::TearDown()
{
	sleep(1);
	std::for_each(added_ids.begin(), added_ids.end(),
			std::bind(&PxdTest::dev_remove, this, _1));

	if (fd >= 0) {
		close(fd);
		fd = -1;
	}

	ASSERT_EQ(0, system("/usr/bin/sudo /sbin/rmmod px.ko"));
}

void PxdTest::dev_add(pxd_add_out &add, int &minor, std::string &name)
{
	fuse_out_header oh;
	struct iovec iov[2];

	ASSERT_TRUE(added_ids.find(add.dev_id) == added_ids.end());

	oh.unique = 0;
	oh.error = PXD_ADD,
	oh.len = sizeof(oh) + sizeof(add);

	iov[0].iov_base = &oh;
	iov[0].iov_len = sizeof(oh);
	iov[1].iov_base = &add;
	iov[1].iov_len = sizeof(add);

	ssize_t write_bytes = writev(fd, iov, 2);
	ASSERT_GT(write_bytes, 0);

	added_ids.insert(add.dev_id);

	minor = write_bytes;
	name = std::string(PXD_DEV_PATH) + std::to_string(add.dev_id);
}

int PxdTest::wait_msg(int timeout)
{
	struct pollfd fds = {};
	int ret;

	fds.fd = fd;
	fds.events = POLLIN;

	ret = poll(&fds, 1, timeout * 1000);

	switch (ret) {
	case 1:
		return 0;
	case 0:
		return -ETIMEDOUT;
	default:
		return -errno;
	}
}

static ::testing::AssertionResult verify_pattern(std::vector<uint64_t> &v)
{
	for (size_t i = 0; i < v.size(); ++i) {
		if (v[i] != i) {
			return ::testing::AssertionFailure() << "at " <<
					i << " val " << v[i];
		}
	}
	return ::testing::AssertionSuccess();
}

static ::testing::AssertionResult verify_pattern(void *buf, size_t len)
{
	uint64_t *d = (uint64_t *)buf;
	for (size_t i = 0; i < len / sizeof(uint64_t); ++i) {
		if (d[i] != i) {
			return ::testing::AssertionFailure() << "at " <<
					i << " val " << d[i];
		}
	}
	return ::testing::AssertionSuccess();
}

static std::vector<uint64_t> make_pattern(size_t size)
{
	std::vector<uint64_t> v(size / sizeof(uint64_t));
	for (size_t i = 0; i < v.size(); ++i)
		v[i] = i;
	return v;
}

struct fuse_notify_header : public ::fuse_out_header {
	fuse_notify_header(int32_t opcode, uint32_t op_len);
};

fuse_notify_header::fuse_notify_header(int32_t opcode, uint32_t op_len)
{
	unique = 0;
	error = opcode;
	len = sizeof(fuse_out_header) + op_len;
}

// Read one block from kernel
void PxdTest::read_block(fuse_in_header *hdr, pxd_rdwr_in *req)
{
	int iovcnt = 1;
	struct iovec iov[iovcnt];
	size_t iovlen = iovcnt * sizeof(iovec);
	char buf[req->size];
	size_t ret = 0;

	// Setup request header and payload
	fuse_notify_header oh(PXD_READ_DATA, sizeof(pxd_read_data_out) + iovlen);
	pxd_read_data_out rd_out = {hdr->unique, iovcnt, (uint32_t)req->offset};

	memset(buf, 0, req->size);
	iov[0].iov_base = buf;
	iov[0].iov_len = req->size;
	struct iovec wr_iov[3] = { { &oh, sizeof(oh) }, { &rd_out, sizeof(rd_out) },
		{ iov, 1*sizeof(iovec) } };

	// Send a read request to kernel
	ret = writev(fd, wr_iov, 3);
	ASSERT_EQ(ret, oh.len);
	for (auto i = 0; i < 16; i++) {
		fprintf(stderr, "%x \t", buf[i*8]);
	}
	ASSERT_TRUE(verify_pattern(buf, req->size));
}

void PxdTest::write_thread(const char *name)
{
	std::vector<uint64_t> v(make_pattern(write_len));
	boost::iostreams::file_descriptor dev_fd(name);
	for (auto i = 0; i < 16; i++) {
		fprintf(stderr, "%lx \t", v[i]);
	}

	ssize_t write_bytes = write(dev_fd.handle(), v.data(), write_len);
	ASSERT_EQ(write_bytes, write_len);
}

void PxdTest::read_thread(const char *name)
{
	std::vector<uint64_t> read_buf(write_len / sizeof(uint64_t));
	boost::iostreams::file_descriptor dev_fd(name);

	ssize_t read_bytes = read(dev_fd.handle(), read_buf.data(), write_len);
	ASSERT_EQ(read_bytes, write_len);
	ASSERT_TRUE(verify_pattern(read_buf));
}

void PxdTest::dev_remove(uint64_t dev_id)
{
	pxd_remove_out remove;
	fuse_out_header oh;
	struct iovec iov[2];

	while (1) {
		oh.unique = 0;
		oh.error = PXD_REMOVE;
		oh.len = sizeof(oh) + sizeof(remove);

		remove.dev_id = dev_id;
		remove.force = true;

		iov[0].iov_base = &oh;
		iov[0].iov_len = sizeof(oh);
		iov[1].iov_base = &remove;
		iov[1].iov_len = sizeof(remove);

		ssize_t write_bytes = writev(fd, iov, 2);
		if (write_bytes > 0) {
			ASSERT_EQ(write_bytes, oh.len);
			break;
		}

		ASSERT_EQ(EBUSY, errno);
	}

	added_ids.erase(dev_id);
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

	dev_remove(add.dev_id);
}

TEST_F(PxdTest, write)
{
	pxd_add_out add;
	std::string name;
	int minor = 0;
	char msg_buf[write_len * 2];
	struct rdwr_in *rdwr = NULL;
	fuse_in_header *in = NULL;
	ssize_t read_bytes = 0;

	// Attach a kernel block device (/dev/pxd/pxd1)
	add.dev_id = 1;
	add.size = 1024 * 1024;
	add.queue_depth = 128;
	add.discard_size = 4096;
	dev_add(add, minor, name);

	// Start a thread to perform writes on the attached device
	std::thread wt(&PxdTest::write_thread, this, name.c_str());

	// Now read in the request from kernel
	while (1) {
		int ret = wait_msg(1);
		ASSERT_EQ(0, ret);

		read_bytes = read(fd, msg_buf, sizeof(msg_buf));
		rdwr = reinterpret_cast<rdwr_in *>(msg_buf);

		if (rdwr->in.opcode == PXD_WRITE) {
			read_block(&rdwr->in, reinterpret_cast<pxd_rdwr_in *>(&rdwr->rdwr));
			break;
		}
	}

	// Process the write request
	pxd_rdwr_in *wr = reinterpret_cast<pxd_rdwr_in *>(&rdwr->rdwr);
	ASSERT_EQ(rdwr->in.opcode, PXD_WRITE);
	ASSERT_EQ(wr->minor, minor);
	ASSERT_EQ(wr->offset, 0);
	ASSERT_EQ(wr->size, write_len);
	
	// Reply to the kernel
	fuse_out_header oh;
	oh.len = sizeof(oh);
	oh.error = 0;
	oh.unique = rdwr->in.unique;
	size_t ret = ::write(fd, &oh, sizeof(oh));
	ASSERT_EQ(sizeof(oh), ret);

	wt.join();
	// Detach block device
	dev_remove(add.dev_id);
}

TEST_F(PxdTest, read)
{
	pxd_add_out add;
	std::string name;
	int minor = 0;
	char msg_buf[write_len * 2];
	struct rdwr_in *rdwr = NULL;
	fuse_in_header *in = NULL;
	ssize_t read_bytes = 0;
	struct iovec iov[2];
	char buf[PXD_LBS];
	int ret = -1;

	// Attach a kernel block device (/dev/pxd/pxd1)
	add.dev_id = 1;
	add.size = 1024 * 1024;
	add.queue_depth = 128;
	add.discard_size = 4096;
	dev_add(add, minor, name);

	// Start a thread to perform reads on the attached device
	std::thread rt(&PxdTest::read_thread, this, name.c_str());

	pxd_rdwr_in *rd;
	while (1) {
		ret = wait_msg(1);
		ASSERT_EQ(0, ret);

		read_bytes = read(fd, msg_buf, sizeof(msg_buf));
		rdwr = reinterpret_cast<rdwr_in *>(msg_buf);
		rd = reinterpret_cast<pxd_rdwr_in *>(&rdwr->rdwr);
		if (rdwr->in.opcode == PXD_READ) {
			break;
		}
	}

	// Reply to the kernel
	fuse_out_header oh;
	rd->size = 4096;
	oh.len = sizeof(oh) + 4096;
	oh.error = 0;
	oh.unique = rdwr->in.unique;
	iov[0].iov_base = &oh;
	iov[0].iov_len = sizeof(oh);
	for (auto i = 1; i < 2; i++) {
		iov[i].iov_base = buf;
		iov[i].iov_len = PXD_LBS;
	}

	ret = writev(fd, iov, 1 + 1);

	rt.join();

#if 0
	ASSERT_EQ(PXD_READ, in->opcode);
	ASSERT_EQ(32 * 1024, rd->offset);
	ASSERT_EQ(write_len, rd->size);
	ASSERT_EQ(minor, rd->minor);
#endif

	// Detach block device
	dev_remove(add.dev_id);
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
