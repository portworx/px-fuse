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

const char *pxd_op_name(int opcode)
{
	if (opcode < PXD_INIT || opcode >= PXD_LAST) {
		return "unknown";
	} else {
		return pxd_op_names[opcode - PXD_INIT];
	}
}

class GddBasicTest : public ::testing::Test {

};

TEST_F(GddBasicTest, insert_module) {
	ASSERT_EQ(0, seteuid(0));
	ASSERT_EQ(0, system("sudo insmod px_fuse/px.ko"));
	ASSERT_EQ(0, system("sudo rmmod px_fuse/px.ko"));
}

class GddTest : public ::testing::Test {
protected:
	virtual void SetUp() {
		ASSERT_EQ(0, seteuid(0));
		ASSERT_EQ(0, system("sudo insmod px_fuse/px.ko"));
	}

	virtual void TearDown() {
		ASSERT_EQ(0, system("sudo rmmod px_fuse/px.ko"));
	}
};

TEST_F(GddTest, sysfs_created) {
	struct stat st;

	ASSERT_EQ(0, stat("/sys/bus/pxd", &st));
	ASSERT_TRUE(S_ISDIR(st.st_mode));
}

TEST_F(GddTest, device_created) {
	struct stat st;

	ASSERT_EQ(0, stat(PXD_CONTROL_DEV, &st));
}

TEST_F(GddTest, device_open) {
	boost::iostreams::file_descriptor fd(PXD_CONTROL_DEV);

	ASSERT_GE(fd.handle(), 0);
}

TEST_F(GddTest, device_read_init) {
	char buf[2048];
	int ret;
	struct pollfd fds;
	ssize_t read_bytes;
	ssize_t init_size = sizeof(fuse_in_header) + sizeof(pxd_init_in);
	fuse_in_header *h;
	pxd_init_in *in;

	boost::iostreams::file_descriptor fd(PXD_CONTROL_DEV);

	memset(&fds, 0, sizeof(fds));

	fds.fd = fd.handle();
	fds.events = POLLIN;

	ret = poll(&fds, 1, 0);
	ASSERT_EQ(1, ret);
	ASSERT_TRUE(fds.revents & POLLIN);

	read_bytes = fd.read(buf, sizeof(buf));
	ASSERT_EQ(init_size, read_bytes);

	h = reinterpret_cast<fuse_in_header *>(buf);
	in = reinterpret_cast<pxd_init_in *>(buf + sizeof(*h));

	ASSERT_GT(h->unique, 0);
	ASSERT_EQ(PXD_INIT, h->opcode);
	ASSERT_EQ(PXD_VERSION, in->version);
}

class GddTestWithControl : public ::testing::Test {
protected:
	int fd;		// control file descriptor
	std::set<uint64_t> added_ids;
	const size_t write_len = 4096;

	GddTestWithControl() : fd(-1) {}
	virtual ~GddTestWithControl() {
		if (fd >= 0)
			close(fd);
	}

	virtual void SetUp();
	virtual void TearDown();

	void dev_add(pxd_add_out &add, int &minor, std::string &name);
	void dev_remove(uint64_t dev_id);
	int wait_msg(int timeout); // timeout in seconds
	void read_zeroes(fuse_in_header *in, pxd_rdwr_in *rd);
	void read_pattern(fuse_in_header *in, pxd_rdwr_in *rd);
	void read_all_zeroes(int timeout);
public:
	void write_thread(const char *name);
	void read_thread(const char *name);
};

void GddTestWithControl::SetUp()
{
	ASSERT_EQ(0, seteuid(0));
	ASSERT_EQ(0, system("sudo insmod px_fuse/px.ko"));

	fd = open(PXD_CONTROL_DEV, O_RDWR);
	ASSERT_GT(fd, 0);

	char buf[2048];
	ssize_t init_size = sizeof(fuse_in_header) + sizeof(pxd_init_in);
	ssize_t read_bytes = read(fd, buf, sizeof(buf));
	ASSERT_GE(read_bytes, init_size);
	fuse_in_header *ih = reinterpret_cast<fuse_in_header *>(buf);
	ASSERT_EQ(ih->opcode, PXD_INIT);
}

void GddTestWithControl::TearDown()
{
	sleep(1);
	std::for_each(added_ids.begin(), added_ids.end(),
			std::bind(&GddTestWithControl::dev_remove, this, _1));

	if (fd >= 0) {
		close(fd);
		fd = -1;
	}

	ASSERT_EQ(0, system("sudo rmmod px_fuse/px.ko"));
}

void GddTestWithControl::dev_add(pxd_add_out &add, int &minor, std::string &name)
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

int GddTestWithControl::wait_msg(int timeout)
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

void GddTestWithControl::read_zeroes(fuse_in_header *in, pxd_rdwr_in *rd)
{
	char buf[rd->size];
	fuse_out_header oh;
	oh.error = 0;
	oh.len = sizeof(oh) + rd->size;
	oh.unique = in->unique;
	struct iovec iov[2];
	iov[0].iov_base = &oh;
	iov[0].iov_len = sizeof(oh);
	iov[1].iov_base = buf;
	iov[1].iov_len = rd->size;
	memset(buf, 0, rd->size);
	ssize_t write_bytes = writev(fd, iov, 2);
	ASSERT_EQ(write_bytes, oh.len);
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

static std::vector<uint64_t> make_pattern(size_t size)
{
	std::vector<uint64_t> v(size / sizeof(uint64_t));
	for (size_t i = 0; i < v.size(); ++i)
		v[i] = i;
	return v;
}

void GddTestWithControl::read_pattern(fuse_in_header *in, pxd_rdwr_in *rd)
{
	ASSERT_EQ(0, rd->size % sizeof(uint64_t));

	std::vector<uint64_t> buf(make_pattern(rd->size));

	fuse_out_header oh;
	oh.error = 0;
	oh.len = sizeof(oh) + rd->size;
	oh.unique = in->unique;
	struct iovec iov[2];
	iov[0].iov_base = &oh;
	iov[0].iov_len = sizeof(oh);
	iov[1].iov_base = buf.data();
	iov[1].iov_len = rd->size;
	ssize_t write_bytes = writev(fd, iov, 2);
	ASSERT_EQ(write_bytes, oh.len);
}

void GddTestWithControl::read_all_zeroes(int timeout)
{
	char msg_buf[8192];
	while (!wait_msg(timeout)) {
		ssize_t read_bytes = read(fd, msg_buf, sizeof(msg_buf));
		ASSERT_LE(read_bytes, sizeof(msg_buf));
		fuse_in_header *in = reinterpret_cast<fuse_in_header *>(msg_buf);
		if (in->opcode == PXD_READ)
			read_zeroes(in, reinterpret_cast<pxd_rdwr_in *>(in + 1));
	}
}

void GddTestWithControl::write_thread(const char *name)
{
	std::vector<uint64_t> v(make_pattern(write_len));
	boost::iostreams::file_descriptor dev_fd(name);

	ASSERT_EQ(8192, lseek(dev_fd.handle(), 8192, SEEK_SET));
	ssize_t write_bytes = write(dev_fd.handle(), v.data(), write_len);
	ASSERT_EQ(write_bytes, write_len);
}

void GddTestWithControl::read_thread(const char *name)
{
	std::vector<uint64_t> read_buf(write_len / sizeof(uint64_t));
	boost::iostreams::file_descriptor dev_fd(name);

	ASSERT_EQ(32 * 1024, lseek(dev_fd.handle(), 32 * 1024, SEEK_SET));
	ssize_t read_bytes = read(dev_fd.handle(), read_buf.data(), write_len);
	ASSERT_EQ(read_bytes, write_len);
	ASSERT_TRUE(verify_pattern(read_buf));
}

void GddTestWithControl::dev_remove(uint64_t dev_id)
{
	pxd_remove_out remove;
	fuse_out_header oh;
	struct iovec iov[2];

	ASSERT_FALSE(added_ids.find(dev_id) == added_ids.end());

	while (1) {
		oh.unique = 0;
		oh.error = PXD_REMOVE;
		oh.len = sizeof(oh) + sizeof(remove);

		remove.dev_id = dev_id;

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

		read_all_zeroes(1);
	}

	added_ids.erase(dev_id);
}

TEST_F(GddTestWithControl, device_size)
{
	pxd_add_out add;
	std::string name;
	int minor, ret;
	uint64_t dev_size;
	const uint64_t target_dev_size = 1024 * 1024;

	add.dev_id = 1;
	add.size = target_dev_size;
	add.queue_depth = 0;
	dev_add(add, minor, name);

	boost::iostreams::file_descriptor dev_fd(name);
	ASSERT_GT(dev_fd.handle(), 0);

	ret = ioctl(dev_fd.handle(), BLKGETSIZE64, &dev_size);
	ASSERT_EQ(0, ret);
	ASSERT_EQ(dev_size, target_dev_size);
}

TEST_F(GddTestWithControl, read_write)
{
	pxd_add_out add;
	std::string name;
	int minor;
	char msg_buf[write_len * 2];
	fuse_in_header *in;
	ssize_t read_bytes;

	add.dev_id = 1;
	add.size = 1024 * 1024;
	add.queue_depth = 256;
	dev_add(add, minor, name);

	std::thread wt(&GddTestWithControl::write_thread, this, name.c_str());

	while (1) {
		int ret = wait_msg(1);
		ASSERT_EQ(0, ret);

		read_bytes = read(fd, msg_buf, sizeof(msg_buf));
		in = reinterpret_cast<fuse_in_header *>(msg_buf);
		if (in->opcode == PXD_READ) {
			read_zeroes(in, reinterpret_cast<pxd_rdwr_in *>(in + 1));
		} else {
			break;
		}
	}

	pxd_rdwr_in *wr = reinterpret_cast<pxd_rdwr_in *>(in + 1);

	ASSERT_EQ(in->opcode, PXD_WRITE);
	ASSERT_EQ(wr->minor, minor);
	ASSERT_EQ(wr->offset, 8192);
	ASSERT_EQ(wr->size, write_len);
	ASSERT_EQ(sizeof(fuse_in_header) + sizeof(pxd_rdwr_in), read_bytes);

	fuse_out_header oh;
	oh.unique = in->unique;
	oh.error = 0;
	oh.len = sizeof(oh);
	ssize_t write_bytes = write(fd, &oh, sizeof(oh));
	ASSERT_EQ(sizeof(oh), write_bytes);

	wt.join();

	std::thread rt(&GddTestWithControl::read_thread, this, name.c_str());

	pxd_rdwr_in *rd;
	while (1) {
		int ret = wait_msg(1);
		ASSERT_EQ(0, ret);

		read_bytes = read(fd, msg_buf, sizeof(msg_buf));
		in = reinterpret_cast<fuse_in_header *>(msg_buf);
		rd = reinterpret_cast<pxd_rdwr_in *>(in + 1);
		if (in->opcode == PXD_READ && rd->offset != 32*1024) {
			read_zeroes(in, rd);
		} else {
			break;
		}
	}

	ASSERT_EQ(PXD_READ, in->opcode);
	ASSERT_EQ(32 * 1024, rd->offset);
	ASSERT_EQ(write_len, rd->size);
	ASSERT_EQ(minor, rd->minor);

	read_pattern(in, rd);

	rt.join();
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
