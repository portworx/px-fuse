#undef TRACE_SYSTEM
#define TRACE_SYSTEM pxd

#if !defined(_PXD_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _PXD_TRACE_H

#include <linux/tracepoint.h>

TRACE_EVENT(
	pxd_open,
	TP_PROTO(uint64_t dev_id, int major, int minor, fmode_t mode, int err),
	TP_ARGS(dev_id, major, minor, mode, err),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, major)
		__field(int, minor)
		__field(fmode_t, mode)
		__field(int, err)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->major = major,
		__entry->minor = minor,
		__entry->mode = mode,
		__entry->err = err
	),
	TP_printk(
		"dev_id %llu major %d minor %d mode %x err %d",
		__entry->dev_id, __entry->major, __entry->minor,
		__entry->mode, __entry->err)
);

TRACE_EVENT(
	copy_in_read_data_iovec,
	TP_PROTO(uint64_t req_id, int prev_iovcnt, int curr_iovcnt),
	TP_ARGS(req_id, prev_iovcnt, curr_iovcnt),
	TP_STRUCT__entry(
		__field(uint64_t, req_id)
		__field(int, prev_iovcnt)
		__field(int, curr_iovcnt)
	),
	TP_fast_assign(
		__entry->req_id = req_id,
		__entry->prev_iovcnt = prev_iovcnt,
		__entry->curr_iovcnt = curr_iovcnt
	),
	TP_printk(
		"req_id %llu prev_iovcnt %d curr_iovcnt %d",
		__entry->req_id, __entry->prev_iovcnt, __entry->curr_iovcnt)
);

TRACE_EVENT(
	fuse_notify_read_data_request,
	TP_PROTO(uint64_t devid, uint64_t req_id,uint64_t rq_offset, uint64_t rq_size, uint64_t rdwr_offset, uint64_t read_data_p_offset),
	TP_ARGS(devid, req_id, rq_offset, rq_size, rdwr_offset, read_data_p_offset),
	TP_STRUCT__entry(
		__field(uint64_t, devid)
		__field(uint64_t, req_id)
		__field(uint64_t, rq_offset)
		__field(uint64_t, rq_size)
		__field(uint64_t, rdwr_offset)
		__field(uint64_t, read_data_p_offset)
	),
	TP_fast_assign(
		__entry->devid = devid,
		__entry->req_id = req_id,
		__entry->rq_offset = rq_offset,
		__entry->rq_size = rq_size,
		__entry->rdwr_offset = rdwr_offset,
		__entry->read_data_p_offset = read_data_p_offset
	),
	TP_printk(
		"devid %llu req_id %llu rq_offset %llu rq_size %llu rdwr_offset %llu read_data_p_offset %llu",
		__entry->devid, __entry->req_id, __entry->rq_offset, __entry->rq_size, __entry->rdwr_offset, __entry->read_data_p_offset)
);

TRACE_EVENT(
	fuse_notify_read_data_segment_info,
	TP_PROTO(uint64_t devid, uint64_t req_id, uint64_t bv_offset, uint64_t bv_len),
	TP_ARGS(devid, req_id,bv_offset, bv_len),
	TP_STRUCT__entry(
		__field(uint64_t, devid)
		__field(uint64_t, req_id)
		__field(uint64_t, bv_offset)
		__field(uint64_t, bv_len)
	),
	TP_fast_assign(
		__entry->devid = devid,
		__entry->req_id = req_id,
		__entry->bv_offset = bv_offset,
		__entry->bv_len = bv_len
	),
	TP_printk(
		"devid %llu req_id %llu bv_offset %llu bv_len %llu",
		__entry->devid, __entry->req_id, __entry->bv_offset, __entry->bv_len)
);

TRACE_EVENT(
	fuse_notify_read_data_copy,
	TP_PROTO(uint64_t devid, uint64_t req_id, size_t copied, size_t copy_this, uint64_t bv_offset, uint64_t offset, uint64_t bv_len, uint64_t len, uint64_t iter_count),
	TP_ARGS(devid, req_id, copied, copy_this, bv_offset, offset, bv_len, len, iter_count),
	TP_STRUCT__entry(
		__field(uint64_t, devid)
		__field(uint64_t, req_id)
		__field(size_t, copied)
		__field(size_t, copy_this)
		__field(uint64_t, bv_offset)
		__field(uint64_t, offset)
		__field(uint64_t, bv_len)
		__field(uint64_t, len)
		__field(uint64_t, iter_count)
	),
	TP_fast_assign(
		__entry->devid = devid,
		__entry->req_id = req_id,
		__entry->copied = copied,
		__entry->copy_this = copy_this,
		__entry->bv_offset = bv_offset,
		__entry->offset = offset,
		__entry->bv_len = bv_len,
		__entry->len = len,
		__entry->iter_count = iter_count
	),
	TP_printk(
		"devid %llu req_id %llu copied %zu copy_this %zu bv_offset %llu offset %llu bv_len %llu len %llu iter_count %llu",
		__entry->devid, __entry->req_id, __entry->copied, __entry->copy_this, __entry->bv_offset, __entry->offset, __entry->bv_len, __entry->len, __entry->iter_count)
);

TRACE_EVENT(
	fuse_notify_read_data_finalcopy,
	TP_PROTO(uint64_t devid, uint64_t req_id, uint64_t len, uint64_t copied, uint64_t bv_offset, uint64_t offset, uint64_t bv_len),
	TP_ARGS(devid, req_id, len, copied, bv_offset, offset, bv_len),
	TP_STRUCT__entry(
		__field(uint64_t, devid)
		__field(uint64_t, req_id)
		__field(uint64_t, len)
		__field(uint64_t, copied)
		__field(uint64_t, bv_offset)
		__field(uint64_t, offset)
		__field(uint64_t, bv_len)
	),
	TP_fast_assign(
		__entry->devid = devid,
		__entry->req_id = req_id,
		__entry->len = len,
		__entry->copied = copied,
		__entry->bv_offset = bv_offset,
		__entry->offset = offset,
		__entry->bv_len = bv_len
	),
	TP_printk(
		"devid %llu req_id %llu len %llu copied %llu bv_offset %llu offset %llu bv_len %llu",
		__entry->devid, __entry->req_id, __entry->len, __entry->copied, __entry->bv_offset, __entry->offset, __entry->bv_len)
);

TRACE_EVENT(
	pxd_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0) || defined(__RHEL_GT_94__) || defined(__SUSE_GTE_SP6__) || defined(__SLE_MICRO_GTE_6_0__)
	TP_PROTO(uint64_t dev_id, int major, int minor),
	TP_ARGS(dev_id, major, minor),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, major)
		__field(int, minor)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->major = major,
		__entry->minor = minor
	),
	TP_printk(
		"dev_id %llu major %d minor %d",
		__entry->dev_id, __entry->major, __entry->minor)
#else
	TP_PROTO(uint64_t dev_id, int major, int minor, fmode_t mode),
	TP_ARGS(dev_id, major, minor, mode),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, major)
		__field(int, minor)
		__field(fmode_t, mode)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->major = major,
		__entry->minor = minor,
		__entry->mode = mode
	),
	TP_printk(
		"dev_id %llu major %d minor %d mode %x",
		__entry->dev_id, __entry->major, __entry->minor, __entry->mode)
#endif
);

TRACE_EVENT(
	pxd_ioctl,
	TP_PROTO(uint64_t dev_id, int major, int minor, fmode_t mode,
			 unsigned int cmd, unsigned long arg, int err),
	TP_ARGS(dev_id, major, minor, mode, cmd, arg, err),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, major)
		__field(int, minor)
		__field(fmode_t, mode)
		__field(unsigned, cmd)
		__field(unsigned long, arg)
		__field(int, err)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->major = major,
		__entry->minor = minor,
		__entry->mode = mode,
		__entry->cmd = cmd,
		__entry->arg = arg,
		__entry->err = err
	),
	TP_printk(
		"dev_id %llu major %d minor %d mode %x cmd %u arg %lu err %d",
		__entry->dev_id, __entry->major, __entry->minor,
		__entry->mode, __entry->cmd, __entry->arg, __entry->err)
);

TRACE_EVENT(
	pxd_request,
	TP_PROTO(
		uint64_t unique, uint32_t size, uint64_t off,
		uint32_t minor, uint32_t flags),
	TP_ARGS(unique, size, off, minor, flags),
	TP_STRUCT__entry(
		__field(uint64_t, unique)
		__field(uint32_t, size)
		__field(uint64_t, off)
		__field(uint32_t, minor)
		__field(uint32_t, flags)
	),
	TP_fast_assign(
		__entry->unique = unique,
		__entry->size = size,
		__entry->off = off,
		__entry->minor = minor,
		__entry->flags = flags
	),
	TP_printk(
		"unique %llu size %u off %llu minor %u flags %x",
		__entry->unique, __entry->size, __entry->off,
		__entry->minor, __entry->flags)
);

TRACE_EVENT(
	pxd_reply,
	TP_PROTO(uint64_t unique, uint32_t flags),
	TP_ARGS(unique, flags),
	TP_STRUCT__entry(
		__field(uint64_t, unique)
		__field(uint32_t,flags)
	),
	TP_fast_assign(
		__entry->unique = unique,
		__entry->flags = flags
	),
	TP_printk(
		"unique %llu flags %x",
		__entry->unique, __entry->flags)
);

TRACE_EVENT(
	pxd_get_fuse_req,
	TP_PROTO(int nr_pages),
	TP_ARGS(nr_pages),
	TP_STRUCT__entry(
		__field(int, nr_pages)
	),
	TP_fast_assign(
		__entry->nr_pages = nr_pages
	),
	TP_printk(
		"nr_pages %d",
		__entry->nr_pages)
);

TRACE_EVENT(
	pxd_get_fuse_req_result,
	TP_PROTO(int status, int eintr),
	TP_ARGS(status, eintr),
	TP_STRUCT__entry(
		__field(int, status)
		__field(int, eintr)
	),
	TP_fast_assign(
		__entry->status = status,
		__entry->eintr = eintr
	),
	TP_printk(
		"status %d eintr %d",
		__entry->status, __entry->eintr)
);
#endif /* _PXD_TP_H */

#include <trace/define_trace.h>
