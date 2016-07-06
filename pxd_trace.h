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
	pxd_release,
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
		uint64_t reqctr, uint64_t unique, uint32_t size, uint64_t off,
		uint32_t minor, uint32_t flags, bool qfn),
	TP_ARGS(reqctr, unique, size, off, minor, flags, qfn),
	TP_STRUCT__entry(
		__field(uint64_t, reqctr)
		__field(uint64_t, unique)
		__field(uint32_t, size)
		__field(uint64_t, off)
		__field(uint32_t, minor)
		__field(uint32_t, flags)
		__field(bool, qfn)
	),
	TP_fast_assign(
		__entry->reqctr = reqctr,
		__entry->unique = unique,
		__entry->size = size,
		__entry->off = off,
		__entry->minor = minor,
		__entry->flags = flags,
		__entry->qfn = qfn),
	TP_printk(
		"reqctr %llu unique %llu size %u off %llu minor %u flags %x qrn %u",
		__entry->reqctr, __entry->unique, __entry->size, __entry->off,
		__entry->minor, __entry->flags, __entry->qfn)
);

TRACE_EVENT(
	pxd_reply,
	TP_PROTO(uint64_t reqctr, uint64_t unique, uint32_t flags),
	TP_ARGS(reqctr, unique, flags),
	TP_STRUCT__entry(
		__field(uint64_t, reqctr)
		__field(uint64_t, unique)
		__field(uint32_t,flags)
	),
	TP_fast_assign(
		__entry->reqctr = reqctr,
		__entry->unique = unique,
		__entry->flags = flags
	),
	TP_printk(
		"reqctr %llu unique %llu flags %x",
		__entry->reqctr, __entry->unique, __entry->flags)
);

TRACE_EVENT(
	pxd_get_fuse_req,
	TP_PROTO(uint64_t reqctr, int nr_pages),
	TP_ARGS(reqctr, nr_pages),
	TP_STRUCT__entry(
		__field(uint64_t, reqctr)
		__field(int, nr_pages)
	),
	TP_fast_assign(
		__entry->reqctr = reqctr,
		__entry->nr_pages = nr_pages
	),
	TP_printk(
		"reqctr %llu nr_pages %d",
		__entry->reqctr, __entry->nr_pages)
);

TRACE_EVENT(
	pxd_get_fuse_req_result,
	TP_PROTO(uint64_t reqctr, int status, int eintr),
	TP_ARGS(reqctr, status, eintr),
	TP_STRUCT__entry(
		__field(uint64_t, reqctr)
		__field(int, status)
		__field(int, eintr)
	),
	TP_fast_assign(
		__entry->reqctr = reqctr,
		__entry->status = status,
		__entry->eintr = eintr
	),
	TP_printk(
		"reqctr %llu status %d eintr %d",
		__entry->reqctr, __entry->status, __entry->eintr)
);
#endif /* _PXD_TP_H */

#include <trace/define_trace.h>
