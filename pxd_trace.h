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
	pxd_queue_rq,
	TP_PROTO(uint64_t dev_id, int minor, int dir, uint32_t op,
		uint64_t offset, uint64_t size, unsigned short nr_phys_segments,
		uint32_t flags, void *bio, void *bio_tail, bool single_bio, uint64_t bio_offset),
	TP_ARGS(dev_id, minor, dir, op, offset, size, nr_phys_segments, flags, bio, bio_tail, single_bio, bio_offset),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
		__field(int, dir)
		__field(uint32_t, op)
		__field(uint64_t, offset)
		__field(uint64_t, size)
		__field(unsigned short, nr_phys_segments)
		__field(uint32_t, flags)
		__field(void *, bio)
		__field(void *, bio_tail)
		__field(bool, single_bio)
		__field(uint64_t, bio_offset)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor,
		__entry->dir = dir,
		__entry->op = op,
		__entry->offset = offset,
		__entry->size = size,
		__entry->nr_phys_segments = nr_phys_segments,
		__entry->flags = flags,
		__entry->bio = bio,
		__entry->bio_tail = bio_tail,
		__entry->single_bio = single_bio,
		__entry->bio_offset = bio_offset
	),
	TP_printk(
		"dev_id %llu minor %d dir %d op %u rq_offset %llu size %llu nr_phys_segments %u flags %x bio %p bio_tail %p single_bio %d bio_offset %llu",
		__entry->dev_id, __entry->minor, __entry->dir, __entry->op,
		__entry->offset, __entry->size, __entry->nr_phys_segments,
		__entry->flags, __entry->bio, __entry->bio_tail, __entry->single_bio, __entry->bio_offset)
);

TRACE_EVENT(
	fp_discard_reply,
	TP_PROTO(uint64_t dev_id, int minor, int dir, uint32_t op,
		uint64_t offset, uint64_t size, unsigned short nr_phys_segments,
		bool discard, uint32_t flags, int status),
	TP_ARGS(dev_id, minor, dir, op, offset, size, nr_phys_segments, discard, flags, status),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
		__field(int, dir)
		__field(uint32_t, op)
		__field(uint64_t, offset)
		__field(uint64_t, size)
		__field(unsigned short, nr_phys_segments)
		__field(bool, discard)
		__field(uint32_t, flags)
		__field(int, status)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor,
		__entry->dir = dir,
		__entry->op = op,
		__entry->offset = offset,
		__entry->size = size,
		__entry->nr_phys_segments = nr_phys_segments,
		__entry->discard = discard,
		__entry->flags = flags,
		__entry->status = status
	),
	TP_printk(
		"dev_id %llu minor %d dir %d op %u offset %llu size %llu nr_phys_segments %u discard = %d flags %x status %d",
		__entry->dev_id, __entry->minor, __entry->dir, __entry->op,
		__entry->offset, __entry->size, __entry->nr_phys_segments, __entry->discard,
		__entry->flags, __entry->status)
);

TRACE_EVENT(
	end_clone_bio,
	TP_PROTO(uint64_t dev_id, int minor, uint32_t bio_op, uint64_t bio_offset, uint64_t bio_size,
	uint32_t rq_op, uint64_t rq_offset, uint64_t rq_size, int status, void* bio, void* biotail),
	TP_ARGS(dev_id, minor, bio_op, bio_offset, bio_size, rq_op, rq_offset, rq_size, status, bio, biotail),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
		__field(uint32_t, bio_op)
		__field(uint64_t, bio_offset)
		__field(uint64_t, bio_size)
		__field(uint32_t, rq_op)
		__field(uint64_t, rq_offset)
		__field(uint64_t, rq_size)
		__field(int, status)
		__field(void*, bio)
		__field(void*, biotail)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor,
		__entry->bio_op = bio_op,
		__entry->bio_offset = bio_offset,
		__entry->bio_size = bio_size,
		__entry->rq_op = rq_op,
		__entry->rq_offset = rq_offset,
		__entry->rq_size = rq_size,
		__entry->status = status,
		__entry->bio = bio,
		__entry->biotail = biotail
	),
	TP_printk(
		"dev_id %llu minor %d bio_op %u bio_offset %llu bio_size %llu rq_op %u rq_offset %llu rq_size %llu status %d bio %p biotail %p",
		__entry->dev_id, __entry->minor, __entry->bio_op, __entry->bio_offset, __entry->bio_size,
		__entry->rq_op, __entry->rq_offset, __entry->rq_size, __entry->status, __entry->bio, __entry->biotail)
);

TRACE_EVENT(
	pxd_fastpath_reset_device,
	TP_PROTO(uint64_t dev_id, int minor, bool ioswitch_active, uint64_t switch_uid),
	TP_ARGS(dev_id, minor, ioswitch_active, switch_uid),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
		__field(bool, ioswitch_active)
		__field(uint64_t, switch_uid)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor,
		__entry->ioswitch_active = ioswitch_active,
		__entry->switch_uid = switch_uid
	),
	TP_printk(
		"dev_id %llu minor %d ioswitch_active %d switch_uid %llu, action = %s",
		__entry->dev_id, __entry->minor, __entry->ioswitch_active, __entry->switch_uid, __entry->ioswitch_active ? "abort IOs" : "no action")
);

TRACE_EVENT(
	fuse_notify_add_ext,
	TP_PROTO(uint64_t dev_id, size_t size, int32_t queue_depth, int32_t discard_size, mode_t open_mode, int enable_fp, int path_count),
	TP_ARGS(dev_id, size, queue_depth, discard_size, open_mode, enable_fp, path_count),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(size_t, size)
		__field(int32_t, queue_depth)
		__field(int32_t, discard_size)
		__field(mode_t, open_mode)
		__field(int, enable_fp)
		__field(int, path_count)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->size = size,
		__entry->queue_depth = queue_depth,
		__entry->discard_size = discard_size,
		__entry->open_mode = open_mode,
		__entry->enable_fp = enable_fp,
		__entry->path_count = path_count
	),
	TP_printk(
		"dev_id %llu size %zu queue_depth %d discard_size %d open_mode %x enable_fp %d path_count %d",
		__entry->dev_id, __entry->size, __entry->queue_depth, __entry->discard_size,
		__entry->open_mode, __entry->enable_fp, __entry->path_count)
);

TRACE_EVENT(
	pxd_export,
	TP_PROTO(uint64_t dev_id, int minor, bool exported),
	TP_ARGS(dev_id, minor, exported),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
		__field(bool, exported)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor,
		__entry->exported = exported
	),
	TP_printk(
		"dev_id %llu minor %d exported %d",
		__entry->dev_id, __entry->minor, __entry->exported)
);

#ifndef TRACE_ENUM_DEFINED
#define TRACE_ENUM_DEFINED
enum {
	TRANSITION_FP_HANDLE_IO = 0,
	TRANSITION_REISSUE_FAILQ,
	TRANSITION_PXD_IO_FAILOVER
};

enum {
	FAILOVER_REASON_IOFAILURE = 0,
	FAILOVER_REASON_USERSPACE
};
#endif /* TRACE_ENUM_DEFINED */



TRACE_EVENT(
	pxd_reroute_slowpath_transition,
	TP_PROTO(uint64_t dev_id, int minor, int transition, int dir, uint32_t op, uint64_t offset, uint64_t size, unsigned short nr_phys_segments, uint32_t flags),
	TP_ARGS(dev_id, minor, transition, dir, op, offset, size, nr_phys_segments, flags),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
		__field(int, transition)
		__field(int, dir)
		__field(uint32_t, op)
		__field(uint64_t, offset)
		__field(uint64_t, size)
		__field(unsigned short, nr_phys_segments)
		__field(uint32_t, flags)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor,
		__entry->transition = transition,
		__entry->dir = dir,
		__entry->op = op,
		__entry->offset = offset,
		__entry->size = size,
		__entry->nr_phys_segments = nr_phys_segments,
		__entry->flags = flags
	),
	TP_printk(
		"dev_id %llu minor %d transition %d dir %d op %u offset %llu size %llu nr_phys_segments %u flags %x",
		__entry->dev_id, __entry->minor, __entry->transition,
		__entry->dir, __entry->op, __entry->offset, __entry->size, __entry->nr_phys_segments,
		__entry->flags)
);

TRACE_EVENT(
	pxd_rq_fn,
	TP_PROTO(uint64_t dev_id, int minor, int dir, uint32_t op,
		uint64_t offset, uint64_t size, unsigned short nr_phys_segments,
		uint32_t flags),
	TP_ARGS(dev_id, minor, dir, op, offset, size, nr_phys_segments, flags),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
		__field(int, dir)
		__field(uint32_t, op)
		__field(uint64_t, offset)
		__field(uint64_t, size)
		__field(unsigned short, nr_phys_segments)
		__field(uint32_t, flags)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor,
		__entry->dir = dir,
		__entry->op = op,
		__entry->offset = offset,
		__entry->size = size,
		__entry->nr_phys_segments = nr_phys_segments,
		__entry->flags = flags
	),
	TP_printk(
		"dev_id %llu minor %d dir %d op %u offset %llu size %llu nr_phys_segments %u flags %x",
		__entry->dev_id, __entry->minor, __entry->dir, __entry->op,
		__entry->offset, __entry->size, __entry->nr_phys_segments,
		__entry->flags)
);

TRACE_EVENT(
	pxd_request,
	TP_PROTO(
		uint64_t dev_id, uint64_t unique, uint32_t size, uint64_t off,
		uint32_t minor, uint32_t req_op, uint32_t req_flags, uint32_t pxd_op, uint32_t pxd_flags),
		TP_ARGS(dev_id, unique, size, off, minor, req_op, req_flags, pxd_op, pxd_flags),
		TP_STRUCT__entry(
			__field(uint64_t, dev_id)
			__field(uint64_t, unique)
			__field(uint32_t, size)
			__field(uint64_t, off)
			__field(uint32_t, minor)
			__field(uint32_t, req_op)
			__field(uint32_t, req_flags)
			__field(uint32_t, pxd_op)
			__field(uint32_t, pxd_flags)
		),
		TP_fast_assign(
			__entry->dev_id = dev_id;
			__entry->unique = unique;
			__entry->size = size;
			__entry->off = off;
			__entry->minor = minor;
			__entry->req_op = req_op;
			__entry->req_flags = req_flags;
			__entry->pxd_op = pxd_op;
			__entry->pxd_flags = pxd_flags;
		),
		TP_printk(
			"dev_id %llu minor %u unique %llu off %llu size %u req_op %u req_flags %x pxd_op %u pxd_flags %x",
			__entry->dev_id, __entry->minor, __entry->unique, __entry->off,
			__entry->size, __entry->req_op, __entry->req_flags, __entry->pxd_op, __entry->pxd_flags)
);

TRACE_EVENT(
	pxd_ioc_update_size,
	TP_PROTO(uint64_t dev_id, int minor, uint64_t old_size, uint64_t new_size),
	TP_ARGS(dev_id, minor, old_size, new_size),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
		__field(uint64_t, old_size)
		__field(uint64_t, new_size)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor,
		__entry->old_size = old_size,
		__entry->new_size = new_size
	),
	TP_printk(
		"dev_id %llu minor %d old_size %llu new_size %llu",
		__entry->dev_id, __entry->minor, __entry->old_size, __entry->new_size)
);

TRACE_EVENT(
	pxd_request_complete,
	TP_PROTO(uint64_t dev_id, int minor, uint64_t unique, uint64_t offset, uint64_t len, uint32_t op, uint32_t flags, int status),
	TP_ARGS(dev_id, minor, unique, offset, len, op, flags, status),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
		__field(uint64_t, unique)
		__field(uint64_t, offset)
		__field(uint64_t, len)
		__field(uint32_t, op)
		__field(uint32_t, flags)
		__field(int, status)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor,
		__entry->unique = unique,
		__entry->offset = offset,
		__entry->len = len,
		__entry->op = op,
		__entry->flags = flags,
		__entry->status = status
	),
	TP_printk(
		"dev_id %llu minor %d unique %llu offset %llu len %llu op %u flags %x status %d",
		__entry->dev_id, __entry->minor, __entry->unique, __entry->offset,
		__entry->len, __entry->op, __entry->flags, __entry->status)
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

TRACE_EVENT(
	pxd_initiate_failover,
	TP_PROTO(uint64_t dev_id, int minor, int reason),
	TP_ARGS(dev_id, minor, reason),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
		__field(int, reason)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor,
		__entry->reason = reason
	),
	TP_printk(
		"dev_id %llu minor %d reason %d",
		__entry->dev_id, __entry->minor, __entry->reason)
);

TRACE_EVENT(
	pxd_initiate_fallback,
	TP_PROTO(uint64_t dev_id, int minor),
	TP_ARGS(dev_id, minor),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor
	),
	TP_printk(
		"dev_id %llu minor %d",
		__entry->dev_id, __entry->minor)
);

TRACE_EVENT(
	pxd_ioswitch_complete,
	TP_PROTO(uint64_t dev_id, int minor, int opcode),
	TP_ARGS(dev_id, minor, opcode),
	TP_STRUCT__entry(
		__field(uint64_t, dev_id)
		__field(int, minor)
		__field(int, opcode)
	),
	TP_fast_assign(
		__entry->dev_id = dev_id,
		__entry->minor = minor,
		__entry->opcode = opcode
	),
	TP_printk(
		"dev_id %llu minor %d opcode %d",
		__entry->dev_id, __entry->minor, __entry->opcode)
);

TRACE_EVENT(
	pxd_close_ctrl_fd,
	TP_PROTO(int ctx_id),
	TP_ARGS(ctx_id),
	TP_STRUCT__entry(
		__field(int, ctx_id)
	),
	TP_fast_assign(
		__entry->ctx_id = ctx_id
	),
	TP_printk(
		"closed control fd for px : %d",
		__entry->ctx_id)
);
#endif /* _PXD_TP_H */

#include <trace/define_trace.h>
