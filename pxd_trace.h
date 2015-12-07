#undef TRACE_SYSTEM
#define TRACE_SYSTEM pxd

#if !defined(_PXD_TP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _PXD_TP_H

#include <linux/tracepoint.h>

#include <linux/timekeeping.h>

TRACE_EVENT(
		make_request_wait,
		TP_PROTO(
			uint32_t opcode,
			uint64_t reqid,
			uint32_t iter,
			uint64_t unique,
			struct timespec *start,
			struct timespec *end
		),
		TP_ARGS(
			opcode,
			reqid,
			iter,
			unique,
			start,
			end
		),
		TP_STRUCT__entry(
			__field(	uint32_t, opcode)
			__field(	uint64_t, reqid)
			__field(	uint32_t, iter)
			__field(	uint64_t, unique)
			__field(	uint64_t, start_sec)
			__field(	uint32_t, start_nsec)
			__field(	uint64_t, end_sec)
			__field(	uint32_t, end_nsec)
		),
		TP_fast_assign(
			__entry->opcode	= opcode,
			__entry->reqid	= reqid,
			__entry->iter	= iter,
			__entry->unique	= unique,
			__entry->start_sec	= (uint64_t)start->tv_sec,
			__entry->start_nsec	= (uint32_t)start->tv_nsec,
			__entry->end_sec	= (uint64_t)end->tv_sec,
			__entry->end_nsec	= (uint32_t)end->tv_nsec
		),
		TP_printk("op_code %u reqid %lld iter %u start sec %lld start "
			"nsec %u end sec %lld end nsec %u",
			__entry->opcode, __entry->reqid, __entry->iter,
			(long long int)__entry->start_sec, (unsigned int)__entry->start_nsec,
			(long long int)__entry->end_sec, (unsigned int)__entry->end_nsec)
);

TRACE_EVENT(
		make_request_lat,
		TP_PROTO(
			uint32_t opcode,
			uint64_t reqid,
			uint64_t unique,
			uint32_t num_background,
			struct timespec *start,
			struct timespec *end
		),
		TP_ARGS(
			opcode,
			reqid,
			unique,
			num_background,
			start,
			end
		),
		TP_STRUCT__entry(
			__field(	uint32_t, opcode)
			__field(	uint64_t, reqid)
			__field(	uint64_t, unique)
			__field(	uint32_t, num_background)
			__field(	uint64_t, start_sec)
			__field(	uint32_t, start_nsec)
			__field(	uint64_t, end_sec)
			__field(	uint32_t, end_nsec)
		),
		TP_fast_assign(
			__entry->opcode	= opcode,
			__entry->reqid	= reqid,
			__entry->unique	= unique,
			__entry->num_background	= num_background, 
			__entry->start_sec	= (uint64_t)start->tv_sec,
			__entry->start_nsec	= (uint32_t)start->tv_nsec,
			__entry->end_sec	= (uint64_t)end->tv_sec,
			__entry->end_nsec	= (uint32_t)end->tv_nsec
		),
		TP_printk("op_code %u reqid %lld pend %u start sec %lld start "
			"nsec %u end sec %lld end nsec %u",
			__entry->opcode, __entry->reqid, __entry->num_background,
			(long long int)__entry->start_sec, (unsigned int)__entry->start_nsec,
			(long long int)__entry->end_sec, (unsigned int)__entry->end_nsec)
);

#endif /* _PXD_TP_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE pxd_trace

#include <trace/define_trace.h>
