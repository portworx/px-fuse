# pxd fastpath: control flows and invariants

Scope: how the px_fuse kernel driver drives the fastpath / native-path IO
state machine, and what invariants the code maintains when multiple flows
race. Files touched: pxd.c, pxd_bio_blkmq.c, pxd_fastpath.c, pxd_core.h.

The invariants below are what the recent refactor added; the flows are
what the driver was already doing, restated with the invariants in mind.

Naming reminder:
  ctx            = struct pxd_context, one per pxd-control-N device
  pxd_dev        = struct pxd_device,  one per exported /dev/pxd/pxdN
  fc             = &ctx->fc, the fuse_conn attached to that ctx
  failover_work  = per-ctx work_struct, scheduled by pxd_control_release
  abort_work     = per-ctx delayed_work, scheduled T + pxd_timeout_secs
                   after pxd_control_release
  freeze         = ctx-scoped quiescent window enforced by
                   pxd_fp_freeze_start / pxd_fp_freeze_end (module-local;
                   NOT kernel workqueue freeze - see pxd_fastpath.c
                   comments for why that primitive is not usable from a
                   module).


## Part 1. Independent operations

Each subsection describes one operation triggered from userspace or from
a timer, running in isolation.


### 1.1 Device attach

Trigger: PXD_ADD / PXD_ADD_EXT / PXD_ADD_EXT_V2 fuse op on ctl_fd.

Flow (pxd.c pxd_add):
  1. kzalloc(pxd_device); pxd_dev->connected = true; pxd_dev->fastpath =
     enable_fp; INIT_WORK(&pxd_dev->remove_work, pxd_finish_remove).
  2. Allocate minor, register gendisk, add to ctx->list.
  3. If enable_fp, backing paths arrive via a separate
     PXD_UPDATE_PATH ioctl. pxd_init_fastpath_target opens the backing
     files, sets fp->fastpath = true.

Post-condition: device is on ctx->list; fp.fastpath reflects whether
fastpath is armed.


### 1.2 Device detach

Trigger: PXD_REMOVE fuse op, or PXD_IOC_DETACH_DEVICE ioctl (from any
context - detach can be issued via a tool control fd, e.g. ctx-10).

Flow (pxd.c pxd_remove_dev -> pxd_finish_remove):
  1. Under ctx->lock + pxd_dev->lock: check exported / open_count /
     force. Set removing = true (WRITE_ONCE). schedule_work(remove_work).
  2. schedule_timeout(500ms) waiting on pxd_dev->remove_wait, so the
     removal is bounded even if finish_remove hangs.
  3. pxd_finish_remove (async):
     a. pxd_fastpath_reset_device(skip_sync=true, fail_io=true).
        Disables fastpath and drains failQ via __pxd_abortfailQ.
     b. blk_freeze_queue_start; pxd_mark_device_dead (sets QUEUE_FLAG_
        DYING / blk_mark_disk_dead per kernel version).
     c. pxd_free_disk; device_unregister (waits for external
        get_device() refs to drop).
     d. Removes from ctx->list; wakes remove_wait.

Post-condition: pxd_dev fully unregistered; kfree happens after the
last put_device.

Deliberate non-behaviour: pxd_finish_remove does NOT touch
pxd_dev->connected. That flag is a ctx-scope connectivity signal owned
by _pxd_setup / freeze windows; removal is a device-lifecycle event and
should not race the ctx state machine.


### 1.3 Fastpath IO error -> pxd_io_failover

Trigger: fastpath IO error on the backing device (fp_handle_io error
path calls pxd_failover_initiate).

Flow (pxd_bio_blkmq.c pxd_io_failover):
  Entry check: if READ_ONCE(ctx->fp_freeze) is set, park the fproot on
  pxd_dev->fp.failQ under fp.fail_lock and return. See invariant 2.

  Otherwise, four-way branch on state:
    (a) !pxd_dev->connected                : hard-fail with -EIO
    (b) !ctx->fc.connected                 : disableFastPath(skip_sync=
                                             true), reroute to slowpath
                                             via pxdmq_reroute_slowpath
    (c) both connected                     : list_add to failQ,
                                             pxd_initiate_failover
                                             (coordinated switch)
    (fallback) pxd_initiate_failover fails : __pxd_abortfailQ

Branches (a) and (c) do not need the freeze because the state they read
was mutated inside a completed freeze window (invariant 1). Branch (b)
calls disableFastPath which is concurrency-safe on its own (see 1.7).


### 1.4 Control fd close (userspace exits or crashes)

Trigger: last close() of /dev/pxd/pxd-control-N.

Flow (pxd.c pxd_control_release):
  1. Under ctx->lock: WRITE_ONCE(fc.connected, 0). Order matters -
     see invariant 6.
  2. schedule_delayed_work(&ctx->abort_work, pxd_timeout_secs * HZ).
     This is the backstop that fires if userspace never reopens.
  3. schedule_work(&ctx->failover_work). Runs async.

pxd_failover_work (async):
  1. pxd_fp_freeze_start(ctx).
  2. pxdctx_reset_fastpath(ctx, fail_io=false). For each device on
     ctx->list: snap+refcount, flush_work(remove_work), skip if
     removing, otherwise pxd_fastpath_reset_device(skip_sync=true,
     fail_io=false).
  3. pxd_fp_freeze_end(ctx, fail_io=false). Drains any pxd_io_failover
     items that parked between step 2's failQ drain and the gate clear,
     reissuing them to native via pxd_reissuefailQ(status=0).

Post-condition: every fastpath device on this ctx is on the native
path. Requests already queued in fc->pending / fc->processing remain
queued (they'll be handled on reopen or aborted at T + pxd_timeout_secs).


### 1.5 Control fd open (userspace reconnects)

Trigger: open() of /dev/pxd/pxd-control-N.

Flow (pxd.c pxd_control_open):
  1. Access control: comm-name whitelist (px-storage, pxd, pxd_test,
     etc.).
  2. Refuse if fc.connected == 1 already (double-open).
  3. cancel_delayed_work_sync(&ctx->abort_work) - cancels the backstop
     if it hasn't fired.
  4. flush_work(&ctx->failover_work) - waits for a failover_work that
     was scheduled by a prior close() to complete.
  5. fuse_restart_requests(fc) - re-queues requests that were in
     flight when the fd closed.
  6. pxd_fp_freeze_start(ctx).
  7. Under ctx->lock: reset pxd_timeout_secs, WRITE_ONCE(fc.connected,
     1), WRITE_ONCE(fc.allow_disconnected, 1).
  8. pxdctx_set_connected(ctx) - iterates devices, _pxd_setup(true)
     under pxd_dev->lock, sets pxd_dev->connected = true for each.
  9. pxd_fp_freeze_end(ctx, fail_io=false). Any pxd_io_failover items
     that parked during the reopen get reissued to native (userspace
     is now up, they'll be serviced through the fuse queue).

Post-condition: fc.connected = 1, allow_disconnected = 1, every
non-removing device on ctx->list has connected = true, no parked items
on failQ.


### 1.6 Abort timeout

Trigger: ctx->abort_work fires (T + pxd_timeout_secs after
pxd_control_release, if pxd_control_open didn't cancel it).

Flow (pxd.c pxd_abort_context):
  1. BUG_ON(fc.connected)  - abort must not fire while connected.
  2. WRITE_ONCE(fc.allow_disconnected, 0).
  3. synchronize_rcu() - waits for readers of allow_disconnected to
     exit their rcu_read_lock sections (dev.c fuse_request_send_nowait).
  4. Under fc->lock: fuse_end_queued_requests(fc). Walks
     fc->pending and fc->processing, ends each request with
     -ECONNABORTED via req->end (pxd_process_write/read_reply_q ->
     blk_mq_end_request).
  5. pxd_fp_freeze_start(ctx).
  6. pxdctx_reset_fastpath(ctx, fail_io=true). Same iteration as 1.4
     but _pxd_setup(false) clears pxd_dev->connected and
     __pxd_abortfailQ aborts every leftover failQ entry with -EIO.
  7. pxd_fp_freeze_end(ctx, fail_io=true). Aborts stragglers with
     -EIO (matching the hard-fail semantic).

Post-condition: every request that was in flight is completed with
error; every pxd_dev on this ctx has connected = false; the pxd_dev
records still exist but reject new IO at pxd_open (returns -ENXIO).


### 1.7 disableFastPath (per-device fastpath teardown)

Trigger: called from many sites - pxdctx_reset_fastpath, pxd_io_failover
branch (b), pxd_finish_remove, pxd_fastpath_vol_cleanup,
pxd_debug_switch_nativepath, pxd_init_fastpath_target's error unwind.

Flow (pxd_fastpath.c disableFastPath):
  1. If fastpath was never enabled or nfd == 0: normalize state and
     return.
  2. prev = xchg(&fp->fastpath, false). See invariant 3.
     If prev == false, another caller is already handling the disable
     (or has finished); return immediately.
  3. Winner path:
     a. pxd_suspend_io(pxd_dev) - freezes blk_mq queue and waits for
        in-flight requests to drain.
     b. synchronize_rcu() - waits for existing rcu_read_lock readers of
        fp->fastpath (from pxd_queue_rq) to finish.
     c. fastpath_flush_work() - drains fastpath kthread workers
        excluding the current one (see invariant 4).
     d. Optional wait_for_sync.
     e. For each slot i in [0, MAX_PXD_BACKING_DEVS):
          f = xchg(&fp->file[i], NULL);
          if (f) filp_close(f, NULL);
        Only the caller that xchg's out a non-NULL pointer closes it.
        No double-close.
     f. fp->nfd = 0. pxd_resume_io.

Post-condition: fp->fastpath = false, all backing files closed, all
slots NULL, blk_mq queue accepting new IO through the native path.


## Part 2. Concurrent operations and invariants

The invariants are what makes the flows in Part 1 compose safely.


### Invariant 1 - state-mutation lives inside a freeze window

Every write to a decision-carrying state variable
  pxd_dev->connected
  pxd_dev->fp.fastpath (true -> false)
  ctx->fc.connected
runs inside a matched pxd_fp_freeze_start / pxd_fp_freeze_end pair.

Exceptions and why they're safe:
  - pxd_add's plain init writes (pxd_dev->connected = true,
    pxd_dev->fastpath = ...): the device is not on ctx->list yet, no
    reader can find it.
  - enableFastPath sets fp->fastpath = true. It's called from
    pxd_init_fastpath_target which runs from an ioctl path serialized
    by userspace attach ordering; concurrent enableFastPath/
    disableFastPath doesn't happen in practice.
  - fc.connected 1 -> 0 in pxd_control_release is written under
    ctx->lock BEFORE the freeze is scheduled (see invariant 6).

Corollary: a reader (pxd_io_failover) that observes any of these
variables outside a freeze window sees fully post-transition state;
inside a freeze window it parks.


### Invariant 2 - pxd_io_failover parks on failQ during freeze

pxd_io_failover checks READ_ONCE(ctx->fp_freeze) at entry. If set, it
takes fp.fail_lock, re-checks the gate, and list_add_tail's the fproot
on pxd_dev->fp.failQ.

Rationale: the reader must NOT commit to a branch decision while state
is transient. Parking on failQ is preferable to hard-failing because
the ctx-teardown code drains failQ in a mode appropriate to the
transition:
  - failover_work path (fail_io=false): pxd_reissuefailQ(status=0) ->
    native
  - abort_work path   (fail_io=true) : __pxd_abortfailQ -> -EIO

Freeze_end has a second-pass drain to catch items parked between
pxdctx_reset_fastpath's initial drain and the gate-clear.

Note fproot->wait linkage is shared with branch (c). A single fproot is
either parked-during-freeze or on-failQ-via-branch-(c), never both,
because the gate check runs first and returns on park.


### Invariant 3 - disableFastPath is single-owner via xchg, no locks

Multiple callers reach disableFastPath simultaneously (documented in
1.7). Ownership is arbitrated by:

  prev = xchg(&fp->fastpath, false);
  if (!prev) return;

Exactly one caller sees prev = true and executes the suspend / RCU /
flush / file-close sequence. Every other caller returns immediately
having observed fp->fastpath = false (which is the only post-condition
callers need).

Files are closed with a matching xchg:

  struct file *f = xchg(&fp->file[i], NULL);
  if (f) filp_close(f, NULL);

Even if a caller sneaks past the ownership gate through a
manufactured race, only the one who xchg's out the non-NULL pointer
closes it. No double-close reachable.

Locks are deliberately NOT used here. A mutex around disableFastPath
would deadlock: caller A holds mutex and blocks in pxd_suspend_io
waiting for the blk_mq freeze counter to hit zero; caller B on a
fastpath worker holds an rq ref (via pxd_io_failover) and blocks
trying to take the mutex; circular wait.

xchg is atomic, full-barrier, and arch-agnostic (defined by every arch
Linux supports via asm/cmpxchg.h). It works on any word-sized lvalue
including plain struct pointer fields.


### Invariant 4 - fastpath_flush_work never self-flushes

fastpath_flush_work iterates every pxfp kthread_worker and calls
kthread_flush_worker on each. If invoked from within a work item
running on one of those very workers, self-flush would deadlock:
kthread_flush_worker enqueues a barrier and wait_for_completion's on
it; the barrier can only run after the current work returns; the
current work can only return after the completion fires.

Fix: skip the worker whose ->task == current. This surfaces on the
branch (b) path (pxd_io_failover -> disableFastPath ->
fastpath_flush_work) but the fix is universal.

Consequence: work items queued on the current worker AFTER the current
one are not drained by this flush. That's acceptable because
kthread_worker is single-threaded per worker - those items don't run
until we return, by which time all file slots have been xchg'd to
NULL and any dereferencer must handle NULL.


### Invariant 5 - list iteration snapshots devices with get_device

pxdctx_reset_fastpath (and pxd_fp_freeze_end's drain) never dereferences
pxd_dev while holding ctx->lock across a sleeping call. Pattern:

  1. Under ctx->lock, count and allocate snap_list; walk ctx->list;
     bounds-check first, removing-check next, get_device last; store
     into snap_list.
  2. Release ctx->lock.
  3. For each snap: flush_work(remove_work) to wait for any in-flight
     pxd_finish_remove; re-check removing; process; put_device.

flush_work on remove_work is always safe because INIT_WORK is done in
pxd_add (not deferred to pxd_remove_dev), so the work_struct is never
uninitialised memory.

Removing is checked twice: once under ctx->lock (bail without ref) and
once after flush_work (bail with put_device). This prevents any window
where we mutate a device that is being removed.


### Invariant 6 - fc.connected transitions before failover_work is scheduled

pxd_control_release ordering:

  spin_lock(&ctx->lock);
  WRITE_ONCE(fc.connected, 0);
  schedule_delayed_work(&abort_work, ...);
  spin_unlock(&ctx->lock);
  schedule_work(&failover_work);

pxd_failover_work's invariant is WARN_ON_ONCE(fc.connected). If we
scheduled the work before the write, a kworker could pick it up in the
tiny window and observe fc.connected == 1. Doing the write first
closes that race by construction.

pxd_control_open's write (fc.connected 0 -> 1) is inside its own
freeze window, so pxd_io_failover racing the reconnect parks on failQ
and is reissued to native at freeze_end.


### What is NOT protected by the freeze

These are managed by their own mechanisms; the freeze protocol does not
apply:

  - pxd_dev->exported, pxd_dev->removing, pxd_dev->open_count:
    pxd_dev->lock (spinlock). Their transitions don't affect
    fastpath IO branch decisions.
  - ctx->fc.allow_disconnected: FUSE's own RCU. Writers pair
    WRITE_ONCE with synchronize_rcu; readers pair READ_ONCE with
    rcu_read_lock (dev.c fuse_request_send_nowait).
  - pxd_dev->fp.fastpath false -> true (enableFastPath): userspace
    serializes attach; no concurrent racers observed.
  - Fastpath IO's own bio submission (fp_handle_io): natively serial
    per rq, protected by blk_mq freeze during teardown via
    pxd_suspend_io.


## Part 3. Named concurrent scenarios and how the invariants keep them safe

### A. Fastpath IO error during failover_work

Timeline:
  T0: continuous fastpath IO to failing range triggers pxd_io_failover
      work items on kthread workers.
  T1: userspace close(ctl_fd) -> pxd_control_release:
      fc.connected=0; schedule failover_work.
  T2: failover_work runs freeze_start: fp_freeze=1, flushes kthread
      workers (drains items queued before T1).
  T3: freeze_start returns. pxdctx_reset_fastpath switches each device
      to native and drains failQ.
  T4: freeze_end drains any items parked between T3 and T4, reissuing
      them to native.

pxd_io_failover items queued after T2 see fp_freeze=1, park. Never
observe mid-transition state. Never hard-fail during a transition
that would otherwise legitimately re-route them.


### B. Detach concurrent with control fd close

Timeline:
  Thread A: close(ctl_fd)                 -> pxd_control_release
  Thread B: PXD_IOC_DETACH_DEVICE ioctl   -> pxd_remove_dev

pxd_remove_dev sets removing=true under lock and schedules remove_work
(which will run pxd_finish_remove). pxd_control_release schedules
failover_work.

Both work items run async. failover_work's pxdctx_reset_fastpath
iterates ctx->list. For the racing device:
  - If removing was already true when snap_list was built: skip the
    device entirely (no ref taken, no work done on it).
  - Otherwise: get_device, snap. Then outside ctx->lock,
    flush_work(remove_work) waits for pxd_finish_remove to finish (if
    it's already running or scheduled). After flush_work returns,
    re-check removing: if true (pxd_finish_remove ran), skip. Otherwise
    do the reset.

pxd_finish_remove's own pxd_fastpath_reset_device -> disableFastPath is
concurrency-safe (invariant 3) against a possible concurrent
disableFastPath from failover_work or pxd_io_failover branch (b).


### C. Rapid close+reopen while fastpath IO is failing

Timeline:
  T0: close(ctl_fd)                       -> schedule failover_work
  T1: open(ctl_fd)                        -> pxd_control_open
      - cancel_delayed_work_sync(abort_work)
      - flush_work(failover_work)         [waits for T0's work]
      - freeze_start; state writes;
        pxdctx_set_connected; freeze_end
  T2: close(ctl_fd) again                 -> new failover_work
  ...

flush_work at T1 ensures the previous freeze cycle has fully completed
before pxd_control_open enters its own freeze cycle. Two freeze cycles
never overlap on the same ctx. pxd_io_failover items racing either
freeze park on failQ and get reissued to native at the appropriate
freeze_end.


### D. Detach with active ioswitch (coordinated failover in flight)

Timeline:
  T0: fastpath IO error -> pxd_io_failover branch (c) adds fproot to
      failQ, calls pxd_initiate_failover which sends a fuse switch
      request. Waits for PX ack via req->end callback.
  T1: PXD_REMOVE arrives. pxd_remove_dev sets removing, schedules
      remove_work.
  T2: pxd_finish_remove runs pxd_fastpath_reset_device. That function
      handles an active ioswitch: overrides the switch req to
      PXD_FAILOVER_TO_USERSPACE with error -EIO and request_end's it,
      which triggers pxd_process_ioswitch_complete to fail the failQ
      IOs.
  T3: __pxd_abortfailQ (defensive backstop inside
      pxd_fastpath_reset_device) drains any leftover failQ entries.

The in-flight ioswitch is resolved to error; failover doesn't complete
to userspace but the driver reaches a consistent state. Device removal
proceeds normally.


## Part 4. Summary for reviewers

Adding a new writer of pxd_dev->connected, fp.fastpath, or
fc.connected? Put it inside a freeze window (invariant 1) or explain
why the state isn't decision-carrying for that call site.

Adding a new reader that makes a branch decision on those fields?
Copy the READ_ONCE + park-on-failQ pattern from pxd_io_failover
(invariant 2).

Adding a new caller of disableFastPath? Nothing to do; xchg handles
the concurrency (invariant 3).

Adding a new synchronous call to fastpath_flush_work from a code path
that might already be a fastpath worker? The self-flush is already
skipped (invariant 4), but consider whether the flush is redundant
given pxd_suspend_io's blk_mq freeze already drains rq-tied work.

Adding a new iteration over ctx->list? Use the snap+refcount pattern
(invariant 5).
