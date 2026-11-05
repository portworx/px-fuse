Release-wise supported kernel metrics: https://docs.portworx.com/portworx-enterprise/support-matrix/supported-kernels


# v3.7.2

This release reworks fastpath failover and teardown and raises the device limit to 2048;
there are no kernel or distribution compatibility changes. v3.7.1 and v3.7.1.1 shipped
the v3.7.0 driver unchanged, so the changes below are relative to v3.7.0.

- e7ad504 Ignore stale path switch completions and wait for a running completion before resetting a device
- 5f48c2c Raise the maximum number of devices from 1024 to 2048
- 164fc18 Set the module version to 3.7.2
- 9a6446b Add a fast failover capability bit for remote fastpath volumes, and allow re-adding an existing device at the device limit
- 6cd66d9 Do not resubmit failed fastpath IOs on the native path while a path switch is pending
- be953c2 Fix a sleep in atomic context in the release sysfs attribute, and add graceful and force release modes
- bd3d141 Fix a deadlock and backing files closing under in-flight IO during fastpath failover, and reduce the backing-file sync timeout from 60s to 10s
- 43e1f6a Switch fastpath devices to the native path when the PX control connection closes, fix suspend and resume handling, and allow detach during a path switch
- be462e1 Fail fastpath devices over to the native path when PX is down; reverted in v3.7.0 by 1d681fa


# v3.7.0

This release is kernel and distribution compatibility work;
there are no changes to driver behaviour relative to v3.6.0.

- 1d681fa Revert driver failover on PX shutdown; the v3.6.x behaviour is retained
- 71b7324 Use the argument-less blk_mq_freeze_queue()/blk_mq_unfreeze_queue() signature on Oracle UEK 10
- f058aa9 Detect Oracle UEK 7, 8, 9 and 10 kernels, previously only UEK 8 and 9 were recognised
- 99547db Configure queue limits through queue_limits instead of blk_queue_max_*() on Oracle UEK 6.12 and later
- 5172e54 Fail the driver over when PX is down; reverted later in this release by 1d681fa
- de7c405 Compile the disk allocation helper only on kernel 5.14 and later so older kernels build cleanly
- 7ac76e6 Move queue freeze and unfreeze into SUSE-aware helpers and check for a NULL string before taking its length
- 62fcbe7 Separate the pre-5.11 and 5.11-and-later capacity update paths in the resize ioctl; no behaviour change
- 4a5ecca Collapse the per-kernel blk_mq_alloc_disk() variants into a single pxd_alloc_disk() helper
- 55498de Apply a new device capacity after releasing the device spinlock, fixing a sleep-in-atomic during filesystem resize
- b5aae61 Support the write-zeroes opcode and derive max_write_zeroes_sectors from the device discard size
- 221f613 Restore the build on Linux 4.18 and 5.16 and centralise the device teardown API selection
- 0a2133c Set the module version to 3.7.0
- 3c483de Declare the queue freeze flag with the type the kernel API returns
- 9630a18 Detect RHEL 9 and RHEL 10 kernels carrying the back-ported blk_mq_freeze_queue() signature change
- 06fdd77 Replace ida_simple_get()/ida_simple_remove(), removed in kernel 6.18, with ida_alloc_range()/ida_free() wrappers
- 9e89fd4 Select the blk_mode_t open and release signatures on SUSE from the kernel build number, and add an ELRepo disk allocation path
- 58a4551 Detect SUSE kernels from CONFIG_SUSE_PATCHLEVEL and the build number to pick the correct block layer APIs
- 7867d96 Advertise discard support only when the device reports a non-zero discard size
- 3d00764 Remove unused RPM build scripts
- b533b8a Log the device ID and minor number when the device list is longer than the snapshot list
- baba23e Release the spinlock before calling blk_mq_quiesce_queue(), which may sleep
- f8cdc83 Identify ELRepo el9 and el10 kernels and select the matching flush and partition number APIs
- 7c410ff Associate cloned bios with the root cgroup by passing a NULL css, restoring the previous behaviour on RHEL
- 3446b70 Support RHEL 9.7 and 10.1, which removed BLK_MQ_F_SHOULD_MERGE and require bdev_partno()
- 9685402 Trigger a fastpath failover when a backing device returns -ENOLINK
- e9588ef Read the fastpath flag under RCU so disabling fastpath cannot race with IO submission
- 5b887e3 Correct active IO accounting on remote fastpath so retried IOs are not counted twice
- d54d0881 compatibility: pass suse 5.15.x-15sp4 through blk_set_queue_dying()
- 9e160e70 PWX-57597: log line fix for releasing fastpath devices
