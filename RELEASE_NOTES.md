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
