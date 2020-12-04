root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# insmod ./pxtgt.ko
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# dmesg -T | tail
[Wed Oct 21 16:21:02 2020] For pxd device 121219129384428022 IO still suspended(2)
[Wed Oct 21 16:21:02 2020] pxd_dev 121219129384428022 fastpath 1 mode 0x48002 setting up with 1 backing volumes, [ffff920746851b00,0000000000000000,0000000000000000]
[Wed Oct 21 16:21:02 2020] For pxd device 121219129384428022 IO still suspended(1)
[Wed Oct 21 16:21:02 2020] dev121219129384428022 completed setting up 1 paths
[Wed Oct 21 16:21:02 2020] device 121219129384428022 completed ioswitch 8209 with status 0
[Wed Oct 21 16:21:02 2020] For pxd device 121219129384428022 IO resumed
[Wed Oct 21 16:21:02 2020] device 121219129384428022 resumed IO from userspace
[Wed Oct 21 18:14:11 2020] e1000: enp0s3 NIC Link is Down
[Wed Oct 21 18:14:13 2020] e1000: enp0s3 NIC Link is Up 1000 Mbps Full Duplex, Flow Control: RX
[Wed Oct 21 18:25:54 2020] pxtgt: blk-mq driver loaded version master:6758cff061f7b1074383fdb1a81bb6c62ee4ca46
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse#
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# ls -al /sys/devices/virtual/misc/pxtgt\!control-0/
attach     detach     dev        info       power/     subsystem/ uevent
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# ls -al /sys/devices/virtual/misc/pxtgt\!control-0/
total 0
drwxr-xr-x  3 root root    0 Oct 21 18:26 .
drwxr-xr-x 50 root root    0 Oct 20 18:03 ..
-rw-r--r--  1 root root 4096 Oct 21 18:26 attach
-rw-r--r--  1 root root 4096 Oct 21 18:26 detach
-r--r--r--  1 root root 4096 Oct 21 18:26 dev
-rw-r--r--  1 root root 4096 Oct 21 18:26 info
drwxr-xr-x  2 root root    0 Oct 21 18:26 power
lrwxrwxrwx  1 root root    0 Oct 21 18:26 subsystem -> ../../../../class/misc
-rw-r--r--  1 root root 4096 Oct 21 18:25 uevent
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse#

root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# truncate -s512M /tmp/tgtfile
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# echo -n /tmp/tgtfile > /sys/devices/virtual/misc/pxtgt\!control-0/attach
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# ls -al /dev/pxtgt/
total 0
drwxr-xr-x  2 root root     280 Oct 21 18:27 .
drwxr-xr-x 22 root root    4360 Oct 21 18:25 ..
brw-rw----  1 root disk 251,  1 Oct 21 18:27 17153956419767857995
crw-------  1 root root  10, 38 Oct 21 18:25 control-0
crw-------  1 root root  10, 37 Oct 21 18:25 control-1
crw-------  1 root root  10, 28 Oct 21 18:25 control-10
crw-------  1 root root  10, 36 Oct 21 18:25 control-2
crw-------  1 root root  10, 35 Oct 21 18:25 control-3
crw-------  1 root root  10, 34 Oct 21 18:25 control-4
crw-------  1 root root  10, 33 Oct 21 18:25 control-5
crw-------  1 root root  10, 32 Oct 21 18:25 control-6
crw-------  1 root root  10, 31 Oct 21 18:25 control-7
crw-------  1 root root  10, 30 Oct 21 18:25 control-8
crw-------  1 root root  10, 29 Oct 21 18:25 control-9
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# blkid /dev/pxtgt/17153956419767857995
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# mkfs.ext4 /dev/pxtgt/17153956419767857995
mke2fs 1.44.1 (24-Mar-2018)
Discarding device blocks: done
Creating filesystem with 131072 4k blocks and 32768 inodes
Filesystem UUID: a773467e-86e0-4fe2-a68e-d488e65b933d
Superblock backups stored on blocks:
        32768, 98304

Allocating group tables: done
Writing inode tables: done
Creating journal (4096 blocks): done
Writing superblocks and filesystem accounting information: done

root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# blkid /dev/pxtgt/17153956419767857995
/dev/pxtgt/17153956419767857995: UUID="a773467e-86e0-4fe2-a68e-d488e65b933d" TYPE="ext4"
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# md5sum /tmp/tgtfile
b7ac4b710b5038f61f54cb7661aaeb25  /tmp/tgtfile
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse# md5sum /dev/pxtgt/17153956419767857995
b7ac4b710b5038f61f54cb7661aaeb25  /dev/pxtgt/17153956419767857995
root@bionic:/home/lns/srcs/src/px-fuse-target/px-fuse#

