#!/bin/bash -x 
#TARGET="/var/.px/1/pxtest/pxdev"
#TARGET="/var/.px/1/pxtest/iotest"
TARGET="/test2/file"
#TARGET="/dev/nvme0n1"
#TARGET="/dev/md/pxmd_test"
#TARGET="/dev/io/iotest"
#TARGET="/dev/myloop0"

sudo dd if=/dev/zero of=$TARGET bs=1M count=32768
#for i in seq{1..10}; do
#echo "Random Read - loop $i"
echo "Random Read"
#sudo rm -f $TARGET
#sudo truncate -s10G $TARGET
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo fio --bs=4k --ioengine=libaio --rw=randread --size=32G --name=test  --fallocate=none --iodepth=128 --randrepeat=1 --direct=1 --time_based --runtime=10 --group_reporting --filename=$TARGET
#done

echo "Random Write"
#sudo rm -f $TARGET
#sudo truncate -s10G $TARGET
#sudo dd if=/dev/zero of=$TARGET bs=1M count=10000
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo fio --bs=4k --ioengine=libaio --rw=randwrite --size=32G --name=test  --fallocate=none --iodepth=128 --randrepeat=1 --direct=1 --time_based --runtime=10 --group_reporting --filename=$TARGET
echo "Sequential Read"
#sudo rm -f $TARGET
#sudo truncate -s10G $TARGET
#sudo dd if=/dev/zero of=$TARGET bs=1M count=10000
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo fio --bs=4k --ioengine=libaio --rw=read --size=32G --name=test  --fallocate=none --iodepth=128 --randrepeat=1 --direct=1 --time_based --runtime=10 --group_reporting --filename=$TARGET
echo "Sequential Write"
#sudo rm -f $TARGET
#sudo truncate -s10G $TARGET
#sudo dd if=/dev/zero of=$TARGET bs=1M count=10000
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo fio --bs=4k --ioengine=libaio --rw=write --size=32G --name=test  --fallocate=none --iodepth=128 --randrepeat=1 --direct=1 --time_based --runtime=10 --group_reporting --filename=$TARGET
echo "Random ReadWrite"
#sudo rm -f $TARGET
#sudo truncate -s10G $TARGET
#sudo dd if=/dev/zero of=$TARGET bs=1M count=10000
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo fio --bs=4k --ioengine=libaio --rw=randrw --size=32G --name=test  --fallocate=none --iodepth=128 --randrepeat=1 --direct=1 --time_based --runtime=10 --group_reporting --filename=$TARGET
