sudo modprobe uio
sudo mkdir -p /tmp/px
pushd .. 
make && sudo insmod ./px.ko
popd
./build.sh && sudo ./mmclient
