sudo modprobe uio
pushd .. 
make && sudo insmod ./px.ko
popd
./build.sh && sudo ./mmclient
