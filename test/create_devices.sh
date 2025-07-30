#!/ bin / bash

#Create / dev / pxd directory
mkdir - p / dev /
            pxd

#Read misc devices and create device nodes
                grep pxd /
            proc / misc |
    while read minor name;
do
echo "Creating device /dev/$name with minor $minor" mknod / dev /
            $name c 10 $minor 2 >
        / dev / null ||
    true chmod 666 / dev /
            $name done

#List created devices
                ls -
        la / dev / pxd /