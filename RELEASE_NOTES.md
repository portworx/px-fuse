Release-wise supported kernel metrics: https://docs.portworx.com/portworx-enterprise/support-matrix/supported-kernels


# v3.8.0

- 684b517 Filter -fmin-function-alignment=<n> from the compile line on Ubuntu 6.17, 6.19, 7.1 and 7.2 kernels when the module's gcc is older than the one that built the kernel (PWX-58784)
- 6fc7e63 Print inode->i_ino with %llu and an unsigned-long-long cast so the format matches the u64 widening that ELRepo 7.1 (7.1.1-1.el10.elrepo) carries (PWX-58787)
- 127e0a8 Include <linux/string.h> in pxd.c and pxd_fastpath.c on kernel 7.2 and later, where ELRepo (7.2.2-1.el9.elrepo) dropped the transitive chain that used to make strncpy() visible (PWX-58787)
