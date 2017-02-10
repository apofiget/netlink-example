obj-m += src/kernel_netlink.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc src/userspace_netlink.c -o src/userspace_netlink
	gcc src/userspace_netlink_mmaped.c -o src/userspace_netlink_mmaped

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f src/userspace_netlink src/userspace_netlink_mmaped

