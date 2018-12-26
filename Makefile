obj-m = bl_drv.o
PWD = $(shell pwd)
all:
	make -C /lib/modules/$(shell uname -r)/build M="$(PWD)" modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M="$(PWD)" clean
do_all:
	mkfs.vfat /dev/sbd0p1
	mkfs.vfat /dev/sbd0p5
	mkfs.vfat /dev/sbd0p6
	
	mkdir -p /tmp/p1 /tmp/p2
	mount /dev/sbd0p1 /tmp/p1
	mount /dev/sbd0p6 /tmp/p2
	
	dd if=/dev/zero of=/tmp/p1/file bs=512 count=10240 &>/dev/null
	dd if=/tmp/p1/file of=/tmp/p2/file bs=512 count=10240 status=progress
	
	dd if=/dev/zero of=/tmp/p1/file bs=512 count=10240 &>/dev/null
	dd if=/tmp/p1/file of=/tmp/file bs=512 count=10240 status=progress
	rm /tmp/file
	
	
	umount /tmp/p1
	umount /tmp/p2
	rm -r /tmp/p1 /tmp/p2
reload: all
	rmmod bl_drv
	insmod bl_drv.ko
	dd if=/dev/sbd0 of=/home/dmitry/ifmo/io2/disk3.img
	

