obj-m := char_device_demo.o
#lkm_example-y := x.o

#KDIR ?= /home/chonepieceyb/CODING/Src/linux-6.0
KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
test:
	# We put a — in front of the rmmod command to tell make to ignore
	# an error in case the module isn’t loaded.
	-sudo rmmod char_device_demo
	# Clear the kernel log without echo
	sudo dmesg -C
	# Insert the module
	sudo insmod char_device_demo.ko
	# Display the kernel log
	dmesg


