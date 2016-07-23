obj-m = jprobe_fault.o

KBUILD_FLAGS += -w

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules $(KBUILD_FLAGS)
	gcc user.c -o user.o
	gcc file_io_test.c -o file_io_test.o
	gcc qsort_test.c -o qsort_test.o
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
