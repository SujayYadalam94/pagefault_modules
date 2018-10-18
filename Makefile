#obj-m += largepages_fault.o
#obj-m += codepage_fault.o
obj-m = datafault_stable.o

KBUILD_FLAGS += -w

all:
	make -C /home/sujay/Documents/linux M=$(PWD) modules
	gcc user.c -o user.o
	gcc file_io_test.c -o file_io_test.o
	gcc qsort_test.c -o qsort_test.o
	gcc malloc_test.c -o malloc_test.o
clean:
	make -C /home/sujay/Documents/linux M=$(PWD) clean
