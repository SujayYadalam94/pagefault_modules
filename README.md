Acknowledgement
----------------
The base kernel module to track page faults was obtained from 
https://github.com/pradykaushik/Jprobes
Thanks to him.
The modules in this repo have been developed on top of the above kernel module.

What is this repo?
------------------
This repo contains kernel modules that are used to track page faults of a particular process of interest. It is important to note that the module has been written keeping in mind few particular processes which were of interest to us. So, you might not be able to use this module off-the-shelf to track the page faults of an arbitrary process. Also the Linux kernel was modified to support these modules.
Linux Kernel version: v4.14.0. This version was used because future versions of linux removed support for Jprobes which is the core of these modules.

Repo files:
-----------
datafault_stable.c : Kernel Module to track data page faults of a particular process. The PID of the process is obtained when the process makes a syscall with number 333. This syscall was implanted by us inside the kernel. This has been modified specifically to capture page faults for 'Hunspell' application. Can be modified to track data page faults of other application by making minor changes (remove check for 'log').

codepage_fault.c : Kernel module to track code page faults of a 'Freetype' application.

file_io_test.c, malloc_test.c, qsort_test.c, user.c : Test programs to test the modules on.


Note: ASLR has to be disabled. If large pages are being used, transparent large pages have to be enabled by changing /sys/kernel/mm/transparent_hugepage/enabled to "always", if hugetlbfs is used, then mount the filesystem using 'mount -t /mnt/hugetlbfs none' and change the owner and group if you don't want to use sudo.
