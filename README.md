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
datafault_stable.c : Kernel Module to track data page faults of a particular process. The PID of the process is obtained when the process makes a syscall with number 333. This syscall was implanted by us inside the kernel.

codepage_fault.c : Kernel module to track code page faults of a particular process. This module has been modified for use with a particular process using Freetype font library. Also ASLR was disabled while using this module.

file_io_test.c, malloc_test.c, qsort_test.c, user.c : Test programs to test the modules on.

