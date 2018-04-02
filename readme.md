# pintos

UCD Operating Systems - Spring 2018
(Johnathan Becker; Nate Terry)

Pintos Project 3: Virtual Memory
There are several groups of tests for the required functionality: dynamic paging/lazy loading, stack growth, memory-mapped files, extra synchronization for user memory access. There are 34 new functionality tests and 79 regression tests. The regression tests are the same as in Project 2. Each test passed is worth 10 points. Note that you need a working Project 2, at the very least working argument passing and system calls, to work on Project 3.


You will work in the vm directory for this project. The vm directory contains only Makefiles. The only change from userprog is that this new Makefile turns on the setting -DVM. All code you write will be in new files or in files introduced in earlier projects.

You will probably be encountering just a few files for the first time:

devices/block.h

devices/block.c

Provides sector-based read and write access to block device. You will use this interface to access the swap partition as a block device.
