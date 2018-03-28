#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

void exit(int);

// we need to check our stack address for validity
// accepts an address
// calls exit(-1) if the address is out of range
void validate_theStackAddress(void *addr);

#endif /* userprog/syscall.h */
