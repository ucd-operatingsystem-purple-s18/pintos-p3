#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

static struct lock filesys_lock;
void syscall_init (void);

void exit(int);

/* checks if function is correctly in user space */
void check_addr_valid(void *addr);

#endif /* userprog/syscall.h */
