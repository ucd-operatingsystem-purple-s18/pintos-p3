#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* for pid_t */
#include "lib/user/syscall.h"

void syscall_init (void);

void sys_halt (struct intr_frame *f) NO_RETURN;
void sys_exit (int* status, struct intr_frame *f) NO_RETURN;
pid_t sys_exec (const char **file, struct intr_frame *f);
int sys_wait (pid_t*, struct intr_frame *f);
bool sys_create (const char **file, unsigned* initial_size, struct intr_frame *f);
bool sys_remove (const char **file, struct intr_frame *f);
int sys_open (const char **file, struct intr_frame *f);
int sys_filesize (int* fd, struct intr_frame *f);
int sys_read (int* fd, void *buffer, unsigned* length, struct intr_frame *f);
int sys_write (int* fd, const void *buffer, unsigned* length, struct intr_frame *f);
void sys_seek (int* fd, unsigned* position, struct intr_frame *f);
unsigned sys_tell (int* fd, struct intr_frame *f);
void sys_close (int* fd, struct intr_frame *f);

void exit(int);

void verify_valid_address(void *addr);

#endif /* userprog/syscall.h */
