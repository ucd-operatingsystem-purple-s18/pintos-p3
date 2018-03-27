#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/kernel/console.h"
#include "lib/user/syscall.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
//-----------------------------
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "string.h"

/* temp  */

static void syscall_handler (struct intr_frame *);


void
syscall_init (void) 
{
  /*
2nd param = int dpl
    dpl - determines how the interrupt can be invoked. if dpl is 0, then the interrupt
        can eb invoked only by kernel threads.
    Otherwise dpl should be set to 3 (set it here)
        3 allows user processes to invoke the interrupt with an explicit INT instruction.
    The value of dpl doesnt affect user processes' ability to invoke the interrupt
        indirectly e.g. an invalid memory reference will cause a page fault regardless of dpl.
*/ 
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

static void
syscall_handler (struct intr_frame *f) 
{          
  int *sys_call_number = (int *) f->esp;
  verify_valid_address(sys_call_number);

  /* only get to here with valid sys_call_number */
  void* esp = f->esp + 4;

  switch(*sys_call_number)
  {
    case SYS_HALT: sys_halt(f); break;
    case SYS_EXIT: sys_exit((int*)esp, f); break;
    case SYS_EXEC: sys_exec((char **) esp, f); break; 
    case SYS_WAIT: sys_wait((pid_t*) esp, f); break;
    case SYS_CREATE: sys_create((char**) esp, (unsigned*)esp+4, f); break;
    case SYS_REMOVE: sys_remove((char**) esp, f); break;
    case SYS_OPEN: sys_open((char**) esp, f); break;
    case SYS_FILESIZE: sys_filesize((int*) esp, f); break;
    case SYS_READ: sys_read((int*)esp, *((void**)esp+4), (unsigned*)esp+8, f); break;
    case SYS_WRITE: sys_write((int*)esp, *((void**)esp+4), (unsigned*)esp+8, f); break;
    case SYS_SEEK: sys_seek((int*)esp, (unsigned*)esp+4, f); break;
    case SYS_TELL: sys_tell((int*)esp, f); break;
    case SYS_CLOSE: sys_close((int*)esp, f); break;

    /* bad system call */
    default: break;
  }
}

/*
  Terminates Pintos by calling shutdown_power_off() 
  (declared in ‘devices/shutdown.h’). This should be seldom used, 
  because you lose some information about possible deadlock 
  situations, etc.
*/
void 
sys_halt (struct intr_frame *f) 
{
  shutdown_power_off();
}

/*
  Terminates the current user program, returning status to the kernel. If the process’s
  parent waits for it (see below), this is the status that will be returned. Conventionally,
  a status of 0 indicates success and nonzero values indicate errors.
*/
void 
sys_exit (int* status, struct intr_frame *f)
{
  verify_valid_address(status);
  int retval = *status;
  f->eax = retval;
  exit(retval);
}

/*
  Runs the executable whose name is given in cmd line, passing any given arguments,
  and returns the new process’s program id (pid). Must return pid -1, which otherwise
  should not be a valid pid, if the program cannot load or run for any reason. Thus,
  the parent process cannot return from the exec until it knows whether the child
  process successfully loaded its executable. You must use appropriate synchronization
  to ensure this.
*/
pid_t 
sys_exec (const char **file, struct intr_frame *f)
{
  //Use our validate function to make sure this address is valid
  //is this raw address available???
  verify_valid_address(file);
  int i = 0;
  do
  {
    // Now we must validate that these 4 bytes hold what we are actually trying to access
    verify_valid_address(*file+i);
    i+=4;
    //This while runs until we hit the end of our 4byte address
  }while(*file[i-4] != '\0');
  /* Starts a new thread running a user program loaded from
  FILENAME. Returns the new process's thread id, or TID_ERROR if
  the thread cannot be created. */
  f->eax = process_execute(*file);
  return (pid_t)f->eax;
}

/*
  Waits for a child process pid and retrieves the child’s exit status.
  If pid is still alive, waits until it terminates. Then, returns the status that pid passed
  to exit. If pid did not call exit(), but was terminated by the kernel (e.g. killed due
  to an exception), wait(pid) must return -1. It is perfectly legal for a parent process
  to wait for child processes that have already terminated by the time the parent calls
  wait, but the kernel must still allow the parent to retrieve its child’s exit status, or
  learn that the child was terminated by the kernel.
  wait must fail and return -1 immediately if any of the following conditions is true:

    • pid does not refer to a direct child of the calling process. pid is a direct child
    of the calling process if and only if the calling process received pid as a return
    value from a successful call to exec.
    Note that children are not inherited: if A spawns child B and B spawns child
    process C, then A cannot wait for C, even if B is dead. A call to wait(C) by
    process A must fail. Similarly, orphaned processes are not assigned to a new
    parent if their parent process exits before they do.

    • The process that calls wait has already called wait on pid. That is, a process
    may wait for any given child at most once.

  Processes may spawn any number of children, wait for them in any order, and may
  even exit without having waited for some or all of their children. Your design should
  consider all the ways in which waits can occur. All of a process’s resources, including
  its struct thread, must be freed whether its parent ever waits for it or not, and
  regardless of whether the child exits before or after its parent.
  You must ensure that Pintos does not terminate until the initial process exits.
  The supplied Pintos code tries to do this by calling process_wait() (in
  ‘userprog/process.c’) from main() (in ‘threads/init.c’). We suggest that you
  implement process_wait() according to the comment at the top of the function
  and then implement the wait system call in terms of process_wait().
  Implementing this system call requires considerably more work than any of the rest.
*/
int 
sys_wait (pid_t* wait_pid, struct intr_frame *f)
{
  //is this raw address available???
  verify_valid_address(wait_pid);
  //printf("Waiting for thread: %d\n", wait_pid);
  //process_wait(wait_pid);
  //f->eax = process_wait(wait_pid);
  f->eax = process_wait(*wait_pid);
  return (int)f->eax;
}

/*
  Creates a new file called file initially initial size bytes in size. Returns true if suc-
  cessful, false otherwise. Creating a new file does not open it: opening the new file is
  a separate operation which would require a open system call.
*/
bool 
sys_create (const char **file, unsigned* initial_size, struct intr_frame *f)
{
  return 0;
}

/*
  Deletes the file called file. Returns true if successful, false otherwise. A file may be
  removed regardless of whether it is open or closed, and removing an open file does
  not close it. See [Removing an Open File], page 35, for details.
*/
bool 
sys_remove (const char **file, struct intr_frame *f)
{
  return 0;
}

/*
  Opens the file called file. Returns a nonnegative integer handle called a “file descrip-
  tor” (fd), or -1 if the file could not be opened.
  File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is
  standard input, fd 1 (STDOUT_FILENO) is standard output. The open system call will
  never return either of these file descriptors, which are valid as system call arguments
  only as explicitly described below.

  Each process has an independent set of file descriptors. File descriptors are not
  inherited by child processes.

  When a single file is opened more than once, whether by a single process or different
  processes, each open returns a new file descriptor. Different file descriptors for a single
  file are closed independently in separate calls to close and they do not share a file
  position.
*/
int 
sys_open (const char **file, struct intr_frame *f)
{
  //is this raw address available???
  verify_valid_address(file);
  int i = 0;
  do
  {
  //is this raw address available???
    verify_valid_address(*file + i);
    i+=4;
    //remember we have a byte address, that ends in a NULL
  }while(*file[i-4] != '\0');
  //return our current thread
  struct thread *t = thread_current();
  int retval;
  /* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
  struct file *op = filesys_open(*file);
  struct file_map fm;
  if(op == NULL)
  {
    retval = -1;
  }else{
    fm.fd = ++t->next_fd;
    fm.file = op;
    list_push_back(&t->files, &fm.file_elem);
    retval = fm.fd;
  }
  f->eax = retval;
  return (int)f->eax;
}

/*
  returns the size, in bytes, of the file open as fd.
*/
int 
sys_filesize (int* fd, struct intr_frame *f)
{
  return 0;
}

/*
  Reads size bytes from the file open as fd into buffer. Returns the number of bytes
  actually read (0 at end of file), or -1 if the file could not be read (due to a condition
  other than end of file). Fd 0 reads from the keyboard using input_getc().
*/
int 
sys_read (int* fd, void *buffer, unsigned* length, struct intr_frame *f)
{
  return 0;
}

/*
  Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
  written, which may be less than size if some bytes could not be written.
  Writing past end-of-file would normally extend the file, but file growth is not imple-
  mented by the basic file system. The expected behavior is to write as many bytes as
  possible up to end-of-file and return the actual number written, or 0 if no bytes could
  be written at all.
*/
int 
sys_write (int* fd, const void *buffer, unsigned* length, struct intr_frame *f)
{
  int retval = 0;
  if (*fd == 1)
  {
    /* use putbuf to push buffer onto console */
    putbuf(buffer, length);
    retval = length;
  }
  /* put return value in EAX for return from interrupt */
  f->eax = retval;
  return retval;
}

/*
  Changes the next byte to be read or written in open file fd to position, expressed in
  bytes from the beginning of the file. (Thus, a position of 0 is the file’s start.)
  A seek past the current end of a file is not an error. A later read obtains 0 bytes,
  indicating end of file. A later write extends the file, filling any unwritten gap with
  zeros. (However, in Pintos files have a fixed length until project 4 is complete, so
  writes past end of file will return an error.) These semantics are implemented in the
  file system and do not require any special effort in system call implementation.
*/
void 
sys_seek (int* fd, unsigned* position, struct intr_frame *f)
{
  
}

/*
  Returns the position of the next byte to be read or written in open file fd, expressed
  in bytes from the beginning of the file.
*/
unsigned 
sys_tell (int* fd, struct intr_frame *f)
{
  return 0;
}

/*
  Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open
  file descriptors, as if by calling this function for each one.
*/
void 
sys_close (int* fd, struct intr_frame *f)
{
  //is this raw address available???
  verify_valid_address(fd);
  struct thread *t = thread_current();
  if(*fd != 0 && *fd != 1)
  {
    struct list_elem *e;
    for (e = list_begin (&t->files); e != list_end (&t->files);
    e = list_next (e))
    {
      struct file_map *fmp = list_entry (e, struct file_map, file_elem);
      if(fmp->fd == *fd)
      {
        list_remove(e);
        file_close(fmp->file);
        break;
      }
    }
  }
}

void 
exit (int status)
{
  struct thread *t = thread_current();
  t->parent_share->exit_code = status;
  //t->parent_share->reference_count -= 1;
  //t->parent_share->ref_count -= 1;
  char *thr_name = thread_name();
  printf("%s: exit(%d)\n", thr_name, status);
  //sema_up(&thread_current()->wait_sema);
  sema_up(&thread_current()->parent_share->dead_sema);
  thread_exit();
}

/* verifies whether a passed stack address is valid to work with */
void 
verify_valid_address(void *addr)
{

  /* First check for each byte of address whether this is a valid address */
  for(int i = 0; i < 4; ++i)
  {
    if(addr + i == NULL || !is_user_vaddr(addr+i) || 
      pagedir_get_page(thread_current()->pagedir,addr+i) == NULL)
    {
      /* If address invalid we need to exit process */
      exit(-1);
    }
  }
}