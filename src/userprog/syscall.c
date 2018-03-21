#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/kernel/console.h"
#include "lib/user/syscall.h"
#include "userprog/process.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
//syscall_handler (struct intr_frame *f UNUSED)
syscall_handler (struct intr_frame *f) 
{
  //printf ("\n\nsystem call! from /home/pintos/pintos/src/userprog/syscall.c\n");
  int *sys_call_number = (int *) f->esp;
  //printf("System call number is: %d\n", *sys_call_number);
  
  /*
  3.3.4 System Calls
    Implement the system call handler in ‘userprog/syscall.c’. The skeleton implementation
    we provide “handles” system calls by terminating the process. It will need to retrieve the
    system call number, then any system call arguments, and carry out appropriate actions.
    Implement the following system calls. The prototypes listed are those seen by a user
    program that includes ‘lib/user/syscall.h’. (This header, and all others in ‘lib/user’,
    are for use by user programs only.) System call numbers for each system call are defined in
    ‘lib/syscall-nr.h’:
  */
  switch(*sys_call_number)
  {
    /*
    void halt (void)
      [System Call] 
    Terminates Pintos by calling shutdown_power_off() 
    (declared in ‘devices/shutdown.h’). This should be seldom used, 
    because you lose some information about possible deadlock 
    situations, etc.
    */
    case SYS_HALT: 
    {
      printf("syscall.c ==> SYS_HALT!\n");

      shutdown_power_off();
      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    void exit (int status )
      [System Call]
    Terminates the current user program, returning status to the kernel. If the process’s
    parent waits for it (see below), this is the status that will be returned. Conventionally,
    a status of 0 indicates success and nonzero values indicate errors.
    */
    case SYS_EXIT: 
    {
      //printf("syscall.c ==> SYS_EXIT!\n");
      char *thr_name = thread_name();
      int *exit_code = (int *) (f->esp + 4);
      int retval = *exit_code;
      printf("%s: exit(%d)\n", thr_name, *exit_code);
      f->eax = retval;
      sema_up(&thread_current()->wait_sema);
      thread_exit();
      
      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    pid_t exec (const char * cmd_line )
      [System Call]
    Runs the executable whose name is given in cmd line, passing any given arguments,
    and returns the new process’s program id (pid). Must return pid -1, which otherwise
    should not be a valid pid, if the program cannot load or run for any reason. Thus,
    the parent process cannot return from the exec until it knows whether the child
    process successfully loaded its executable. You must use appropriate synchronization
    to ensure this.
    */
    case SYS_EXEC: 
    {
      //printf("syscall.c ==> SYS_EXEC!\n");
      //printf --> calls for printf in these cases are causing tests to fail???
      char *buffer = *((char **) (f->esp + 4));
      printf("syscall.c ==> SYS_EXEC: %s\n", buffer);
      f->eax = process_execute(buff);

      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    int wait (pid t pid )
      [System Call]
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
    case SYS_WAIT: 
    {
      //printf("syscall.c ==> SYS_WAIT!\n");
      pid_t wait_pid = *((pid_t *) (f->esp + 4));
      printf("Waiting for thread: %d\n", wait_pid);
      process_wait(wait_pid);
      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    bool create (const char * file , unsigned initial_size )
      [System Call]
    Creates a new file called file initially initial size bytes in size. Returns true if suc-
    cessful, false otherwise. Creating a new file does not open it: opening the new file is
    a separate operation which would require a open system call.
    */
    case SYS_CREATE: 
    {
      //printf("syscall.c ==> SYS_CREATE!\n");

      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    bool remove (const char * file )
      [System Call]
    Deletes the file called file. Returns true if successful, false otherwise. A file may be
    removed regardless of whether it is open or closed, and removing an open file does
    not close it. See [Removing an Open File], page 35, for details.
    */
    case SYS_REMOVE: 
    {
      //printf("syscall.c ==> SYS_REMOVE!\n");

      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    int open (const char * file )
      [System Call]
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
    case SYS_OPEN: 
    {
      //printf("syscall.c ==> SYS_OPEN!\n");

      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    int filesize (int fd )
      [System Call]
    Returns the size, in bytes, of the file open as fd.
    */
    case SYS_FILESIZE: 
    {
      //printf("syscall.c ==> SYS_FILESIZE!\n");

      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    int read (int fd , void * buffer , unsigned size )
      [System Call]
    Reads size bytes from the file open as fd into buffer. Returns the number of bytes
    actually read (0 at end of file), or -1 if the file could not be read (due to a condition
    other than end of file). Fd 0 reads from the keyboard using input_getc().
    */
    case SYS_READ: 
    {
      //printf("syscall.c ==> SYS_READ!\n");

      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    int write (int fd , const void * buffer , unsigned size )
      [System Call]
    Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
    written, which may be less than size if some bytes could not be written.
    Writing past end-of-file would normally extend the file, but file growth is not imple-
    mented by the basic file system. The expected behavior is to write as many bytes as
    possible up to end-of-file and return the actual number written, or 0 if no bytes could
    be written at all.

    Fd 1 writes to the console. Your code to write to the console should write all of buffer
    in one call to putbuf(), at least as long as size is not bigger than a few hundred
    bytes. (It is reasonable to break up larger buffers.) Otherwise, lines of text output
    by different processes may end up interleaved on the console, confusing both human
    readers and our grading scripts.
    */
    case SYS_WRITE: 
    {
      //printf("syscall.c ==> SYS_WRITE!\n");

      int *fd = (int *) (f->esp + 4);
      char *buffer = *((char **) (f->esp + 8));
      unsigned size = *((unsigned *) (f->esp + 12));
     // printf("Write Call!\n");
      int retval = 0;
      if (*fd == 1){
        //printf("Write to Console:\n");
        putbuf(buffer,size);
        retval = size;
      }
      f->eax = retval;
      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    void seek (int fd , unsigned position )
      [System Call]
    Changes the next byte to be read or written in open file fd to position, expressed in
    bytes from the beginning of the file. (Thus, a position of 0 is the file’s start.)
    A seek past the current end of a file is not an error. A later read obtains 0 bytes,
    indicating end of file. A later write extends the file, filling any unwritten gap with
    zeros. (However, in Pintos files have a fixed length until project 4 is complete, so
    writes past end of file will return an error.) These semantics are implemented in the
    file system and do not require any special effort in system call implementation.
    */
    case SYS_SEEK: 
    {
      //printf("syscall.c ==> SYS_SEEK!\n");

      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    unsigned tell (int fd )
      [System Call]
    Returns the position of the next byte to be read or written in open file fd, expressed
    in bytes from the beginning of the file.
    */
    case SYS_TELL: 
    {
      //printf("syscall.c ==> SYS_TELL!\n");

      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
    void close (int fd )
      [System Call]
    Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open
    file descriptors, as if by calling this function for each one.
    */
    case SYS_CLOSE: 
    {
      //printf("syscall.c ==> SYS_CLOSE!\n");

      break;
    }
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    /*
The file defines other syscalls. Ignore them for now. You will implement some of them
in project 3 and the rest in project 4, so be sure to design your system with extensibility in
mind.

To implement syscalls, you need to provide ways to read and write data in user virtual
address space. You need this ability before you can even obtain the system call number,
because the system call number is on the user’s stack in the user’s virtual address space. This
can be a bit tricky: what if the user provides an invalid pointer, a pointer into kernel memory,
or a block partially in one of those regions? You should handle these cases by terminating
the user process. We recommend writing and testing this code before implementing any
other system call functionality. See Section 3.1.5 [Accessing User Memory], page 27, for
more information.

You must synchronize system calls so that any number of user processes can make them
at once. In particular, it is not safe to call into the file system code provided in the ‘filesys’
directory from multiple threads at once. Your system call implementation must treat the
file system code as a critical section. Don’t forget that process_execute() also accesses
files. For now, we recommend against modifying code in the ‘filesys’ directory.
We have provided you a user-level function for each system call in ‘lib/user/syscall.c’.
These provide a way for user processes to invoke each system call from a C program. Each
uses a little inline assembly code to invoke the system call and (if appropriate) returns the
system call’s return value.

When you’re done with this part, and forevermore, Pintos should be bulletproof. Nothing
that a user program can do should ever cause the OS to crash, panic, fail an assertion, or
otherwise malfunction. It is important to emphasize this point: our tests will try to break
your system calls in many, many ways. You need to think of all the corner cases and handle
them. The sole way a user program should be able to cause the OS to halt is by invoking
the halt system call.

If a system call is passed an invalid argument, acceptable options include returning an
error value (for those calls that return a value), returning an undefined value, or terminating
the process.
    */
    default: 
    {
      //printf("syscall.c ==> default!\n");

      //Place the code for a bad system call number here.
      break;
    }
        //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
    //----------------------------------------------
  }
  
  //thread_exit ();
}