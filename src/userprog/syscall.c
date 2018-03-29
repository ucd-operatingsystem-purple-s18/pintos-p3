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
// i think we need the string lib. I still dont completely get the 
//      difference with this and c vs c++
#include "string.h"
//-----------------------------

/*
Whenever a user process wants to access some kernel functionality, 
it invokes a system call. This is a skeleton system call handler. 
Currently, it just prints a message and terminates the user process. 
In part 2 of this project you will add code to do everything else needed by system calls.
*/
/*
Remember we cannot execute kernel code from the user space.
We need to signal the kernel that we want to execute and have the system switch to the kernel mode.
i.e. interrupt
If we have an  interrupt/exception then the system will switch to kernel mode.
This can then execute the exception handler i.e. syscall_handler
We can easily register the system_call here, but implementing is what is hard.

esp should point syscall --> remember esp is the stack pointer
---> @ param f
eax should contain return value of syscall

*/
static void syscall_handler (struct intr_frame *);

/*
  When a user program calls one of the functions deﬁned in lib/user/syscall.h, it causes a soft- 
ware interrupt and creates an interrupt frame. This suspends the currently running thread. 
The syscall function that the user program calls takes anywhere between 1 and 3 parameters. 
The pointers to each parameter are pushed onto the stack from the end of the beginning, then 
an integer value (the syscall code) is pushed last. This frame is then dispatched to the void 
syscall_handler(struct intr_frame* f); function. This function should look at the ﬁrst 
element of the frame’s stack pointer (f->esp), and determine the type of syscall to execute. You 
can get the syscall code by doing the following: 
int sys_code = (int )f->esp;
*/
void
syscall_init (void) 
{
  /*
Function: 
void intr_register_int (uint8_t vec, int dpl, enum intr_level level, intr_handler_func *handler, const char *name)
https://web.stanford.edu/class/cs140/projects/pintos/pintos_6.html

Registers handler to be called when internal interrupt numbered vec is triggered. 
Names the interrupt name for debugging purposes.

0x30 - pintos uses for system calls
    user processes will push parameters onto the stack and execute int 0x30
In the kernel, pintos will handle int 0x30 by callign syscall_handler

Remember that syscalls are implemented only in kernel, not in userland.

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

static void
//syscall_handler (struct intr_frame *f UNUSED)
syscall_handler (struct intr_frame *f) 
{
  //printf ("\n\nsystem call! from /home/pintos/pintos/src/userprog/syscall.c\n");
  /*
  Adding taken notes, to stop from flipping back and forth for minor issues.
    const char *p = "abc"; ----> 4bytes for a, b, c, \0   which are stored somewhere.
        p = the address where those 4 bytes are stored.

    if that string started at:    0x1000 and p=32bit pointer at 0x2000
        then the memory content = 
        Memory Address(hex)     Variable name     Contents
        1000                                      'a' == 97 (ascii)
        1001                                      'b' == 98
        1002                                      'c' == 99
        1003                                      0
        ...
        2000 - 2003             p                 1000 (hex)

        So p is storing the address of 0x1000
        *p    == 'a'          the first character at address p
        p[1]  == 'b'
        ...
        i.e. (*(p+1) == 'b')   which is another notation for p[1]

        Note for our loops we can ++p for move from 0x1000 to 0x1001
            So if we go:
                *p == 'a'
                ++p
                *p == 'b' //now

        Remember to use our pointers when we actually need to write to it.
            int x     = 2     //var x = 2
            int *p_x  = &x    //pointer that holds the address of x
            *p_x      = 4     //change the memory at the address in p_x so inherently we are changing x

        Dereferencing and accessing a structure data member
            We have a variable, that is a pointer to a structure.
                The structure has data members
                We can access those member using the dereference pointer  '->'

                typedef struct X {
                  int i_;
                  double d_;
                } X;

                X x;              //create a struct xe
                X *p  = &x;       //create a struct pointer, points to address of x
                p->d_ = 3.14159;  //dereference and access data member x.d_
                (*p).d_ *= -1;    //another equivalent notation for accessing x.d_  


  */            
  int *sys_call_number = (int *) f->esp;
  //printf("System call number is: %d\n", *sys_call_number);
  // Remember that if we do not send a valid syscall number
  //    then we have no syscall to jump to. The Validate function helps us to check it out 
  //    otherwise the Validate will exit and skip over this switch call
  validate_theStackAddress(sys_call_number);
  
  /*
  3.3.4 System Calls
    Implement the system call handler in ‘userprog/syscall.c’. The skeleton implementation
    we provide “handles” system calls by terminating the process. It will need to retrieve the
    system call number, then any system call arguments, and carry out appropriate actions.
    Implement the following system calls. The prototypes listed are those seen by a user
    program that includes ‘lib/user/syscall.h’. (This header, and all others in ‘lib/user’,
    are for use by user programs only.) System call numbers for each system call are defined in
    ‘lib/syscall-nr.h’:

        / Projects 2 and later. /
    SYS_HALT,                   / Halt the operating system. /
    SYS_EXIT,                   / Terminate this process. /
    SYS_EXEC,                   / Start another process. /
    SYS_WAIT,                   / Wait for a child process to die. /
    SYS_CREATE,                 / Create a file. /
    SYS_REMOVE,                 / Delete a file. /
    SYS_OPEN,                   / Open a file. /
    SYS_FILESIZE,               / Obtain a file's size. /
    SYS_READ,                   / Read from a file. /
    SYS_WRITE,                  / Write to a file. /
    SYS_SEEK,                   / Change position in a file. /
    SYS_TELL,                   / Report current position in a file. /
    SYS_CLOSE,                  / Close a file. /
  */

  /*
    Remem:
    system call number is passed int he %eax register (32 bit)
        This is to distinguish which syscall to invoke
    alltrap() saves it along with all other registers (dont understand alltrap???)
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
      //printf("syscall.c ==> SYS_HALT!\n");

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
      //char *thr_name = thread_name();
      int *exit_code = (int *) (f->esp + 4);
      //is this raw address available???
      validate_theStackAddress(exit_code);
      int retval = *exit_code;
      //printf("%s: exit(%d)\n", thr_name, *exit_code);
      f->eax = retval;
      //sema_up(&thread_current()->wait_sema);
      //thread_exit();
      exit(retval);
      
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
      //char *buffer = *((char **) (f->esp + 4));
      // Remember ** points to a pointer which points at an address
      //    int x       = 6; 
      //    int *ptr2   = &var;
      //    int **ptr1  = &ptr2;
      // set our raw to the char at our stack pointer, + 4bytes
      char **raw = (char **) (f->esp+4);//---------------------
      //Use our validate function to make sure this address is valid
      //is this raw address available???
      validate_theStackAddress(raw);//---------------------
      
      //=============================
      // We had this do/while, but it risks holding 
      //    switch to a for instead of do while.
      //int i = 0;//---------------------
      // do
      // {//---------------------
      // // Now we must validate that these 4 bytes hold what we are actually trying to access
      //   //is this raw address available???
      //   validate_theStackAddress(*raw+i);//---------------------
      //   i+=4;//---------------------
      //   //This while runs until we hit the end of our 4byte address
      // }while(*raw[i-4] != '\0');//---------------------
      validate_theStackAddress(*raw);
      for(int i=0; i<strlen(*raw); ++i)
      {
        validate_theStackAddress(*raw + i);
      }
      //---------------------
      //printf("syscall.c ==> SYS_EXEC: %s\n", buffer);
      //is this raw address available???
      //validate_theStackAddress(buffer);
      //f->eax = process_execute(buffer);
      /* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
      f->eax = process_execute(*raw);
      //printf("after execution.\n");
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
      //pid_t wait_pid = *((pid_t *) (f->esp + 4));
      pid_t *wait_pid = ((pid_t *) (f->esp + 4));
      //is this raw address available???
      validate_theStackAddress(wait_pid);
      //printf("Waiting for thread: %d\n", wait_pid);
      //process_wait(wait_pid);
      //f->eax = process_wait(wait_pid);
      f->eax = process_wait(*wait_pid);
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
      char **raw = (char **) (f->esp+4);
      validate_theStackAddress(raw);
      validate_theStackAddress(*raw);
      for(int i=0; i<strlen(*raw); ++i)
      {
        validate_theStackAddress(*raw + i);
      }
      unsigned *size = (unsigned *) (f->esp + 8);
      validate_theStackAddress(size);
      f->eax = filesys_create(*raw, *size);

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
      char **raw = (char **) (f->esp + 4);
      //is this raw address available???
      validate_theStackAddress(raw);
      
      // FORGET THE DO/WHILE, WILL GET CAUGHT
      //    SWITCH TO FOR
      // int i = 0;
      // do
      // {
      // //is this raw address available???
      //   validate_theStackAddress(*raw + i);
      //   i+=4;
      //   //remember we have a byte address, that ends in a NULL
      // }while(*raw[i-4] != '\0');
      //return our current thread
      validate_theStackAddress(*raw);
      for(int i=0; i<strlen(*raw); ++i)
      {
        validate_theStackAddress(*raw + i);
      }
      struct thread *t = thread_current();
      int retval;

      /* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.

   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
      struct file *op = filesys_open(*raw);
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

    */
    case SYS_WRITE: 
    {
      //printf("syscall.c ==> SYS_WRITE!\n");
      //    Fd 1 writes to the console. 
      int *fd = (int *) (f->esp + 4);
      //char *buffer = *((char **) (f->esp + 8));
      //unsigned size = *((unsigned *) (f->esp + 12));
      //Dont need buffer, size need to be a pointer
      validate_theStackAddress(fd);
      unsigned *size = ((unsigned *) (f->esp + 12));
      validate_theStackAddress(size);
      char **raw = (char **) (f->esp + 8);
      validate_theStackAddress(raw);
      validate_theStackAddress(*raw);
      for(int i=0; i<*size; ++i)
      {
        validate_theStackAddress(*raw + i);
      }
      
      //printf("Write Call!\n");
      int retval = 0;
      if (*fd == 1)
      {
        //printf("Write to Console:\n");
        /*
          Your code to write to the console should write all of buffer
    in one call to putbuf(), at least as long as size is not bigger than a few hundred
    bytes. (It is reasonable to break up larger buffers.) Otherwise, lines of text output
    by different processes may end up interleaved on the console, confusing both human
    readers and our grading scripts.
        */
        //putbuf(buffer, size);
        //retval = size;
        //====changed to pointers
        putbuf(*raw, *size);
        retval = *size;
      }
      else{
        struct list_elem *e;
        struct thread* t = thread_current();
        
        
        for (e = list_begin (&t->files); e != list_end (&t->files);
          e = list_next (e))
          {
            struct file_map *fmp = list_entry (e, struct file_map, file_elem);
            if(fmp->fd == *fd)
            {
              retval = file_write(fmp->file, *raw, *size);
              break;
            }
          }

      }
      //Remember the the eax register is for the 32 bit 
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
      int  *fd = (int *) (f->esp + 4);
      //is this raw address available???
      validate_theStackAddress(fd);
      struct thread *t = thread_current();
      if(*fd != 0 && *fd != 1)
      {
        //Each list element is a struct containing a previous and next pointer:
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
      break;    }
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
//----------------------------------------------
//----------------------------------------------
void exit(int exit_code)
{
  struct thread *t = thread_current();
  t->parent_share->exit_code = exit_code;
  //t->parent_share->reference_count -= 1;
  //t->parent_share->ref_count -= 1;
  char *thr_name = thread_name();
  printf("%s: exit(%d)\n", thr_name, exit_code);
  //sema_up(&thread_current()->wait_sema);
  sema_up(&thread_current()->parent_share->dead_sema);
  thread_exit();
}

// Checking to verify that the address we are sending in is valid.
//is this raw address available???
void validate_theStackAddress(void *addr)
{
  // if(addr == NULL || !is_user_vaddr(addr) || pagedir_get_page(thread_current()->pagedir, addr) == NULL)
  // { 
  //   exit(-1);
  // }
  // Remember we are working with 4 bytes.
  // 'a' 'b' 'c' '\0'     --> not chars, but that byte is the same
  for(int i = 0; i < 4; ++i)
  {
    if(addr + i == NULL || !is_user_vaddr(addr+i) || pagedir_get_page(thread_current()->pagedir, addr+i) == NULL)
    {
      //Remember that we need to break out of the total execution
      //      process if we do not have a legitmate RAW addess
      exit(-1);
    }
  }
}
//----------------------------------------------
//----------------------------------------------