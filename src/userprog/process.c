#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  //char *fn_copy;
  tid_t tid; //the user thread
  //  first_arg is for us to allocate an array before we strcpy down below
  //    Remember we have a following NULL, and strlen wont account for that, need +1
  //    Now we will be pointing to the allocation of memory for our future strcpy+NULL
  char *first_arg = malloc(strlen(file_name) + 1);
  char *dummy_arg; //our token pointer
  struct thread *t = thread_current();


  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  //----------------------------------------------
  //----------------------------------------------
  //----------------------------------------------
  //----------------------------------------------
  //----------------------------------------------
  //=================process.c - changes 1 start============== - 
  //MAX_WORDS Setting a string limit for word @50char (as per manual) - 
  //  This limit is for the size of the file_name - 
  //    This limit = approx. 128 byte size arguement for string. - 


  /*
  //------------------------------------------
  strtok_r explanation:
    strtok_r() for splitting a string with some delimiter. Splitting a string is a common task
    For example, we have a comma separated list of items from a file and we want individual
      items in an array.
    strtok_r does the same task of parsing as strtok, but is a reentrant version.
        reentrant version = a function is said to be reentrant if there is a provision to interrupt
          the function in the course of execution, service the interrupt service routine adn then 
          resume the earlier going on function, without hampering its earlier course of action.

          //We are splitting a string base on a space character
          char str[] = "Geeks for Geeks";
          char *token;
          char *rest = str;
          while ((token = strtok_r(rest, " ", &rest)))
            printf("%s\n", token)

            -->result = 
                Geeks
                for
                Geeks
  //-------------------------------------------
  for (token = strtok_r(s, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr));
  {
    printf("argument: '%s'\n", token);
    arguments[arg_count] = token; //set ptr at index arg_count to token, a char * returned from strtok_r() - 
    ++arg_count;
  }//-------------end for---------------------
  */


  // NOTE THIS IS A EXPLANATION FOR THE MEMSET() FUNCTION USED HERE.
  // Establish the NULL pointer sentinel
  // memset() is used to fill a block of memory with a particular value
  //      ptr ==> starting address of memory to be filled
  //      x   ==> value to be filled
  //      n   ==> number of bytes to be filled, starting from ptr to be filled
  // void *memset(void *ptr, int x, size_t n);
  //  Note: that the ptr is a void pointer, so that we can pass any type of ptr to this function.
  /*
  //========================
  //========================
  //========================
      // C example of memset
      #include <studio.h>
      #include <string.h>

      int main()
      {
        char str[50] = "GeeksForGeeks is for programming geeks.";
        printf("\nBefore memset(): %s\n", str);

        //Fill 8 characters starting from str[13] with '.'
        memset(str + 13, '.', 8*sizeof(char));

        printf("After memset(): %s", str);
        return 0;
      }

      //Before memset(): GeeksForGeeks is for programming geeks.
      //After memset(): GeeksForGeeks........programming geeks.
      //========================
      Explanation - (str + 13) points to first space (0 based index) of the string - 
      "GeeksForGeeks is for programming geeks.", and memset() sets the character '.' starting from first
      ' ' of the string up to 8 character positiion of the given string and hence we get the output.
      //========================
  */

  //-------------------------------------------
  //----------------------------------------------
  //----------------------------------------------
  //----------------------------------------------
  //----------------------------------------------
  //=================process.c - changes 1 end================
  //==========================================

  //-----------------------------------------------------------
  //s-----------------------------------------------------------
  //fn_copy = palloc_get_page (0); 
  //struct pass_in *data = palloc_get_page(0);
  /*
    We are malloc-ing to allocate ehap memory the size of our struct.
        We have to keep in mind where all variables are stored, on the stack and heap.
        Inside of our function, we have local variables.
            These are stored on our stack.
            That stack will be cleared out of the function.
        We want to reference or use those variables outside, once we have left the funtion
            and therefore cleared the stack.
        We need to allocate that memory space on the heap.
            This lets us use that "local" variable outside.

        The malloc() function allocates SIZE bytes, and returns a pointer to the allocated
            memory. The memory in not initialized. If size==0 then malloc returns NULL
                             |||     SIZE            |||  */
  struct pass_in *data = malloc(sizeof(struct pass_in));
      /*
          So we just allocated a memory chunk of:  size=sizeof(pass_in) in bytes
              And the address return from malloc is stored in 'data'
      */
  //if (fn_copy == NULL)
  //Remember if the address that we are pointing to does not have what we want, ie space
  //    we cannot use this space.
  //    so return an error not a space thread
  if (data == NULL)
  {
    return TID_ERROR;
  }//-----------------------------------------------------------
  //-----------------------------------------------------------
  
  //strlcpy (fn_copy, file_name, PGSIZE);
  //strlcpy (fn_copy, arguments[0], PGSIZE);


  // Parse the first part of the name here. We need it for the thread's name.
  //  first_arg was for us to allocate an array before we strcpy down below
  //    Remember we have a following NULL, and strlen wont account for that, need +1
  //    Now first_arg will be pointing to the allocation of memory for our future strcpy+NULL
  /*
      So we are pointing at the allocated space
          We are bringing along our file_name pointer
          And the size of the file + a null
        This is all copied into the first_arg allocated space
  */
  strlcpy(first_arg, file_name, strlen(file_name) + 1);
  /*
  exp. strtok_r

          //We are splitting a string base on a space character
          char str[] = "Geeks for Geeks";
          char *token;
          char *rest = str;
          while ((token = strtok_r(rest, " ", &rest)))
            printf("%s\n", token)

            -->result = 
                Geeks
                for
                Geeks
  */
  strtok_r(first_arg, " ", &dummy_arg);

  // Copy the complete command line args into fn_copy. We'll pass this
  //        to the child thread for parsing.
  //s-----------------------------------------------------------
  //strlcpy (fn_copy, file_name, PGSIZE);
  /*
    data is pointing at our allocated struct space, with the internal file_name attribute
        -> we are allocating space for that attribute as well
        Then we are copying that original filename that was sent in via pointer
            through the process_execute and while based on size + NULL
  */
  data->file_name = malloc(strlen(file_name) + 1);
  strlcpy(data->file_name, file_name, strlen(file_name) + 1);
  //e-----------------------------------------------------------


  //s-----------------------------------------------------------
  /*
    I DONT COMPLETELY UNDERSTAND WHAT WE ARE DOING HERE WITH THE SEMAPHORE
    //Sema_init si the Linux kernel's counting semaphore implementation initializing the function.

    sema_init - Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). 
void
sema_init (struct semaphore *sema, unsigned value) 
{
  ASSERT (sema != NULL);

  sema->value = value;
  list_init (&sema->waiters);
}
  */
  sema_init(&data->load_sema, 0);
    /* Create a new thread to execute FILE_NAME. */
  //tid = thread_create(arguments[0], PRI_DEFAULT, start_process, fn_copy);
  //tid = thread_create (first_arg, PRI_DEFAULT, start_process, fn_copy);
  /*
    Which means when a thread is created with thread_create in this function to run the user 
      program, you will notice that the thread is named the raw ﬁlename: 
        tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_copy);

  Also notice fn_copy. This is a copy of the raw ﬁlename and passed in as an 
  auxiliary parameter. This will come in handy. The function this thread will run 
  is start_process, which takes in an argument void *file_name_. 
  
  fn_copy is passed in as this argument, allowing you access to a copy of the full 
  raw ﬁlename in this function. This will come in handy. 
  
  If you look at the start_process function, you will see a load function; this function is where 
the user program gets loaded with all its data. In this load function, Pintos will 
try to load the executable (a ﬁle) with filesys_open(file_name). 
Once again, this ﬁlename should not be the raw ﬁlename but instead just the executable name. 
You will decide when to extract the executable name and pass in the correct string. 
In the load function you will also ﬁnd a function called setup_stack. 
This is the function in which you will setup the stack for each user program

  */
  tid = thread_create (first_arg, PRI_DEFAULT, start_process, data);

  sema_down(&data->load_sema);
  //Check if the return value is true
  //  data = struct --> load_success is boolean attribute in struct
  //      we are just verifying that we actually loaded the struct.
  if(data->load_success)
  {
    //if loaded successfully, we know that the child allocated the data
    //  so our pointer is valid
    //  Here we are pushing back in order to save the old interrpt level
    list_push_back(&t->children, &data->shared->child_elem);
  }
  //================================
  else
  {
    // we did not have thread success above, so we need to otherwise free the memory
    free(data->shared);
    return -1;
  }
  //================================

  if (tid == TID_ERROR)
  {
    //palloc_free_page(fn_copy);
    /*
      We are getting this error obviously here
          we need to call palloc_free_page  in order to free the page.
          When the page is freed, the bits are set to false, 
              That means that the page is now unmapped.
    */
    palloc_free_page (data); 
    //e-----------------------------------------------------------
  }
  //We have made it here, we have allocated for, 
  //    and established our thread. Send it back
  return tid;
}

//-----------------------------------------------------------
//-----------------------------------------------------------
// Altering from our initial *char to *struct that was initiated above
/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *in_data)
{
  //char *file_name = file_name_;
  struct intr_frame if_;
  //bool success;
  //create our local struct, based on our incoming reference
  struct pass_in *data = (struct pass_in*) in_data;
  //-----------------------------------------------------------

  //need to allocate the structure for the pass_in data, here???
  struct shared_data *share = malloc(sizeof(struct shared_data));

  //sema_init(&share->wait_sema, 0);
  //everything for the shared data needs to be allocated for
  sema_init(&share->dead_sema, 0);
  /*
  /pintos/synch.c
 Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. 
void
lock_init (struct lock *lock)
{
  ASSERT (lock != NULL);

  lock->holder = NULL;
  sema_init (&lock->semaphore, 1);
}
//lock_init - initializes the lock as a new lock. The lock is not initially owne by any thread
  */
  lock_init(&share->ref_lock);
  //Setting that struct share attribute as our current thread id
  share->tid = thread_current()->tid;
  share->exit_code = -2;
  //share->reference_count = 2;
  share->ref_count = 2;
  //thread_current()->parent_share = share;

  data->shared = share;

  //Now we need to add the structure to the parent thread's list
  //list_push_front(&data->parent->children, &share->child_elem);
  //current thread
  thread_current()->parent_share = share;
  //-----------------------------------------------------------

// NOTE THIS IS A EXPLANATION FOR THE MEMSET() FUNCTION USED HERE.
  // Establish the NULL pointer sentinel
  // memset() is used to fill a block of memory with a particular value
  //      ptr ==> starting address of memory to be filled
  //      x   ==> value to be filled
  //      n   ==> number of bytes to be filled, starting from ptr to be filled
  // void *memset(void *ptr, int x, size_t n);
  //  Note: that the ptr is a void pointer, so that we can pass any type of ptr to this function.
  /*
  //========================
  //========================
  //========================
      // C example of memset
      #include <studio.h>
      #include <string.h>

      int main()
      {
        char str[50] = "GeeksForGeeks is for programming geeks.";
        printf("\nBefore memset(): %s\n", str);

        //Fill 8 characters starting from str[13] with '.'
        memset(str + 13, '.', 8*sizeof(char));

        printf("After memset(): %s", str);
        return 0;
      }

      //Before memset(): GeeksForGeeks is for programming geeks.
      //After memset(): GeeksForGeeks........programming geeks.
      //========================
      Explanation - (str + 13) points to first space (0 based index) of the string - 
      "GeeksForGeeks is for programming geeks.", and memset() sets the character '.' starting from first
      ' ' of the string up to 8 character positiion of the given string and hence we get the output.
      //========================
  */
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  //-----------------------------------------------------------
  //-----------------------------------------------------------
  //-----------------------------------------------------------
  //success = load (file_name, &if_.eip, &if_.esp); //was original
  data->load_success = load(data->file_name, &if_.eip, &if_.esp);
  //-----------------------------------------------------------
  //-----------------------------------------------------------
  //-----------------------------------------------------------
  sema_up(&data->load_sema);
  // If load failed, quit. 
  //-----------------------------------------------------------
  //palloc_free_page(file_name);
  //if (!success)
  //palloc_free_page(data);

  if(!data->load_success) 
    thread_exit();
    //-----------------------------------------------------------

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. 
   
   ---(process_wait) = Waits for the child process with designated 
        tid process_wait to ﬁnish before continuing execution.
   */
int
process_wait (tid_t child_tid) 
{
  //struct thread *rt_thread;
  //rt_thread = thread_at_tid(child_tid);
  //if(rt_thread->tid == -1)
  //{
  //  return -1;
  //}
  struct thread *t = thread_current();
  //Each list element is a struct containing a previous and next pointer:
  //    Note: we are cycling through our list_elem but this is auto empty 
  //      This is where we have to finish with wait. This has to be assigned first
  struct list_elem *e;
  for (e = list_begin (&t->children); e != list_end (&t->children); e = list_next (e))
  {
      struct shared_data *share = list_entry (e, struct shared_data, child_elem);
      //Checking for our child to finnish
      if(share->tid == child_tid)
      {
        sema_down(&share->dead_sema);
        list_remove(&share->child_elem);
        return share->exit_code;
      }
  }
  //sema_down(&rt_thread->wait_sema);
  //the -1 means the parent process will return without the child closing
  return -1;
}

/* Free the current process's resources. */
void process_exit (void)
{
  struct thread *cur = thread_current();
  uint32_t *pd;

  //================================================
  // If the child outlives the parent, the child must deallocate the
  // shared memory.
  if(cur->parent_share->ref_count == 1)
  {
    free(cur->parent_share);
  }
  // Otherwise, decrement count and let parent deallocate.
  else if (cur->parent_share->ref_count == 2)
  {
    --cur->parent_share->ref_count;
    //list_remove(&cur->parent_share->child_elem);
  }
  

  // Iterate through each child in the list. If the parent outlived the child, 
  // the parent should deallocate.
  for(int i = 0; i < list_size(&cur->children); ++i)
  {
    //Each list element is a struct containing a previous and next pointer:
    struct list_elem *e = list_pop_front(&cur->children);
    struct shared_data *data = list_entry(e, struct shared_data, child_elem);
    if(data->ref_count == 1)
    {
      free(data);
    }
    else if (data->ref_count == 2)
    {
      --data->ref_count;
      list_push_back(&cur->children,&data->child_elem);
    }
  }
  //================================================

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *in_args);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;

  //-----------------------------------------------------------
  //----------------------------
  //----------------------------
  // New char* for first arg in file_name (the executable name)  
  char *exec_name = malloc(strlen(file_name) + 1);
  char *dummy_arg;
  strlcpy(exec_name, file_name, strlen(file_name) + 1);
  // Get first argument of name.
    /*
  exp. strtok_r
  
          //We are splitting a string base on a space character
          char str[] = "Geeks for Geeks";
          char *token;
          char *rest = str;
          while ((token = strtok_r(rest, " ", &rest)))
            printf("%s\n", token)

            -->result = 
                Geeks
                for
                Geeks
  */
  strtok_r(exec_name, " ", &dummy_arg);
  //----------------------------
  //----------------------------
  //-----------------------------------------------------------
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL) 
    goto done;
  process_activate();

  /* Open executable file. */
  //file = filesys_open (file_name);
  file = filesys_open(exec_name);
  if (file == NULL) 
    {
      //printf ("load: %s: open failed\n", file_name);
      printf ("load: %s: open failed\n", exec_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", exec_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  int i;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  //=======================================
  // Allocate a new string so we don't modify the original argument.
  char *args_ptr = malloc(strlen(file_name) + 1);
  strlcpy(args_ptr, file_name, strlen(file_name) + 1);
  //=======================================

  /* Set up stack. 
  Remember we are sending in our pointer to our stack and
      the pointer to the allocated space, with our copied args
  */
  //=======================================
  if (!setup_stack(esp, args_ptr))
  //make sure to account for if we 
  //=======================================
    goto done;

  /* Start address. */
  *eip = (void(*)(void))ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_deny_write(file);
  file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}


/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      /*
    Can't let our stack get too big.
      Can't let it overflow, or else we will not have room on kernel stack
      The struct thread is only a few bytes
      But we cannot allocate large structures or arrays as non-static local variables.
      We have to use the malloc or the palloc_get_page
  */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
    /*
          we need to call palloc_free_page  in order to free the page.
          When the page is freed, the bits are set to false, 
              That means that the page is now unmapped.
    */
          palloc_free_page (kpage);
          return false; 
        }
        // NOTE THIS IS A EXPLANATION FOR THE MEMSET() FUNCTION USED HERE.
  // Establish the NULL pointer sentinel
  // memset() is used to fill a block of memory with a particular value
  //      ptr ==> starting address of memory to be filled
  //      x   ==> value to be filled
  //      n   ==> number of bytes to be filled, starting from ptr to be filled
  // void *memset(void *ptr, int x, size_t n);
  //  Note: that the ptr is a void pointer, so that we can pass any type of ptr to this function.
  /*
  //========================
  //========================
  //========================
      // C example of memset
      #include <studio.h>
      #include <string.h>

      int main()
      {
        char str[50] = "GeeksForGeeks is for programming geeks.";
        printf("\nBefore memset(): %s\n", str);

        //Fill 8 characters starting from str[13] with '.'
        memset(str + 13, '.', 8*sizeof(char));

        printf("After memset(): %s", str);
        return 0;
      }

      //Before memset(): GeeksForGeeks is for programming geeks.
      //After memset(): GeeksForGeeks........programming geeks.
      //========================
      Explanation - (str + 13) points to first space (0 based index) of the string - 
      "GeeksForGeeks is for programming geeks.", and memset() sets the character '.' starting from first
      ' ' of the string up to 8 character positiion of the given string and hence we get the output.
      //========================
  */
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
              /*
          we need to call palloc_free_page  in order to free the page.
          When the page is freed, the bits are set to false, 
              That means that the page is now unmapped.
    */
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. 
   
   If a user tries to access an unmapped addrss, it will page fault.
   Even if we are in kernel mode you can page fault if you try to 
      access an unmapped address.

      cp -r pintos .
                        argc = 4
                        argv[0] = "cp"
                        argv[1] = "-r"
                        argv[2] = "pintos"
                        argv[3] = "."
                        argv[4] = 0

      PHYS_BASE
          .
          os
          pint
          -r
          cp
          argv[4]
          argv[3]
          argv[2]
          argv[1]
          argv
          argc
          Return Value  <-----stack pointer
          |
          v
   */
  /*
The void** esp is the stack pointer. 
This is a double pointer because you will be doing pointer
manipulation, and since you want these modifications to be global and not just 
within this function’s scope, you are given a pointer to the stack pointer 
(pass by pointer for a pointer). 

Meaning to write things to the stack you will want to dereference void** esp.

Initially, void** esp is initialized to PHYS_BASE, 
which is basically the bottom of the stack
(0xbffffffff).
*esp = PHYS_BASE;

After that, we can start writing to the stack.
  */
static bool
//setup_stack (void **esp) 
setup_stack (void **esp, char *in_args) 
{
  /*
    Can't let our stack get too big.
      Can't let it overflow, or else we will not have room on kernel stack
      The struct thread is only a few bytes
      But we cannot allocate large structures or arrays as non-static local variables.
      We have to use the malloc or the palloc_get_page
  */
  uint8_t *kpage;
  bool success = false;
  int index = 0;
  const int WORD_LIMIT = 50; //our char per/limit from the manual
  
  /*
      void *palloc_get_page(enum palloc_flags FLAGS)
          PAL_ZER0 - zero all the bytes in the allocated pages before returning them
                if not set, the contents of new allocated pages are unpredictable
          PAL_USER - obtain the pages from teh user pool. if not set, pages are 
                allocated from the kernel pool 
  */
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  //if it is not NULL then it was allocated and we can continue
  if (kpage != NULL) 
    {
      /*install_page -  Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   
    Can't let our stack get too big.
      Can't let it overflow, or else we will not have room on kernel stack
      The struct thread is only a few bytes
      But we cannot allocate large structures or arrays as non-static local variables.
      We have to use the malloc or the palloc_get_page
  
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      //if (success)
            //NOTE: the manual hints at /*esp = PHYS_BASE - 12;
            //      this messes the program, not sure why

      //=======PHYS_BASE - 12=====================================
      //*esp = PHYS_BASE      //ORIGINAL 
      //*esp = PHYS_BASE - 12; //changed w/-12 on 3/14/18
      if (success)
      {  
        // Parsing arguments:
        char *current;
        char *buffer;
        char *current_arg[WORD_LIMIT];

        //in_args coming in with function
        //esp = stack pointer, coming in with function.
          /*
          exp. strtok_r
  
          //We are splitting a string base on a space character
          char str[] = "Geeks for Geeks";
          char *token;
          char *rest = str;
          while ((token = strtok_r(rest, " ", &rest)))
            printf("%s\n", token)

            -->result = 
                Geeks
                for
                Geeks
  */
  // Remember we have to run through and place our args in place
        for(current = strtok_r(in_args, " ", &buffer); current != NULL; current = strtok_r(NULL, " ", &buffer))
        {
          //we get our allocation details, remember not to forget the inherent NULL
          int size_of_curr = strlen(current) + 1;
          //We need to allocate in precision, and in line with each arg
          //    once we have allocated make sure to copy into place
          current_arg[index] = malloc(size_of_curr);
          strlcpy(current_arg[index], current, size_of_curr);

          ++index;
        }

        // Stack pointer is set here. Now we can copy over the arguments.
        *esp = PHYS_BASE - 12;

        // Loop to copy arugments.
        char *char_ptrs[WORD_LIMIT];
        for(int i = index-1; i >= 0; --i)
        {
          int size_of_curr = strlen(current_arg[i]) + 1;
          // Decrement esp to size of arugment to be copied.
          *esp -= size_of_curr;  
          strlcpy(*esp, current_arg[i], size_of_curr);
          char_ptrs[i] = (char *) *esp;
        }
        // At this point, all string parts of arguments are on the stack.
        // We need to:
        // 1. Word align the next address.
        // 2. Push NULL pointer.
        // 3. Push args in reverse order.
        // 4. Push pointer to argv[0] (argv).
        // 5. Push argc (count of args, currently in 'index')
        // 6. Push 'fake' return address.

        // 1. Word Align
        //    If the current *esp address is not word aligned
        //    (It's not word-aligned if the either of the lowest two bits are set)
        if((int) *esp & 0x03)
        {

          // Clear the lowest two bits. 
          // This gets us the 'closest' next word-aligned address.
          *esp =  (void*) ((int) *esp & ~0x03);
        }
        // 2. Push NULL pointer
        *esp -= 4;
        // NOTE THIS IS A EXPLANATION FOR THE MEMSET() FUNCTION USED HERE.
  // Establish the NULL pointer sentinel
  // memset() is used to fill a block of memory with a particular value
  //      ptr ==> starting address of memory to be filled
  //      x   ==> value to be filled
  //      n   ==> number of bytes to be filled, starting from ptr to be filled
  // void *memset(void *ptr, int x, size_t n);
  //  Note: that the ptr is a void pointer, so that we can pass any type of ptr to this function.
  /*
  //========================
  //========================
  //========================
      // C example of memset
      #include <studio.h>
      #include <string.h>

      int main()
      {
        char str[50] = "GeeksForGeeks is for programming geeks.";
        printf("\nBefore memset(): %s\n", str);

        //Fill 8 characters starting from str[13] with '.'
        memset(str + 13, '.', 8*sizeof(char));

        printf("After memset(): %s", str);
        return 0;
      }

      //Before memset(): GeeksForGeeks is for programming geeks.
      //After memset(): GeeksForGeeks........programming geeks.
      //========================
      Explanation - (str + 13) points to first space (0 based index) of the string - 
      "GeeksForGeeks is for programming geeks.", and memset() sets the character '.' starting from first
      ' ' of the string up to 8 character positiion of the given string and hence we get the output.
      //========================
  */
        memset(*esp, 0, 4);



        //         ///////////////
        // memset(current_stack_pos, 0, 4);
        // current_stack_pos -= 4;
        // hex_dump(current_stack_pos, current_stack_pos, 25, true);
        // ///////////////
        
        // 3. Push args in reverse order.
        for(int i = index-1; i >= 0; --i)
        {
          *esp -= 4;
          memcpy(*esp, &char_ptrs[i], 4);
        }
        // 4. Push pointer to argv[0] (argv).
        char **argv = *esp;
        *esp -= 4;
        memcpy(*esp, &argv, 4);

        // 5. Push argc (count of args, currently in 'index').
        *esp -= 4;
        memcpy(*esp, &index, 4);

        // 6. Push 'fake' return address.
        *esp -= 4;
        // NOTE THIS IS A EXPLANATION FOR THE MEMSET() FUNCTION USED HERE.
  // Establish the NULL pointer sentinel
  // memset() is used to fill a block of memory with a particular value
  //      ptr ==> starting address of memory to be filled
  //      x   ==> value to be filled
  //      n   ==> number of bytes to be filled, starting from ptr to be filled
  // void *memset(void *ptr, int x, size_t n);
  //  Note: that the ptr is a void pointer, so that we can pass any type of ptr to this function.
  /*
      int main()
      {
        char str[50] = "GeeksForGeeks is for programming geeks.";
        printf("\nBefore memset(): %s\n", str);

        //Fill 8 characters starting from str[13] with '.'
        memset(str + 13, '.', 8*sizeof(char));

        printf("After memset(): %s", str);
        return 0;
      }

      //Before memset(): GeeksForGeeks is for programming geeks.
      //After memset(): GeeksForGeeks........programming geeks.
      //========================
      Explanation - (str + 13) points to first space (0 based index) of the string - 
      "GeeksForGeeks is for programming geeks.", and memset() sets the character '.' starting from first
      ' ' of the string up to 8 character positiion of the given string and hence we get the output.
      //========================
  */
        memset(*esp, 0, 4);
        //*esp -= 4;
        //printf("esp =%x\n",*esp);
      }
      else
          /*
          we need to call palloc_free_page  in order to free the page.
          When the page is freed, the bits are set to false, 
              That means that the page is now unmapped.
    */
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.

   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().

   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
//===========================================
