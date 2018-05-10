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
#include "vm/page.h"

//Approximately 79/80 tests. 

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  tid_t tid; //the user thread
  char *first_arg = malloc(strlen(file_name) + 1);
  char *dummy_arg; //our token pointer
  struct thread *t = thread_current();
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  struct pass_in *data = malloc(sizeof(struct pass_in));
  if (data == NULL)
  {
    return TID_ERROR;
  }

  strlcpy(first_arg, file_name, strlen(file_name) + 1);

  strtok_r(first_arg, " ", &dummy_arg);


  data->file_name = malloc(strlen(file_name) + 1);
  strlcpy(data->file_name, file_name, strlen(file_name) + 1);

  sema_init(&data->load_sema, 0);

  tid = thread_create (first_arg, PRI_DEFAULT, start_process, data);

  sema_down(&data->load_sema);

  if(data->load_success)
  {
    list_push_back(&t->children, &data->shared->child_elem);
  }
  else
  {
    free(data->shared);
    return -1;
  }
  //================================

  if (tid == TID_ERROR)
  {
    palloc_free_page (data); 
  }

  return tid;
}


/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *in_data)
{
  struct intr_frame if_;

  struct pass_in *data = (struct pass_in*) in_data;

  struct shared_data *share = malloc(sizeof(struct shared_data));

  sema_init(&share->dead_sema, 0);

  lock_init(&share->ref_lock);
  struct thread *t = thread_current();
  share->tid = t->tid;
  share->exit_code = -2;
  share->ref_count = 2;

  data->shared = share;

  thread_current()->parent_share = share;

  hash_init(&t->sup_page_table, page_hash, page_hash_less, NULL);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  data->load_success = load(data->file_name, &if_.eip, &if_.esp);

  sema_up(&data->load_sema);


  if(!data->load_success) 
    thread_exit();

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
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *t = thread_current();
  struct list_elem *e;
  for (e = list_begin (&t->children); e != list_end (&t->children); e = list_next (e))
  {
      struct shared_data *share = list_entry (e, struct shared_data, child_elem);
      if(share->tid == child_tid)
      {
        sema_down(&share->dead_sema);
        list_remove(&share->child_elem);
        return share->exit_code;
      }
  }
  //sema_down(&rt_thread->wait_sema);
  return -1;
}

/* Free the current process's resources. */
void process_exit (void)
{
  struct thread *cur = thread_current();
  uint32_t *pd;

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

  if(cur->exec_file != NULL)
    file_close(cur->exec_file);
  

  // Iterate through each child in the list. If the parent outlived the child, 
  // the parent should deallocate.
  for(int i = 0; i < list_size(&cur->children); ++i)
  {
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


  /* New char* for first arg in file_name (the executable name) */  
  char *exec_name = malloc(strlen(file_name) + 1);
  char *dummy_arg;
  strlcpy(exec_name, file_name, strlen(file_name) + 1);

  strtok_r(exec_name, " ", &dummy_arg);

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

    // Allocate and initialize the page hash table.
  t->page_table = malloc(sizeof(struct hash));
  hash_init(t->page_table, &page_hash, &page_less, NULL);


  /* Open executable file. */
  file = filesys_open (exec_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", exec_name);
      goto done; 
    }

  file_deny_write(file);
  t->exec_file = file;

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
  // Allocate a new string so we don't modify the original argument.
  char *args_ptr = malloc(strlen(file_name) + 1);
  strlcpy(args_ptr, file_name, strlen(file_name) + 1);

  /* Set up stack. 
  Remember we are sending in our pointer to our stack and
      the pointer to the allocated space, with our copied args
  */
  if (!setup_stack (esp, args_ptr))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
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

#ifdef VM
  struct thread *t = thread_current();

  /* create DISK supplemental page table */
  struct sup_page_table *sup_table = (struct sup_page_table*)malloc(sizeof(struct sup_page_table));
  if(sup_table == NULL)
  {
    free(sup_table);
    return false;
  }

  sup_table->upage = upage;
  sup_table->kpage = NULL;
  sup_table->frame = NULL;
  sup_table->dirty = false;
  sup_table->loc = DISK;
  sup_table->owner = file;
  sup_table->offset = ofs;
  sup_table->num_bytes = read_bytes;
  sup_table->writeable = writeable;
  sup_table->swap_index = -1;

  if(hash_insert(&t->sup_page_table, &sup_table->hash_elem) != NULL)
  {
    PANIC("Element already exists in Sup Page Hashtable!\n");
    return false;
  }
  return true;


#else
      /* Get a page of memory. */
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

      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {

          palloc_free_page (kpage);
          return false; 
        }
#endif

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += PGSIZE;
      upage += PGSIZE;
    }
  return true;
}


static bool
setup_stack (void **esp, char *in_args) 
{

  uint8_t *kpage;
  bool success = false;
  int index = 0;
  const int WORD_LIMIT = 50;
  
#ifdef VM
  /* create FRAME supllemental page table and put into frame */
  struct sup_page_table *sup_table = (struct sup_page_table*)malloc(sizeof(struct sup_page_table));
  if(sup_table == NULL)
  {
    free(sup_table);
    return false;
  }

  sup_table->upage = NULL;
  sup_table->kpage = PHYS_BASE-PGSIZE;
  sup_table->dirty = false;
  sup_table->loc = FRAME;
  sup_table->owner = NULL;
  sup_table->offset = 0;
  sup_table->num_bytes = 0;
  sup_table->writeable = true;
  sup_table->swap_index = -1;
  frame = frame_get_page(PAL_USER | PAL_ZERO, sup_table);
  kpage = frame->page;
  sup_table->frame = frame;
#else
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
#endif

  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
      {  
        // Parsing arguments:
        char *current;
        char *buffer;
        char *current_arg[WORD_LIMIT];

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
        *esp = PHYS_BASE;

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

        if((int) *esp & 0x03)
        {

          // Clear the lowest two bits. 
          // This gets us the 'closest' next word-aligned address.
          *esp =  (void*) ((int) *esp & ~0x03);
        }
        // 2. Push NULL pointer
        *esp -= 4;

        memset(*esp, 0, 4);
        
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
