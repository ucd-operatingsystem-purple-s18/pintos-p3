#include "vm/frame.h"
#include "threads/init.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"

static struct lock frame_table_lock; 
static struct list frame_table;  

void 
frame_table_init (void)
{
  list_init(&frame_table);
  lock_init(&frame_table_lock);
}

void*
frame_get_page (enum palloc_flags flags, void* spte)
{
  return frame_get_multiple(flags, spte, 1);
}

void*
frame_get_multiple (enum palloc_flags flags, void* spte, size_t page_cnt)
{
  lock_acquire(&frame_table_lock);
  void* page = palloc_get_page(flags);
  if(page == NULL)
  {
    page = frame_evict(flags, spte);
    if(page == NULL)
    {
      PANIC("No usable Physical Frames!\n");
    }
  }
  struct thread* t = thread_current();
  struct frame_entry* new_frame = (struct frame_entry*)malloc(sizeof(struct frame_entry));
  if(new_frame == NULL)
  {
    lock_release(&frame_table_lock);
    return new_frame;
  }
  new_frame->page = page;
  new_frame->cur_thread = t;
  new_frame->spte = spte;
  lock_release(&frame_table_lock);
  list_push_back(&frame_table, &new_frame->elem);
  return new_frame;
}

void 
frame_free_page (void* frame, void* spte)
{
  return frame_free_multiple(frame, spte, 1);
}

void 
frame_free_multiple (void* frame, void* spte, size_t page_cnt)
{
  lock_acquire(&frame_table_lock);
  struct list_elem* e;

  for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
  {
    struct frame_entry* frame_elem = list_entry(e, struct frame_entry, elem);
    if(frame_elem->page = frame)
    {
      list_remove(e);
      palloc_free_page(frame_elem->page);
      free(frame_elem);
      break;
    }
  }
  lock_release(&frame_table_lock);
}

/* Virtual Memory Eviction policy */
void* 
frame_evict(enum palloc_flags flags, void* spte)
{
  return NULL;
}