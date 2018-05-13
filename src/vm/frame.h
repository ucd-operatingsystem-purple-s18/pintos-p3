#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include "threads/palloc.h"

struct frame_entry 
{
  void *page;
  struct sup_page_entry *spte;
  struct thread* cur_thread;
  struct list_elem elem;
};


void frame_table_init (void);
void* frame_get_page (enum palloc_flags flags, void* spte);
void* frame_get_multiple (enum palloc_flags flags, void* spte, size_t page_cnt);
void frame_free_page (void *,void*spte);
void frame_free_multiple (void *, void* spte, size_t page_cnt);
void* frame_evict(enum palloc_flags flags, void* spte);


#endif /* vm/frame.h */