#include "vm/frame.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "threads/loader.h"
#include <stdio.h>

#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
// Not sure if we need this or not.
//#define FRAME_ARR_SIZE 1
//increase our frame array size
//========p3===========================
#define FRAME_ARR_SIZE 500



static int frame_ct;
//static struct frame frames[FRAME_ARR_SIZE];
//change to a pointer to our frames========================
static struct frame *frames[FRAME_ARR_SIZE];


static struct lock scan_lock;
static int hand;

//original 
//struct frame get_free_frame(){
static int used_pages = 0;
struct frame *get_free_frame(){
    lock_acquire(&scan_lock);
    struct thread *t = thread_current();
    for(int i = 0; i < used_pages; ++i){
        if(frames[i]->page == NULL){
           lock_release(&scan_lock); 
           return frames[i];
        }
    }
    lock_release(&scan_lock);
    PANIC("Nate hates everything. frame.c");
    NORETURN();
}

void init_user_mem(){
    lock_init(&scan_lock);
    lock_acquire(&scan_lock);
    for(int i = 0; i < FRAME_ARR_SIZE; ++i){
        void* page = palloc_get_page(PAL_USER | PAL_ZERO);
        if(page == NULL){
            break;
        }else{
            frames[i] = (struct frame *) malloc(sizeof(struct frame));
            lock_init(&frames[i]->f_lock);
            frames[i]->base = page;
            frames[i]->page = NULL;
            ++used_pages;
        }
    }
    lock_release(&scan_lock);
    printf("%d User Pages Allocated.\n", used_pages);
}

void lock_frame(struct frame *frame){

}

void frame_table_init (void)
{
  list_init(&frame_table);
  lock_init(&frame_table_lock);
}

void* frame_alloc (enum palloc_flags flags)
{
  if ( (flags & PAL_USER) == 0 )
    {
      return NULL;
    }
  void *frame = palloc_get_page(flags);
  if (frame)
    {
      frame_add_to_table(frame);
    }
  else
    {
      if (!frame_evict(frame))
	{
	  PANIC ("Frame could not be evicted because swap is full!");
	}
    }
  return frame;
}

void frame_free (void *frame)
{
  struct list_elem *e;
  
  lock_acquire(&frame_table_lock);
  for (e = list_begin(&frame_table); e != list_end(&frame_table);
       e = list_next(e))
    {
      struct frame_entry *fte = list_entry(e, struct frame_entry, elem);
      if (fte->frame == frame)
	{
	  list_remove(e);
	  free(fte);
	  break;
	}
    }
  lock_release(&frame_table_lock);
  palloc_free_page(frame);
}

void frame_add_to_table (void *frame)
{
  struct frame_entry *fte = malloc(sizeof(struct frame_entry));
  fte->frame = frame;
  fte->tid = thread_tid();
  
  lock_acquire(&frame_table_lock);
  list_push_back(&frame_table, &fte->elem);
  lock_release(&frame_table_lock);
}

bool frame_evict (void *frame)
{
  return false;
  // Use clock algorithm with 2 hands
}