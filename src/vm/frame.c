#include "vm/frame.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "threads/loader.h"
#include <stdio.h>

static struct bitmap used_frames; /* to keep track of usable frames */

/* initializes frame table to size size */
void 
init_frame_table(uint32_t size)
{

}

struct frame_entry *
get_free_frame(void)
{
    get_frame_multiple(1);
}

struct frame_entry *
get_frame_multiple(uint32_t size)
{
  if (size == 0)
    return NULL;

  size_t page_idx = bitmap_scan_and_flip (used_frames, 0, size, false);

  if (page_idx != BITMAP_ERROR)
    frame_table[page_idx].holding_page = palloc_get_page(PAL_USER | PAL_ZERO);
  else
    {
        /* evict frame */
        bool success = try_evicting_frame(&frame_table[page_idx]);
        if(success)
            evict_frame(&frame_table[page_idx])
        else
            PANIC("FRAME_GET: Unable to evict and allocate new frame");
    }

  return &frame_table[page_idx];
}
bool 
try_evicting_frame(struct *frame)
{

}

void 
evict_Frame(struct *frame)
{

}

void 
free_frame_elem(struct frame_elem)
{

}
