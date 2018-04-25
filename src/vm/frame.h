#ifndef _FRAME_H
#define _FRAME_H

#include "threads/synch.h"
#include "vm/page.h"

struct frame_table
{
	struct list list_frames;
	size_t used_count;

}

struct frame_elem
{
	struct page *holding_page; /* page that frame holds */
	struct thread *current_thread; /* current thread holding frame */
	struct list_elem elem; /* used for list */
};

void init_frame_table(size_t);
struct frame_entry *get_free_frame(void);
struct frame_entry *get_frame_multiple(size_t);
bool try_evicting_frame(struct *frame);
void evict_Frame(struct *frame);
void free_frame_elem(struct frame_elem);
