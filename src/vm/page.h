#ifndef _PAGE_H
#define _PAGE_H

#include "vm/frame.h"
#include <hash.h>
#include "threads/thread.h"
#include "filesys/file.h"
#include "devices/block.h"

// Structure to represent a virtual address page.
struct page{

void *addr;
bool read_only;
struct thread *thread;

struct hash_elem hash_elem;

struct frame *frame;

block_sector_t sector;

bool private;

struct file *file;
off_t file_offset;
off_t file_bytes;

}; //end page

// Hash function for pages.
unsigned page_hash(const struct hash_elem *e, void *aux);

// Comparison function for pages.
bool page_less(const struct hash_elem *a, const struct hash_elem *b, void* aux);

//want a page func for 
//void *get_user_page();
//change function to return struct for our page
//we want to get and possibly allocated a user page
//struct page *get_user_page(void);
//change, try returning based on the allocation instead.
// Function to get (and possibly allocate) a user page.
struct page *page_allocate(void* addr);
/*
USC Notes
Virtual Address vs Physical Address
Recall that virtual address is the processes’ addresses that they
use. Physical memory is the actual memory in the hardware.
You will have to do all the book-keeping to keep track of which physical
memory is mapped to which processes’ virtual memory. This happens
when you map a memory from physical to virtual.
*/
bool page_in(void *addr);

bool page_in_core(struct page *in_page);
//
#endif