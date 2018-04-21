#include "vm/page.h"
#include <hash.h>
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
//=======p3
#include <string.h>




unsigned page_hash(const struct hash_elem *e, void *aux) {
    struct page *pg = hash_entry(e, struct page, hash_elem);
    //change the return pull
    //return ((int) pg->addr << PGBITS);
    return ((int) pg->addr >> PGBITS);
}

bool page_less(const struct hash_elem *a, const struct hash_elem *b, void* aux){
    struct page *first = hash_entry(a, struct page, hash_elem);
    struct page *second = hash_entry(b, struct page, hash_elem);

    return (first->addr < second->addr);
}

//change
//function to get a user page of memory
//void *get_user_page(enum palloc_flags flags){
// change function 
// struct return -- still to get a user page of memory.
//struct page *get_user_page(){
// change to pulling based on our allocation, not a straight pull
// Allocates a page of memory that contains the address void* addr.
// Note: Doesn't allocate the struct frame yet. This is handled in page_in().
struct page *page_allocate(void* addr){
    struct page *p = malloc(sizeof(struct page));
    //struct thread *t = thread_current();
    p->thread = thread_current();
    p->addr = pg_round_down(addr);

    //struct hash_elem *h_elem = hash_insert(t->page_table, &p->hash_elem);
    struct hash_elem *h_elem = hash_insert(p->thread->page_table, &p->hash_elem);
    // This page already exists in the table.
    if(h_elem != NULL){
        // free the existing structure.
        free(p);
        // Return the structure that already exists in the table.
        return hash_entry(h_elem, struct page, hash_elem);
    }else{
        // Return the newly allocated page.
        p->file = NULL;
        p->frame = NULL;
        p->sector = NULL;
        return p;
        
    }
}
/*
USC Notes
Virtual Address vs Physical Address
Recall that virtual address is the processes’ addresses that they
use. Physical memory is the actual memory in the hardware.
You will have to do all the book-keeping to keep track of which physical
memory is mapped to which processes’ virtual memory. This happens
when you map a memory from physical to virtual.
*/
//========================================================
bool page_in(void *addr){
    struct thread *t = thread_current();

    // Temporary page structure.
    struct page p;

    // Set p to the address we were given above.
    p.addr = pg_round_down(addr);
    struct hash_elem *h_elem = hash_find(t->page_table, &p.hash_elem);

    //if(!h_elem){
    if (h_elem != NULL) {
        // Pointer to the new page.
        struct page *pg = hash_entry(h_elem, struct page, hash_elem);

        // Create a new zeroed page.
        if(pg->file == NULL && pg->sector == NULL && pg->frame == NULL){
            pg->frame = get_free_frame();
            lock_acquire(&pg->frame->f_lock);
            memset(pg->frame->base, 0, PGSIZE);
            lock_release(&pg->frame->f_lock);
        }
        //we should then install the frame into the page table
        // using that pointer to the newly created page
        pagedir_set_page(pg->thread->pagedir, pg->addr, pg->frame->base, true);
    }
}

bool page_in_core(struct page *in_page){
    
}