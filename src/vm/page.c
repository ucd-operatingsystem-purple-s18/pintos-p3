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
    struct thread *t = thread_current();


    p->addr = pg_round_down(addr);
    struct hash_elem *h_elem = hash_insert(t->page_table, &p->hash_elem);
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