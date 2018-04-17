#include "vm/page.h"
#include <hash.h>
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"



unsigned page_hash(const struct hash_elem *e, void *aux) {
    struct page *pg = hash_entry(e, struct page, hash_elem);
    return ((int) pg->addr << PGBITS);
}

bool page_less(const struct hash_elem *a, const struct hash_elem *b, void* aux){
    struct page *first = hash_entry(a, struct page, hash_elem);
    struct page *second = hash_entry(b, struct page, hash_elem);

    return (first->addr < second->addr);
}

void *get_user_page(enum palloc_flags flags){
    struct page *p = malloc(sizeof(struct page));
    struct thread *t = thread_current();
}