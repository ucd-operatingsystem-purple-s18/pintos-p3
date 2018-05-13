#include "vm/page.h"
#include <hash.h>
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include <string.h>




unsigned 
page_hash(const struct hash_elem *e, void *aux)
{
    const struct sup_page_entry* sup_table = hash_entry(e, struct sup_page_entry, hash_elem);
    return hash_bytes(&sup_table->upage, sizeof(sup_table->upage));
}

bool
page_in(void* page)
{
    // 1. Check if the memory reference is valid
    struct sup_page_entry *sup_table = page_lookup(page);

    if(sup_table == NULL) 
        return false;

    void *frame = frame_get_page(PAL_USER, sup_table);
    if (frame == NULL)
      return false;

    if(!pagedir_set_page(thread_current()->pagedir, page, frame, true))
    {
        return false;
    }

    if(sup_table->loc == FRAME)
        return false;
    if(sup_table->loc == DISK)
    {
        //file_seek(sup_table->owner, sup_table->offset);
        if (file_read (sup_table->owner, frame, sup_table->num_bytes) != sup_table->num_bytes)
        {
            frame_free_page (frame, sup_table);
            return false;
        }
        sup_table->loc = FRAME;
        sup_table->kpage = frame;
    }
    if(sup_table->loc == SWAP)
        return false;

    PANIC ("Page entry is in an unknown state!\n");


return true;
}

void 
page_out(struct hash_elem *e, void*aux)
{
    /* let me see how everything functions first */
    struct sup_page_entry *sup_table = hash_entry(e, struct sup_page_entry, hash_elem);
    /*
    void *upage;
    void *kpage;
    struct frame_entry *frame;
    bool dirty;
    enum page_location loc;
    struct file *owner;
    off_t offset;
    size_t num_bytes;
    bool writeable;
    size_t swap_index;
    struct hash_elem hash_elem;
    */
}

void* 
page_lookup(void* page)
{
    struct sup_page_entry p;
    struct hash_elem *e;
    p.upage = page;
    e = hash_find (&thread_current()->sup_page_table, &p.hash_elem);
    return e != NULL ? hash_entry (e, struct sup_page_entry, hash_elem) : NULL;
}

bool 
page_hash_less(const struct hash_elem *a, const struct hash_elem *b, void* aux)
{
    const struct sup_page_entry *left = hash_entry(a, struct sup_page_entry, hash_elem);
    const struct sup_page_entry *right = hash_entry(b, struct sup_page_entry, hash_elem);
    return left->upage < right->upage; /* virtual address */
}
