#include "vm/page.h"
#include <hash.h>
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
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
    page = pg_round_down(page);
    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage == NULL)
        return false;
    struct sup_page_entry *sup_table = (struct sup_page_entry*) page_lookup(page);
    if(sup_table == NULL)
        return false;



    if(sup_table->loc == FRAME)
        return true;
    else if(sup_table->loc == DISK)
    {
        file_seek(sup_table->owner, sup_table->offset);
        /* Load this page. */
        if (file_read(sup_table->owner, kpage, sup_table->read_bytes) != (int) sup_table->read_bytes)
        {
            /*
            we need to call palloc_free_page  in order to free the page.
            When the page is freed, the bits are set to false, 
              That means that the page is now unmapped.
            */
            palloc_free_page(kpage);
            return false; 
        }

        memset (kpage + sup_table->read_bytes, 0, PGSIZE-sup_table->read_bytes); /*HACK : PGSIZE-read_bytes should be zero_bytes */


        /* Add the page to the process's address space. */
        if(! (pagedir_get_page (&thread_current()->pagedir, sup_table->upage) == NULL && 
            pagedir_set_page (&thread_current()->pagedir, sup_table->upage, kpage, sup_table->writeable)))
        //if (!install_page (sup_table->upage, kpage, sup_table->writeable)) 
        {

            palloc_free_page (kpage);
            return false; 
        }

        sup_table->loc = FRAME;
        sup_table->kpage = kpage;
    }
    else if(sup_table->loc == SWAP)
        return false;
    else
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
page_add_file(struct file *f, int32_t ofs, uint8_t *upage, uint32_t page_read_bytes, uint32_t page_zero_bytes, bool writable)
{

    struct sup_page_entry *sup_table = (struct sup_page_entry*)malloc(sizeof(struct sup_page_entry));
    if(sup_table == NULL)
    {
        free(sup_table);
        return false;
    }

    sup_table->upage = upage;
    sup_table->kpage = NULL;
    sup_table->dirty = false;
    sup_table->loc = DISK;
    sup_table->owner = f;
    sup_table->offset = ofs;
    sup_table->read_bytes = page_read_bytes;
    sup_table->zero_bytes = page_zero_bytes;
    sup_table->writeable = writable;
    sup_table->swap_index = -1;
    return hash_insert(&thread_current()->sup_page_table, &sup_table->hash_elem) != NULL;
}

bool 
page_hash_less(const struct hash_elem *a, const struct hash_elem *b, void* aux)
{
    const struct sup_page_entry *left = hash_entry(a, struct sup_page_entry, hash_elem);
    const struct sup_page_entry *right = hash_entry(b, struct sup_page_entry, hash_elem);
    return left->upage < right->upage; /* virtual address */
}