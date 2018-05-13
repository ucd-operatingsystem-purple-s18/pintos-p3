#ifndef _PAGE_H
#define _PAGE_H

#include "vm/frame.h"
#include <hash.h>
#include "threads/thread.h"
#include "filesys/file.h"
#include "devices/block.h"


enum page_location
  {
    FRAME = 001,           /* Currently In Memory */
    DISK = 002,             /* Currently in File Sys(Possibly Executable) */
    SWAP = 003              /* Currently on Swap Disk */
  };

struct sup_page_entry
{
	/* will depend on situation */
	void *upage;
	void *kpage;

	struct frame_entry *frame;
	bool dirty;
	bool page_location loc;


	/* if in file */
	struct file *owner;
	off_t offset;
	size_t num_bytes;
	bool writeable;

	/* if in swap */
	size_t swap_index;
	
	/* used for hash table */
	struct hash_elem hash_elem;

};

unsigned page_hash(const struct hash_elem *e, void *aux);
void page_out(struct hash_elem *e, void*aux);
void* page_lookup(void*);
bool page_hash_less(const struct hash_elem *a, const struct hash_elem *b, void* aux);


#endif