// #include "vm/swap.h"
// #include "devices/block.h"
// #include "bitmap.h"
// #include "vm/frame.h"
// #include "vm/page.h"


// #define NUM_OF_SECTORS_PER_PAGE = (PGSIZE/BLOCK_SECTOR_SIZE)


// static struct bitmap used_swaps;
// struct block *swap_table;

// static struct lock swap_lock;

// void 
// swap_table_init(void)
// {
// 	swap_get = block_get_role(BLOCK_SWAP);
// 	if(swap_get == NULL)
// 		/* cannot get swap */
// 		PANIC("Swap block cannot be initialized!\n");
// 	else
// 	{
// 		size_t swap_size = block_size(swap_get)/NUM_OF_SECTORS_PER_PAGE; 
// 		swap_d = bitmap_create(swap_size);
// 		if(swap_d == NULL)
// 		{
// 			PANIC("Swap bitmap failed to initialize!\n");
// 		}
// 		else
// 		{
// 			bitmap_set_all(swap_available, true);
// 		}
// 	}
// }

// void
// swap_insert_table(void* page)
// {
// 	lock_acquire(&swap_lock);
// 	size_t available_index = bitmap_scan_and_flip (used_swaps, 0, 1, true);

// 	/* loop through one sector at a time inserting
// 	   into table */
// 	for(int i = 0; i < PAGE_SECTORS; ++i)
// 	{
// 		block_write(swap_table, available_index*NUM_OF_SECTORS_PER_PAGE + i, page+BLOCK_SECTOR_SIZE*i);
// 	}

// 	lock_release(&swap_lock);
// }

// void 
// swap_get_table(void* page)
// {
// 	return NULL;
// }

// void 
// swap_remove_table(void* page)
// {
// 	lock_acquire(&swap_lock);

// 	if(bitmap_test(used_swaps, ) == true)
// 		PANIC("")
// }