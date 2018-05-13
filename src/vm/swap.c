#include "vm/swap.h"
#include "devices/block.h"
#include <bitmap.h>
#include "threads/synch.h"
#include "threads/vaddr.h"

static struct bitmap used_swaps;
struct block *swap_table;

static struct lock swap_lock;