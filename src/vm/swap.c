#include <threads/synch.h>
#include <devices/block.h>

static struct lock swap_lock;
static struct bitmap *swap_bitmap;
static struct block *swap_block;

void init_swap ()
{
    swap_block = block_get_role(BLOCK_SWAP);
    size_t size = block_size(swap)
}