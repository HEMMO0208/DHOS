#include "vm/swap.h"
#include "threads/synch.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"

#include <bitmap.h>

#define SECTOR_NUM_PER_PAGE (PGSIZE/BLOCK_SECTOR_SIZE)

static struct lock swap_lock;
static struct bitmap *swap_bitmap;
static struct block *swap_block;

void init_swap()
{
	swap_block = block_get_role(BLOCK_SWAP);
	size_t swap_bitmap_size = block_size(swap_block) / SECTOR_NUM_PER_PAGE;
	swap_bitmap = bitmap_create(swap_bitmap_size);

	lock_init(&swap_lock);
}

bool swap_in(size_t slot_index, void *kaddr)
{
	// 1. calculate number of sector for storing page
	int start_sector = SECTOR_NUM_PER_PAGE * slot_index;

    lock_acquire(&swap_lock); // lock acquire
	
	// 2. block read를 통해 swap slot에서 data 가져오기
	int i;
	for (i=0 ; i < SECTOR_NUM_PER_PAGE ; i++)
	{	
		block_read(swap_block, start_sector + i, kaddr + i * BLOCK_SECTOR_SIZE);
	}
	// 3. slot_index 부분에 false라고 세팅
	bitmap_set(swap_bitmap, slot_index, false);

    lock_release(&swap_lock); // lock release

	return true;
}

size_t swap_out(void* kaddr)
{
	size_t slot_index;
	int start_sector;
    lock_acquire(&swap_lock);
	slot_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);

	if(slot_index == BITMAP_ERROR)
	{
		lock_release(&swap_lock);
		NOT_REACHED();
		return BITMAP_ERROR;
	}

	start_sector = SECTOR_NUM_PER_PAGE * slot_index;
	
	int i;
	for (i = 0; i < SECTOR_NUM_PER_PAGE; i++)
	{
		block_write(swap_block, start_sector + i, kaddr + i * BLOCK_SECTOR_SIZE);
	}
	lock_release(&swap_lock);
	// 3. swap한 index 반환
    return slot_index;
}