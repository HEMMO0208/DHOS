#include "vm/frame.h"
#include "vm/swap.h"
#include <list.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include <string.h>
#include "filesys/file.h"

struct lock frame_lock;
extern struct lock file_lock;

struct list frame_table;
struct list_elem *frame_clock;

void frame_lock_acquire ()
{
	if (!lock_held_by_current_thread(&frame_lock))
		lock_acquire(&frame_lock);
}

void frame_lock_release ()
{
	if (lock_held_by_current_thread(&frame_lock))
		lock_release(&frame_lock);
}

void frame_table_init ()
{
    list_init(&frame_table);
	lock_init(&frame_lock);
	frame_clock = NULL;
}

void frame_insert (struct frame *frame)
{
    list_push_back(&frame_table, &frame->ft_elem);
}

void frame_delete (struct frame *frame)
{	
	bool is_clock = (frame_clock == &frame->ft_elem);
	struct list_elem *next = list_remove(&frame->ft_elem);
	
	if (is_clock)
		frame_clock = next;
}

struct frame* frame_find(void *addr)
{
    struct list_elem *it = list_begin(&frame_table);
	struct list_elem *end = list_end(&frame_table);

	for (it; it != end; it = list_next(it))
	{
		struct frame *frame = list_entry(it, struct frame, ft_elem);

		if (frame->page_addr == addr)
			return frame;
	}

	return NULL;
}

void frame_init (struct frame *frame, void *paddr)
{
	frame->thread = thread_current();
	frame->page_addr = paddr;
	frame->vme = NULL;
	frame->pinned = false;
}

struct frame* alloc_frame (enum palloc_flags flags)
{
	void *paddr;
	struct frame *frame;

    frame = (struct frame *)malloc(sizeof(struct frame));
    if (!frame) 
		return NULL;

	while(true) {
		paddr = palloc_get_page(flags);

		if (paddr != NULL)
			break;

		evict_frame();
	}

	ASSERT(pg_ofs(paddr) == 0);

	frame_init(frame, paddr);
	frame_insert(frame);		

    return frame;
}

void free_frame(void *addr)
{
	struct frame *frame = frame_find(addr);
	if (frame == NULL)
		return;

	frame->vme->is_on_memory = false;
	pagedir_clear_page(frame->thread->pagedir, frame->vme->vaddr);
	palloc_free_page(frame->page_addr);
	frame_delete(frame);
	free(frame);
}

void evict_frame()
{
  	struct frame *frame = find_victim();
	struct vm_entry *vme = frame->vme;

  	bool dirty = pagedir_is_dirty(frame->thread->pagedir, vme->vaddr);
	 
	switch(vme->type)
	{
		case VM_FILE:
			if(dirty)
			{	
				lock_acquire(&file_lock);
				file_seek(vme->file, vme->offset);
				file_write(vme->file, frame->page_addr, vme->read_bytes);
				lock_release(&file_lock);
			}
			break;

		case VM_BIN:
			if(dirty)
			{	
				vme->swap_slot = swap_out(frame->page_addr);
				vme->type = VM_ANON;
			}
			break;

		case VM_ANON:
			vme->swap_slot = swap_out(frame->page_addr);
			break;
	}
	
	pagedir_clear_page(frame->thread->pagedir, vme->vaddr);
	palloc_free_page(frame->page_addr);
	frame_delete(frame);

	vme->is_on_memory = false;
	free(frame);
}


struct frame* find_victim()
{
	struct list_elem *e;
	struct frame *frame;
	
	while (true)
	{
		if (!frame_clock || (frame_clock == list_end(&frame_table)))
		{
			if (!list_empty(&frame_table))
			{
				frame_clock = list_begin(&frame_table);
				e = list_begin(&frame_table);
			}
			else // frame table이 비어있는 경우
				return NULL;
		}
		else // next로 이동
		{
			frame_clock = list_next(frame_clock);
			if (frame_clock == list_end(&frame_table))
				continue;
			e = frame_clock;
		}
		
		frame = list_entry(e, struct frame, ft_elem);
		// access bit 확인 -> 0이면 바로 Return
		if(!frame->pinned)
		{
			if (!pagedir_is_accessed(frame->thread->pagedir, frame->vme->vaddr))
			{
				return frame;
			}
			else
			{
				// access bit 1이면 0으로 바꾸고 그 다음으로 clock이동
				pagedir_set_accessed(frame->thread->pagedir, frame->vme->vaddr, false);
			}
		}
		
	}
}

void frame_pin(void *kaddr)
{
	struct frame *f;
	f = frame_find(kaddr);
	f->pinned = true;
}

void frame_unpin(void *kaddr)
{
	struct frame *f;
	f = frame_find(kaddr);
	f->pinned = false;
}