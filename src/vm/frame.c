#include "vm/frame.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "userprog/syscall.h"
#include <malloc.h>

static struct list frame_table;
static struct lock frame_lock;
static struct list_elem *clock;

void lock_frame()
{
    lock_acquire(&frame_lock);
}

void release_frame()
{
    lock_release(&frame_lock);
}

void init_frame_table () 
{
    list_init(&frame_table);
    lock_init(&frame_lock);
    clock = NULL;
}

void init_frame (struct frame *f, void *paddr)
{
    f->t = thread_current();
    f->page_addr = paddr;
    f->vme = NULL;
    f->pinned = false;
}

void insert_frame (struct frame* f)
{
    list_push_back(&frame_table, &f->elem);
}

void delete_frame (struct frame* f)
{
    struct list_elem *next = list_remove(&f->elem);

    if (&f->elem == clock)
        clock = next;
}

struct frame *find_frame (void *addr)
{
    struct list_elem *it = list_begin(&frame_table);
    struct list_elem *end = list_end(&frame_table);

    for (it; it != end; it = list_next(it)) {
        struct frame *f  = list_entry(it, struct frame, elem);
        if (f->page_addr == addr)
            return f;
    }

    return NULL;
}

struct frame *alloc_frame(enum palloc_flags flags)
{
    struct frame *f;
    void *paddr;

    f = (struct frame*)malloc(sizeof(struct frame));
    if (f == NULL)
        return NULL;

    while(true) {
        paddr = palloc_get_page(flags);
        if (paddr != NULL)
            break;

        evict_frame();
    }

    init_frame(f, paddr);
    insert_frame(f);

    return f;
}

void free_frame(void *addr)
{
    struct frame *f;

    f = find_frame(addr);
    if (f == NULL)
        return;

    f->vme->is_on_memory = false;
    pagedir_clear_page(f->t->pagedir, f->vme->vaddr);
    palloc_free_page(f->page_addr);
    delete_frame(f);
    
    free(f);
}

void evict_frame()
{
  	struct frame *f = find_victim();

  	bool dirty = pagedir_is_dirty(f->t->pagedir, f->vme->vaddr);
	 
	switch(f->vme->type)
	{
		case VM_FILE:
			if(dirty)
			{	
				lock_file_sys();
				file_write_at(f->vme->f, f->page_addr, f->vme->size, f->vme->offset);
				release_file_sys();
			}
			break;
		case VM_BIN:
			if(dirty)
			{	
				frame->vme->swap_slot = swap_out(frame->page_addr);
				frame->vme->type = VM_ANON;
			}
			break;
		case VM_ANON:
			frame->vme->swap_slot = swap_out(frame->page_addr);
			break;
	}
	
	pagedir_clear_page(f->t->pagedir, f->vme->vaddr);
	palloc_free_page(f->page_addr);
	frame_delete(f);

	f->vme->is_on_memory = false;
	free(f);
	
}
