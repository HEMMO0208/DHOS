#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "vm/page.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"

struct frame
{
	void *page_addr; 
	struct vm_entry *vme;
	struct thread *thread;
	struct list_elem elem; 
	bool pinned;
};

void frame_lock_acquire();
void frame_lock_release();

void frame_table_init();
void frame_init();
void frame_insert(struct frame *frame);
void frame_delete(struct frame *frame);

struct frame* alloc_frame(enum palloc_flags flags);
struct frame* frame_find(void* addr);
void free_frame(void *addr);

void evict_frame(void);
struct frame* find_victim(void);

void frame_pin(void *kaddr);
void frame_unpin(void *kaddr);

#endif