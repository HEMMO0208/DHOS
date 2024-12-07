#ifndef FRAME_H
#define FRAME_H

#include <list.h>
#include "vm/page.h"
#include "threads/vaddr.h"

struct frame{
    void *page_addr;
    struct thread *t;
    struct vm_entry *vme;
    struct list_elem elem;
    bool pinned;
};

void lock_frame();
void release_frame();

void init_frame_table();
void init_frame(struct frame* f, void *paddr);
void insert_frame(struct frame* f);
void delete_frame(struct frame* f);

struct frame *alloc_frame(enum palloc_flags flags);
void free_frame(void *addr);

struct frame *find_frame(void *addr);
struct frame *find_frame_vaddr(void *vaddr);


#endif