#ifndef FRAME_H
#define FRAME_H

#include <list.h>
#include <vm/page.h>
#include <threads/vaddr.h>

struct frame{
    void *page_addr;
    struct thread *t;
    struct list_elem elem;
    bool pinned;
};

void init_frame_table();
void insert_frame(struct frame* f);
void delete_frame(struct frame* f);
void free_frame(void *addr);

struct frame *alloc_frame();
struct frame *find_frame(void *addr);
struct frame *find_frame_vaddr(void *vaddr);


#endif