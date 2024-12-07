#ifndef PAGE_H
#define PAGE_H

typedef int mapid_t;

#include <hash.h>
#include "userprog/syscall.h"

enum page_type{
    VM_FILE, VM_ANON, VM_BIN
};

struct vm_entry
{
    enum page_type type;
    void *vaddr;

    bool is_writable;
    bool is_on_memory;

    struct hash_elem elem;
    struct list_elem mmap_elem;

    struct file *f;

    size_t offset;
    size_t size;
    size_t swap_slot;
};

struct map_entry
{
    mapid_t mid;
    struct file *f;

    struct list_elem elem;
    struct list vmes;
};

void init_vm (struct hash *vm);

struct vm_entry *find_vm(void *vaddr);

void init_vme (struct vm_entry *vme,
               enum page_type type,
               void *vaddr, 
               bool is_writable, 
               bool is_loaded, 
               struct file *f, 
               size_t offset, 
               size_t size
);

void init_me (
    struct map_entry *map,
    mapid_t mid,
    struct file *f
);

void vm_insert (struct vm_entry *vme);
void vm_delete (struct vm_entry *vme);

bool load_file (void* addr, struct vm_entry *vme);

#endif