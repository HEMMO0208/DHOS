#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "userprog/syscall.h"
#include "threads/palloc.h"
#include "filesys/off_t.h"

enum page_type{
	PAGE_CODE, PAGE_MMAP, PAGE_SWAP
};

struct vm_entry 
{
	enum page_type type; 

	void *vaddr;
	bool is_writable;
	bool is_on_memory;

	struct file* file; 

	size_t offset;
	size_t read_bytes;
	size_t zero_bytes;

    struct hash_elem elem;
    struct list_elem mmap_elem;

    size_t swap_slot;
};

struct mmap_elem {
	mapid_t mid;

	struct file* file;     
	struct list vmes;  
	struct list_elem elem; 
};

void vm_init (struct hash *vm);
struct vm_entry *vme_find (void *vaddr);

bool vme_insert (struct hash *vm, struct vm_entry *vme);
bool vme_delete (struct hash *vm, struct vm_entry *vme);

void vm_destroy_fn(struct hash_elem *e, void *aux);
void vm_destroy (struct hash *vm);

bool load_file (void* kaddr, struct vm_entry *fte);

void init_vme(
	struct vm_entry *vme, 
	enum page_type type, 
	void *vaddr, 
	bool writable, 
	bool is_loaded, 
	struct file* file, 
	size_t offset, 
	size_t read_bytes, 
	size_t zero_bytes);

void *mfe_find (mapid_t mid);
void init_mfe (struct mmap_elem *mfe, struct file* file, mapid_t mid);

#endif