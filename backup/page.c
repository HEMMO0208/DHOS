#include "vm/page.h"
#include "vm/frame.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "vm/swap.h"

static unsigned vm_hash_fn (const struct hash_elem *e, void *aux);
static bool vm_compare_fn (const struct hash_elem *a, const struct hash_elem *b, void *aux);

extern struct lock file_lock;
extern struct lock frame_lock;

// vm (hash table) initialization
void vm_init (struct hash *vm) //
{
	hash_init(vm, vm_hash_fn, vm_compare_fn, NULL);
}

static unsigned vm_hash_fn (const struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	int addr = (int)vme->vaddr;

	return hash_int(addr);
}

static bool vm_compare_fn (const struct hash_elem *l, const struct hash_elem *r, void *aux UNUSED)
{
	struct vm_entry *vl, *vr;
	
	vl = hash_entry(l, struct vm_entry, elem)->vaddr;
	vr = hash_entry(r, struct vm_entry, elem)->vaddr;

	return  vl < vr;
}	

void vm_destroy_fn(struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	frame_lock_acquire();

	if(vme->is_on_memory)
		free_frame(pagedir_get_page(thread_current()->pagedir, vme->vaddr));

	free(vme);

	frame_lock_release();
}

bool vme_insert (struct hash *vm, struct vm_entry *vme)
{	
	struct hash_elem *ret = hash_insert(vm, &vme->elem);

	return ret != NULL;
}

bool vme_delete (struct hash *vm, struct vm_entry *vme)
{
	frame_lock_acquire();

	struct hash_elem *ret = hash_delete(vm, &vme->elem);

	if (ret == NULL){
		frame_lock_release();
		return false;
	}

	free_frame(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
	free(vme);
	frame_lock_release();

	return true;

}	

struct vm_entry *vme_find (void *vaddr)
{
	struct hash *vm = &thread_current()->vm;
	struct vm_entry vme;
	struct hash_elem *it;

	vme.vaddr = pg_round_down(vaddr);
	it = hash_find(vm, &vme.elem);
	
	if (it != NULL)
		return hash_entry(it, struct vm_entry, elem);

	return NULL;
}

void vm_destroy (struct hash *vm)
{
	hash_destroy(vm, vm_destroy_fn);
}

bool load_file (void* addr, struct vm_entry *vme)
{
	file_lock_acquire();

	file_seek(vme->file, vme->offset);
	int byte_read = file_read(vme->file, addr, vme->read_bytes);

	file_lock_release();

	if (byte_read != vme->read_bytes)
		return false;

	memset(addr + vme->read_bytes, 0, vme->zero_bytes);
	return true;

}

void init_vme(
	struct vm_entry *vme, 
	enum page_type type, 
	void *vaddr, 
	bool writable, 
	bool is_loaded, 
	struct file* file, 
	size_t offset, 
	size_t read_bytes, 
	size_t zero_bytes) 
{
	vme->type = type;
	vme->vaddr = vaddr;
	vme->is_writable = writable;
	vme->is_on_memory = is_loaded;
	vme->file = file;
	vme->offset = offset;
	vme->read_bytes = read_bytes;
	vme->zero_bytes = zero_bytes;
}

struct mmap_elem *me_find (mapid_t mid) {
	struct thread *cur = thread_current();
  	struct list_elem *it = list_begin(&cur->mmap_list);
  	struct list_elem *end = list_end(&cur->mmap_list);
	
	for (it; it != end; it = list_next(it)) {
		struct mmap_elem* me = list_entry(it, struct mmap_elem, elem);

		if (me->mid == mid) 
			return me;
	}

	return NULL;
}

void init_me(struct mmap_elem *me, struct file* file, mapid_t mid) {
	list_init(&me->vmes);
	me->file = file;
	me->mid = mid;
}