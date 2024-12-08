#include "vm/page.h"
#include "vm/frame.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "vm/swap.h"

static unsigned vm_hash (const struct hash_elem *e, void *aux);
static bool vm_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);

extern struct lock file_lock;
extern struct lock frame_lock;

// vm (hash table) initialization
void vm_init (struct hash *vm) //
{
	hash_init(vm, vm_hash, vm_less, NULL);
}

static unsigned vm_hash (const struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	int addr = (int)vme->vaddr;

	return hash_int(addr);
}

static bool vm_less (const struct hash_elem *l, const struct hash_elem *r, void *aux UNUSED)
{
	struct vm_entry *vl, *vr;
	
	vl = hash_entry(l, struct vm_entry, elem)->vaddr;
	vr = hash_entry(r, struct vm_entry, elem)->vaddr;

	return  vl < vr;
}	

// vm entry
bool vme_insert (struct hash *vm, struct vm_entry *vme)
{	
	// 인자로 넘겨 받은 vme를 vm entry에 insert
	if (hash_insert(vm, &vme->elem)) 
		return true;
	else 
		return false;
	
}

bool vme_delete (struct hash *vm, struct vm_entry *vme) // syscall munmap에서 호출
{
	lock_acquire(&frame_lock);

	if (hash_delete(vm, &vme->elem))
	{
		free_frame(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
		free(vme);
		lock_release(&frame_lock);
		return true;
	}

	else
	{
		lock_release(&frame_lock);
		return false;
	}
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

void vm_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);

	lock_acquire(&frame_lock);
	if(vme)
	{
		if(vme->is_on_memory)
		{
			free_frame(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
		}
		free(vme);
	}

	lock_release(&frame_lock);
	
}

void vm_destroy (struct hash *vm)
{
	hash_destroy(vm, vm_destroy_func);
}


bool load_file (void* addr, struct vm_entry *vme)
{
	lock_acquire(&file_lock);
	file_seek(vme->file, vme->offset);
	int byte_read = file_read(vme->file, addr, vme->read_bytes);
	lock_release(&file_lock);

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

struct vm_entry *vme_construct (enum page_type type, void *vaddr, bool writable, bool is_loaded, struct file* file, size_t offset, size_t read_bytes, size_t zero_bytes)
{
	struct vm_entry* vme = (struct vm_entry*)malloc(sizeof(struct vm_entry));
	if (!vme) 
		return NULL;
	memset(vme, 0, sizeof(struct vm_entry));
	vme->type = type;
	vme->vaddr = vaddr;
	vme->is_writable = writable;
	vme->is_on_memory = is_loaded;
	vme->file = file;
	vme->offset = offset;
	vme->read_bytes = read_bytes;
	vme->zero_bytes = zero_bytes;

	return vme;
}
