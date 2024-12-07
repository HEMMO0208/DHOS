#include "threads/vaddr.h"
#include "vm/page.h"
#include "filesys/file.h"
#include "vm/frame.h"

static unsigned vm_hash_fn (const struct hash_elem *e, void *aux) 
{
    struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
    return hash_bytes(vme->vaddr, sizeof(vme->vaddr));
}

static bool vm_compare_fn (const struct hash_elem *l, const struct hash_elem *r, void *aux)
{
    struct vm_entry *vl, *vr;
    vl = hash_entry(l, struct vm_entry, elem);
    vr = hash_entry(r, struct vm_entry, elem);

    return vl->vaddr < vr->vaddr;
}

static void vm_destroy_fn(struct hash_elem *e, void *aux)
{
    struct thread *cur = thread_current();
    struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);

    lock_frame();

    if(vme) {
        if (vme->is_on_memory)
            free_frame(pagedir_get_page(cur->pagedir, vme->vaddr));

        free(vme);
    }

    unlock_frame();
}

void init_vm (struct hash *vm)
{
    hash_init(vm, vm_hash_fn, vm_compare_fn, NULL);
}

struct vm_entry *find_vm(void *vaddr) 
{
    struct hash *vm = &thread_current()->vm;
    struct vm_entry vme;
    struct hash_elem *e;

    vme.vaddr = vaddr;
    e = hash_find(vm, &vme.elem);

    if (e == NULL)
        return NULL;

    return hash_entry(e, struct vm_entry, elem);    
}

void init_vme (struct vm_entry *vme,
               enum page_type type,
               void *vaddr, 
               bool is_writable, 
               bool is_loaded, 
               struct file *f, 
               size_t offset, 
               size_t size)
{
    ASSERT(vme != NULL);

    vme->type = type;
    vme->vaddr = vaddr;
    vme->is_writable = is_writable;
    vme->is_on_memory = is_loaded;
    vme->f = f;
    vme->offset = offset;
    vme->size = size;
}

void destory_vm (struct hash *vm)
{
    hash_destroy(vm, vm_destroy_fn);
}

void init_me (
    struct map_entry *map,
    mapid_t mid,
    struct file *f
)
{
    struct thread *cur = thread_current();
    
    map->mid = mid;
    map->f = f;
    list_init(&map->vmes);

    list_push_back(&cur->list_mmap, &map->elem);
}

void vm_insert (struct vm_entry *vme)
{	
    struct thread *cur = thread_current();

    hash_insert(&cur->vm, &vme->elem);
}

void vm_delete (struct vm_entry *vme)
{
    struct thread *cur = thread_current();
    
    lock_frame();
    
    hash_delete(&cur->vm, &vme->elem);
    free_frame(pagedir_get_page(cur->pagedir, vme->vaddr));
    free(vme);

    release_frame();
}

bool load_file (void* addr, struct vm_entry *vme)
{
	int bytes_read;
    
    lock_file_sys();
	bytes_read = file_read_at(vme->f, addr, vme->size, vme->offset);
	release_file_sys();

	if (bytes_read != vme->size)
		return false;

    int pad = PGSIZE - vme->size;

	memset(addr + vme->size, 0, pad);
	return true;
}