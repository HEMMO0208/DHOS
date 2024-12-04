#include <page.h>

static unsigned vm_hash_fn (const struct hash_elem *e, void *aux) 
{
    struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
    return hash_int(vme->vaddr);
}

static bool vm_compare_fn (const struct hash_elem *l, const struct hash_elem *r, void *aux)
{
    struct vm_entry *vl, *vr;
    vl = hash_entry(l, struct vm_entry, elem);
    vr = hash_entry(r, struct vm_entry, elem);

    return vl->vaddr < vr->vaddr;
}

void init_vm (struct hash *vm)
{
    hash_init(vm, vm_hash_fn, vm_compare_fn, NULL);
}

struct vm_entry *find_vm(void *vaddr) {
    struct hash *vm = &thread_current->vm;
    struct vm_entry vme;
    struct hash_elem *e;

    vme.vaddr = vaddr;
    e = hash_find(vm, &vme.elem);

    if (e == NULL)
        return NULL;

    return hash_entry(e, struct vm_entry, elem);    
}

void init_vme (struct vm_entry *vme, 
               void *vaddr, 
               bool writable, 
               bool is_loaded, 
               struct file *f, 
               size_t offset, 
               size_t zero_bytes)
{
    ASSERT(vme != NULL);

    vme->vaddr = vaddr;
    
}