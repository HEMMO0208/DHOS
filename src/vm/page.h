#include <hash.h>
#include <userprog/syscall.h>

typedef int mapid_t;

enum page_type{
    PAGE_CODE, PAGE_SWAP, PAGE_MMAP, PAGE_STACK, PAGE_FILE
};

struct vm_entry
{
    enum page_type type;
    void *vaddr;

    bool is_writable;
    bool is_on_memory;

    struct hash_elem elem;

    struct file *file;

    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;
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
               void *vaddr, 
               bool is_writable, 
               bool is_on_memory, 
               struct file *f, 
               size_t offset, 
               size_t zero_bytes
);

void init_map_e (
    struct map_entry *map,
    mapid_t mid,
    struct file *f
);