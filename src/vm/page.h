#include <hash.h>
#include <userprog/syscall.h>

struct vm_entry
{
    char type;
    void *vaddr;
    bool writable;
    bool is_loaded;
    struct hash_elem elem;
    struct file* file;
    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;
};
