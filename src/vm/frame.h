#include <list.h>
#include <vm/page.h>
#include <threads/vaddr.h>

struct frame{
    void *page_addr;
    struct thread *t;
    struct list_elem elem;
    bool pinned;
}