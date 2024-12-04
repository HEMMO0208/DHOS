#include <frame.h>

static struct list frame_table;
static struct lock frame_lock;
static struct list_elem *clock;

void init_frame_table () 
{
    list_init(&frame_table);
    lock_init(&frame_lock);
    clock = NULL;
}

void insert_frame (struct frame* f)
{
    list_push_back(&frame_table, &f->elem);
}

void delete_frame (struct frame* f)
{
    struct list_elem *next = list_remove(&f->elem);

    if (&f->elem == clock)
        clock = next;
}

struct frame *find_frame (void *addr)
{
    struct list_elem *it = list_begin(&frame_table);
    struct list_elem *end = list_end(&frame_table);

    for (it; it != end; it = list_next(it)) {
        struct frame *f  = list_entry(it, struct frame, elem);
        if (f->page_addr == addr)
            return f;
    }

    return NULL;
}


