#ifndef THREADS_LIST_UTILS_H
#define THREADS_LIST_UTILS_H

#include <list.h>

typedef int list_key_func(const struct list_elem *a);
typedef void list_apply_func(const struct list_elem *a);

struct list_elem* list_pop_max(struct list *, list_key_func *);
int list_max_val(struct list *, list_key_func *);

#endif