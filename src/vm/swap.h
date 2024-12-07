#ifndef SWAP_H
#define SWAP_H

#include <stddef.h>
#include <stdbool.h>

void init_swap(void);
bool swap_in(size_t slot_index, void *kaddr);
size_t swap_out(void* kaddr);

#endif