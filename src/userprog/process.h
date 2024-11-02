#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <list.h>
#include "threads/thread.h"
#define MAX_ARGC 128

struct parse_result{
    int argc;
    char *argv[MAX_ARGC];
    int data_size;
    struct thread *parent;
    char data_start;
};

struct file_elem{
    struct file *file;
    struct list_elem elem;
    int fd;
};

void push_stack(char **rsp, void* val, int size);
void pop_stack(char **rsp, void* dst, int size);

struct parse_result* parse_command(char* command);

tid_t process_execute (const char *command);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
