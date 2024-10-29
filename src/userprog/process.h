#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#define MAX_ARGC 128

struct parse_result{
    int argc;
    char* argv[MAX_ARGC];
    int data_size;
    char data_start;
};

#include "threads/thread.h"

struct parse_result* parse_command(char* command);

tid_t process_execute (const char *command);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
