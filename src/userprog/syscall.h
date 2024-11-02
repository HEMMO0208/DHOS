#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"

void syscall_init (void);

struct lock file_sys_lock;

static struct file_elem *
getFile (int fd);

static void
userprog_halt ();

static void
userprog_exit (int status);

static tid_t
userprog_exec (const char *cmd_line);

static int
userprog_wait (tid_t tid);

static bool
userprog_create (const char *file, unsigned initial_size);

static bool
userprog_remove (const char *file);

static int
userprog_open (const char *file);

static int
userprog_filesize (int fd);

static int
userprog_read (int fd, void *buffer, unsigned size);

static int
userprog_write (int fd, const void *buffer, unsigned size);

static void
userprog_seek (int fd, unsigned position);

static unsigned
userprog_tell (int fd);

static void
userprog_close (int fd);


#endif /* userprog/syscall.h */
