#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <string.h>

#define BUF_MAX 200
#define parse(rsp, dst) exit_if_not_valid(*rsp); pop_stack((rsp), &(dst), sizeof(dst))

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_sys_lock);
}

bool
is_memory_valid(void* addr) {
	struct thread *t = thread_current ();

	if (addr == NULL)
		return false;
  if (is_kernel_vaddr (addr))
    return false;
  if (pagedir_get_page (t->pagedir, addr) == NULL)
   	return false;
  
	return true;
}

bool
exit_if_not_valid(void* addr) {
  if (!is_user_vaddr(addr))
    sys_exit(-1);
}

void 
init_bit_vector (struct bit_vector* v)
{
  int i = 0;

  for (; i < 4; ++i)
    v->bits[0] = 0;
}

int
find_min(struct bit_vector* v)
{
    int pos = 2;

    for (; pos < 128; ++pos) {
        unsigned int result = (v->bits[pos / 32] >> (pos % 32)) & 0x1;
        if (!result)
            return pos;
    }

    return -1;
}

void
set_vector(struct bit_vector* v, int pos)
{
    unsigned int result = 0x1 << (pos % 32);
    v->bits[pos / 32] |= result;
}

void
unset_vector(struct bit_vector* v, int pos)
{
    unsigned int result = 0x1 << (pos % 32);
    v->bits[pos / 32] &= ~result;
}


static void
syscall_handler (struct intr_frame *f) 
{
  char *base = f->esp;

  char **rsp = &base;
  int *ret = &f->eax;

  int syscall_num;
  parse(rsp, syscall_num);

  switch (syscall_num) {
  	case 0:
  	  sys_halt ();
  	  break;
  	case 1:
  	{
  	  int status;
      parse(rsp, status);

  	  sys_exit (status);
  	  break;
  	}
  	case 2:
  	{
  	  const char *cmd_line;
      parse(rsp, cmd_line);

  	  *ret = sys_exec(cmd_line);
  	  break;
  	}
  	case 3:
  	{
  	  tid_t tid;
      parse(rsp, tid);

  	  *ret = sys_wait(tid);
  	  break;
  	}
  	case 4:
  	{
  	  const char *file;
  	  unsigned initial_size;
      parse(rsp, file);
      parse(rsp, initial_size);

  	  *ret = sys_create(file, initial_size);
  	  break;
  	}
  	case 5:
  	{
  	  const char *file;
      parse(rsp, file);

  	  *ret = sys_remove(file);
  	  break;
  	}
  	case 6:
  	{
  	  const char *file;
      parse(rsp, file);

  	  *ret = sys_open(file);
  	  break;
  	}
  	case 7:
  	{
  	  int fd;
      parse(rsp, fd);

  	  *ret = sys_filesize(fd);
  	  break;
  	}
  	case 8:
  	{
  	  int fd;
  	  void *buffer;
  	  unsigned size;
      parse(rsp, fd);
      parse(rsp, buffer);
      parse(rsp, size);

  	  *ret = sys_read(fd, buffer, size);
  	  break;
  	}
  	case 9:
  	{
  	  int fd;
  	  void *buffer;
  	  unsigned size;
      parse(rsp, fd);
      parse(rsp, buffer);
      parse(rsp, size);

  	  *ret = sys_write(fd, buffer, size);

  	  break;
  	}
  	case 10:
  	{
  	  int fd;
  	  unsigned position;
      parse(rsp, fd);
      parse(rsp, position);

      sys_seek(fd, position);
  	  break;
  	}
  	case 11:
  	{
  	  int fd;
      parse(rsp, fd);

  	  *ret = (uint32_t) sys_tell(fd);
  	  break;
  	}
  	case 12:
  	{
  	  int fd;
      parse(rsp, fd);

  	  sys_close(fd);
  	  break;
  	}
  }
}

struct file_elem *
getFile (int fd)
{
  struct thread *t = thread_current ();

  struct list_elem *it = list_begin(&t->list_file);
  struct list_elem *end = list_end(&t->list_file);

  for (; it != end; it = list_next(it))
    {
      struct file_elem *f_elem = list_entry (it, struct file_elem, elem);
      if(f_elem->fd == fd)
        return f_elem;
    }
  return NULL;
}


void
sys_halt ()
{
	shutdown_power_off ();
}

void
sys_exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
	thread_exit ();
}

tid_t
sys_exec (const char *cmd_line)
{
  tid_t child_tid = TID_ERROR;

  if(!is_memory_valid(cmd_line))
    sys_exit (-1);

  child_tid = process_execute (cmd_line);

	return child_tid;
}

int
sys_wait (tid_t tid)
{
  return process_wait (tid);
}

bool
sys_create (const char *file, unsigned initial_size)
{
  bool retval;
  if(is_memory_valid(file)) {
    lock_acquire (&file_sys_lock);
    retval = filesys_create (file, initial_size);
    lock_release (&file_sys_lock);
    return retval;
  }
	else
    sys_exit (-1);

  return false;
}

bool
sys_remove (const char *file)
{
  bool ret;
  
	if(!is_memory_valid(file))
    sys_exit (-1);

  lock_acquire (&file_sys_lock);
  ret = filesys_remove (file);
  lock_release (&file_sys_lock);
  return ret;
}

struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

int
sys_open (const char *file)
{
	if (!is_memory_valid(file))
    sys_exit(-1);
  
  struct thread *cur = thread_current();
  struct file_elem *new = palloc_get_page (0);

  int fd = find_min(&cur->fd_map);
  new->fd = fd;

  lock_acquire (&file_sys_lock);
  new->file = filesys_open(file);
  lock_release (&file_sys_lock);

  if (new->file == NULL)
    return -1;

  if (strcmp(file, cur->name) == 0){
    file_deny_write(new->file);
  }
    

  set_vector(&cur->fd_map, fd);
  list_push_back(&cur->list_file, &new->elem);
  return new->fd;
}

int
sys_filesize (int fd)
{
  int ret;
  struct file_elem *f_elem = NULL;

	f_elem = getFile (fd);

  if (f_elem == NULL)
    return 0;

  lock_acquire (&file_sys_lock);
  ret = file_length (f_elem->file);
  lock_release (&file_sys_lock);

  return ret;
}

int
sys_read (int fd, void *buffer, unsigned size)
{
  int bytes_read = 0;
  char *bufChar = NULL;
  struct file_elem *f_elem = NULL;

	if (!is_memory_valid(buffer))
    sys_exit (-1);

  bufChar = (char *)buffer;
	if(fd == 0) {
    while(size > 0) {
      input_getc();
      size--;
      bytes_read++;
    }
    return bytes_read;
  }

  else {
    f_elem = getFile (fd);
    if (f_elem == NULL)
      return -1;

    lock_acquire (&file_sys_lock);
    bytes_read = file_read (f_elem->file, buffer, size);
    lock_release (&file_sys_lock);

    return bytes_read;
  }
}

int
sys_write (int fd, const void *buffer, unsigned size)
{
  int bytes_written = 0;
  struct file_elem *f_elem = NULL;

	if (!is_memory_valid(buffer))
		sys_exit (-1);

  if(fd == 1) {
    putbuf(buffer, size);
    bytes_written += size;
    return bytes_written;
  }

  else {
    f_elem = getFile (fd);
    if (f_elem == NULL)
      return 0;

    lock_acquire (&file_sys_lock);
    bytes_written = file_write (f_elem->file, buffer, size);
    lock_release (&file_sys_lock);
    return bytes_written;
  }
}

void
sys_seek (int fd, unsigned position)
{
	struct file_elem *f_elem = getFile (fd);
  if (f_elem == NULL)
    return;

  lock_acquire (&file_sys_lock);
  file_seek (f_elem->file, position);
  lock_release (&file_sys_lock);
}

unsigned
sys_tell (int fd)
{
  unsigned ret;

	struct file_elem *f_elem = getFile (fd);
  if (f_elem == NULL)
    return 0;

  lock_acquire (&file_sys_lock);
  ret = file_tell (f_elem->file);
  lock_release (&file_sys_lock);

  return ret;
}

void
sys_close (int fd)
{
	struct thread *cur = thread_current();
  struct file_elem *f_elem = NULL;

  f_elem = getFile (fd);
  if (f_elem == NULL)
    return;

  lock_acquire (&file_sys_lock);
  file_close (f_elem->file);
  lock_release (&file_sys_lock);

  unset_vector(&cur->fd_map, fd);
  list_remove (&f_elem->elem);

  palloc_free_page (f_elem);
}

