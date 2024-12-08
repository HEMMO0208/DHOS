#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include <list.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

static void get_args (int *sp, int *dest, size_t num);
static bool get_user_bytes (void *dest, const void *src, size_t num);

static void sys_halt ();
static pid_t sys_exec (const char *cmd_line);
static int sys_wait (pid_t pid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);
static mapid_t sys_mmap(int fd, void* addr);
static void sys_munmap (mapid_t mid);

 	
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Reads NUM bytes at user address SRC, stores at DEST.
   Note that DEST is not a vmem address.
   Returns true if every byte copies are successful. */
static bool
get_user_bytes (void *dest, const void *src, size_t num)
{
  uint8_t *_dest = dest;
  const uint8_t *_src = src;
  for (size_t i = 0; i < num; i++)
  {
    if (!check_ptr_in_user_space (_src)) return false;
    int res = get_user (_src);
    if (res == -1) return false;
    *_dest = (uint8_t) res;
    _dest++;
    _src++;
  }
  return true;
}

/* Only checks whether its in the user space */
bool
check_ptr_in_user_space (const void *ptr)
{
  return ptr < PHYS_BASE;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
get_args (int *sp, int *dest, size_t num)
{
  for(size_t i = 0; i < num; i++)
  {
    int *src = sp + i + 1;
    if (!check_ptr_in_user_space (src)) sys_exit (-1);
    if (!get_user_bytes (dest + i, src, 4)) sys_exit (-1);
  }
}

static void
syscall_handler (struct intr_frame *f) 
{
  int arg[4];
  if (!check_ptr_in_user_space (f->esp))
    sys_exit (-1);
  switch(*(uint32_t *) (f->esp))
  {
    case SYS_HALT:
      sys_halt ();
      break;
    case SYS_EXIT:
      get_args (f->esp, arg, 1);
      sys_exit (arg[0]);
      break;
    case SYS_EXEC:
      get_args (f->esp, arg, 1);
      f->eax = sys_exec ((const char *) arg[0]);
      break;
    case SYS_WAIT:
      get_args (f->esp, arg, 1);
      f->eax = sys_wait ((pid_t) arg[0]);
      break;
    case SYS_CREATE:
      get_args (f->esp, arg, 2);
      f->eax = sys_create ((const char *) arg[0], (unsigned) arg[1]);
      break;
    case SYS_REMOVE:
      get_args (f->esp, arg, 1);
      f->eax = sys_remove ((const char *) arg[0]);
      break;
    case SYS_OPEN:
      get_args (f->esp, arg, 1);
      f->eax = sys_open ((const char *) arg[0]);
      break;
    case SYS_FILESIZE:
      get_args (f->esp, arg, 1);
      f->eax = sys_filesize (arg[0]);
      break;
    case SYS_READ:
      get_args (f->esp, arg, 3);
      f->eax = sys_read (arg[0], (void *) arg[1], (unsigned) arg[2]);
      break;
    case SYS_WRITE:
      get_args (f->esp, arg, 3);
      f->eax = sys_write(arg[0], (const void *) arg[1], (unsigned) arg[2]);
      break;
    case SYS_SEEK:
      get_args (f->esp, arg, 2);
      sys_seek (arg[0], (unsigned) arg[1]);
      break;
    case SYS_TELL:
      get_args (f->esp, arg, 1);
      f->eax = sys_tell (arg[0]);
      break;
    case SYS_CLOSE:
      get_args (f->esp, arg, 1);
      sys_close (arg[0]);
      break;
    case SYS_MMAP:
      get_args (f->esp, arg, 2);
      f->eax = sys_mmap(arg[0], (void *)arg[1]);
      break;
    case SYS_MUNMAP:
      get_args (f->esp, arg, 1);
      sys_munmap(arg[0]);
      break;
    default:
      sys_exit (-1);
  }
}

static void
sys_halt ()
{
  shutdown_power_off ();
  NOT_REACHED ();
}

static pid_t
sys_exec (const char *cmd_line)
{
  struct list_elem *elem;
  struct process *p;
  tid_t tid = process_execute (cmd_line);
  if (tid == TID_ERROR)
    return PID_ERROR;
  /* Last added child */
  elem = list_back (&thread_current ()->process_ptr->children);
  p = list_entry (elem, struct process, elem);
  return p->pid;
}

void
sys_exit (int status)
{
  struct thread *cur = thread_current ();
  printf ("%s: exit(%d)\n", cur->name, status);
  cur->process_ptr->exit_code = status;

  int i;

  file_close (cur->process_ptr->file_exec);
  for (i = 2; i < OPEN_MAX; i++)
  {
    if(cur->process_ptr->fd_table[i].in_use)
    {
      file_close (cur->process_ptr->fd_table[i].file);
      remove_fd (cur->process_ptr, i);
    }
  }
  for (i = 0; i < cur->next_mid; ++i){
    sys_munmap(i);
  }
  vm_destroy(&cur->vm);
  sema_up (&(cur->process_ptr->exit_code_sema));
  thread_exit ();
  NOT_REACHED ();
}

static int
sys_wait (pid_t pid)
{
  struct thread *cur = thread_current ();
  struct list* children = &cur->process_ptr->children;

  /* find pid process in children */
  for (struct list_elem *e = list_begin (children); e != list_end (children); 
    e = list_next (e))
  {
    struct process *p = list_entry (e, struct process, elem);
    if (p->pid == pid)
    {
      /* Wait for child exit */
      sema_down (&p->exit_code_sema);
      list_remove (e);
      int exit_code = p->exit_code;
      palloc_free_page (p);
      return exit_code;
    }
  }
  return -1;
}

static bool
sys_create (const char *file, unsigned initial_size)
{
  if (file == NULL || !check_ptr_in_user_space (file))
    sys_exit (-1);
  file_lock_acquire ();
  bool res = filesys_create (file, initial_size);
  file_lock_release ();
  return res;
}

static bool
sys_remove(const char *file)
{
  if(file == NULL || !check_ptr_in_user_space(file))
    sys_exit(-1);
  file_lock_acquire();
  bool res = filesys_remove(file);
  file_lock_release();
  return res;
}

static int
sys_open(const char *file)
{
  if(file == NULL || !check_ptr_in_user_space(file))
    sys_exit(-1);
  
  /* Whole section is critical section due to open-twice test */
  file_lock_acquire();
  struct process *cur = thread_current()->process_ptr;

  int fd = get_available_fd(cur);
  if(fd == -1)
  {
    file_lock_release();
    return -1;
  }

  struct file *target_file = filesys_open(file);
  if(target_file == NULL)
  {
    file_lock_release();
    return -1;
  }

  /* Should verify the return value but seems okay now */
  set_fd(cur, fd, target_file);

  file_lock_release();
  return fd;
}

static int
sys_filesize(int fd)
{
  if(!(0 <= fd && fd < OPEN_MAX))
    return -1;
  
  struct process *cur = thread_current()->process_ptr;

  struct fd_table_entry *fd_entry = &(cur->fd_table[fd]);
  if(!(fd_entry->in_use && 
       fd_entry->type == FILETYPE_FILE && 
       fd_entry->file != NULL))
       return -1;
  
  file_lock_acquire();
  int res = file_length(fd_entry->file);
  file_lock_release();

  return res;
}

static int
sys_read(int fd, void *buffer, unsigned size)
{
  if(!check_ptr_in_user_space(buffer))
    sys_exit(-1);
  if(!(0 <= fd && fd < OPEN_MAX))
    return -1;
  
  struct process *cur = thread_current()->process_ptr;

  if(!cur->fd_table[fd].in_use)
    return -1;
  
  int file_type = cur->fd_table[fd].type;
  if(file_type == FILETYPE_STDIN)
  {
    void *cur_pos = buffer;
    unsigned write_count = 0;
    while(write_count < size)
    {
      if(!check_ptr_in_user_space(cur_pos))
        sys_exit(-1);
      uint8_t c = input_getc();
      if(!put_user((uint8_t *)cur_pos, c))
        sys_exit(-1);
      write_count++;
      cur_pos++;
    }
    return write_count;
  } 
  else if(file_type == FILETYPE_STDOUT)
  {
    /* Actually it also works same as STDIN in LINUX */
    sys_exit(-1);
  }
  else
  {
    file_lock_acquire();
    int res = file_read(cur->fd_table[fd].file, buffer, size);
    file_lock_release();
    return res;
  }
}

static int
sys_write(int fd, const void *buffer, unsigned size)
{
  if(!check_ptr_in_user_space(buffer))
    sys_exit(-1);
  if(!(0 <= fd && fd < OPEN_MAX))
    return -1;
  
  struct process *cur = thread_current()->process_ptr;

  if(!cur->fd_table[fd].in_use)
    return -1;
  
  int file_type = cur->fd_table[fd].type;
  if(file_type == FILETYPE_STDIN)
  {
    /* Actually it also works same as STDOUT in LINUX */
    sys_exit(-1);
  } 
  else if(file_type == FILETYPE_STDOUT)
  {
    putbuf(buffer, size);
    return size;
  }
  else
  {
    file_lock_acquire();
    int res = file_write(cur->fd_table[fd].file, buffer, size);
    file_lock_release();
    return res;
  }
}

static void
sys_seek(int fd, unsigned position)
{
  if(!(0 <= fd && fd < OPEN_MAX))
    return;
  
  struct process *cur = thread_current()->process_ptr;

  struct fd_table_entry *fd_entry = &(cur->fd_table[fd]);
  if(!(fd_entry->in_use && 
       fd_entry->type == FILETYPE_FILE && 
       fd_entry->file != NULL))
       return;
  
  file_lock_acquire();
  file_seek(fd_entry->file, position);
  file_lock_release();
}

static unsigned
sys_tell(int fd)
{
  if(!(0 <= fd && fd < OPEN_MAX))
    return -1;
  
  struct process *cur = thread_current()->process_ptr;

  struct fd_table_entry *fd_entry = &(cur->fd_table[fd]);
  if(!(fd_entry->in_use && 
       fd_entry->type == FILETYPE_FILE && 
       fd_entry->file != NULL))
       return -1;
  
  file_lock_acquire();
  unsigned res = file_tell(fd_entry->file);
  file_lock_release();

  return res;
}

static void
sys_close(int fd)
{
  if(!(0 <= fd && fd < OPEN_MAX))
    return;
  
  struct process *cur = thread_current()->process_ptr;

  struct fd_table_entry *fd_entry = &(cur->fd_table[fd]);
  if(fd_entry->in_use && 
     fd_entry->type == FILETYPE_FILE && 
     fd_entry->file != NULL)
  {
    file_lock_acquire();
    file_close(fd_entry->file);
    file_lock_release();
  }

  remove_fd(cur, fd);
}

// static mapid_t 
// sys_mmap(int fd, void* addr)
// {
//   mapid_t mid;
//   int bytes_remain;
//   size_t offset = 0;
  
//   struct mmap_elem *me;
//   struct file *file;
//   struct thread *cur = thread_current();
//   struct process *p = cur->process_ptr;

// 	me = (struct mmap_elem *)malloc(sizeof(struct mmap_elem));
//   if (!me) 
//     return -1;

//   file_lock_acquire();
//   file = file_reopen(p->fd_table[fd].file);
//   bytes_remain = file_length(file);
//   file_lock_release();

//   if (bytes_remain == 0){
//     free(me);
//     return -1;
//   }

//   mid = cur->next_mid++;
// 	init_me(me, file, mid);
  
// 	while(bytes_remain > 0) {
//     if (vme_find(addr)) 
//       return -1;

//     size_t page_read_bytes = bytes_remain < PGSIZE ? bytes_remain : PGSIZE;
//     size_t page_zero_bytes = PGSIZE - page_read_bytes;

//     struct vm_entry* vme = (struct vm_entry*)malloc(sizeof(struct vm_entry));
//     if (vme == NULL) 
//       return false;

//     init_vme(vme, PAGE_MMAP, addr, true, false, file, offset, page_read_bytes, page_zero_bytes);

//     list_push_back(&me->vmes, &vme->mmap_elem);
//     vme_insert(&cur->vm, vme);
		
//     addr += PGSIZE;
//     offset += PGSIZE;
//     bytes_remain -= PGSIZE;
// 	}

//   list_push_back(&cur->mmap_list, &me->elem);
// 	return me->mid;
// }

// static void 
// sys_munmap (mapid_t mid)
// {
// 	struct mmap_elem *me = me_find(mid);
//   if(me == NULL) return;

//   struct thread *cur = thread_current();
//   struct list_elem *it = list_begin(&me->vmes);
//   struct list_elem *end = list_end(&me->vmes);

// 	for (it; it != end;) {
//     struct vm_entry *vme = list_entry(it, struct vm_entry, mmap_elem);
//     bool is_dirty = pagedir_is_dirty(cur->pagedir, vme->vaddr);

//     if(vme->is_on_memory && is_dirty) {
//       file_lock_acquire();
//       file_write_at(vme->file, vme->vaddr, vme->read_bytes, vme->offset);
//       file_lock_release();

//       frame_lock_acquire();
//       free_frame(pagedir_get_page(cur->pagedir, vme->vaddr));
//       frame_lock_release();
//     }

//     vme->is_on_memory = false;
//     vme_delete(&cur->vm, vme);
//     it = list_remove(it);
//   }

//   list_remove(&me->elem);
//   free(me); 
// }

// modified for lab3
mapid_t sys_mmap(int fd, void* addr)
{
  if(is_kernel_vaddr(addr))
    sys_exit(-1);
  // addr이 0인 경우, addr이 page 정렬되지 않은 경우
  if(!addr || pg_ofs(addr) != 0 || (int)addr%PGSIZE !=0)
    return -1;

  // for vm_entry
  int file_remained;
  size_t offset = 0;

  struct process *cur = thread_current()->process_ptr;

  // 1. mmap_file 구조체 생성 및 메모리 할당
	struct mmap_file *mfe = (struct mmap_file *)malloc(sizeof(struct mmap_file));
  if (!mfe) return -1;   
	memset(mfe, 0, sizeof(struct mmap_file));

	// 2. file open
  file_lock_acquire();
  struct file* file = file_reopen(cur->fd_table[fd].file);
  file_remained = file_length(file);
  file_lock_release();
  // fd로 열린 파일의 길이가 0바이트인 경우
  if (!file_remained) 
  {
    return -1;
  }


	// 3. vm_entry 할당
	list_init(&mfe->vme_list);	
  
	while(file_remained > 0)// file 다 읽을 때 까지 반복
	{
		// vm entry 할당
    if (vme_find(addr)) return -1;

    size_t page_read_bytes = file_remained < PGSIZE ? file_remained : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    struct vm_entry* vme = vme_construct(VM_FILE, addr, true, false, file, offset, page_read_bytes, page_zero_bytes);
    if (!vme) 
      return false;

		// 2. vme_list에 mmap_elem과 연결된 vm entry 추가
    list_push_back(&mfe->vme_list, &vme->mmap_elem);
		// 3. current thread에 대해 vme insert
    vme_insert(&thread_current()->vm, vme);
		
    // 4. file addr, offset 업데이트 (page size만큼)
    addr += PGSIZE;
    offset += PGSIZE;
		// 5. file에 남은 길이 업데이트 (page size만큼)
    file_remained -= PGSIZE;
	}

  // 4. mmap_list, mmap_next 관리
  mfe->mapid = thread_current()->next_mid++;
  list_push_back(&thread_current()->mmap_list, &mfe->elem);
  mfe->file = file;
	return mfe->mapid;
}


void sys_munmap(mapid_t mapid)
{
  // 1. thread의 mmap_list에서 mapid에 해당하는 mfe 찾기
	struct mmap_file *mfe = NULL;
  struct list_elem *e;
  for (e = list_begin(&thread_current()->mmap_list); e != list_end(&thread_current()->mmap_list); e = list_next(e))
  {
    mfe = list_entry (e, struct mmap_file, elem);
    if (mfe->mapid == mapid) break;
  }
  if(mfe == NULL) return;

	// 2. 해당 mfe의 vme_list를 돌면서 vme를 지우기
	for (e = list_begin(&mfe->vme_list); e != list_end(&mfe->vme_list);)
  {
    struct vm_entry *vme = list_entry(e, struct vm_entry, mmap_elem);
    if(vme->is_loaded && (pagedir_is_dirty(thread_current()->pagedir, vme->vaddr)))
    {
      file_lock_acquire();
      file_write_at(vme->file, vme->vaddr, vme->read_bytes, vme->offset);
      file_lock_release();

      frame_lock_acquire();
      free_frame(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
      frame_lock_release();
    }
    vme->is_loaded = false;
    e = list_remove(e);
    vme_delete(&thread_current()->vm, vme);
  }
	// 4. mfe를 mmap_list에서 제거
  list_remove(&mfe->elem);
  // 5. mfe 구조체 자체를 free
  free(mfe); 
}