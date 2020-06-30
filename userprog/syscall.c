#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"


struct aux_file
  {
    struct list_elem elem;
    int fd;
    struct file *file;
  };

static void syscall_handler (struct intr_frame *f);

static uint32_t get_stack_arguments (struct intr_frame *f, int);
bool is_valid_ptr (void *);
bool is_valid_buffer (void *buffer, size_t length);
bool is_valid_string (const char *str);

void sys_halt (void);
void sys_exit (int status);
pid_t sys_exec (const char *cmd_line);
int sys_wait (pid_t pid);
bool sys_create (const char *name, unsigned int initial_size);
bool sys_remove (const char *file UNUSED);
int sys_open (const char *file UNUSED);
int sys_filesize (int fd UNUSED);
int sys_read (int fd, void *buffer UNUSED, unsigned length UNUSED);
int sys_write (int fd, const void *buffer, unsigned int length);
void sys_seek (int fd UNUSED, unsigned position UNUSED);
unsigned sys_tell (int fd UNUSED);
void sys_close (int fd UNUSED);

bool is_valid_fd (int fd);
struct aux_file *get_file (int fd);

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  if ((uint32_t) uaddr >= (uint32_t) PHYS_BASE)
    return -1;

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));

  return result;
}
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  int code = (int) get_stack_arguments (f, 0);

  switch (code)
    {
      case SYS_HALT:
      {
        sys_halt();
        break;
      }
      case SYS_EXIT:
      {
        int status=(int) get_stack_arguments (f, 1);
        sys_exit (status);
        break;
      }
      case SYS_EXEC:
      {
        const char * cmd_line=(const char *) get_stack_arguments (f, 1);
        f->eax = sys_exec (cmd_line);
        break;
      }
      case SYS_WAIT:
      {
        pid_t pid = (pid_t) get_stack_arguments (f, 1);
        f->eax = sys_wait (pid);
        break;
      }
      case SYS_CREATE:
      {
        const char * name= (const char *) get_stack_arguments (f, 1);
        unsigned int initial_size=(unsigned int) get_stack_arguments (f, 2);
        f->eax = sys_create (name,initial_size);
        break;
      }
      case SYS_REMOVE:
      {
        const char * file = (const char *) get_stack_arguments (f, 1);
        f->eax = sys_remove (file);
        break;
      }
      case SYS_OPEN:
      {
        const char * file = (const char *) get_stack_arguments (f, 1);
        f->eax = sys_open (file);
        break;
      }
      case SYS_FILESIZE:
      {
        int fd=(int) get_stack_arguments (f, 1);
        f->eax = sys_filesize (fd);
        break;
      }
      case SYS_READ:
      {
        int fd=(int) get_stack_arguments (f, 1);
        void * buffer = (void *) get_stack_arguments (f, 2);
        unsigned length=(unsigned int) get_stack_arguments (f, 3);
        f->eax = sys_read (fd,buffer,length);
        break;
      }
      case SYS_WRITE:
      {
        int fd=(int) get_stack_arguments (f, 1);
        void * buffer = (void *) get_stack_arguments (f, 2);
        unsigned length=(unsigned int) get_stack_arguments (f, 3);
        f->eax = sys_write (fd,buffer,length);
        break;
      }
      case SYS_SEEK:
      {
        int fd=(int) get_stack_arguments (f, 1);
        unsigned position=(unsigned) get_stack_arguments (f, 2);
        sys_seek (fd,position);
        break;
      }
      case SYS_TELL:
      {
        int fd=*((int *) get_stack_arguments (f, 1));
        f->eax = sys_tell (fd);
        break;
      }
      case SYS_CLOSE:
      {
        int fd=(int) get_stack_arguments (f, 1);
        sys_close (fd);
        break;
      }
      default:
        sys_exit (-1);
        break;
    }
}

static uint32_t
get_stack_arguments (struct intr_frame *f, int offset)
{
  offset=offset*4;
  if (!is_valid_ptr (f->esp + offset))
    sys_exit (-1);

  return *((uint32_t *) (f->esp + offset));
}

bool
is_valid_ptr (void *vaddr)
{
  if (get_user ((uint8_t *) vaddr) == -1)
    return false;

  return true;
}

bool
is_valid_buffer (void *buffer, size_t length)
{
  size_t i;
  char *buf = (char *) buffer;

  for (i = 0; i < length; i++)
    {
      if (!is_valid_ptr (buf + i))
        return false;
    }

  return true;
}

bool
is_valid_string (const char *str)
{
  int c;
  size_t i = 0;

  while (1)
    {
      c = get_user((uint8_t *) (str + i));

      if (c == -1)
        return false;

      if (c == '\0')
        return true;

      i++;
    }
}

void
sys_halt (void)
{
  shutdown_power_off();
}

void
sys_exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;

  thread_exit ();
}

pid_t
sys_exec (const char *cmd_line)
{
  if (!is_valid_string (cmd_line))
    sys_exit (-1);

  return process_execute(cmd_line);
}

int
sys_wait (pid_t pid)
{
  return process_wait(pid);
}

bool
sys_create (const char *name, unsigned int initial_size)
{
  if (!is_valid_string(name))
    sys_exit (-1);

  bool success;

  success = filesys_create(name, initial_size);

  return success;
}

bool
sys_remove (const char *file)
{
  if (!is_valid_string (file))
    sys_exit (-1);

  bool success;

  success = filesys_remove(file);

  return success;
}

int
sys_open (const char *file)
{
  if (!is_valid_string (file))
    sys_exit (-1);

  int fd = 2;
  struct aux_file *fm;
  struct thread *cur;

  while (fd >= 2 && get_file (fd) != NULL)
    fd++;

  if (fd < 2)
    sys_exit (-1);

  fm = malloc (sizeof (struct aux_file));

  if (fm == NULL)
    return -1;

  fm->fd = fd;
  fm->file = filesys_open (file);

  if (fm->file == NULL)
    {
      free (fm);
      return -1;
    }

  cur = thread_current ();
  list_push_back (&cur->files, &fm->elem);

  return fm->fd;
}

int
sys_filesize (int fd)
{
  struct aux_file *fm = get_file (fd);

  if (fm == NULL)
    return -1;

  return file_length (fm->file);
}

int
sys_read (int fd, void *buffer, unsigned length)
{
  size_t i;
  struct aux_file *fm;

  if (!is_valid_buffer(buffer, length))
    sys_exit (-1);

  if (fd == STDIN_FILENO)
    {
      i = 0;

      while (i++ < length)
        ((char *) buffer)[i] = (char) input_getc ();

      return i;
    }

  fm = get_file (fd);

  if (fm == NULL)
    sys_exit (-1);

  return file_read (fm->file, buffer, length);
}

int
sys_write (int fd, const void *buffer, unsigned int length)
{
  struct aux_file *fm;

  if (!is_valid_buffer ((void *) buffer, length))
    sys_exit (-1);

  if (fd == STDOUT_FILENO)
    {
      putbuf ((const char *) buffer, (size_t) length);
      return length;
    }

  fm = get_file (fd);

  if (fm == NULL)
    sys_exit (-1);

  return file_write (fm->file, buffer, length);
}

void
sys_seek (int fd, unsigned position)
{
  struct aux_file *fm = get_file (fd);

  if (fm == NULL)
    return;

  file_seek (fm->file, position);
}

unsigned
sys_tell (int fd)
{
  struct aux_file *fm = get_file (fd);

  if (fm == NULL)
    return 0;

  return file_tell (fm->file);
}

void
sys_close (int fd)
{
  struct aux_file *fm = get_file (fd);

  if (fm == NULL)
    return;

  file_close (fm->file);
  list_remove (&fm->elem);
  free (fm);
}

bool
is_valid_fd(int fd)
{
  if (fd < 2)
    return false;

  if (get_file (fd) == NULL)
    return false;

  return true;
}

struct aux_file *
get_file(int fd)
{
  struct thread *t = thread_current ();
  struct list_elem *e;
  struct aux_file *fm;

  for (e = list_begin (&t->files); e != list_end (&t->files);
    e = list_next (e))
    {
      fm = list_entry (e, struct aux_file, elem);

      if (fm->fd == fd)
        return fm;
    }

  return NULL;
}

void
close_all_files (struct thread *t)
{
  struct list_elem *e;
  struct aux_file *fm;

  e = list_begin (&t->files);

  while (e != list_end (&t->files))
    {
      fm = list_entry (e, struct aux_file, elem);
      e = list_next (e);

      file_close (fm->file);
      list_remove (&fm->elem);
      free (fm);
    }
}

