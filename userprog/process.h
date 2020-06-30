#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

typedef int pid_t;

struct process
  {
    struct list_elem elem;
    pid_t pid;
    bool is_alive;
    bool is_waited;
    int exit_status;
    enum load_status load_status;
    struct semaphore wait;
    struct semaphore load;              
  };

tid_t process_execute (const char *);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */

