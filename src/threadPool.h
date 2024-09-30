#include <pthread.h>

#ifndef BB_THREAD_POOL
#define BB_THREAD_POOL

#define BB_MAX_THREADS 16
#define BB_MAX_TASKS   1000

struct task {
    void (*function)(void *);
    void *argument;
};

struct thread_pool {
    pthread_t       threads [BB_MAX_THREADS];
    struct task          tasks   [BB_MAX_TASKS];
    pthread_mutex_t lock;
    pthread_cond_t  notify;
    int             task_count;
    int             task_head;
    int             task_tail;
    int             shutdown;
};

int  createThreadPool    (struct thread_pool **pool);
void addTaskToThreadPool (struct thread_pool *pool, 
                          void (*function)(void *), 
                          void *argument);
void destroyThreadPool   (struct thread_pool **pool); 


#endif
