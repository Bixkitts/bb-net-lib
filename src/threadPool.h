#ifndef BB_THREAD_POOL
#define BB_THREAD_POOL

#define BB_MAX_THREADS 16
#define BB_MAX_TASKS   1000

typedef struct threadPool_T *threadPool;

void initThreadPool      (threadPool pool);
void addTaskToThreadPool (threadPool pool, 
                          void (*function)(void *), 
                          void *argument);
void destroyThreadPool   (threadPool pool); 


#endif
