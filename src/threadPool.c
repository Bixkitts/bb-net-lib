#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "threadPool.h"

// Task structure
typedef struct {
    void (*function)(void *);
    void *argument;
} task_T;

// Thread pool structure
typedef struct threadPool_T {
    pthread_t       threads [BB_MAX_THREADS];
    task_T          tasks   [BB_MAX_TASKS];
    pthread_mutex_t lock;
    pthread_cond_t  notify;
    int             task_count;
    int             task_head;
    int             task_tail;
    int             shutdown;
} threadPool_T;

static void *executeTask(void *arg);

// Initialize the thread pool
void initThreadPool(threadPool_T *pool) 
{
    pthread_mutex_init (&pool->lock, NULL);
    pthread_cond_init  (&pool->notify, NULL);
    pool->task_count = 0;
    pool->task_head  = 0;
    pool->task_tail  = 0;
    pool->shutdown   = 0;

    for (int i = 0; i < BB_MAX_THREADS; i++) {
        pthread_create(&pool->threads[i], NULL, executeTask, pool);
    }
}

// Execute the task
static void *executeTask(void *arg) 
{
    threadPool_T *pool = (threadPool_T *)arg;

    while (1) {
        pthread_mutex_lock(&pool->lock);

        while (pool->task_count == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->notify, &pool->lock);
        }

        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->lock);
            pthread_exit(NULL);
        }

        task_T task = pool->tasks[pool->task_head];
        pool->task_head = (pool->task_head + 1) % BB_MAX_TASKS;
        pool->task_count--;

        pthread_mutex_unlock(&pool->lock);

        // Execute the task
        task.function(task.argument);
    }

    return NULL;
}

// Add a task to the thread pool
void addTaskToThreadPool(threadPool_T *pool, void (*function)(void *), void *argument) 
{
    pthread_mutex_lock(&pool->lock);

    if (pool->task_count == BB_MAX_TASKS) {
        fprintf              (stderr, "Task queue is full!\n");
        pthread_mutex_unlock (&pool->lock);
        return;
    }

    pool->tasks[pool->task_tail].function = function;
    pool->tasks[pool->task_tail].argument = argument;

    pool->task_tail = (pool->task_tail + 1) % BB_MAX_TASKS;
    pool->task_count++;

    pthread_cond_signal  (&pool->notify);
    pthread_mutex_unlock (&pool->lock);
}

// Shutdown the thread pool
void destroyThreadPool(threadPool_T *pool) 
{
    pthread_mutex_lock     (&pool->lock);
    pool->shutdown = 1;
    pthread_mutex_unlock   (&pool->lock);
    pthread_cond_broadcast (&pool->notify);

    for (int i = 0; i < BB_MAX_THREADS; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    pthread_mutex_destroy (&pool->lock);
    pthread_cond_destroy  (&pool->notify);
}

// Example task function
static void example_task(void *argument) 
{
    int *value = (int *)argument;
    printf("Task executing with argument: %d\n", *value);
}
