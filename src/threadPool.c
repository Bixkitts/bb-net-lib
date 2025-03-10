#include "threadPool.h"
#include <stdio.h>
#include <stdlib.h>

static void *execute_task(void *arg);

struct thread_pool *create_thread_pool()
{
    struct thread_pool *pool = calloc(1, sizeof(struct thread_pool));
    if (!pool) {
        return NULL;
    }

    pthread_mutex_init(&pool->lock, NULL);
    pthread_cond_init(&pool->notify, NULL);
    pool->task_count = 0;
    pool->task_head  = 0;
    pool->task_tail  = 0;
    pool->shutdown   = 0;

    for (int i = 0; i < BB_MAX_THREADS; i++) {
        pthread_create(&pool->threads[i], NULL, execute_task, pool);
    }
    return pool;
}

// Execute the task
static void *execute_task(void *arg)
{
    struct thread_pool *pool = (struct thread_pool *)arg;

    while (1) {
        pthread_mutex_lock(&pool->lock);

        while (pool->task_count == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->notify, &pool->lock);
        }

        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->lock);
            pthread_exit(NULL);
        }

        struct task task = pool->tasks[pool->task_head];
        pool->task_head  = (pool->task_head + 1) % BB_MAX_TASKS;
        pool->task_count--;

        pthread_mutex_unlock(&pool->lock);

        // Execute the task
        task.function(task.argument);
    }

    return NULL;
}

// Add a task to the thread pool
void add_task_to_thread_pool(struct thread_pool *pool,
                             void (*function)(void *),
                             void *argument)
{
    pthread_mutex_lock(&pool->lock);

    if (pool->task_count == BB_MAX_TASKS) {
        fprintf(stderr, "Task queue is full!\n");
        pthread_mutex_unlock(&pool->lock);
        return;
    }

    pool->tasks[pool->task_tail].function = function;
    pool->tasks[pool->task_tail].argument = argument;

    pool->task_tail = (pool->task_tail + 1) % BB_MAX_TASKS;
    pool->task_count++;

    pthread_cond_signal(&pool->notify);
    pthread_mutex_unlock(&pool->lock);
}

// Shutdown the thread pool
void destroy_thread_pool(struct thread_pool **pool)
{
    if ((*pool) == NULL) {
        return;
    }
    pthread_mutex_lock(&(*pool)->lock);
    (*pool)->shutdown = 1;
    pthread_mutex_unlock(&(*pool)->lock);
    pthread_cond_broadcast(&(*pool)->notify);

    for (int i = 0; i < BB_MAX_THREADS; i++) {
        pthread_join((*pool)->threads[i], NULL);
    }

    pthread_mutex_destroy(&(*pool)->lock);
    pthread_cond_destroy(&(*pool)->notify);
    free(*pool);
    *pool = NULL;
}
