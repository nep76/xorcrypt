#ifndef MUTEX_H
#define MUTEX_H

#include <inttypes.h>

#ifdef _WIN32
#include <windows.h>
struct mutex_ctx {
    HANDLE mutex;
    uint32_t free;
};
#else
#include <pthread.h>
struct mutex_ctx {
    pthread_mutex_t mutex;
    uint32_t free;
};
#endif

typedef struct mutex_ctx MutexCtx;

MutexCtx *mutex_new( MutexCtx *reuse );
int mutex_lock( MutexCtx *c );
int mutex_unlock( MutexCtx *c );
int mutex_destroy( MutexCtx *c );
void mutex_free_ctx( MutexCtx *c );

#endif