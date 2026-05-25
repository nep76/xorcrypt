#ifndef SEMAPHORE_H
#define SEMAPHORE_H

#include <stddef.h>
#include <inttypes.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
struct sema_ctx {
    HANDLE   sema;
    uint32_t free;
};
#else
#include <semaphore.h>
struct sema_ctx {
    sem_t    sema;
    uint32_t free;
};
#endif

typedef struct sema_ctx SemaCtx;

SemaCtx *sema_new( int initial, SemaCtx *reuse );
int sema_post( SemaCtx *c );
int sema_wait( SemaCtx *c );
int sema_trywait( SemaCtx *c );
int sema_timedwait( SemaCtx *c, time_t timeout );
int sema_destroy( SemaCtx *c );

#endif