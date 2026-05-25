#ifndef THRW_H
#define THRW_H

#include <inttypes.h>

typedef int (*ThrwMain)( void* );

#ifdef _WIN32
#include <windows.h>
typedef struct thrw_ctx {
    uint32_t     free;
    HANDLE       handle;
    unsigned int thrw_id;
    ThrwMain     fn_main;
    void         *argp;
} ThrwCtx;
#else
#include <pthread.h>
typedef struct thrw_ctx {
    uint32_t free;
    pthread_t pthr;
    ThrwMain fn_main;
    void     *argp;
} ThrwCtx;
#endif

ThrwCtx *thrw_new( ThrwMain cb, void *argp, ThrwCtx *reuse );
int thrw_wait_for_exit( ThrwCtx *c );
int thrw_destroy( ThrwCtx *c );

#endif