#define _GNU_SOURCE
#include "thrw.h"

#include <stdlib.h>
#include <pthread.h>

#ifndef __APPLE__
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#endif

static void *thread_start( void *c )
{
    ((ThrwCtx *)c)->fn_main( ((ThrwCtx *)c)->argp );
    return NULL;
}

ThrwCtx *thrw_new( ThrwMain cb, void *argp, ThrwCtx *reuse )
{
    ThrwCtx *c = reuse ? reuse : malloc( sizeof( *c ) );
    if( c ){
        c->fn_main = cb;
        c->argp    = argp;
        c->free    = reuse ? 0 : 1;

        if( pthread_create( &(c->pthr), NULL, thread_start, c ) != 0 ){
            if( c->free )free( c );
            c = NULL;
        }
    }

    return c;
}

int thrw_wait_for_exit( ThrwCtx *c )
{
    return pthread_join( c->pthr, NULL );;
}

int thrw_destroy( ThrwCtx *c )
{
    if( c->free ) free( c );
    return 0;
}

int thrw_set_background_self( void )
{
#if defined(__APPLE__)
    return pthread_set_qos_class_self_np( QOS_CLASS_BACKGROUND, 0 );
#else
    pid_t thid = syscall( SYS_gettid );
    return syscall( SYS_ioprio_set, 1, thid, (((2) << 13) | (7)) );
#endif
}

int thrw_set_foreground_self( void )
{
#if defined(__APPLE__)
    return pthread_set_qos_class_self_np( QOS_CLASS_USER_INITIATED, 0 );
#else
    pid_t thid = syscall( SYS_gettid );
    return syscall( SYS_ioprio_set, 1, thid, (((2) << 13) | (4)) );
#endif
}
