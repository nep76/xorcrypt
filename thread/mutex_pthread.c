#include "mutex.h"

#include <stdlib.h>
#include <stddef.h>

MutexCtx *mutex_new( MutexCtx *reuse )
{
    MutexCtx *c = reuse ? reuse : malloc( sizeof( *c ) );
    if( c ){
        c->free = reuse ? 0 : 1;
        if( pthread_mutex_init( &c->mutex, NULL ) != 0 ){
            if( c->free ) free( c );
            c = NULL;
        }
    }

    return c;
}

int mutex_lock( MutexCtx *c )
{
    return pthread_mutex_lock( &c->mutex );
}

int mutex_unlock( MutexCtx *c )
{
    return pthread_mutex_unlock( &c->mutex );
}

int mutex_destroy( MutexCtx *c )
{
    int rv = pthread_mutex_destroy( &c->mutex );
    if( rv == 0 && c->free ){
        free( c );
    }
    return rv;
}

