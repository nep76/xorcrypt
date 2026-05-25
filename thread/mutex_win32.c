#include "mutex.h"

#include <stdlib.h>
#include <stddef.h>
#include <synchapi.h>

MutexCtx *mutex_new( MutexCtx *reuse )
{
    MutexCtx *c;

    if( reuse ){
        c = reuse;
    } else{
        c = malloc( sizeof( *c ) );
    }

    if( c ){
        c->free = reuse ? 0 : 1;
        c->mutex = CreateMutexA( NULL, FALSE, NULL );
        if( ! c->mutex ){
            if( c->free ) free( c );
            c = NULL;
        }
    }

    return c;
}

int mutex_lock( MutexCtx *c )
{
    DWORD rv = WaitForSingleObject( c->mutex, INFINITE );

    return ( rv == WAIT_OBJECT_0 || rv == WAIT_ABANDONED ) ? 0 : -1;
}

int mutex_unlock( MutexCtx *c )
{
    return ( ReleaseMutex( c->mutex ) ? 0 : -1 );
}

int mutex_destroy( MutexCtx *c )
{
    WINBOOL rv = CloseHandle( c->mutex );
    if( rv && c->free ){
        free( c );
    }
    return rv ? 0 : -1;
}

