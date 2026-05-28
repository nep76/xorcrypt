#include "sema.h"

#include <stdlib.h>
#include <winbase.h>
#include <synchapi.h>

SemaCtx *sema_new( int initial, SemaCtx *reuse )
{
    SemaCtx *c = reuse ? reuse : malloc( sizeof( *c ) );
    if( c ){
        c->free = reuse ? 0 : 1;
        
        c->sema = CreateSemaphoreA( NULL, initial, LONG_MAX, NULL );
        if( ! c->sema ){
            if( c->free ) free( c );
            c = NULL;
        }
    }

    return c;
}

int sema_post( SemaCtx *c )
{
    return ReleaseSemaphore( c->sema, 1, NULL ) ? 0 : -1;
}

static inline int _sema_wait( SemaCtx *c, DWORD timeout )
{
    DWORD rv = WaitForSingleObject( c->sema, timeout );
    return ( rv == WAIT_OBJECT_0 ) ? 0 : -1;
}

int sema_wait( SemaCtx *c )
{
    return _sema_wait( c, INFINITE );
}

int sema_trywait( SemaCtx *c )
{
    return _sema_wait( c, 0 );
}

int sema_timedwait( SemaCtx *c, time_t timeout )
{
    return _sema_wait( c, timeout );
}

int sema_destroy( SemaCtx *c )
{
    WINBOOL rv = CloseHandle( c->sema );
    if( rv && c->free ){
        free( c );
    }
    return rv ? 0 : -1;
}
