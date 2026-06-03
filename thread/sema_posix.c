#include "sema.h"

#include <stdlib.h>

SemaCtx *sema_new( int initial, SemaCtx *reuse )
{
    SemaCtx *c = reuse ? reuse : malloc( sizeof( *c ) );
    if( c ){
        c->free = reuse ? 0 : 1;
        
        if( sem_init( &c->sema, 0, initial ) != 0 ){
            if( c->free ) free( c );
            c = NULL;
        }
    }
    
    return c;
}

int sema_post( SemaCtx *c )
{
    return sem_post( &c->sema );
}

int sema_wait( SemaCtx *c )
{
    return sem_wait( &c->sema );
}

int sema_trywait( SemaCtx *c )
{
    return sem_trywait( &c->sema );
}

int sema_timedwait( SemaCtx *c, time_t timeout )
{
    struct timespec ts;

    if( timeout == 0 ) return sem_trywait( c );

    if( clock_gettime( CLOCK_REALTIME, &ts ) != 0 ) return -1;

    ts.tv_sec  += timeout / 1000;
    ts.tv_nsec += ( timeout % 1000 ) * 1000000;
    // ナノ秒が10億以上なら秒に繰り上げ
    if( ts.tv_nsec >= 1000000000 ){
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000;
    }

    return sem_timedwait( &c->sema, &ts );
}

int sema_destroy( SemaCtx *c )
{
    int rv = sem_destroy( &c->sema );
    if( rv == 0 && c->free ){
        free( c );
    }
    return rv;
}
