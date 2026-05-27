#include "rqueue.h"

#include <limits.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

RqueueCtx *rqueue_new( size_t size, int cnt )
{
    RqueueCtx *c = malloc( sizeof( *c ) );
    SemaCtx   *s = malloc( sizeof( *s ) * 2 );
    MutexCtx  *m = malloc( sizeof( *m ) );

    if( 
        size <= 0 || cnt <= 0 ||
        ! c || ! s || ! m ||
        ! sema_new( 0, s ) || ! sema_new( cnt, s + 1 ) || ! mutex_new( m )
    ) goto FAIL;

    c->items = s;
    c->slots = s + 1;
    c->mutex = m;

    c->off_pop  = 0;
    c->off_push = 0;

    c->chunk_size = ( size + 7 ) & ~7;
    c->max_chunks = cnt;

    c->buf = malloc( c->chunk_size * c->max_chunks );
    if( ! c->buf ) goto FAIL;

    return c;

    FAIL:
        if( c ) free( c );
        if( s ) free( s );
        if( m ) free( m );
        return NULL;
}

static int _rqueue_push( RqueueCtx *c, void *data, size_t size )
{
    mutex_lock( c->mutex );

    memcpy( c->buf + c->chunk_size * c->off_push, data, size );
    c->off_push = ( c->off_push + 1 ) % c->max_chunks;

    mutex_unlock( c->mutex );
    sema_post( c->items );

    return 0;
}

int rqueue_push( RqueueCtx *c, void *data, size_t size )
{
    if( c->chunk_size < size || sema_wait( c->slots ) != 0 ) return -1;
    return _rqueue_push( c, data, size );
}

int rqueue_try_push( RqueueCtx *c, void *data, size_t size )
{
    if( c->chunk_size < size || sema_trywait( c->slots ) != 0 ) return -1;
    return _rqueue_push( c, data, size );
}

static int _rqueue_pop( RqueueCtx *c, void *data, size_t size )
{
    mutex_lock( c->mutex );

    memcpy( data, c->buf + c->chunk_size * c->off_pop, size );
    c->off_pop = ( c->off_pop + 1 ) % c->max_chunks;

    mutex_unlock( c->mutex );
    sema_post( c->slots );

    return 0;
}

int rqueue_pop( RqueueCtx *c, void *data, size_t size )
{
    if( c->chunk_size < size || sema_wait( c->items )  != 0 ) return -1;
    return _rqueue_pop( c, data, size );
}

int rqueue_try_pop( RqueueCtx *c, void *data, size_t size )
{
    if( c->chunk_size < size || sema_trywait( c->items ) != 0 ) return -1;
    return _rqueue_pop( c, data, size );
}

int rqueue_timed_pop( RqueueCtx *c, void *data, size_t size, time_t timeout_ms )
{
    if( c->chunk_size < size || sema_timedwait( c->items, timeout_ms ) != 0 ) return -1;
    return _rqueue_pop( c, data, size );
}

void rqueue_destroy( RqueueCtx *c )
{
    sema_destroy( c->items );
    sema_destroy( c->slots );
    mutex_destroy( c->mutex );
    free( c->buf );
    free( c->items );
    free( c->mutex );
    free( c );
}
