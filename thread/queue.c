#include "queue.h"

#include <limits.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

struct queue_node {
    struct queue_node *next;
};

static QueueCtx *_ctx_init( QueueCtx *c, SemaCtx *s1, SemaCtx *s2, MutexCtx *m1 )
{
    c->items = s1;
    c->slots = s2;
    c->mutex = m1;

    c->head = NULL;
    c->tail = NULL;

    return c;
}

QueueCtx *queue_new_ex( QueueCtx *c, SemaCtx *items, SemaCtx *slots, MutexCtx *mutex )
{
    c->free = 0;

    return _ctx_init( c, items, slots, mutex );
}

QueueCtx *queue_new( int capacity )
{
    QueueCtx *c = malloc( sizeof( *c ) );
    SemaCtx  *s = malloc( sizeof( *s ) * 2 );
    MutexCtx *m = malloc( sizeof( *m ) );

    if( 
        ! c || ! s || ! m ||
        ! sema_new( 0, s ) || ! sema_new( capacity, s + 1 ) || ! mutex_new( m )
    ){
        if( c ) free( c );
        if( s ) free( s );
        if( m ) free( m );
        return NULL;
    }

    c->free = 1;

    return _ctx_init( c, s, s + 1, m );
}

static int _queue_push( QueueCtx *c, void *data, size_t size )
{
    struct queue_node *node;
    
    node = malloc( sizeof( struct queue_node ) + size );
    if( ! node ){
        sema_post( c->slots );
        return -1;
    }

    node->next = NULL;
    memcpy( ((unsigned char *)node) + sizeof( *node ), data, size );

    mutex_lock( c->mutex );

    if( c->tail ){
        c->tail->next = node;
        c->tail = node;
    } else{
        c->head = node;
        c->tail = node;
    }

    mutex_unlock( c->mutex );
    sema_post( c->items );

    return 0;
}

int queue_push( QueueCtx *c, void *data, size_t size )
{
    if( sema_wait( c->slots ) != 0 ) return -1;
    return _queue_push( c, data, size );
}

int queue_try_push( QueueCtx *c, void *data, size_t size )
{
    if( sema_trywait( c->slots ) != 0 ) return -1;
    return _queue_push( c, data, size );
}

static void *_queue_pop( QueueCtx *c )
{
    struct queue_node *node;

    mutex_lock( c->mutex );

    node = c->head;
    c->head = node->next;
    if( ! c->head ) c->tail = NULL;

    mutex_unlock( c->mutex );
    sema_post( c->slots );

    return ( void *)( node + 1 );
}

void *queue_pop( QueueCtx *c )
{
    if( sema_wait( c->items )  != 0 ) return NULL;
    return _queue_pop( c );
}

void *queue_try_pop( QueueCtx *c )
{
    if( sema_trywait( c->items ) != 0 ) return NULL;
    return _queue_pop( c );
}

void *queue_timed_pop( QueueCtx *c, time_t timeout_ms )
{
    if( sema_timedwait( c->items, timeout_ms ) != 0 ) return NULL;
    return _queue_pop( c );
}

#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O2")))
#endif
void queue_giveback(void *data)
{
    free((struct queue_node *)data - 1);
}

void queue_destroy( QueueCtx *c )
{
    struct queue_node *node = c->head, *next;
    while( node ){
        next = node->next;
        free( node );
        node = next;
    }
    if( c->free ){
        sema_destroy( c->items );
        sema_destroy( c->slots );
        mutex_destroy( c->mutex );
        free( c->items );
        free( c->mutex );
        free( c );
    }
}
