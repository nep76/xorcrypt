#include "queue.h"

#include <limits.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

struct queue_ctx { 
    SemaCtx  items;
    SemaCtx  slots;
    MutexCtx mutex;

    struct queue_node *head;
    struct queue_node *tail;
};

struct queue_node {
    struct queue_node *next;
};

QueueCtx *queue_new( int capacity )
{
    QueueCtx *c = malloc( sizeof( *c ) );
    if( ! c ) return NULL;

    if(
        ! c ||
        ! sema_new( 0, &c->items )      ||
        ! sema_new( capacity, &c->slots ) ||
        ! mutex_new( &c->mutex )
    ){
        if( c ) free( c );
        return NULL;
    }

    c->head = NULL;
    c->tail = NULL;

    return c;
}

static int _queue_push( QueueCtx *c, void *data, size_t size )
{
    struct queue_node *node;
    
    node = malloc( sizeof( struct queue_node ) + size );
    if( ! node ){
        sema_post( &c->slots );
        return -1;
    }

    node->next = NULL;
    memcpy( ((unsigned char *)node) + sizeof( *node ), data, size );

    mutex_lock( &c->mutex );

    if( c->tail ){
        c->tail->next = node;
        c->tail = node;
    } else{
        c->head = node;
        c->tail = node;
    }

    mutex_unlock( &c->mutex );
    sema_post( &c->items );

    return 0;
}

int queue_push( QueueCtx *c, void *data, size_t size )
{
    if( sema_wait( &c->slots ) != 0 ) return -1;
    return _queue_push( c, data, size );
}

int queue_try_push( QueueCtx *c, void *data, size_t size )
{
    if( sema_trywait( &c->slots ) != 0 ) return -1;
    return _queue_push( c, data, size );
}

static void *_queue_pop( QueueCtx *c )
{
    struct queue_node *node;

    mutex_lock( &c->mutex );

    node = c->head;
    c->head = node->next;
    if( ! c->head ) c->tail = NULL;

    mutex_unlock( &c->mutex );
    sema_post( &c->slots );

    return ( void *)( node + 1 );
}

void *queue_pop( QueueCtx *c )
{
    if( sema_wait( &c->items )  != 0 ) return NULL;
    return _queue_pop( c );
}

void *queue_try_pop( QueueCtx *c )
{
    if( sema_trywait( &c->items ) != 0 ) return NULL;
    return _queue_pop( c );
}

void *queue_timed_pop( QueueCtx *c, time_t timeout_ms )
{
    if( sema_timedwait( &c->items, timeout_ms ) != 0 ) return NULL;
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
    sema_destroy( &c->items );
    sema_destroy( &c->slots );
    mutex_destroy( &c->mutex );
    free( c );
}
