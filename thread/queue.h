#ifndef QUEUE_H
#define QUEUE_H

#include "mutex.h"
#include "sema.h"

#include <time.h>
#include <inttypes.h>

typedef struct queue_ctx QueueCtx;

QueueCtx *queue_new( int capacity );
int queue_push( QueueCtx *c, void *data, size_t size );
int queue_try_push( QueueCtx *c, void *data, size_t size );
void *queue_pop( QueueCtx *c );
void *queue_try_pop( QueueCtx *c );
void *queue_timed_pop( QueueCtx *c, time_t timeout_ms );
void queue_giveback( void *data );
void queue_destroy( QueueCtx *c );

#endif