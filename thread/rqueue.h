#ifndef RQUEUE_H
#define RQUEUE_H

#include "mutex.h"
#include "sema.h"

#include <time.h>
#include <inttypes.h>

typedef struct rqueue_ctx RqueueCtx;

RqueueCtx *rqueue_new( size_t size, int cnt );
int rqueue_push( RqueueCtx *c, void *data, size_t size );
int rqueue_try_push( RqueueCtx *c, void *data, size_t size );
int rqueue_pop( RqueueCtx *c, void *data, size_t size );
int rqueue_try_pop( RqueueCtx *c, void *data, size_t size );
int rqueue_timed_pop( RqueueCtx *c, void *data, size_t size, time_t timeout_ms );
void rqueue_destroy( RqueueCtx *c );

#endif
