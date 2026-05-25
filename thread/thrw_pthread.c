#include "thrw.h"

#include <stdlib.h>
#include <pthread.h>

static void *thread_start( void *c )
{
    ((ThrwCtx *)c)->fn_main( ((ThrwCtx *)c)->argp );
    return NULL;
}

ThrwCtx *thrw_new( ThrwMain cb, void *argp, ThrwCtx *reuse )
{
    ThrwCtx *c;

    if( ! reuse ){
        c = malloc( sizeof( *c ) );
    } else{
        c = reuse;
    }

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
