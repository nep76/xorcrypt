#include "thrw.h"

#include <process.h>
#include <handleapi.h>
#include <synchapi.h>

static unsigned int __stdcall thread_start( void *c )
{
    return ((ThrwCtx *)c)->fn_main( ((ThrwCtx *)c)->argp );
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

        c->handle = (HANDLE)_beginthreadex( NULL, 0, thread_start, c, 0, &(c->thrw_id) );
        if( ! c->handle ){
            if( c->free ) free( c );
            c = NULL;
        }
    }

    return c;
}

int thrw_wait_for_exit( ThrwCtx *c )
{
    DWORD rv = WaitForSingleObject( c->handle, INFINITE );
    if( rv != WAIT_FAILED ){
        //GetExitCodeThread( c->handle, &rv );
        rv = 0;
    }
    return (int)rv;
}

int thrw_destroy( ThrwCtx *c )
{
    WINBOOL rv = CloseHandle( c->handle );
    if( rv && c->free ){
        free( c );
    }
    return rv ? 0 : -1;
}

