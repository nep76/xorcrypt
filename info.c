#include "info.h"

#include <stdarg.h>

int qinfo( RqueueCtx *c, info_fn_rqueue_push fn_push, const char *fmt, ... )
{
    char buf[XNC_ERRBUF_SIZE];
    int pos;
    va_list ap;
    va_start( ap, fmt );
    pos = vsnprintf( buf, sizeof( buf ), fmt, ap );
    va_end( ap );

    if( pos < 0 ){
        return -1;
    } else if( (size_t)pos >= sizeof( buf ) ){
        pos = sizeof( buf ) - 2;
    }

    buf[pos++] = '\n';
    buf[pos++] = '\0';

    return fn_push( c, buf, pos );
}

void _info( FILE *stream, const char *fmt, ... )
{
    va_list ap;
    va_start( ap, fmt );
    vfprintf( stream, fmt, ap );
    va_end( ap );
    fputc( '\n', stream );
}

void _dumpbin( const char *label, const char *fmt, const unsigned char *bytes, size_t len )
{
    if( label ) printf( "%s: ", label );
    for( size_t i = 0; i < len; i++ ){
        if( i % 0x10 == 0 ) printf( "\n  " );
        printf( fmt, bytes[i] );
    }
    fputc( '\n' ,stdout );
}
