#include "info.h"

void _info( FILE *stream, const char *format, ... )
{
    va_list ap;
    va_start( ap, format );
    vfprintf( stream, format, ap );
    va_end( ap );
    fputc( '\n', stream );
}

void _dumpbin( const char *label, const char *fmt, const unsigned char *bytes, size_t len )
{
    if( label ) printf( "%s: ", label );
    for( int i = 0; i < len; i++ ){
        if( i % 0x10 == 0 ) printf( "\n  " );
        printf( fmt, bytes[i] );
    }
    fputc( '\n' ,stdout );
}
