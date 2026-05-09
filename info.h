#ifndef INFO_H
#define INFO_H

#include "xorcrypt.h"

void _info( FILE *stream, const char *format, ... );
void _dumpbin( const char *label, const char *fmt, const unsigned char *bytes, size_t len );
#define info( p_xnc, msg )                  if( (p_xnc)->flags & XNC_F_VERBOSE ){ _info( stdout, msg ); }
#define infof( p_xnc, fmt, ... )            if( (p_xnc)->flags & XNC_F_VERBOSE ){ _info( stdout, fmt, __VA_ARGS__ ); }
#define einfo( msg )                        _info( stderr, msg )
#define einfof( fmt, ... )                  _info( stderr, fmt, __VA_ARGS__ )
#define info_dumphex( p_xnc, label, hash, len )  if( (p_xnc)->flags & XNC_F_VERBOSE ){ _dumpbin( label, "%02x ", hash, len ); }

#endif