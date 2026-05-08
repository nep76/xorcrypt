#ifndef HASH_H
#define HASH_H

#include "xorcrypt.h"

#ifdef _WIN32
#include <windows.h>
#endif

void hash_init( struct XncContext *xnc );
void hash_destroy( struct XncContext *xnc );
void _sha256( const unsigned char *msg, DWORD msg_len, unsigned char *key, DWORD key_len, unsigned char *dst, struct XncBCryptPvd *pvd );
#define sha256( p_xnc, msg, len, dst ) _sha256( msg, len, NULL, 0, dst, &((p_xnc)->hash.sha256) )
#define sha256hmac( p_xnc, msg, msg_len, key, key_len, dst ) _sha256( msg, msg_len, key, key_len, dst, &((p_xnc)->hash.hmac_sha256) )

#endif