#ifndef HASH_H
#define HASH_H

#include "xorcrypt.h"

#ifdef _WIN32

#define XNC_HASH_CONTEXT( xnc )

#include <windows.h>

void hash_init( struct XncContext *xnc );
void hash_destroy( struct XncContext *xnc );
void _hash_sha256( const unsigned char *msg, DWORD msg_len, unsigned char *key, DWORD key_len, unsigned char *dst, struct XncBCryptPvd *pvd );
#define hash_sha256( p_xnc, msg, len, dst ) _hash_sha256( msg, len, NULL, 0, dst, &((p_xnc)->hash.sha256) )
#define hash_sha256hmac( p_xnc, msg, msg_len, key, key_len, dst ) _hash_sha256( msg, msg_len, key, key_len, dst, &((p_xnc)->hash.hmac_sha256) )

#else

#define XNC_HASH_CONTEXT( xnc ) UNUSED( xnc )

#define INLINE
#ifdef XNC_PERMIT_INLINE
#undef INLINE
#define INLINE static inline
#endif

#include <openssl/sha.h>
#include <openssl/hmac.h>

#define hash_init( p_xnc )
#define hash_destroy( p_xnc )
INLINE void _hash_sha256( unsigned char *msg, size_t len, unsigned char *output );
INLINE void _hash_sha256hmac( unsigned char *msg, size_t msg_len, unsigned char *key, size_t key_len, unsigned char *output );
#define hash_sha256( p_xnc, msg, len, dst ) _hash_sha256( msg, len, dst )
#define hash_sha256hmac( p_xnc, msg, msg_len, key, key_len, dst ) _hash_sha256hmac( msg, msg_len, key, key_len, dst )

#endif

#endif