#ifndef HASH_H
#define HASH_H

#include "xorcrypt.h"
#include <stddef.h>

struct XncHash;

void hash_init( struct XncContext *xnc );
void hash_destroy( struct XncContext *xnc );
void hash_sha256( struct XncContext *xnc, const unsigned char *msg, size_t len, unsigned char *dst );
void hash_sha256hmac( struct XncContext *xnc, const unsigned char *msg, size_t msg_len, unsigned char *key, size_t key_len, unsigned char *dst );

#ifdef _WIN32
size_t hash_get_sha256_workspace_size( struct XncContext *xnc );
size_t hash_get_sha256hmac_workspace_size( struct XncContext *xnc );
void hash_sha256_ready( struct XncContext *xnc, void *sha_work, void *hmac_work );
#endif

#endif
