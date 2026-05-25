#ifndef HASH_H
#define HASH_H

struct XncHash;

#include "xorcrypt.h"
#include <stddef.h>

struct XncHash *hash_init();
void hash_destroy( struct XncHash *hash );
void hash_sha256( struct XncHash *hash, const unsigned char *msg, size_t len, unsigned char *dst );
void hash_sha256hmac( struct XncHash *hash, const unsigned char *msg, size_t msg_len, unsigned char *key, size_t key_len, unsigned char *dst );

#endif
