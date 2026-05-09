#ifndef SIMPLE_XOR
#define SIMPLE_XOR

#define XNC_HASH_PERMIT_INLINE
#include "xorcrypt.h"

struct XncSimpleXor {
    unsigned char salt[XNC_SALT_SIZE];
    unsigned char hash[XNC_HASH_SIZE];
};

int simple_xor( struct XncContext *xnc, FILE *src, uint64_t src_size, FILE *dst );

#endif
