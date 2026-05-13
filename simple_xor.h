#ifndef SIMPLE_XOR
#define SIMPLE_XOR

#include "xorcrypt.h"

struct XncSimpleXor {
    unsigned char salt[XNC_SALT_SIZE];
    unsigned char hash[XNC_HASH_SIZE];
};

int simple_xor( struct XncContext *xnc, FILE *src, off_t src_size, FILE *dst );

#endif
