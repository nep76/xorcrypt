#ifndef SEED_XOR_H
#define SEED_XOR_H

#include "xorcrypt.h"

int seed_xor( struct XncContext *xnc, FILE *src, off_t src_size, FILE *dst );

#endif
