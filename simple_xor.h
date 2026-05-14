#ifndef SIMPLE_XOR
#define SIMPLE_XOR

#include "xorcrypt.h"

int simple_xor( struct XncContext *xnc, FILE *src, off_t src_size, FILE *dst );

#endif
