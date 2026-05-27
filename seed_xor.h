#ifndef SEED_XOR_H
#define SEED_XOR_H

#include "xorcrypt.h"

int seed_xor_init( const struct Xnc *xnc, struct XncJob *job );
int seed_xor_finish( const struct Xnc *xnc, struct XncJob *job );
int seed_xor_work( struct XncHash *hs, unsigned char * restrict buf, size_t blocks, XncAlgoCtx ctx );

#endif
