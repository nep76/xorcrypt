#ifndef SIMPLE_XOR
#define SIMPLE_XOR

#include "xorcrypt.h"

int simple_xor_init( const struct Xnc *xnc, struct XncJob *job );
int simple_xor_finish( const struct Xnc *xnc, struct XncJob *job );
int simple_xor_work( struct XncHash *hs, unsigned char * restrict buf, size_t blocks, XncAlgoCtx ctx );

#endif
