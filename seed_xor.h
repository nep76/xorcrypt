#ifndef SEED_XOR_H
#define SEED_XOR_H

#include "xorcrypt.h"

struct XncSeedXor{
    unsigned char state[XNC_HASH_SIZE];
    uint64_t cnt;
};

struct XncSeedXorMsg{
    uint32_t label_be;
    uint64_t cnt_be;
} __attribute__((packed));

int seed_xor( struct XncContext *xnc, FILE *src, uint64_t src_size, FILE *dst );

#endif
