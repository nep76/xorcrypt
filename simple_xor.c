#include "simple_xor.h"

#include <string.h>

static int algo_simple_xor( struct XncContext *xnc, unsigned char *restrict buf, size_t blocks, void *ctx )
{
    struct XncSimpleXor *c = (struct XncSimpleXor *)ctx;

    UNUSED( xnc );

    for( size_t i = 0; i < blocks; i++ ){
        for( size_t j = 0; j < sizeof( c->hash ); j++ ){
            buf[j] ^= c->hash[j];
        }
        buf += sizeof( c->hash );
    }

    return 1;
}

int simple_xor( struct XncContext *xnc, FILE *src, off_t src_size, FILE *dst )
{
    struct XncAlgoParams p;
    struct XncSimpleXor  c;
    unsigned char salt[XNC_SALT_SIZE];
    int rv;
    
    p.xor = algo_simple_xor;
    p.ctx = &c;

    switch( xnc->mode ){
        case XNC_ENCODE:
            xnc_create_salt( xnc, salt, sizeof( salt ) );
            break;
        case XNC_DECODE:
            src_size -= xnc_read_salt( salt, sizeof( salt ), src ) * sizeof( salt );
            break;
    }

    // パスワードが設定されている場合はキーとパスワードを合わせて
    // もう一度ハッシュ化したものを最終的なキーにする
    if( xnc->passwd.string ){
        struct {
            char   salt[XNC_SALT_SIZE];
            char passwd[XNC_MAX_PASSWD];
        } __attribute__((packed)) seed;

        memcpy( (void *)seed.salt, salt, sizeof( salt ) );
        memcpy( (void *)seed.passwd, xnc->passwd.string, xnc->passwd.length );
        hash_sha256( xnc, (unsigned char *)&seed, sizeof( seed.salt ) + xnc->passwd.length, c.hash );
    } else{
        memcpy( c.hash, salt, sizeof( salt ) );
    }

    info_dumphex( xnc, "Salt", (unsigned char *)c.hash, sizeof( c.hash ) );
    
    // 変換
    rv = xnc_xor_conv( xnc, src, src_size, dst, &p );

    if( rv == 0 && xnc->mode == XNC_ENCODE ){
        xnc_write_salt( salt, sizeof( salt ), dst );
    }

    return rv;
}
