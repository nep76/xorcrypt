#include "simple_xor.h"

static int _algo_simple_xor( struct XncContext *xnc, unsigned char *restrict buf, size_t blocks, void *ctx )
{
    struct XncSimpleXor *c = (struct XncSimpleXor *)ctx;

    for( size_t i = 0; i < blocks; i++ ){
        for( int j = 0; j < sizeof( c->hash ); j++ ){
            buf[j] ^= c->hash[j];
        }
        buf += sizeof( c->hash );
    }

    return 1;
}

int simple_xor( struct XncContext *xnc, FILE *src, uint64_t src_size, FILE *dst )
{
    struct XncAlgoParams p;
    struct XncSimpleXor c;
    unsigned char hash[XNC_HASH_SIZE];

    p.fn_xor = _algo_simple_xor;
    p.ctx = &c;

    switch( xnc->mode ){
        case XNC_ENCODE:
            keygen( c.salt, sizeof( c.salt ) );
            sha256( xnc, c.salt, sizeof( c.salt ), hash );
            break;
        case XNC_DECODE:
            fseek64( src, -( sizeof( hash ) ), SEEK_END );
            fread( hash, sizeof( char ), sizeof( hash ), src );
            src_size -= sizeof( hash );
            break;
        default:
            return 0;
    }

    // パスワードが設定されている場合はキーとパスワードを合わせて
    // もう一度ハッシュ化したものを最終的なキーにする
    if( xnc->passwd ){
        size_t pass_len = strlen( xnc->passwd );

        struct {
            char hash[XNC_HASH_SIZE];
            char passwd[XNC_MAX_PASSWD];
        } __attribute__((packed)) seed;

        memcpy( (void *)seed.hash, hash, sizeof( seed.hash ) );
        memcpy( (void *)seed.passwd, xnc->passwd, pass_len );
        sha256( xnc, (unsigned char *)&seed, sizeof( seed.hash ) + pass_len, c.hash );
    } else{
        memcpy( c.hash, hash, sizeof( hash ) );
    }

    dumphash( xnc, "Hash", (unsigned char *)c.hash, sizeof( c.hash ) );
    
    // 変換
    xor_conv( xnc, src, src_size, dst, &p );

    if( xnc->mode == XNC_ENCODE ){
        info( xnc, "Added decode key.");
        fwrite( hash, sizeof( char ), sizeof( hash ), dst );
    }

    return 1;
}
