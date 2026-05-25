#include "simple_xor.h"

#include <string.h>

struct XncSimpleXor {
    unsigned char salt[XNC_SALT_SIZE];
    unsigned char hash[XNC_HASH_SIZE];
};

static int algo_simple_xor( struct XncHash *hs, unsigned char *restrict buf, size_t blocks, void *ctx )
{
    struct XncSimpleXor *c = (struct XncSimpleXor *)ctx;

    UNUSED( hs );

    for( size_t i = 0; i < blocks; i++ ){
        for( size_t j = 0; j < sizeof( c->hash ); j++ ){
            buf[j] ^= c->hash[j];
        }
        buf += sizeof( c->hash );
    }

    return 1;
}

int simple_xor( const struct Xnc *xnc, struct XncJob *job )
{
    struct XncAlgoParams p;
    struct XncSimpleXor  c;
    unsigned char salt[XNC_SALT_SIZE];
    int rv;
    
    p.xor = algo_simple_xor;
    p.ctx = &c;

    switch( job->mode ){
        case XNC_ENCODE:
            xnc_create_salt( job->hs, salt, sizeof( salt ) );
            break;
        case XNC_DECODE:
            job->file.src.size -= xnc_read_salt( salt, sizeof( salt ), job->file.src.fh ) * sizeof( salt );
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
        hash_sha256( job->hs, (unsigned char *)&seed, sizeof( seed.salt ) + xnc->passwd.length, c.hash );
    } else{
        memcpy( c.hash, salt, sizeof( salt ) );
    }

    //info_dumphex( xnc, "Salt", (unsigned char *)c.hash, sizeof( c.hash ) );
    
    // 変換
    rv = xnc_xor_conv( xnc, job, &p );

    if( rv == 0 && job->mode == XNC_ENCODE ){
        if( ! xnc_write_salt( salt, sizeof( salt ), job->file.dst.fh ) ){
            rv |= 0x1000;
        }
    }

    return rv;
}
