#include "simple_xor.h"

#include <stdlib.h>
#include <string.h>

struct XncSimpleXor {
    unsigned char salt[XNC_SALT_SIZE];
    unsigned char hash[XNC_HASH_SIZE];
};

int simple_xor_work( struct XncHash *hs, unsigned char *restrict buf, size_t blocks, XncAlgoCtx ctx )
{
    struct XncSimpleXor *c = (struct XncSimpleXor *)ctx;

    UNUSED( hs );

    for( size_t i = 0; i < blocks; i++ ){
        for( size_t j = 0; j < sizeof( c->hash ); j++ ){
            buf[j] ^= c->hash[j];
        }
        buf += sizeof( c->hash );
    }

    return 0;
}

int simple_xor_init( const struct Xnc *xnc, struct XncJob *job )
{
    struct XncSimpleXor *c = malloc( sizeof( *c ) );
    if( ! c ) return -1;

    switch( job->mode ){
        case XNC_DECODE:
            if( ! xnc_read_salt( job, c->salt, sizeof( c->salt ) ) ){
                free( c );
                return - 1;
            }
            break;
        case XNC_ENCODE:
            xnc_create_salt( job, c->salt, sizeof( c->salt ) );
            break;
    }

    // パスワードが設定されている場合はキーとパスワードを合わせて
    // もう一度ハッシュ化したものを最終的なキーにする
    if( xnc->passwd.string ){
        struct {
            char   salt[XNC_SALT_SIZE];
            char passwd[XNC_MAX_PASSWD];
        } __attribute__((packed)) seed;

        memcpy( (void *)seed.salt, c->salt, sizeof( c->salt ) );
        memcpy( (void *)seed.passwd, xnc->passwd.string, xnc->passwd.length );
        hash_sha256( job->hs, (unsigned char *)&seed, sizeof( seed.salt ) + xnc->passwd.length, c->hash );
    } else{
        memcpy( c->hash, c->salt, sizeof( c->salt ) );
    }

    // jobにコンテキストを紐づけ
    xnc_set_algo_ctx( job, c );

    return 0;
}

int simple_xor_finish( const struct Xnc *xnc, struct XncJob *job )
{
    struct XncSimpleXor *c = job->algo_ctx;

    UNUSED( xnc );
    
    if( job->mode == XNC_ENCODE ){
        if( ! xnc_write_salt( job, c->salt, sizeof( c->salt ) ) ){
            free( c );
            return -1;
        }
    }

    free( c );
    return 0;
}
