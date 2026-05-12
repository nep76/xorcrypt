#include "seed_xor.h"

#include <string.h>

static int algo_seed_xor( struct XncContext *xnc, unsigned char *restrict buf, size_t blocks, void *ctx )
{
    struct XncSeedXor *c = (struct XncSeedXor *)ctx;
    unsigned char ks[XNC_HASH_SIZE];
    struct XncSeedXorMsg msg;

    XNC_HASH_SUPPRESS_UNUSED_WARN( xnc );

    for( size_t i = 0; i < blocks; i++ ){
        msg.label_be = xnc_be32( XNC_SEED_KS );
        msg.cnt_be   = xnc_be64( c->cnt );
        hash_sha256hmac( xnc, (unsigned char *)&msg, sizeof( msg ), c->state, sizeof( c->state ), ks );

        for( int j = 0; j < XNC_HASH_SIZE; j++ ){
            buf[j] ^= ks[j];
        }
        buf += XNC_HASH_SIZE;

        c->cnt++;
        msg.label_be = xnc_be32( XNC_SEED_STATE );
        msg.cnt_be   = xnc_be64( c->cnt );
        hash_sha256hmac( xnc, (unsigned char *)&msg, sizeof( msg ), c->state, sizeof( c->state ), c->state ); 
    }
    return 1;
}

static void create_initial_state( struct XncContext *xnc, unsigned char *salt, struct XncSeedXor *c )
{
    // key_stretchは SHA256 をin-place（入力と出力に同じポインタを指定）で更新するバッファ。
    // CNG/OpenSSLのSHA256は入力を読み終えてから出力を書くためin-placeでも安全。
    // 初回はstateの代わりにlabel（4バイト）を入れるので、未使用領域をゼロクリアしている。

    uint32_t label_be = xnc_be32( XNC_SEED_STATE );
    uint32_t i = 0;
    struct XncSeedXorMsg msg;

    XNC_HASH_SUPPRESS_UNUSED_WARN( xnc );

    // [HASH] || [i] || [SALT] || [PASSWD]
    struct {
        unsigned char  state[XNC_HASH_SIZE];
        uint32_t i_be;
        unsigned char   salt[XNC_SALT_SIZE];
        unsigned char passwd[XNC_MAX_PASSWD];
    } __attribute__((packed)) stretch;
    
    memset( stretch.state, 0, sizeof( stretch.state ) );     // 本来32バイトのstateを入れる場所に
    memcpy( stretch.state, &label_be, sizeof( label_be ) ); // 代わりにlabelを挿入
    stretch.i_be = xnc_be32( i );
    memcpy( stretch.salt, salt, sizeof( stretch.salt ) );
    if( xnc->passwd.string ){
        memcpy( stretch.passwd, xnc->passwd.string, xnc->passwd.length );
    }
    
    // 初期ハッシュ
    hash_sha256( xnc, (unsigned char *)&stretch, ( sizeof( stretch ) - sizeof( stretch.passwd ) ) + xnc->passwd.length, stretch.state );
    
    // 鍵伸長
    if( ! ( xnc->flags & XNC_F_NO_STRETCH ) ){
        info( xnc, "Key-stretching..." ) ;
        for( ; i < XNC_STRETCH_TIMES; i++ ){
            stretch.i_be = xnc_be32( i );
            hash_sha256hmac(
                xnc,
                (unsigned char *)&stretch,
                sizeof( stretch ) - sizeof( stretch.passwd ) + xnc->passwd.length,
                stretch.state,
                sizeof( stretch.state),
                stretch.state
            );
        }
    } else{
        info( xnc, "No-stretch" );
    }

    // 初期state
    msg.label_be = label_be;
    msg.cnt_be = xnc_be64( c->cnt );
    hash_sha256hmac( xnc, (unsigned char *)&msg, sizeof( msg ), stretch.state, sizeof( stretch.state ), c->state );
}

int seed_xor( struct XncContext *xnc, FILE *src, uint64_t src_size, FILE *dst )
{
    struct XncAlgoParams p;
    struct XncSeedXor    c;
    unsigned char salt[XNC_SALT_SIZE];

    p.xor = algo_seed_xor;
    p.ctx = &c;
    c.cnt = 0;

    switch( xnc->mode ){
        case XNC_ENCODE:
            xnc_create_salt( xnc, salt, sizeof( salt ) );
            break;
        case XNC_DECODE:
            src_size -= xnc_read_salt( salt, sizeof( salt ), src ) * sizeof( salt );
            break;
    }

    info_dumphex( xnc, "Salt", (unsigned char *)salt, sizeof( salt ) );

    // マスターハッシュを作成
    create_initial_state( xnc, salt, &c );

    xnc_xor_conv( xnc, src, src_size, dst, &p );

    if( xnc->mode == XNC_ENCODE ){
        xnc_write_salt( salt, sizeof( salt ), dst );
    }

    return 1;
}
