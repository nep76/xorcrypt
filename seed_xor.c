#include "seed_xor.h"

static int _algo_seed_xor( struct XncContext *xnc, unsigned char *restrict buf, size_t blocks, void *ctx )
{
    struct XncSeedXor *c = (struct XncSeedXor *)ctx;
    unsigned char ks[XNC_HASH_SIZE];
    struct XncSeedXorMsg msg;

    for( size_t i = 0; i < blocks; i++ ){
        msg.label_be = xnc_be32( XNC_SEED_KS );
        msg.cnt_be   = xnc_be64( c->cnt );
        sha256hmac( xnc, (unsigned char *)&msg, sizeof( msg ), c->state, sizeof( c->state ), ks );

        for( int j = 0; j < XNC_HASH_SIZE; j++ ){
            buf[j] ^= ks[j];
        }
        buf += XNC_HASH_SIZE;

        c->cnt++;
        msg.label_be = xnc_be32( XNC_SEED_STATE );
        msg.cnt_be   = xnc_be64( c->cnt );
        sha256hmac( xnc, (unsigned char *)&msg, sizeof( msg ), c->state, sizeof( c->state ), c->state ); 
    }
    return 1;
}

int seed_xor( struct XncContext *xnc, FILE *src, uint64_t src_size, FILE *dst )
{
    struct XncAlgoParams p;
    struct XncSeedXor c;
    unsigned char salt[XNC_SALT_SIZE];

    p.fn_xor = _algo_seed_xor;
    p.ctx = &c;
    c.cnt = 0;

    switch( xnc->mode ){
        case XNC_ENCODE:
            keygen( salt, sizeof( salt ) );
            break;
        case XNC_DECODE:
            fseek64( src, -( sizeof( salt ) ), SEEK_END );
            fread( salt, sizeof( char ), sizeof( salt ), src );
            src_size -= sizeof( salt );
            break;
        default:
            return 0;
    }

    {
        // key_strechは SHA256 をin-place（入力と出力に同じポインタを指定）で更新するバッファ。
        // CNG/OpenSSLのSHA256は入力を読み終えてから出力を書くためin-placeでも安全。
        // 初回はstateの代わりにlabel（4バイト）を入れるので、未使用領域をゼロクリアしている。

        uint32_t label_be = xnc_be32( XNC_SEED_STATE );
        uint32_t i = 0;
        size_t pass_len = 0;
        struct XncSeedXorMsg msg;

        // [HASH] || [i] || [KEY] || [PASSWD]
        struct {
            unsigned char state[XNC_HASH_SIZE];
            uint32_t i_be;
            unsigned char key[XNC_SALT_SIZE];
            unsigned char passwd[XNC_MAX_PASSWD];
        } __attribute__((packed)) strech;
        
        memset( strech.state, 0, sizeof( strech.state ) );     // 本来32バイトのstateを入れる場所に
        memcpy( strech.state, &label_be, sizeof( label_be ) ); // 代わりにlabelを挿入
        strech.i_be = xnc_be32( i );
        memcpy( strech.key, salt, sizeof( salt ) );
        if( xnc->passwd ){
            pass_len = strlen( xnc->passwd );
            memcpy( strech.passwd, xnc->passwd, pass_len );
        }
        sha256( xnc, (unsigned char *)&strech, ( sizeof( strech ) - sizeof( strech.passwd ) ) + pass_len, strech.state );
        for( ; i < XNC_STRECH_TIMES; i++ ){
            strech.i_be = xnc_be32( i );
            sha256hmac(
                xnc,
                (unsigned char *)&strech,
                sizeof( strech ) - sizeof( strech.passwd ) + pass_len,
                strech.state,
                sizeof( strech.state),
                strech.state
            );
        }

        msg.label_be = label_be;
        msg.cnt_be = xnc_be64( c.cnt );
        sha256hmac( xnc, (unsigned char *)&msg, sizeof( msg ), strech.state, sizeof( strech.state ), c.state );
    }

    dumpkey( xnc, "Key", (unsigned char *)salt, sizeof( salt ) );
    xor_conv( xnc, src, src_size, dst, &p );

    if( xnc->mode == XNC_ENCODE ){
        info( xnc, "Added decode key.");
        fwrite( salt, sizeof( char ), sizeof( salt ), dst );
    }

    return 1;
}
