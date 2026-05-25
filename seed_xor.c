#include "seed_xor.h"

#include <string.h>

struct XncSeedXor{
    unsigned char state[XNC_HASH_SIZE];
    uint64_t cnt;
};

struct XncSeedXorMsg{
    uint32_t label_be;
    uint64_t cnt_be;
} __attribute__((packed));

static int algo_seed_xor( struct XncHash *hs, unsigned char *restrict buf, size_t blocks, void *ctx )
{
    struct XncSeedXor *c = (struct XncSeedXor *)ctx;
    unsigned char ks[XNC_HASH_SIZE];

    // [LABEL] || [CNT]
    struct XncSeedXorMsg msg_state, msg_ks;

    msg_ks.label_be    = xnc_be32( XNC_SEED_KS );
    msg_state.label_be = xnc_be32( XNC_SEED_STATE );

    for( size_t i = 0; i < blocks; i++ ){
        msg_ks.cnt_be   = xnc_be64( c->cnt );
        hash_sha256hmac( hs, (unsigned char *)&msg_ks, sizeof( msg_ks ), c->state, sizeof( c->state ), ks );

        for( int j = 0; j < XNC_HASH_SIZE; j++ ){
            buf[j] ^= ks[j];
        }
        buf += XNC_HASH_SIZE;

        c->cnt++;
        msg_state.cnt_be   = xnc_be64( c->cnt );
        hash_sha256hmac( hs, (unsigned char *)&msg_state, sizeof( msg_state ), c->state, sizeof( c->state ), c->state ); 
    }
    return 1;
}

static void create_initial_state( const struct Xnc *xnc,
                                  struct XncJob *job,
                                  unsigned char *salt,
                                  struct XncSeedXor *c )
{
    // key_stretchは SHA256 をin-place（入力と出力に同じポインタを指定）で更新するバッファ。
    // CNG/OpenSSLのSHA256は入力を読み終えてから出力を書くためin-placeでも安全。
    // 初回はstateの代わりにlabel（4バイト）を入れるので、未使用領域をゼロクリアしている。

    uint32_t label_be = xnc_be32( XNC_SEED_STATE );
    uint32_t i = 0;
    struct XncSeedXorMsg msg;

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
    hash_sha256( job->hs, (unsigned char *)&stretch, ( sizeof( stretch ) - sizeof( stretch.passwd ) ) + xnc->passwd.length, stretch.state );
    
    // 鍵伸長
    if( ! ( xnc->flags & XNC_F_NO_STRETCH ) ){
        for( ; i < XNC_STRETCH_TIMES; i++ ){
            stretch.i_be = xnc_be32( i );
            hash_sha256hmac(
                job->hs,
                (unsigned char *)&stretch,
                sizeof( stretch ) - sizeof( stretch.passwd ) + xnc->passwd.length,
                stretch.state,
                sizeof( stretch.state),
                stretch.state
            );
        }
    }

    // 初期state
    msg.label_be = label_be;
    msg.cnt_be = xnc_be64( c->cnt );
    hash_sha256hmac( job->hs, (unsigned char *)&msg, sizeof( msg ), stretch.state, sizeof( stretch.state ), c->state );
}

int seed_xor( const struct Xnc *xnc, struct XncJob *job )
{
    struct XncAlgoParams p;
    struct XncSeedXor    c;
    unsigned char salt[XNC_SALT_SIZE];
    int rv;

    p.xor = algo_seed_xor;
    p.ctx = &c;
    c.cnt = 0;

    switch( job->mode ){
        case XNC_ENCODE:
            xnc_create_salt( job->hs, salt, sizeof( salt ) );
            break;
        case XNC_DECODE:
            job->file.src.size -= xnc_read_salt( salt, sizeof( salt ), job->file.src.fh ) * sizeof( salt );
            break;
    }

    //info_dumphex( xnc, "Salt", (unsigned char *)salt, sizeof( salt ) );

    // マスターハッシュを作成
    create_initial_state( xnc, job, salt, &c );

    rv = xnc_xor_conv( xnc, job, &p );

    if( rv == 0 &&  job->mode == XNC_ENCODE ){
        if( ! xnc_write_salt( salt, sizeof( salt ), job->file.dst.fh ) ){
            rv |= 0x1000;
        }
    }

    return rv;
}
