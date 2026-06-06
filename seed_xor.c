#include "seed_xor.h"

#include <stdlib.h>
#include <string.h>

struct XncSeedXor{
    unsigned char salt[XNC_SALT_SIZE];
    unsigned char state[XNC_HASH_SIZE];
    uint64_t cnt;
};

struct XncSeedXorMsg{
    uint32_t label_be;
    uint64_t cnt_be;    
} __attribute__((packed));

static void _create_initial_state( const char *passwd,
                                   const size_t plen,
                                   struct XncHash *hs,
                                   const uint32_t stretch_times,
                                   struct XncSeedXor *c )
{
    uint32_t label_be = xnc_be32( XNC_SEED_STATE );
    struct XncSeedXorMsg msg;

    unsigned char pre_state[XNC_HASH_SIZE];
    struct {
        uint32_t i_be;
        unsigned char salt[XNC_SALT_SIZE];
        unsigned char passwd[XNC_MAX_PASSWD];
    } __attribute__((packed)) stretch;

    // pre-state準備
    stretch.i_be = xnc_be32( XNC_SEED_STATE );
    memcpy( stretch.salt, c->salt, sizeof( stretch.salt ) );
    if( passwd ) memcpy( stretch.passwd, passwd, plen );

    // pre-state 生成
    hash_sha256( hs, (unsigned char *)&stretch, sizeof( stretch ) - sizeof( stretch.passwd ) + plen, pre_state );
    
    // key_stretchは SHA256 をin-place（入力と出力に同じポインタを指定）で更新するバッファ。
    // CNG/OpenSSLのSHA256は入力を読み終えてから出力を書くためin-placeでも安全。
    // 初回はstateの代わりにlabel（4バイト）を入れるので、未使用領域をゼロクリアしている。
    
    // 鍵伸長
    for( uint32_t i = 0; i < stretch_times; i++ ){
        stretch.i_be = xnc_be32( i );
        hash_sha256hmac( hs,
                         (unsigned char *)&stretch.i_be,
                         sizeof( stretch.i_be ),
                         pre_state,
                         sizeof( pre_state ),
                         pre_state );
    }

    // initial state生成
    c->cnt = 0;
    msg.label_be = label_be;
    msg.cnt_be = xnc_be64( c->cnt );
    hash_sha256hmac( hs, (unsigned char *)&msg, sizeof( msg ), pre_state, sizeof( pre_state ), c->state );
    c->cnt++;
}

int seed_xor_work( struct XncHash *hs, unsigned char *restrict buf, size_t blocks, void *ctx )
{
    struct XncSeedXor *c = (struct XncSeedXor *)ctx;
    unsigned char ks[XNC_HASH_SIZE];

    // [LABEL] || [CNT]
    struct XncSeedXorMsg msg_ks, msg_st;

    msg_ks.label_be = xnc_be32( XNC_SEED_KS );
    msg_st.label_be = xnc_be32( XNC_SEED_STATE );
    
    for( size_t i = 0; i < blocks; i++ ){
        // カウンターセット
        msg_ks.cnt_be = xnc_be64( c->cnt );
        msg_st.cnt_be = msg_ks.cnt_be;

        // KSを生成
        hash_sha256hmac( hs, (unsigned char *)&msg_ks, sizeof( msg_ks ), c->state, sizeof( c->state ), ks );

        // STATEを更新
        hash_sha256hmac( hs, (unsigned char *)&msg_st, sizeof( msg_st ), c->state, sizeof( c->state ), c->state ); 

        // カウンターを進める
        c->cnt++;

        // 変換
        for( int j = 0; j < XNC_HASH_SIZE; j++ ){
            buf[j] ^= ks[j];
        }
        buf += XNC_HASH_SIZE;
    }
    return 0;
}

int seed_xor_finish( const struct Xnc *xnc, struct XncJob *job )
{
    struct XncSeedXor *c = job->algo_ctx;

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

int seed_xor_init( const struct Xnc *xnc, struct XncJob *job )
{
    uint32_t stretch_times;
    struct XncSeedXor *c = malloc( sizeof( *c ) );
    if( ! c ) return -1;

    switch( job->mode ){
        case XNC_DECODE:
            if( ! xnc_read_salt( job, c->salt, sizeof( c->salt ) ) ){
                free( c );
                return -2;
            }

            // saltの各バイトのビット0から鍵伸長回数をビット1とのXOR値で取り出す
            stretch_times = 0;
            for( int i = 0; i < 32; i++ ){
                unsigned char bit0 = ( c->salt[i] & 0x01 ) ^ ( ( c->salt[i] >>1 ) & 0x01 );
                stretch_times |= ( bit0 << ( 31 - i ) );
            }
            break;
        case XNC_ENCODE:
            xnc_create_salt( job, c->salt, sizeof( c->salt ) );

            // saltの各バイトのビット0から鍵伸長回数をビット1とのXOR値で埋め込む
            stretch_times = ( xnc->flags & XNC_F_NO_STRETCH ) ? 0 : XNC_STRETCH_TIMES;
            for( int i = 0; i < 32; i++ ){
                unsigned char bit0 = ( ( stretch_times >> ( 31 - i ) ) & 0x01 ) ^ ( ( c->salt[i] >> 1 ) & 0x01 );
                c->salt[i] = ( c->salt[i] & 0xFE ) | bit0;
            }
            break;
    }

    _create_initial_state( xnc->passwd.string, xnc->passwd.length, job->hs, stretch_times, c );

    // jobにコンテキストを紐づけ
    xnc_set_algo_ctx( job, c );

    return 0;
}
