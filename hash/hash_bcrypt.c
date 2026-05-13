#include "../hash.h"

#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

struct XncBCryptPvd{
    BCRYPT_ALG_HANDLE h_alg;
    PUCHAR hashobj;
    DWORD hashobj_size;
};

struct XncHash {
    struct XncBCryptPvd sha256;
    struct XncBCryptPvd hmac_sha256;
};

static struct XncHash st_hash;

static void _sha256( const unsigned char *msg,
                     size_t msg_len,
                     unsigned char *key,
                     size_t key_len,
                     unsigned char *output,
                     struct XncBCryptPvd *pvd )
{
    BCRYPT_HASH_HANDLE h_hash;
    NTSTATUS rv = 0;

    rv = BCryptCreateHash( pvd->h_alg, &(h_hash), pvd->hashobj, pvd->hashobj_size, key, key_len, 0 );
    if( rv == 0 ){
        rv |= BCryptHashData( h_hash, (PUCHAR)msg, msg_len, 0 );
        rv |= BCryptFinishHash( h_hash, output, XNC_HASH_SIZE, 0 );
        BCryptDestroyHash( h_hash );
    }
    
    if( rv != 0 ){
        einfo( "Failed to calculate SHA256. Aborting." );
        exit( 1 );
    }
}

void hash_init( struct XncContext *xnc )
{
    DWORD result = 0;
    NTSTATUS rv = 0;

    rv |= BCryptOpenAlgorithmProvider( &(st_hash.sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, 0 );
    rv |= BCryptGetProperty( st_hash.sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(st_hash.sha256.hashobj_size), sizeof( DWORD ), &result, 0 );

    rv |= BCryptOpenAlgorithmProvider( &(st_hash.hmac_sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG );
    rv |= BCryptGetProperty( st_hash.hmac_sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(st_hash.hmac_sha256.hashobj_size), sizeof( DWORD ), &result, 0 );

    xnc->hash = &st_hash;

    if( rv != 0 ){
        einfo( "Failed to initialize SHA256 provider. Aborting." );
        exit( 1 );
    }
}

void hash_destroy( struct XncContext *xnc )
{
    // initは失敗するとexit()するのでここにくるなら初期化できているはず
    BCryptCloseAlgorithmProvider( xnc->hash->sha256.h_alg, 0 );
    BCryptCloseAlgorithmProvider( xnc->hash->hmac_sha256.h_alg, 0 );

    memset( xnc->hash, 0, sizeof( struct XncHash ) );

    xnc->hash = NULL;
}

size_t hash_get_sha256_workspace_size( struct XncContext *xnc )
{
    return xnc->hash->sha256.hashobj_size;
}

size_t hash_get_sha256hmac_workspace_size( struct XncContext *xnc )
{
    return xnc->hash->hmac_sha256.hashobj_size;
}

void hash_sha256_ready( struct XncContext *xnc, void *sha_work, void *hmac_work )
{
    xnc->hash->sha256.hashobj = sha_work;
    xnc->hash->hmac_sha256.hashobj = hmac_work;
}

void hash_sha256( struct XncContext *xnc, const unsigned char *msg, size_t len, unsigned char *output )
{
    _sha256( msg, len, NULL, 0, output, &(xnc->hash->sha256) );
}

void hash_sha256hmac( struct XncContext *xnc,
                      const unsigned char *msg,
                      size_t msg_len,
                      unsigned char *key,
                      size_t key_len,
                      unsigned char *output )
{
    _sha256( msg, msg_len, key, key_len, output, &(xnc->hash->hmac_sha256) );
}
