#include "../hash.h"
#include "../info.h"

#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

struct XncBCryptPvd{
    BCRYPT_ALG_HANDLE h_alg;
    DWORD hashobj_size;
};

struct XncHash {
    struct XncBCryptPvd sha256;
    struct XncBCryptPvd hmac_sha256;
};

static void _sha256( const unsigned char *msg,
                     size_t msg_len,
                     unsigned char *key,
                     size_t key_len,
                     unsigned char *output,
                     struct XncBCryptPvd *pvd )
{
    BCRYPT_HASH_HANDLE h_hash;
    NTSTATUS rv = 0;

    //PUCHAR hashobj = alloca( pvd->hashobj_size );
    UCHAR hashobj[512];

    rv = BCryptCreateHash( pvd->h_alg, &(h_hash), hashobj, pvd->hashobj_size, key, key_len, 0 );
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

struct XncHash *hash_init()
{
    DWORD result = 0;
    NTSTATUS rv = 0;

    struct XncHash *h = malloc( sizeof( *h ) );
    if( ! h ) return NULL;

    rv |= BCryptOpenAlgorithmProvider( &(h->sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, 0 );
    rv |= BCryptGetProperty( h->sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(h->sha256.hashobj_size), sizeof( DWORD ), &result, 0 );

    rv |= BCryptOpenAlgorithmProvider( &(h->hmac_sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG );
    rv |= BCryptGetProperty( h->hmac_sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(h->hmac_sha256.hashobj_size), sizeof( DWORD ), &result, 0 );

    if( rv != 0 ){
        einfo( "Failed to initialize SHA256 provider. Aborting." );
        exit( 1 );
    }

    return h;
}

void hash_destroy( struct XncHash *hash )
{
    // initは失敗するとexit()するのでここにくるなら初期化できているはず
    BCryptCloseAlgorithmProvider( hash->sha256.h_alg, 0 );
    BCryptCloseAlgorithmProvider( hash->hmac_sha256.h_alg, 0 );

    free( hash );
}

void hash_sha256( struct XncHash *hash, const unsigned char *msg, size_t len, unsigned char *output )
{
    _sha256( msg, len, NULL, 0, output, &(hash->sha256) );
}

void hash_sha256hmac( struct XncHash *hash,
                      const unsigned char *msg,
                      size_t msg_len,
                      unsigned char *key,
                      size_t key_len,
                      unsigned char *output )
{
    _sha256( msg, msg_len, key, key_len, output, &(hash->hmac_sha256) );
}
