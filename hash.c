#include "hash.h"

#ifdef _WIN32
#include <bcrypt.h>
#else
#include <openssl/sha.h>
#include <openssl/hmac.h>
#endif

void hash_init( struct XncContext *xnc )
{
#ifdef _WIN32
    DWORD result = 0;
    NTSTATUS rv = 0;

    rv |= BCryptOpenAlgorithmProvider( &(xnc->hash.sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, 0 );
    rv |= BCryptGetProperty( xnc->hash.sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(xnc->hash.sha256.hashobj_size), sizeof( DWORD ), &result, 0 );
    xnc->hash.sha256.hashobj = malloc( xnc->hash.sha256.hashobj_size );
    if( ! xnc->hash.sha256.hashobj ){
        rv |= 1;
    }

    rv |= BCryptOpenAlgorithmProvider( &(xnc->hash.hmac_sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG );
    rv |= BCryptGetProperty( xnc->hash.hmac_sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(xnc->hash.hmac_sha256.hashobj_size), sizeof( DWORD ), &result, 0 );
    xnc->hash.hmac_sha256.hashobj = malloc( xnc->hash.hmac_sha256.hashobj_size );
    if( ! xnc->hash.hmac_sha256.hashobj ){
        rv |= 1;
    } 

    if( rv != 0 ){
        einfo( "Failed to initialize SHA256 provider. aborting." );
        exit( 1 );
    }
#else
    return;
#endif
}

void hash_destroy( struct XncContext *xnc )
{
#ifdef _WIN32
    // initは失敗するとexit()するのでここにくるなら初期化できているはず
    BCryptCloseAlgorithmProvider( xnc->hash.sha256.h_alg, 0 );
    free( xnc->hash.sha256.hashobj );

    BCryptCloseAlgorithmProvider( xnc->hash.hmac_sha256.h_alg, 0 );
    free( xnc->hash.hmac_sha256.hashobj );

    memset( &xnc->hash, 0, sizeof( xnc->hash ) );
#else
    return;
#endif
}

#ifdef _WIN32
// 終端にNULLを書きこまない
void _hash_sha256( const unsigned char *msg,
                   DWORD msg_len,
                   unsigned char *key,
                   DWORD key_len,
                   unsigned char *output,
                   struct XncBCryptPvd *pvd )
{

    BCRYPT_HASH_HANDLE h_hash = NULL;
    NTSTATUS rv = 0;

    rv = BCryptCreateHash( pvd->h_alg, &h_hash, pvd->hashobj, pvd->hashobj_size, key, key_len, 0);
    if( rv == 0 ){
        rv |= BCryptHashData( h_hash, (PUCHAR)msg, msg_len, 0);
        rv |= BCryptFinishHash( h_hash, output, XNC_HASH_SIZE, 0);
        BCryptDestroyHash( h_hash );
    }
    
    if( rv != 0 ){
        einfo( "Failed to calculate SHA256. aborting." );
        exit( 1 );
    }
}
#else
void _hash_sha256( unsigned char *msg,
                  size_t len,
                  unsigned char *output )
{
    SHA256_CTX ctx;
    SHA256_Init( &ctx );
    SHA256_Update( &ctx, msg, len );
    SHA256_Final( output, &ctx );
}

void _hash_sha256hmac( unsigned char *msg,
                      size_t msg_len,
                      unsigned char *key,
                      size_t key_len,
                      unsigned char *output )
{
    unsigned int out_len = 0;
    HMAC( EVP_sha256(), key, key_len, msg, msg_len, output, &out_len );
}
#endif
