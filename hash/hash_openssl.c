#include "../hash.h"
#include "../info.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>

struct XncHash {
    struct {
        EVP_MD_CTX *ctx;
    } sha256;
    struct {
        EVP_MAC *mac;
        EVP_MAC_CTX *ctx;
        OSSL_PARAM params[2];
    } hmac_sha256;
};

struct XncHash *hash_init()
{
    struct XncHash *h = malloc( sizeof( *h ) );
    if( ! h ) return NULL;

    h->sha256.ctx = EVP_MD_CTX_new();
    if( ! h->sha256.ctx ) goto ABORT;

    if(
        ! ( h->hmac_sha256.mac = EVP_MAC_fetch( NULL, "HMAC", NULL ) ) ||
        ! ( h->hmac_sha256.ctx = EVP_MAC_CTX_new( h->hmac_sha256.mac ) )
    ){
        goto ABORT;
    }
    h->hmac_sha256.params[0] = OSSL_PARAM_construct_utf8_string( "digest", "SHA256", 0 );
    h->hmac_sha256.params[1] = OSSL_PARAM_construct_end();

    return h;

    ABORT:
        einfof( "Aborting. Failed to initialize SHA256. OpenSSL says: %s", ERR_error_string( ERR_get_error(), NULL ) );
        exit( 1 );
}

void hash_destroy( struct XncHash *hash )
{
    EVP_MD_CTX_free( hash->sha256.ctx );
    EVP_MAC_CTX_free( hash->hmac_sha256.ctx );
    EVP_MAC_free( hash->hmac_sha256.mac );
    free( hash );
}

void hash_sha256( struct XncHash *hash,
                  const unsigned char *msg,
                  size_t len,
                  unsigned char *output )
{
    if(
        ! EVP_DigestInit_ex( hash->sha256.ctx, EVP_sha256(), NULL ) ||
        ! EVP_DigestUpdate( hash->sha256.ctx, msg, len )            ||
        ! EVP_DigestFinal_ex( hash->sha256.ctx, output, NULL )
    ){
        einfof( "Aborting. Failed to calculate SHA256. OpenSSL says: %s", ERR_error_string( ERR_get_error(), NULL ) );
        exit( 1 );
    }
}

void hash_sha256hmac( struct XncHash *hash,
                      const unsigned char *msg,
                      size_t msg_len,
                      unsigned char *key,
                      size_t key_len,
                      unsigned char *output )
{
    if(
        ! EVP_MAC_init( hash->hmac_sha256.ctx, key, key_len, hash->hmac_sha256.params ) ||
        ! EVP_MAC_update( hash->hmac_sha256.ctx, msg, msg_len )                         ||
        ! EVP_MAC_final( hash->hmac_sha256.ctx, output, NULL, XNC_HASH_SIZE )
    ){
        einfof( "Aborting. Failed to calculate HMAC-SHA256. OpenSSL says: %s", ERR_error_string( ERR_get_error(), NULL ) );
        exit( 1 );
    }        
}
