#include "../hash.h"

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

static struct XncHash st_hash;

void hash_init( struct XncContext *xnc )
{
    st_hash.sha256.ctx = EVP_MD_CTX_new();
    if( ! st_hash.sha256.ctx ) goto ABORT;

    if(
        ! ( st_hash.hmac_sha256.mac = EVP_MAC_fetch( NULL, "HMAC", NULL ) ) ||
        ! ( st_hash.hmac_sha256.ctx = EVP_MAC_CTX_new( st_hash.hmac_sha256.mac ) )
    ){
        goto ABORT;
    }
    st_hash.hmac_sha256.params[0] = OSSL_PARAM_construct_utf8_string( "digest", "SHA256", 0 );
    st_hash.hmac_sha256.params[1] = OSSL_PARAM_construct_end();

    xnc->hash = &st_hash;

    return;

    ABORT:
        einfof( "Failed to initialize SHA256. OpenSSL says: %s", ERR_error_string( ERR_get_error(), NULL ) );
        exit( 1 );
}

void hash_destroy( struct XncContext *xnc )
{
    EVP_MD_CTX_free( xnc->hash->sha256.ctx );
    EVP_MAC_CTX_free( xnc->hash->hmac_sha256.ctx );
    EVP_MAC_free( xnc->hash->hmac_sha256.mac );

    memset( xnc->hash, 0, sizeof( struct XncHash ) );

    xnc->hash = NULL;
}

void hash_sha256( struct XncContext *xnc,
                  const unsigned char *msg,
                  size_t len,
                  unsigned char *output )
{
    if(
        ! EVP_DigestInit_ex( xnc->hash->sha256.ctx, EVP_sha256(), NULL ) ||
        ! EVP_DigestUpdate( xnc->hash->sha256.ctx, msg, len )            ||
        ! EVP_DigestFinal_ex( xnc->hash->sha256.ctx, output, NULL )
    ){
        einfof( "Failed to calculate SHA256. OpenSSL says: %s", ERR_error_string( ERR_get_error(), NULL ) );
        exit( 1 );
    }
}

void hash_sha256hmac( struct XncContext *xnc,
                      const unsigned char *msg,
                      size_t msg_len,
                      unsigned char *key,
                      size_t key_len,
                      unsigned char *output )
{
    if(
        ! EVP_MAC_init( xnc->hash->hmac_sha256.ctx, key, key_len, xnc->hash->hmac_sha256.params ) ||
        ! EVP_MAC_update( xnc->hash->hmac_sha256.ctx, msg, msg_len )                          ||
        ! EVP_MAC_final( xnc->hash->hmac_sha256.ctx, output, NULL, XNC_HASH_SIZE )
    ){
        einfof( "Failed to calculate SHA256. OpenSSL says: %s", ERR_error_string( ERR_get_error(), NULL ) );
        exit( 1 );
    }        
}
