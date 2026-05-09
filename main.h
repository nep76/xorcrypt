#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdint.h>
#include <sys/file.h>

#define XNC_NAME    "xorcrypt"
#define XNC_VERSION "26050700"

#define XNC_DEFAULT_EXT "xnc"

#define XNC_HASH_SIZE   32 // bytes
#define XNC_SALT_SIZE   32 // bytes
#define XNC_MAX_PASSWD  64 // char
#define XNC_CHAR_SET    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-_*/:;@[]()<>~={}!#$%&'"
#define XNC_BUF_SIZE    16777216 //16MB

#define XNC_STRECH_TIMES 1000000
#define XNC_SEED_STATE 0xC0DECAFE // ストリームに混ぜる定数 state用
#define XNC_SEED_KS    0x00C0FFEE // ストリームに混ぜる定数 ks用

#ifdef _WIN32
#include <windows.h>
#define MAX_PATH_LEN MAX_PATH
#define ftell64 _ftelli64
#define xnc_be64( x ) _byteswap_uint64( x )
#define xnc_be32( x ) _byteswap_ulong( x )
#else
// そのうち
#define MAX_PATH_LEN PATH_MAX
#define ftell64 ftello
#define xnc_be64( x ) htobe64( x )
#define xnc_be32( x ) htobe32( x )
#endif

#if ( XNC_BUF_SIZE % 32 ) != 0
#error "XNC_BUF_SIZE must be a multiple of 32"
#endif

#define XNC_F_AUTODETECT 0x00000001
#define XNC_F_VERBOSE    0x00000002
#define XNC_F_OVERWRITE  0x00000004

struct XncContext;

typedef int (*XncXorFunc)( struct XncContext*, unsigned char * restrict, size_t, void* );
typedef int (*XncAlgoFunc)( struct XncContext*, FILE*, uint64_t, FILE* );

enum XncRunMode {
    XNC_DECODE,
    XNC_ENCODE,
};

struct XncAlgoParams {
    XncXorFunc xor;
    void *ctx;
};

struct XncAlgo {
    char        *name;
    XncAlgoFunc func;
};

struct XncBCryptPvd{
    BCRYPT_ALG_HANDLE h_alg;
    PUCHAR hashobj;
    DWORD hashobj_size;
};

struct XncHashPvd {
    struct XncBCryptPvd sha256;
    struct XncBCryptPvd hmac_sha256;
};

struct XncContext {
    struct XncAlgo algo;
    struct XncHashPvd hash;
    enum XncRunMode mode;
    uint32_t flags;
    char *ext;
    char *outdir;
    char *passwd;
    unsigned char *buf;
};

void   xnc_salt_seed_gen( unsigned char *buf, size_t len );
void   xnc_create_salt( struct XncContext *xnc, unsigned char *output, size_t len );
size_t xnc_read_salt( unsigned char *output, size_t len, FILE *fp );
void   xnc_write_salt( const unsigned char *salt, size_t len, FILE *fp );
int    xnc_xor_conv( struct XncContext *xnc, FILE *src, uint64_t fsize, FILE *dst, struct XncAlgoParams *p );

#endif