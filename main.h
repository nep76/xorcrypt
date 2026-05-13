#ifndef MAIN_H
#define MAIN_H

#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#undef _FILE_OFFSET_BITS
#include <stdint.h>

#define XNC_DEFAULT_EXT "xnc"

#define XNC_HASH_SIZE   32 // bytes
#define XNC_SALT_SIZE   32 // bytes
#define XNC_MAX_PASSWD  64 // char
#define XNC_BUF_SIZE    16777216 //16MB

#define XNC_STRETCH_TIMES 1000000
#define XNC_SEED_STATE 0xC0DECAFE // ストリームに混ぜる定数 state用
#define XNC_SEED_KS    0x00C0FFEE // ストリームに混ぜる定数 ks用

#include <limits.h>
#ifdef _WIN32
#include <windows.h>
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#define xnc_be64( x ) _byteswap_uint64( x )
#define xnc_be32( x ) _byteswap_ulong( x )
#else
// そのうち
#define xnc_be64( x ) htobe64( x )
#define xnc_be32( x ) htobe32( x )
#endif

#if ( XNC_BUF_SIZE % 32 ) != 0
#error "XNC_BUF_SIZE must be a multiple of 32"
#endif

#define XNC_F_AUTODETECT  0x00000001
#define XNC_F_VERBOSE     0x00000002
#define XNC_F_OVERWRITE   0x00000004
#define XNC_F_NO_STRETCH  0x00000008

struct XncContext;

typedef int (*XncXorFunc)( struct XncContext*, unsigned char * restrict, size_t, void* );
typedef int (*XncAlgoFunc)( struct XncContext*, FILE*, off_t, FILE* );

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

#ifdef _WIN32
struct XncBCryptPvd{
    BCRYPT_ALG_HANDLE h_alg;
    PUCHAR hashobj;
    DWORD hashobj_size;
};

struct XncHashPvd {
    struct XncBCryptPvd sha256;
    struct XncBCryptPvd hmac_sha256;
};
#endif


struct XncContext {
    struct XncAlgo algo;
#ifdef _WIN32
    struct XncHashPvd hash;
#endif
    enum XncRunMode mode;
    uint32_t flags;
    char *ext;
    char *outdir;
    struct {
        char *string;
        size_t length;
    } passwd;
    unsigned char *buf;
};

void xnc_salt_seed_gen( unsigned char *buf, size_t len );
void xnc_create_salt( struct XncContext *xnc, unsigned char *output, size_t len );
int  xnc_read_salt( unsigned char *output, size_t len, FILE *fp );
int  xnc_write_salt( const unsigned char *salt, size_t len, FILE *fp );
int  xnc_xor_conv( struct XncContext *xnc, FILE *src, off_t fsize, FILE *dst, struct XncAlgoParams *p );

#endif