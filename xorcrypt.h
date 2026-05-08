#ifndef XORCRYPT_H
#define XORCRYPT_H

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
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
#include <bcrypt.h>
#define MAX_PATH_LEN MAX_PATH
#define fseek64 _fseeki64
#define ftell64 _ftelli64
#define xnc_be64( x ) _byteswap_uint64( x )
#define xnc_be32( x ) _byteswap_ulong( x )
#else
// そのうち
#define MAX_PATH_LEN PATH_MAX
#define fseek64 fseeko
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
    XncXorFunc fn_xor;
    void *ctx;
};

struct XncSimpleXor {
    unsigned char salt[XNC_SALT_SIZE];
    unsigned char hash[XNC_HASH_SIZE];
};

struct XncSeedXor{
    unsigned char state[XNC_HASH_SIZE];
    uint64_t cnt;
};

struct XncSeedXorMsg{
    uint32_t label_be;
    uint64_t cnt_be;
} __attribute__((packed));

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

void _info( FILE *stream, const char *format, ... );
void _dumpbin( const char *label, const char *fmt, const unsigned char *bytes, size_t len );
void _sha256( const unsigned char *msg, DWORD msg_len, unsigned char *key, DWORD key_len, unsigned char *dst, struct XncBCryptPvd *pvd );

#define sha256( p_xnc, msg, len, dst ) _sha256( msg, len, NULL, 0, dst, &((p_xnc)->hash.sha256) )
#define sha256hmac( p_xnc, msg, msg_len, key, key_len, dst ) _sha256( msg, msg_len, key, key_len, dst, &((p_xnc)->hash.hmac_sha256) )

#define info( p_xnc, msg )                  if( (p_xnc)->flags & XNC_F_VERBOSE ){ _info( stdout, msg ); }
#define infof( p_xnc, fmt, ... )            if( (p_xnc)->flags & XNC_F_VERBOSE ){ _info( stdout, fmt, __VA_ARGS__ ); }
#define einfo( msg )                        _info( stderr, msg )
#define einfof( fmt, ... )                  _info( stderr, fmt, __VA_ARGS__ )
#define dumphash( p_xnc, label, hash, len ) if( (p_xnc)->flags & XNC_F_VERBOSE ){ _dumpbin( label, "%02x", hash, len ); }
#define dumpkey( p_xnc, label, key, len )   if( (p_xnc)->flags & XNC_F_VERBOSE ){ _dumpbin( label, "%c", key, len ); }

#endif