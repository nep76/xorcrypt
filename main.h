#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/types.h>

#include "xorcrypt.h"
#include "thread/thrw.h"
#include "thread/rqueue.h"

#include <limits.h>
#ifdef _WIN32
#include <windows.h>
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#define xnc_be64( x ) _byteswap_uint64( x )
#define xnc_be32( x ) _byteswap_ulong( x )
#else
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define xnc_be64( x ) htobe64( x )
#define xnc_be32( x ) htobe32( x )
#endif
#define RNG_WEYL_CONST64 0x9E3779B97F4A7C15ULL

#define XNC_DEFAULT_EXT   "xnc"
#define XNC_PROGBAR_LEN   20
#define XNC_HASH_SIZE     32 // bytes
#define XNC_SALT_SIZE     32 // bytes
#define XNC_MAX_PASSWD    64 // char
#define XNC_BUF_SIZE      4096000 //4MB
#define XNC_BUF_ALIGN     32 // AVX2
#define XNC_ERRBUF_SIZE   256

#define XNC_STRETCH_TIMES 300000

#define XNC_SEED_STATE    0xC0DECAFE // ストリームに混ぜる定数 state用
#define XNC_SEED_KS       0x00C0FFEE // ストリームに混ぜる定数 ks用

#define XNC_F_AUTODETECT  0x00000001
#define XNC_F_VERBOSE     0x00000002
#define XNC_F_OVERWRITE   0x00000004
#define XNC_F_NO_STRETCH  0x00000008

#if ( XNC_BUF_SIZE % XNC_BUF_ALIGN ) != 0
#error "XNC_BUF_SIZE must be a multiple of XNC_BUF_ALIGN"
#endif
#if XNC_SALT_SIZE < 32
#error "XNC_SALT_SIZE must be at least 32"
#endif

#include "hash.h"

typedef void *XncAlgoCtx;

typedef int (*XncFuncXor)( struct XncHash*, unsigned char * restrict, size_t, XncAlgoCtx );
typedef int (*XncFuncAlgo)( const struct Xnc*, struct XncJob* );

enum XncMode {
    XNC_DECODE,
    XNC_ENCODE,
};

struct XncAlgo {
    char        *name;
    XncFuncAlgo fn_init, fn_destroy;
    XncFuncXor  fn_xor;
};

struct Xnc {
    RqueueCtx *read, *work, *write, *idle, *error;

    struct {
        int            cnt;
        struct XncFile *list;
        struct XncFile **sorted;
    } file;

    unsigned char *buf_addr;

    struct XncAlgo algo;
    enum XncMode   mode;
    uint32_t       flags;
    int            jobs;
    char           *ext;
    char           *outdir;
    struct {
        char   *string;
        size_t length;
    } passwd;
};

struct XncJob {
    enum   XncMode mode;
    struct XncHash *hs;
    XncAlgoCtx algo_ctx;
    struct {
        char path[PATH_MAX];
        FILE *fh;
        off_t size;
        off_t cur_offset;
        size_t read_bytes;
   } fsrc;
    struct {
        char path[PATH_MAX];
        FILE *fh;
    } fdst;
    unsigned char *buf;
    atomic_int progress;
    int rv;

    uint64_t   xorshift;
};

char *xnc_get_mode_name( struct XncJob *job );
void xnc_salt_seed_gen( uint64_t *xorshift_seed, unsigned char *buf, size_t len );
void xnc_set_algo_ctx( struct XncJob *job, void *ctx );
void xnc_create_salt( struct XncJob *job, unsigned char *output, size_t len );
int  xnc_read_salt( struct XncJob *job, unsigned char *output, size_t len );
int  xnc_write_salt( struct XncJob *job, const unsigned char *salt, size_t len );

#endif