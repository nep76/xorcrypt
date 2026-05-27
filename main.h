#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/types.h>

#include "xorcrypt.h"
#include "thread/thrw.h"
#include "thread/queue.h"
#include "thread/rqueue.h"

#define XNC_DEFAULT_EXT "xnc"

#define XNC_PROGBAR_LEN 20

#define XNC_HASH_SIZE   32 // bytes
#define XNC_SALT_SIZE   32 // bytes
#define XNC_MAX_PASSWD  64 // char
#define XNC_BUF_SIZE    4096000 //4MB
#define XNC_BUF_ALIGN   32 // AVX2

#define XNC_STRETCH_TIMES 100000
#define XNC_SEED_STATE    0xC0DECAFE // ストリームに混ぜる定数 state用
#define XNC_SEED_KS       0x00C0FFEE // ストリームに混ぜる定数 ks用

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

#if ( XNC_BUF_SIZE % XNC_BUF_ALIGN ) != 0
#error "XNC_BUF_SIZE must be a multiple of XNC_BUF_ALIGN"
#endif

#include "hash.h"

#define XNC_F_AUTODETECT  0x00000001
#define XNC_F_VERBOSE     0x00000002
#define XNC_F_OVERWRITE   0x00000004
#define XNC_F_NO_STRETCH  0x00000008

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
    RqueueCtx *read, *work, *write, *idle;
    QueueCtx  *error;

    struct xnc_file_id *ids;
    unsigned int       id_cnt;

    unsigned char *buf_addr;

    struct XncAlgo algo;
    enum XncMode   mode;
    uint32_t       flags;
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

    uint32_t   xorshift32;
};

char *xnc_get_mode_name( enum XncMode mode );
void xnc_salt_seed_gen( uint32_t *xorshift32_seed, unsigned char *buf, size_t len );
void xnc_create_salt( struct XncHash *hs, uint32_t *xorshift32, unsigned char *output, size_t len );
int  xnc_read_salt( unsigned char *output, size_t len, FILE *fp );
int  xnc_write_salt( const unsigned char *salt, size_t len, FILE *fp );

#endif