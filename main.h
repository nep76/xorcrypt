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

#define XNC_DEFAULT_EXT "xnc"

#define XNC_PROGBAR_LEN 20

#define XNC_HASH_SIZE   32 // bytes
#define XNC_SALT_SIZE   32 // bytes
#define XNC_MAX_PASSWD  64 // char
#define XNC_BUF_SIZE    4096000 //4MB

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

#if ( XNC_BUF_SIZE % 32 ) != 0
#error "XNC_BUF_SIZE must be a multiple of 32"
#endif

#include "hash.h"

#define XNC_F_AUTODETECT  0x00000001
#define XNC_F_VERBOSE     0x00000002
#define XNC_F_OVERWRITE   0x00000004
#define XNC_F_NO_STRETCH  0x00000008

typedef int (*XncFuncXor)( struct XncHash*, unsigned char * restrict, size_t, void* );
typedef int (*XncFuncAlgo)( const struct Xnc*, struct XncJob* );

enum XncMode {
    XNC_DECODE,
    XNC_ENCODE,
};

struct XncAlgoParams {
    XncFuncXor xor;
    void *ctx;
};

struct XncAlgo {
    char        *name;
    XncFuncAlgo func;
};

struct Xnc {
    QueueCtx *task, *prog, *error;

    struct xnc_file_id *ids;
    unsigned int       id_cnt;

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
    struct {
        struct {
            FILE* fh;
            char path[PATH_MAX];
        } dst;
        struct {
            FILE* fh;
            off_t size;
        } src;
    } file;
    unsigned char *buf;
    int status;
    atomic_int progress;
};

char *xnc_get_mode_name( enum XncMode mode );
void xnc_salt_seed_gen( unsigned char *buf, size_t len );
void xnc_create_salt( struct XncHash *hs, unsigned char *output, size_t len );
int  xnc_read_salt( unsigned char *output, size_t len, FILE *fp );
int  xnc_write_salt( const unsigned char *salt, size_t len, FILE *fp );
int  xnc_xor_conv( const struct Xnc *xnc, struct XncJob *job, struct XncAlgoParams *p );

#endif