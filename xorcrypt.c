#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/file.h>
#include <getopt.h>

#include <windows.h>
#include <bcrypt.h>

#define XNC_NAME    "xorcrypt"
#define XNC_VERSION "26050501"

#define XNC_DEFAULT_EXT "xnc"

#define XNC_F_OVERWRITE 0x00020000
#define XNC_F_VERBOSE   0x00010000

#define XNC_HASH_SIZE   32 // bytes ( アライメント制限で8の倍数 )
#define XNC_KEY_SIZE    32 // bytes
#define XNC_MAX_PASSWD  64 // char
#define XNC_CHAR_SET    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-_*/:;@[]()<>~={}!#$%&'"

#define XNC_BUF_SIZE    16777216 //16MB

#define XNC_KEY_STRECH_TIMES    100000
#define XNC_KEY_STRECH_BUF_SIZE ( XNC_HASH_SIZE +  sizeof( uint32_t ) + XNC_KEY_SIZE + XNC_MAX_PASSWD )

// ストリームに混ぜる定数
#define XNC_SEED_STATE 0xC0DECAFE
#define XNC_SEED_KS    0x00C0FFEE

#ifdef _WIN32
    #define MAX_PATH_LEN MAX_PATH
    #define fseek64 _fseeki64
    #define ftell64 _ftelli64
#else
    #define MAX_PATH_LEN PATH_MAX
    #define fseek64 fseeko
    #define ftell64 ftello
#endif

enum XncRunMode {
    XNC_AUTO = 0,
    XNC_DECODE,
    XNC_ENCODE,
};

enum XncAlgorithm {
    XNC_SIMPLE_XOR = 0,
    XNC_SEED_XOR
};

struct XncBCryptPvd{
    BCRYPT_ALG_HANDLE h_alg;
    PUCHAR hashobj;
    DWORD hashobj_size;
};

struct XncSimpleXor {
    int h_off;
    unsigned char key[XNC_KEY_SIZE];
    unsigned char hash[XNC_HASH_SIZE];
};

struct XncSeedXor{
    int h_off;
    unsigned char state[XNC_HASH_SIZE];
    uint64_t cnt;
    unsigned char key[XNC_KEY_SIZE + XNC_MAX_PASSWD + sizeof( uint64_t )];
};

static struct {
    enum XncRunMode mode;
    enum XncAlgorithm algo;
    uint32_t flags;
    char *ext;
    char *outdir;
    char *passwd;
} xnc;

struct {
    struct XncBCryptPvd sha256;
    struct XncBCryptPvd hmac_sha256;
} st_hashpvd;

static struct {
    char path[MAX_PATH_LEN];
    char dir[MAX_PATH_LEN];
    char file[MAX_PATH_LEN];
} st_path;

static unsigned char st_xnc_buffer[XNC_BUF_SIZE];

typedef int (*XncConvAlgo)( unsigned char*, size_t, void* );

void _info( FILE *stream, const char *format, va_list ap )
{
    vfprintf( stream, format, ap );
    fputc( '\n', stream );
}

void info( const char *format, ... )
{
    if( ! ( xnc.flags & XNC_F_VERBOSE ) ) return;

    va_list ap;
    va_start( ap, format );
    _info( stdout, format, ap );
    va_end( ap );
}

void einfo( const char *format, ... )
{
    va_list ap;
    va_start( ap, format );
    _info( stderr, format, ap );
    va_end( ap );
}

// パスをディレクトリとファイル名に分けて正規化
int get_dir_and_name_by_path( const char *src, char *dst_dir, char *dst_name, size_t max_len )
{
    char buf[MAX_PATH_LEN], *dst, *name = NULL;
    size_t cnt = 0;

    if( max_len < 1 ) return 0;

    dst = buf;

    // '\'を'/'へ置換
    // 重複した'/'をまとめる
    // 最後の'/'の位置（ディレクトリとファイル名の区切り）を保存
    while( cnt < sizeof( buf ) - 1 && ( *dst = *src++ ) != '\0' ){
        if( *dst == '\\' ) *dst = '/';
        if( ( *src == '/' || *src == '\\' ) && *dst == '/' ) continue;
        if( *dst == '/' ) name = dst;
        dst++;
        cnt++;
    }
    *dst = '\0';

    // name（ファイル名候補）にファイル名が入っているか確認し空ならNULL
    // 初めからnameがNULLの場合は区切り文字がないのでファイル名のみのパスとみなして
    // ディレクトリパスを空に
    if( name ){
        *name++ = '\0';
        if( name == dst ){
            name = NULL;
        }
        if( strlen( buf ) + 1 <= max_len ){
            strcpy( dst_dir, buf );
        } else{
            return 0;
        }
    } else{
        dst_dir[0] = '.';
        dst_dir[1] = '\0';
        name = buf;
    }

    if( name ){
        if( strlen( name ) + 1 <= max_len ){
            strcpy( dst_name, name );
        } else{
            return 0;
        }
    } else{
        dst_name[0] = '\0';
    }
    return 1;
}

void hashgen_init()
{
    DWORD result = 0;
    NTSTATUS rv = 0;

    rv |= BCryptOpenAlgorithmProvider( &(st_hashpvd.sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, 0 );
    rv |= BCryptGetProperty( st_hashpvd.sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(st_hashpvd.sha256.hashobj_size), sizeof( DWORD ), &result, 0 );
    st_hashpvd.sha256.hashobj = malloc( st_hashpvd.sha256.hashobj_size );
    if( ! st_hashpvd.sha256.hashobj ){
        rv |= 1;
    }

    rv |= BCryptOpenAlgorithmProvider( &(st_hashpvd.hmac_sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG );
    rv |= BCryptGetProperty( st_hashpvd.hmac_sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(st_hashpvd.hmac_sha256.hashobj_size), sizeof( DWORD ), &result, 0 );
    st_hashpvd.hmac_sha256.hashobj = malloc( st_hashpvd.hmac_sha256.hashobj_size );
    if( ! st_hashpvd.hmac_sha256.hashobj ){
        rv |= 1;
    } 

    if( rv != 0 ){
        einfo( "Failed to initialize SHA256 provider. aborting." );
        exit( 1 );
    }
}

// 終端にNULLを書きこまない
#define sha256( msg, len, dst ) sha256hmac( msg, len, NULL, 0, dst )
void sha256hmac( const unsigned char *msg, DWORD msg_len, unsigned char *key, DWORD key_len, unsigned char *dst )
{
    BCRYPT_ALG_HANDLE h;
    PUCHAR hashobj;
    DWORD hashobj_size;
    BCRYPT_HASH_HANDLE h_hash = NULL;
    NTSTATUS rv = 0;

    if( key ){
        h = st_hashpvd.hmac_sha256.h_alg;
        hashobj = st_hashpvd.hmac_sha256.hashobj;
        hashobj_size = st_hashpvd.hmac_sha256.hashobj_size;
    } else{
        h = st_hashpvd.sha256.h_alg;
        hashobj = st_hashpvd.sha256.hashobj;
        hashobj_size = st_hashpvd.sha256.hashobj_size;  
    }

    rv = BCryptCreateHash( h, &h_hash, hashobj, hashobj_size, key, key_len, 0);
    if( rv == 0 ){
        rv |= BCryptHashData( h_hash, (PUCHAR)msg, msg_len, 0);
        rv |= BCryptFinishHash( h_hash, dst, XNC_HASH_SIZE, 0);
        BCryptDestroyHash( h_hash );
    }
    
    if( rv != 0 ){
        einfo( "Failed to calculate SHA256. aborting." );
        exit( 1 );
    }
}

void hashgen_destroy()
{
    // initは失敗するとexit()するのでここにくるなら初期化できているはず
    BCryptCloseAlgorithmProvider( st_hashpvd.sha256.h_alg, 0 );
    free( st_hashpvd.sha256.hashobj );

    BCryptCloseAlgorithmProvider( st_hashpvd.hmac_sha256.h_alg, 0 );
    free( st_hashpvd.hmac_sha256.hashobj );

    memset( &st_hashpvd, 0, sizeof( st_hashpvd ) );
}

// 終端にNULLを書きこまない
void keygen( unsigned char *buf, size_t len )
{
    const char *charset = XNC_CHAR_SET;
    int cnum = strlen( charset );

    for( int i = 0; i < len; i++ ){
        buf[i] = charset[rand() % cnum];
    }
}

void info_key( const char *label, const unsigned char *hash, size_t len )
{
    if( ! ( xnc.flags & XNC_F_VERBOSE ) ) return;

    if( label ) printf( "%s: ", label );
    for( int i = 0; i < len; i++ ){
        printf( "%c", hash[i] );
    }
    printf( "\n" );
}

void info_hash( const char *label, const unsigned char *hash, size_t len )
{
    if( ! ( xnc.flags & XNC_F_VERBOSE ) ) return;

    if( label ) printf( "%s: ", label );
    for( int i = 0; i < len; i++ ){
        printf( "%02x", hash[i] );
    }
    printf( "\n" );
}

int xor_conv( FILE *src, FILE *dst, int64_t fsize, XncConvAlgo ca, void *ctx )
{
    unsigned char *buf = st_xnc_buffer;
    size_t read_bytes, progress = 0;
    clock_t clock_now, clock_last_notice = 0;

    fseek64( src, 0, SEEK_SET );
    fseek64( dst, 0, SEEK_SET );

    while( progress < fsize ){
        if( xnc.flags & XNC_F_VERBOSE && ( clock_now = clock() ) - clock_last_notice >= CLOCKS_PER_SEC ){
            printf( "\rProgress: %3d%% [%zu / %zu bytes]", (int)( progress * 100 / fsize ), progress, fsize );
            fflush( stdout );
            clock_last_notice = clock_now;
        }

        read_bytes = fread(
            buf,
            sizeof( char ),
            ( fsize - progress < XNC_BUF_SIZE ) ? ( fsize - progress ) : XNC_BUF_SIZE,
            src
        );
        if( ! read_bytes ){
            einfo( "\nFailed to read source file in converting." );
            return 0;
        }
        ca( buf, read_bytes, ctx );
        if( fwrite( buf, sizeof( char ), read_bytes, dst ) != read_bytes ){
            einfo( "\nFailed to write output file in coverting." );
            return 0;
        }
        progress += read_bytes;
    }

    if( xnc.flags & XNC_F_VERBOSE ){
        printf( "\rProgress: 100%% [%zu / %zu bytes]", progress, fsize );
        fflush( stdout );
    }
    printf( "\n" );

    return 1;
}

int parse_args( int argc, char *argv[] )
{
    int mdchk = 0, opt;
    while( ( opt = getopt( argc, argv, "edfvo:x:a:p:" ) ) != -1 )
    {
        switch( opt )
        {
            case 'd':
                xnc.mode = XNC_DECODE;
                mdchk++; //エラーチェック用
                break;
            case 'e':
                xnc.mode = XNC_ENCODE;
                mdchk++; //エラーチェック用
                break;
            case 'a':
                if( strcasecmp( optarg, "xor" ) == 0 ){
                    xnc.algo = XNC_SIMPLE_XOR;
                } else if( strcasecmp( optarg, "seed-xor" ) == 0 ){
                    xnc.algo = XNC_SEED_XOR;
                } else{
                    einfo( "Invalid algorithm specified.\n" );
                    return -1;
                }
                break;
            case 'p': xnc.passwd = optarg;          break;
            case 'o': xnc.outdir = optarg;          break;
            case 'f': xnc.flags |= XNC_F_OVERWRITE; break;
            case 'v': xnc.flags |= XNC_F_VERBOSE;   break;
            case 'x':
                if( optarg[0] != '\0' ) xnc.ext = optarg;
                break;
            default:
                einfo( "Invalid argument: %c\n", opt );
                return -1;
        }
    }

    if( mdchk > 1 ){
        einfo( "Multiple modes specified.\n" );
        return -1;
    }

    if( xnc.passwd && xnc.passwd[0] == '\0' ) xnc.passwd = NULL;

    if( argc < ( optind + 1 ) ){
        einfo( "Xor deNCrypter %s", XNC_VERSION );
        einfo( "Usage: %s [-edfv] [-a xor|seed-xor] [-p passwd] [-o dir] [-x ext] file [file ...]", XNC_NAME );
        return -1;
    }

    return optind;
}

int _algo_simple_xor( unsigned char *buf, size_t buflen, void *ctx )
{
    struct XncSimpleXor *c = (struct XncSimpleXor *)ctx;

    for( size_t i = 0; i < buflen; i++ ){
        if( c->h_off >= XNC_HASH_SIZE ) c->h_off = 0;
        buf[i] ^= c->hash[c->h_off++];
    }

    return 1;
}

#define _XNC_SEED_BUF (sizeof( uint32_t ) + sizeof( uint64_t ) + XNC_HASH_SIZE)
int _algo_seed_xor( unsigned char *buf, size_t buflen, void *ctx )
{
    struct XncSeedXor *c = (struct XncSeedXor *)ctx;
    unsigned char seed[_XNC_SEED_BUF];
    unsigned char ks[XNC_HASH_SIZE];
    uint32_t label;

    for( size_t i = 0; i < buflen; i++ ){
        if( c->h_off == 0 || i == 0 ){ 
            label = XNC_SEED_KS;
            memcpy( (void *)seed, &label, sizeof( label ) );
            memcpy( (void *)seed + sizeof( label ), &(c->cnt), sizeof( c->cnt ) );
            memcpy( (void *)seed + sizeof( label ) + sizeof( c->cnt ), c->state, XNC_HASH_SIZE );
            sha256( seed, _XNC_SEED_BUF, ks );
        }

        buf[i] ^= ks[c->h_off++];
        
        if( c->h_off >= XNC_HASH_SIZE ) c->h_off = 0;

        if( c->h_off == 0 ){
            c->cnt++;

            label = XNC_SEED_STATE;
            memcpy( (void *)seed, &label, sizeof( label ) );
            memcpy( (void *)seed + sizeof( label ), &(c->cnt), sizeof( c->cnt ) );
            sha256( seed, _XNC_SEED_BUF, c->state );
        }        
    }
    return 1;
}
#undef _XNC_SEED_BUF

int simple_xor( FILE *src, FILE *dst, enum XncRunMode mode, size_t src_size )
{
    struct XncSimpleXor ctx;
    unsigned char hash[XNC_HASH_SIZE];

    switch( mode ){
        case XNC_ENCODE:
            keygen( ctx.key, XNC_KEY_SIZE );
            sha256( ctx.key, XNC_KEY_SIZE, hash );
            break;
        case XNC_DECODE:
            fseek64( src, -XNC_HASH_SIZE, SEEK_END );
            fread( hash, sizeof( char ), XNC_HASH_SIZE, src );
            src_size -= XNC_HASH_SIZE;
            break;
        default:
            return 0;
    }
    ctx.h_off = 0;

    if( xnc.passwd ){
        unsigned char seed[XNC_HASH_SIZE + XNC_MAX_PASSWD];
        size_t pass_len = strlen( xnc.passwd );
        memcpy( (void *)seed, hash, XNC_HASH_SIZE );
        memcpy( (void *)seed + XNC_HASH_SIZE, xnc.passwd, pass_len );
        sha256( seed, XNC_HASH_SIZE + pass_len, ctx.hash );
    } else{
        memcpy( ctx.hash, hash, XNC_HASH_SIZE );
    }

    info_hash( "Hash: ", (unsigned char *)ctx.hash, XNC_HASH_SIZE );
    
    // 変換
    xor_conv( src, dst, src_size, _algo_simple_xor, &ctx );

    if( mode == XNC_ENCODE ){
        info( "Added decode key.");
        fwrite( hash, sizeof( char ), XNC_HASH_SIZE, dst );
    }

    return 1;
}

int seed_xor( FILE *src, FILE *dst, enum XncRunMode mode, size_t src_size )
{
    struct XncSeedXor ctx;
    unsigned char key[XNC_KEY_SIZE];
    size_t pass_len = 0;

    switch( mode ){
        case XNC_ENCODE:
            keygen( key, XNC_KEY_SIZE );
            break;
        case XNC_DECODE:
            fseek64( src, -XNC_KEY_SIZE, SEEK_END );
            fread( key, sizeof( char ), XNC_KEY_SIZE, src );
            src_size -= XNC_KEY_SIZE;
            break;
        default:
            return 0;
    }

    memcpy( ctx.key, key, XNC_KEY_SIZE );
    if( xnc.passwd ){
        pass_len = strlen( xnc.passwd );
        if( pass_len > XNC_MAX_PASSWD ) pass_len = XNC_MAX_PASSWD;
        memcpy( ctx.key + XNC_KEY_SIZE, xnc.passwd, pass_len );
    }

    {
        // [HASH] || [i] || [KEY] || [PASSWD]
        unsigned char key_strech[XNC_KEY_STRECH_BUF_SIZE];

        sha256( (unsigned char *)ctx.key, XNC_KEY_SIZE + pass_len, key_strech );
        memcpy( key_strech + XNC_HASH_SIZE + sizeof( uint32_t ), ctx.key, XNC_KEY_SIZE + pass_len );
        for( uint32_t i = 0; i < XNC_KEY_STRECH_TIMES; i++ ){
            memcpy( key_strech + XNC_HASH_SIZE, &i, sizeof( uint32_t ) );
            sha256( key_strech, XNC_HASH_SIZE + sizeof( uint32_t ) + XNC_KEY_SIZE + pass_len, key_strech );
        }
        memcpy( (void *)ctx.state, key_strech, XNC_HASH_SIZE );
    }

    ctx.cnt = 0;

    info_key( "Key: ", (unsigned char *)key, XNC_KEY_SIZE );
    xor_conv( src, dst, src_size, _algo_seed_xor, &ctx );

    if( mode == XNC_ENCODE ){
        info( "Added decode key.");
        fwrite( key, sizeof( char ), XNC_KEY_SIZE, dst );
    }

    return 1;
}

int main( int argc, char *argv[] )
{
    int rv = 0, args_offset, store_len;
    enum XncRunMode mode;
    char *dot, *src_path, *outdir, dst_path[MAX_PATH_LEN];
    FILE *src = NULL, *dst = NULL;
    int64_t src_size;

    xnc.algo   = XNC_SIMPLE_XOR;
    xnc.flags  = 0;
    xnc.ext    = XNC_DEFAULT_EXT;
    xnc.passwd = NULL;
    xnc.outdir = NULL;

    args_offset = parse_args( argc, argv );
    if( args_offset < 0 ) return 1;

    hashgen_init();

    {
        char *algo_name[] = { "xor", "seed-xor" };
        info( "-----------------------------------------------" );
        info( "XOR Algorithm: %s", algo_name[xnc.algo] );

        srand( (unsigned int)time(NULL) ^ ( (unsigned int)clock() << 16 ) );
    }

    for( int offset = args_offset; offset < argc ; offset++ ){
        if( ! get_dir_and_name_by_path( argv[offset], st_path.dir, st_path.file, MAX_PATH_LEN ) ){
            einfo( "Failed to parse source path strings: %s", argv[offset] );
            goto NEXT;
        }

        store_len = snprintf( st_path.path, MAX_PATH_LEN, "%s/%s", st_path.dir, st_path.file );
        if( store_len >= MAX_PATH_LEN ){
            einfo( "Source file path is too long." );
            goto NEXT;
        }

        if( st_path.file[0] == '\0' ){
            einfo( "Empty source file name specified." );
            goto NEXT;
        }

        src_path = st_path.path;
        outdir   = xnc.outdir ? xnc.outdir : st_path.dir;

        info( "-----------------------------------------------" );
        info( "Source file: %s/%s", st_path.dir, st_path.file );

        // 末尾が ".xnc" (xnc.ext) だったら'.'の位置を保存
        dot = strrchr( st_path.file, '.' );
        if( dot && strcasecmp( dot + 1, xnc.ext ) != 0 ){
            dot = NULL;
        }

        // 動作モードを確定
        if( xnc.mode == XNC_AUTO ){
            mode = dot ? XNC_DECODE : XNC_ENCODE;
        } else{
            mode = xnc.mode;
        }

        src = fopen( src_path, "rb" );
        if( ! src ){
            einfo( "Failed to open source file: %s", src_path );
            goto NEXT;
        }

        // ファイルサイズを取得
        fseek64( src, 0, SEEK_END );
        src_size = ftell64( src );

        // 処理に必要な出力パスを取得
        if( mode == XNC_ENCODE ){
            store_len = snprintf( dst_path, MAX_PATH_LEN, "%s/%s.%s", outdir, st_path.file, xnc.ext );
            if( store_len >= MAX_PATH_LEN ){
                einfo( "Filename too long." );
                goto NEXT;
            }
        } else if( mode == XNC_DECODE ){
            if( dot ) *dot = '\0';

            if( src_size < XNC_HASH_SIZE ){
                info( "File size is too small. skipped.");
                goto NEXT;
            }

            store_len = snprintf( dst_path, MAX_PATH_LEN, "%s/%s", outdir, st_path.file );
             if( store_len >= MAX_PATH_LEN ){
                einfo( "Filename too long." );
                goto NEXT;
            }
        } else{
            einfo( "GO DEBUG DUDE\n" );
            goto NEXT;
        }

        // エラーチェック
        if( strcasecmp( src_path, dst_path ) == 0 ){
            einfo( "Source file is same as output file. skipped." );
            goto NEXT;
        }

        info( "Output file: %s", dst_path );
        if( access( dst_path, F_OK ) == 0 && ! ( xnc.flags & XNC_F_OVERWRITE ) ){
            einfo( "Output path is already exists: %s", dst_path );
            goto NEXT;
        }

        dst = fopen( dst_path, "wb" );
        if( ! dst ){
            einfo( "Failed to open output file: %s", dst_path );
            goto NEXT;
        }

        // 変換
        info( "Processing..." );
        switch( xnc.algo ){
            case XNC_SIMPLE_XOR: simple_xor( src, dst, mode, src_size ); break;
            case XNC_SEED_XOR:   seed_xor( src, dst, mode, src_size );   break;
        }

        if( ferror( src ) || ferror( dst ) ){
            einfo( "Some error occured. skipped.");
            fclose( dst );
            remove( dst_path );
            goto NEXT;
        } else{
            fclose( dst );
            fclose( src );
        }

        continue;

        NEXT:
            rv |= 1;
            if( src ) fclose( src );
    }

    hashgen_destroy();

    return rv;
}
