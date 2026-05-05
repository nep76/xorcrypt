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

#define XNC_BUF_SIZE    10485760 //10MB

#define XNC_KEY_STRECH_TIMES    100000
#define XNC_KEY_STRECH_BUF_SIZE ( XNC_HASH_SIZE +  sizeof( uint32_t ) + XNC_KEY_SIZE + XNC_MAX_PASSWD )

// ストリームに混ぜる定数
#define XNC_SEED_STATE     0xC0DECAFE
#define XNC_SEED_KEYSTREAM 0x00C0FFEE

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

struct XncSimpleXor {
    char key[XNC_KEY_SIZE];
    char hash[XNC_HASH_SIZE];
};

struct XncSeedXor{
    char state[XNC_HASH_SIZE];
    char key[XNC_KEY_SIZE + XNC_MAX_PASSWD + sizeof( uint64_t )];
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
    BCRYPT_ALG_HANDLE prvd;
    PUCHAR hashobj;
    DWORD hashobj_size;
} st_bcrypt;

static struct {
    char path[MAX_PATH_LEN];
    char dir[MAX_PATH_LEN];
    char file[MAX_PATH_LEN];
} st_path;

static unsigned char st_xnc_buffer[XNC_BUF_SIZE];

typedef int (*XncConvAlgo)( unsigned char*, size_t, size_t, void* );

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

void sha256_init()
{
    DWORD result = 0;
    NTSTATUS rv = 0;

    rv |= BCryptOpenAlgorithmProvider( &(st_bcrypt.prvd), BCRYPT_SHA256_ALGORITHM, NULL, 0 );
    rv |= BCryptGetProperty( st_bcrypt.prvd, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(st_bcrypt.hashobj_size), sizeof( DWORD ), &result, 0 );
    st_bcrypt.hashobj = malloc( st_bcrypt.hashobj_size );
    if( ! st_bcrypt.hashobj ){
        rv |= 1;
    }

    if( rv != 0 ){
        einfo( "Failed to initialize SHA256 provider. aborting." );
        exit( 1 );
    }
}

// 終端にNULLを書きこまない
void sha256( const unsigned char *src, DWORD src_len, unsigned char *dst )
{
    BCRYPT_HASH_HANDLE h_hash = NULL;
    NTSTATUS rv = 0;

    rv = BCryptCreateHash( st_bcrypt.prvd, &h_hash, st_bcrypt.hashobj, st_bcrypt.hashobj_size, NULL, 0, 0);
    if( rv == 0 ){
        rv |= BCryptHashData( h_hash, (PUCHAR)src, src_len, 0);
        rv |= BCryptFinishHash( h_hash, dst, 32, 0);
        BCryptDestroyHash( h_hash );
    }
    
    if( rv != 0 ){
        einfo( "Failed to calculate SHA256. aborting." );
        exit( 1 );
    }
}

void sha256_destroy()
{
    if( st_bcrypt.prvd )    BCryptCloseAlgorithmProvider( st_bcrypt.prvd, 0 );
    if( st_bcrypt.hashobj ) free( st_bcrypt.hashobj );

    st_bcrypt.prvd         = NULL;
    st_bcrypt.hashobj      = NULL;
    st_bcrypt.hashobj_size = 0;
}

// 終端にNULLを書きこまない
char *keygen( char *buf, size_t len )
{
    const char *charset = XNC_CHAR_SET;
    int cnum = strlen( charset );

    for( int i = 0; i < len; i++ ){
        buf[i] = charset[rand() % cnum];
    }

    return buf;
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
        ca( buf, read_bytes, progress, ctx );
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

    if( xnc.passwd ){
        if( xnc.algo == XNC_SIMPLE_XOR ){
            info( "Warning: xor mode does not use the password during decoding, so the password has no effect." );
        }
        if( xnc.passwd[0] == '\0' ) xnc.passwd = NULL;
    }

    if( argc < ( optind + 1 ) ){
        einfo( "Xor deNCrypter %s", XNC_VERSION );
        einfo( "Usage: %s [-edfv] [-a xor|seed-xor] [-p passwd] [-o dir] [-x ext] file [file ...]", XNC_NAME );
        return -1;
    }

    return optind;
}

int _algo_simple_xor( unsigned char *buf, size_t buflen, size_t offset, void *ctx )
{
    struct XncSimpleXor *c = (struct XncSimpleXor *)ctx;

    for( size_t i = 0; i < buflen; i++ ){
        buf[i] ^= c->hash[( offset + i ) % XNC_HASH_SIZE];
    }

    return 1;
}

#define _XNC_SEED_BUF (sizeof( uint32_t ) + sizeof( uint64_t ) + XNC_HASH_SIZE)
int _algo_seed_xor( unsigned char *buf, size_t buflen, size_t offset, void *ctx )
{
    struct XncSeedXor *c = (struct XncSeedXor *)ctx;
    char keystream[XNC_HASH_SIZE];
    size_t h_offset;
    uint64_t cnt;

    for( size_t i = 0; i < buflen; i++ ){
        h_offset = ( offset + i ) % XNC_HASH_SIZE;
        if( h_offset == 0 || i == 0 ){
            // [LABEL] || [COUNTER] || [STATE]
            char seed[_XNC_SEED_BUF];
            uint32_t label;
            cnt = ( offset + i ) / XNC_HASH_SIZE;

            memcpy( (void *)seed + sizeof( uint32_t ) + sizeof( uint64_t ), c->state, XNC_HASH_SIZE );
            memcpy( (void *)seed + sizeof( uint32_t ), &cnt, sizeof( uint64_t ) );

            label = XNC_SEED_STATE;
            memcpy( (void *)seed, &label, sizeof( uint32_t ) );
            sha256( (unsigned char *)seed, _XNC_SEED_BUF, (unsigned char *)c->state );

            label = XNC_SEED_KEYSTREAM;
            memcpy( (void *)seed, &label, sizeof( uint32_t ) );
            sha256( (unsigned char *)seed, _XNC_SEED_BUF, (unsigned char *)keystream );
        }
        buf[i] ^= keystream[h_offset];
    }

    return 1;
}
#undef _XNC_SEED_BUF

int simple_xor( FILE *src, FILE *dst, enum XncRunMode mode, size_t src_size )
{
    struct XncSimpleXor ctx;
    char hash[XNC_HASH_SIZE];

    switch( mode ){
        case XNC_ENCODE:
            keygen( ctx.key, XNC_KEY_SIZE );
            sha256( (unsigned char *)ctx.key, XNC_KEY_SIZE, (unsigned char *)hash );
            break;
        case XNC_DECODE:
            fseek64( src, -XNC_HASH_SIZE, SEEK_END );
            fread( hash, sizeof( char ), XNC_HASH_SIZE, src );
            src_size -= XNC_HASH_SIZE;
            break;
        default:
            return 0;
    }
    
    if( xnc.passwd ){
        // 一応パスワードをキー生成に使うが実質無意味
        // (XNC_SIMPLE_XORモードはデコード時に末尾のキーをそのまま使う実装なのでパスワードが使われない)
        char pass_key[XNC_HASH_SIZE + XNC_MAX_PASSWD];
        size_t pass_len = strlen( xnc.passwd );
        if( pass_len > XNC_MAX_PASSWD ) pass_len = XNC_MAX_PASSWD;
        memcpy( pass_key, hash, XNC_HASH_SIZE );
        memcpy( pass_key + XNC_HASH_SIZE, xnc.passwd, pass_len );
        sha256( (unsigned char *)pass_key, XNC_HASH_SIZE + pass_len, (unsigned char *)ctx.hash );
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
    char key[XNC_KEY_SIZE];
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
        unsigned char key_strech[XNC_KEY_STRECH_BUF_SIZE] = { 0 };

        sha256( (unsigned char *)ctx.key, XNC_KEY_SIZE + pass_len, key_strech );
        memcpy( key_strech + XNC_HASH_SIZE + sizeof( uint32_t ), ctx.key, XNC_KEY_SIZE + pass_len );
        for( uint32_t i = 0; i < XNC_KEY_STRECH_TIMES; i++ ){
            memcpy( key_strech + XNC_HASH_SIZE, &i, sizeof( uint32_t ) );
            sha256( key_strech, XNC_KEY_STRECH_BUF_SIZE, key_strech );
        }
        memcpy( (void *)ctx.state, key_strech, XNC_HASH_SIZE );
    }
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

    sha256_init();

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

    sha256_destroy();

    return rv;
}
