#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/file.h>
#include <getopt.h>

#define XNC_NAME    "xorcrypt"
#define XNC_VERSION "26050700"

#define XNC_DEFAULT_EXT "xnc"

#define XNC_F_OVERWRITE 0x00020000
#define XNC_F_VERBOSE   0x00010000

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

static struct {
    enum XncRunMode mode;
    enum XncAlgorithm algo;
    uint32_t flags;
    char *mode_str;
    char *ext;
    char *outdir;
    char *passwd;
} xnc;

struct {
    struct XncBCryptPvd sha256;
    struct XncBCryptPvd hmac_sha256;
} st_bcpvd;

static struct {
    char path[MAX_PATH_LEN];
    char  dir[MAX_PATH_LEN];
    char file[MAX_PATH_LEN];
} st_path;

typedef int (*XncConvAlgo)( unsigned char*, size_t, void* );

static unsigned char st_xnc_buffer[XNC_BUF_SIZE];

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

    rv |= BCryptOpenAlgorithmProvider( &(st_bcpvd.sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, 0 );
    rv |= BCryptGetProperty( st_bcpvd.sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(st_bcpvd.sha256.hashobj_size), sizeof( DWORD ), &result, 0 );
    st_bcpvd.sha256.hashobj = malloc( st_bcpvd.sha256.hashobj_size );
    if( ! st_bcpvd.sha256.hashobj ){
        rv |= 1;
    }

    rv |= BCryptOpenAlgorithmProvider( &(st_bcpvd.hmac_sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG );
    rv |= BCryptGetProperty( st_bcpvd.hmac_sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(st_bcpvd.hmac_sha256.hashobj_size), sizeof( DWORD ), &result, 0 );
    st_bcpvd.hmac_sha256.hashobj = malloc( st_bcpvd.hmac_sha256.hashobj_size );
    if( ! st_bcpvd.hmac_sha256.hashobj ){
        rv |= 1;
    } 

    if( rv != 0 ){
        einfo( "Failed to initialize SHA256 provider. aborting." );
        exit( 1 );
    }
}

// 終端にNULLを書きこまない
#define sha256( msg, len, dst ) _sha256( msg, len, NULL, 0, dst, &(st_bcpvd.sha256) )
#define sha256hmac( msg, msg_len, key, key_len, dst ) _sha256( msg, msg_len, key, key_len, dst, &(st_bcpvd.hmac_sha256) )
void _sha256( const unsigned char *msg, DWORD msg_len, unsigned char *key, DWORD key_len, unsigned char *dst, struct XncBCryptPvd *pvd )
{
    BCRYPT_HASH_HANDLE h_hash = NULL;
    NTSTATUS rv = 0;

    rv = BCryptCreateHash( pvd->h_alg, &h_hash, pvd->hashobj, pvd->hashobj_size, key, key_len, 0);
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
    BCryptCloseAlgorithmProvider( st_bcpvd.sha256.h_alg, 0 );
    free( st_bcpvd.sha256.hashobj );

    BCryptCloseAlgorithmProvider( st_bcpvd.hmac_sha256.h_alg, 0 );
    free( st_bcpvd.hmac_sha256.hashobj );

    memset( &st_bcpvd, 0, sizeof( st_bcpvd ) );
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

int xor_conv( FILE *src, FILE *dst, uint64_t fsize, XncConvAlgo ca, void *ctx )
{
    unsigned char *buf = st_xnc_buffer;
    uint64_t progress = 0;
    size_t read_bytes;
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

        // 必ず32バイト境界で読みだしたことにする
        ca( buf, ( read_bytes + 31 ) / 32, ctx );

        // 実際の読み出しサイズのみ書きこむ
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
    while( ( opt = getopt( argc, argv, "edfvo:x:a:p:" ) ) != -1 ){
        switch( opt ){
            case 'd':
                xnc.mode = XNC_DECODE;
                mdchk++; //エラーチェック用
                break;
            case 'e':
                xnc.mode = XNC_ENCODE;
                mdchk++; //エラーチェック用
                break;
            case 'a':
                for( int i = 0; optarg[i] != '\0'; i++ ) optarg[i] = tolower( optarg[i] );
                if( strcmp( optarg, "xor" ) == 0 ){
                    xnc.algo = XNC_SIMPLE_XOR;
                } else if( strcmp( optarg, "seed-xor" ) == 0 ){
                    xnc.algo = XNC_SEED_XOR;
                } else{
                    einfo( "Invalid algorithm specified.\n" );
                    return -1;
                }
                xnc.mode_str = optarg;
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

int _algo_simple_xor( unsigned char *restrict buf, size_t blocks, void *ctx )
{
    struct XncSimpleXor *c = (struct XncSimpleXor *)ctx;

    for( size_t i = 0; i < blocks; i++ ){
        for( int j = 0; j < sizeof( c->hash ); j++ ){
            buf[j] ^= c->hash[j];
        }
        buf += sizeof( c->hash );
    }

    return 1;
}

int _algo_seed_xor( unsigned char *restrict buf, size_t blocks, void *ctx )
{
    struct XncSeedXor *c = (struct XncSeedXor *)ctx;
    unsigned char ks[XNC_HASH_SIZE];
    struct XncSeedXorMsg msg;

    for( size_t i = 0; i < blocks; i++ ){
        msg.label_be = xnc_be32( XNC_SEED_KS );
        msg.cnt_be   = xnc_be64( c->cnt );
        sha256hmac( (unsigned char *)&msg, sizeof( msg ), c->state, sizeof( c->state ), ks );

        for( int j = 0; j < XNC_HASH_SIZE; j++ ){
            buf[j] ^= ks[j];
        }
        buf += XNC_HASH_SIZE;

        c->cnt++;
        msg.label_be = xnc_be32( XNC_SEED_STATE );
        msg.cnt_be   = xnc_be64( c->cnt );
        sha256hmac( (unsigned char *)&msg, sizeof( msg ), c->state, sizeof( c->state ), c->state ); 
    }
    return 1;
}

int simple_xor( FILE *src, FILE *dst, enum XncRunMode mode, size_t src_size )
{
    struct XncSimpleXor ctx;
    unsigned char hash[XNC_HASH_SIZE];

    switch( mode ){
        case XNC_ENCODE:
            keygen( ctx.salt, sizeof( ctx.salt ) );
            sha256( ctx.salt, sizeof( ctx.salt ), hash );
            break;
        case XNC_DECODE:
            fseek64( src, -( sizeof( hash ) ), SEEK_END );
            fread( hash, sizeof( char ), sizeof( hash ), src );
            src_size -= sizeof( hash );
            break;
        default:
            return 0;
    }

    // パスワードが設定されている場合はキーとパスワードを合わせて
    // もう一度ハッシュ化したものを最終的なキーにする
    if( xnc.passwd ){
        size_t pass_len = strlen( xnc.passwd );

        struct {
            char hash[XNC_HASH_SIZE];
            char passwd[XNC_MAX_PASSWD];
        } __attribute__((packed)) seed;

        memcpy( (void *)seed.hash, hash, sizeof( seed.hash ) );
        memcpy( (void *)seed.passwd, xnc.passwd, pass_len );
        sha256( (unsigned char *)&seed, sizeof( seed.hash ) + pass_len, ctx.hash );
    } else{
        memcpy( ctx.hash, hash, sizeof( hash ) );
    }

    info_hash( "Hash", (unsigned char *)ctx.hash, sizeof( ctx.hash ) );
    
    // 変換
    xor_conv( src, dst, src_size, _algo_simple_xor, &ctx );

    if( mode == XNC_ENCODE ){
        info( "Added decode key.");
        fwrite( hash, sizeof( char ), sizeof( hash ), dst );
    }

    return 1;
}

int seed_xor( FILE *src, FILE *dst, enum XncRunMode mode, size_t src_size )
{
    struct XncSeedXor ctx;
    unsigned char salt[XNC_SALT_SIZE];

    ctx.cnt = 0;

    switch( mode ){
        case XNC_ENCODE:
            keygen( salt, sizeof( salt ) );
            break;
        case XNC_DECODE:
            fseek64( src, -( sizeof( salt ) ), SEEK_END );
            fread( salt, sizeof( char ), sizeof( salt ), src );
            src_size -= sizeof( salt );
            break;
        default:
            return 0;
    }

    {
        // key_strechは SHA256 をin-place（入力と出力に同じポインタを指定）で更新するバッファ。
        // CNG/OpenSSLのSHA256は入力を読み終えてから出力を書くためin-placeでも安全。
        // 初回はstateの代わりにlabel（4バイト）を入れるので、未使用領域をゼロクリアしている。

        uint32_t label_be = xnc_be32( XNC_SEED_STATE );
        uint32_t i = 0;
        size_t pass_len = 0;
        struct XncSeedXorMsg msg;

        // [HASH] || [i] || [KEY] || [PASSWD]
        struct {
            unsigned char state[XNC_HASH_SIZE];
            uint32_t i_be;
            unsigned char key[XNC_SALT_SIZE];
            unsigned char passwd[XNC_MAX_PASSWD];
        } __attribute__((packed)) strech;
        
        memset( strech.state, 0, sizeof( strech.state ) );     // 本来32バイトのstateを入れる場所に
        memcpy( strech.state, &label_be, sizeof( label_be ) ); // 代わりにlabelを挿入
        strech.i_be = xnc_be32( i );
        memcpy( strech.key, salt, sizeof( salt ) );
        if( xnc.passwd ){
            pass_len = strlen( xnc.passwd );
            memcpy( strech.passwd, xnc.passwd, pass_len );
        }
        sha256( (unsigned char *)&strech, ( sizeof( strech ) - sizeof( strech.passwd ) ) + pass_len, strech.state );
        for( ; i < XNC_STRECH_TIMES; i++ ){
            strech.i_be = xnc_be32( i );
            sha256hmac(
                (unsigned char *)&strech,
                sizeof( strech ) - sizeof( strech.passwd ) + pass_len,
                strech.state,
                sizeof( strech.state),
                strech.state
            );
        }

        msg.label_be = label_be;
        msg.cnt_be = xnc_be64( ctx.cnt );
        sha256hmac( (unsigned char *)&msg, sizeof( msg ), strech.state, sizeof( strech.state ), ctx.state );
    }

    info_key( "Key", (unsigned char *)salt, sizeof( salt ) );
    xor_conv( src, dst, src_size, _algo_seed_xor, &ctx );

    if( mode == XNC_ENCODE ){
        info( "Added decode key.");
        fwrite( salt, sizeof( char ), sizeof( salt ), dst );
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

    info( "-----------------------------------------------" );
    info( "XOR Algorithm: %s", xnc.mode_str );

    srand( (unsigned int)time( NULL ) ^ ( (unsigned int)clock() << 16 ) );

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
