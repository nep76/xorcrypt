#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <io.h>

#include <unistd.h>
#include <getopt.h>

#include <windows.h>
#include <bcrypt.h>

#define XNC_NAME    "xorcrypt"
#define XNC_VERSION "260504"

#define XNC_DEFAULT_EXT "xnc"

#define XNC_F_OVERWRITE 0x00020000
#define XNC_F_VERBOSE   0x00010000

#define XNC_BUF_SIZE    10485760 //10MB
#define XNC_KEY_SIZE    32 //bytes
#define XNC_HASH_SIZE   32 //bytes
#define XNC_CHAR_SET    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-_*/:;@[]()<>~={}!#$%&'"

#ifdef _WIN32
    #define MAX_PATH_LEN MAX_PATH
    #define fseek64 _fseeki64
    #define ftell64 _ftelli64
#else
    #define MAX_PATH_LEN PATH_MAX
    #define fseek64 fseeko
    #define ftell64 ftello
#endif

enum RunMode {
    XNC_AUTO = 0,
    XNC_DECODE,
    XNC_ENCODE,
};

static struct {
    enum RunMode mode;
    uint32_t flags;
    char *ext;
    char *outdir;
} xnc;

static struct {
    char path[MAX_PATH_LEN];
    char dir[MAX_PATH_LEN];
    char file[MAX_PATH_LEN];
} st_path;

static unsigned char st_xnc_buffer[XNC_BUF_SIZE];

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
        if( strlen( buf ) + 1 < max_len ){
            strcpy( dst_dir, buf );
        } else{
            return 0;
        }
    } else{
        dst_dir[0] = '\0';
        name = buf;
    }

    if( name ){
        if( strlen( name ) + 1 < max_len ){
            strcpy( dst_name, name );
        } else{
            return 0;
        }
    } else{
        dst_name[0] = '\0';
    }
    return 1;
}

void sha256( const unsigned char* input, DWORD inputLen, unsigned char* output ) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashObjectSize = 0, cbData = 0;
    PUCHAR hashObject = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
    return;

    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(DWORD), &cbData, 0);
    hashObject = (PUCHAR)malloc(hashObjectSize);

    BCryptCreateHash(hAlg, &hHash, hashObject, hashObjectSize, NULL, 0, 0);
    BCryptHashData(hHash, (PUCHAR)input, inputLen, 0);
    BCryptFinishHash(hHash, output, 32, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    free(hashObject);
}

char *keygen( char *buf, size_t len )
{
    const char *charset = XNC_CHAR_SET;
    int cnum = strlen( charset );

    for( int i = 0; i < len - 1; i++ ){
        buf[i] = charset[rand() % cnum];
    }
    buf[len - 1] = '\0';

    return buf;
}

int xor( unsigned char *buf, size_t buflen, unsigned char *key, size_t key_len )
{
    int cnt;
    for( cnt = 0; cnt < buflen; cnt++ ){
        buf[cnt] ^= key[cnt % key_len];
    }
    return cnt;
}

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

void info_hash( const char *label, const unsigned char *hash, size_t len )
{
    if( ! ( xnc.flags & XNC_F_VERBOSE ) ) return;

    if( label ) printf( "%s: ", label );
    for( int i = 0; i < len; i++ ){
        printf( "%02x", hash[i] );
    }
    printf( "\n" );
}

void xor_conv( FILE *src, FILE *dst, int64_t fsize, unsigned char *key, size_t key_len )
{
    unsigned char *buf = st_xnc_buffer;
    size_t buf_len, chunks, final_len, progress = 0;

    fseek64( src, 0, SEEK_SET );
    fseek64( dst, 0, SEEK_SET );

    // 一度に処理するチャンクのサイズと数、最後の端数を計算
    buf_len   = (size_t)( XNC_BUF_SIZE / key_len ) * key_len;
    chunks    = (size_t)( fsize / buf_len );
    final_len = fsize - buf_len * chunks;


    while( chunks-- ){
        if( xnc.flags & XNC_F_VERBOSE ){
            printf( "\rProgress: %3d%% [%zu / %zu bytes]", (int)( progress * 100 / fsize ), progress, fsize );
            fflush( stdout );
        }
        fread( buf, sizeof( char ), buf_len, src );
        xor( buf, buf_len, key, key_len );
        fwrite( buf, sizeof( char ), buf_len, dst );
        progress += buf_len;
    }

    if( final_len ){
        fread( buf, sizeof( char ), final_len, src );
        xor( buf, final_len, key, key_len );
        fwrite( buf, sizeof( char ), final_len, dst );

        progress += final_len;
        if( xnc.flags & XNC_F_VERBOSE ){
            printf( "\rProgress: 100%% [%zu / %zu bytes]", progress, fsize );
            fflush( stdout );
        }
    }

    info( "" );
}

int parse_args( int argc, char *argv[] )
{
    int ret = 0, opt;
    while( ( opt = getopt( argc, argv, "edfvo:x:" ) ) != -1 )
    {
        switch( opt )
        {
            case 'd':
                xnc.mode = XNC_DECODE;
                ret++; //エラーチェック用
                break;
            case 'e':
                xnc.mode = XNC_ENCODE;
                ret++; //エラーチェック用
                break;
            case 'f': xnc.flags |= XNC_F_OVERWRITE; break;
            case 'v': xnc.flags |= XNC_F_VERBOSE;   break;
            case 'o': xnc.outdir = optarg;          break;
            case 'x':
                if( strcmp( optarg, "" ) != 0 ) xnc.ext = optarg;
                break;
            default:
                einfo( "Invalid argument: %c\n", opt );
                return -1;
        }
    }
    if( ret > 1 ){
        einfo( "Multiple modes specified.\n" );
        return -1;
    }

    if( argc < ( optind + 1 ) ){
        einfo( "Xor deNCrypter %s", XNC_VERSION );
        einfo( "Usage: %s [-edfv] [-o dir] [-x ext] file [file ...]", XNC_NAME );
        return -1;
    }
    return optind;
}

int main( int argc, char *argv[] )
{
    int args_offset, store_len;
    enum RunMode mode;
    char *dot, *src_path, *outdir, dst_path[MAX_PATH_LEN], key[XNC_KEY_SIZE], hash[XNC_HASH_SIZE];
    FILE *src, *dst;
    int64_t src_size;

    xnc.flags  = 0;
    xnc.ext    = XNC_DEFAULT_EXT;
    xnc.outdir = NULL;

    args_offset = parse_args( argc, argv );
    if( args_offset < 0 ) return 1;

    srand( (unsigned int)time( NULL ) );

    for( int offset = args_offset; offset < argc ; offset++ ){
        if( ! get_dir_and_name_by_path( argv[offset], st_path.dir, st_path.file, MAX_PATH_LEN ) ){
            einfo( "Failed to parse srouce path strings: %s", argv[offset] );
            continue;
        }

        store_len = snprintf( st_path.path, MAX_PATH_LEN, "%s/%s", st_path.dir, st_path.file );
        if( store_len >= MAX_PATH_LEN ){
            einfo( "Source file path is too long." );
            continue;
        }

        if( st_path.file[0] == '\0' ){
            einfo( "Empty source file name specified." );
            continue;
        }

        src_path = st_path.path;
        outdir   = xnc.outdir ? xnc.outdir : st_path.dir;

        info( "-----------------------------------------------" );
        info( "Source file: %s/%s", st_path.dir, st_path.file );

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
            continue;
        }

        fseek64( src, 0, SEEK_END );
        src_size = ftell64( src );

        // 処理に必要な出力パスとハッシュ値を取得
        if( mode == XNC_ENCODE ){
            store_len = snprintf( dst_path, MAX_PATH_LEN, "%s/%s.%s", outdir, st_path.file, xnc.ext );
            if( store_len >= MAX_PATH_LEN ){
                einfo( "Filename too long." );
                goto NEXT;
            }

            keygen( key, XNC_KEY_SIZE );
            info( "Key: %s", key );

            sha256( (unsigned char *)key, (DWORD)XNC_KEY_SIZE, (unsigned char *)hash );
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

            fseek64( src, -XNC_HASH_SIZE, SEEK_END );
            fread( hash, sizeof( char ), XNC_HASH_SIZE, src );

            src_size -= XNC_HASH_SIZE;
        } else{
            einfo( "GO DEBUG DUDE\n" );
            goto NEXT;
        }
        info_hash( "Hash", (unsigned char *)hash, XNC_HASH_SIZE );

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
        xor_conv( src, dst, src_size, (unsigned char *)hash, XNC_HASH_SIZE );
        if( mode == XNC_ENCODE ){
            info( "Added hash for decode.");
            fwrite( hash, sizeof( char ), XNC_HASH_SIZE, dst );
        }

        fclose( dst );
        fclose( src );

        continue;

        NEXT:
            if( src ) fclose( src );
    }
}
