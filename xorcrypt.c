#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <io.h>

#include <unistd.h>
#include <getopt.h>

#include <windows.h>
#include <bcrypt.h>

// つくった
#define VERSION "250417"

#define M_OP_DECRYPT      0x00000004
#define M_OP_ENCRYPT      0x00000002
#define M_OP_AUTO         0x00000001
#define M_OP_UNDEF        0x00000000

#define F_ALLOW_OVERWRITE 0x00010000

#define STR_DEFAULT_EXT "xnc"


#define BUF_SIZE     10485760 //10MB
#define KEY_SIZE     32 //bytes
#define HASH_SIZE    32 //bytes

#define CHAR_SET     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-_*/:;@[]()<>~={}!#$%&'"

static bool _verbose = false;
static unsigned char _xor_buffer[BUF_SIZE];

void sha256sum( const unsigned char* input, DWORD inputLen, unsigned char* output ) {
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
    const char *charset = CHAR_SET;
    int cnum = strlen( charset );

    for( int i = 0; i < len - 1; i++ ){
        buf[i] = charset[rand() % cnum];
    }
    buf[len - 1] = '\0';

    return buf;
}

int calc_xor( unsigned char *buf, size_t buflen, unsigned char *key, size_t key_len )
{
    int cnt;
    for( cnt = 0; cnt < buflen; cnt++ ){
        buf[cnt] ^= key[cnt % key_len];
    }
    return cnt;
}

void info( const char *format, ... )
{
    if( ! _verbose ) return;

    va_list ap;
    va_start( ap, format );
    vprintf( format, ap );
    va_end( ap );
    printf( "\n" );
}

void info_hash( const char *label, const unsigned char *hash, size_t len )
{
    if( ! _verbose ) return;

    printf( "%s", label );
    for( int i = 0; i < len; i++ ){
        printf( "%02x", hash[i] );
    }
    printf( "\n" );
}

// 動作モード、フラグ、入力ファイルパス、出力ファイルパス、キー、拡張子を渡して
// ファイルを一つ操作する。AUTOモード時は入力ファイルパスによって動作が変化し、
// ファイル名にextの拡張子が付いていれば暗号化ファイルと見なして複合モードへ、
// そうでなければ平文ファイルと見なして暗号化モードへ切り替わる。
// また、自動時は出力ファイルパスは出力ディレクトリパスとなる。
// 未指定の場合は入力ファイルと同じディレクトリとなる。
// 暗号化時は拡張子を付与して、そうでなければ拡張子を外したファイル名で生成する。
// 指定したキーは暗号化時のみ使用され、複合時は不要なため無視される。
//
// 逆にAUTO以外のモード時は出力ファイルパスへキーを使って指定動作を行う。
// このときextの拡張子設定は無視される。
int dencrypt(
    unsigned int mode,
    unsigned int flags,
    const char *arg_src,
    const char *arg_dst,
    const char *raw_key,
    const char *ext
){
    char src_path[MAX_PATH];
    char dst_path[MAX_PATH];
    char *src_filename = NULL;
    unsigned char key_buffer[KEY_SIZE];
    unsigned char key[HASH_SIZE];

    FILE *src, *dst;
    struct _stat64 src_stat, dst_stat;
    __int64 file_size;
    size_t buf_len, final_len;
    unsigned int chunks;

    //入力ファイル名を正規化
    GetFullPathNameA( arg_src, MAX_PATH, src_path, &src_filename );

    // 自動モードなら出力パスを生成してモードを特定
    if( mode == M_OP_AUTO ){
        char *dot;

        if( ext == NULL ){
            fprintf( stderr, "Extension name(-x option) is required in AUTO mode.");
            return 1;
        }

        info( "Checking operation mode..." );

        if( arg_dst ){
            if( strlen( arg_dst ) + 1 + strlen( src_filename ) < MAX_PATH ){
                strcpy( dst_path, arg_dst );
                strcat( dst_path, "\\");
                strcat( dst_path, src_filename );
            } else{
                fprintf( stderr, "Destination path is too logn.");
            }
        } else{
            strcpy( dst_path, src_path );
        }
        dot = strrchr( dst_path, '.' );
        if( dot && dot != dst_path && dot != &(dst_path[strlen(dst_path) - 1]) && strcasecmp( ++dot, ext ) == 0 ){
            mode = M_OP_DECRYPT;
            *dot = '\0';
        } else{
            mode = M_OP_ENCRYPT;
            if( strlen( dst_path ) + 1 + strlen( ext ) < sizeof( dst_path ) ){
                strcat( dst_path, "." );
                strcat( dst_path, ext );
            } else{
                fprintf( stderr, "Destination path is too long." );
                return 1;
            }
        }
    }
    
    //エラーチェック
    if ( strcasecmp( src_path, dst_path ) == 0 ){
        fprintf( stderr, "DST_FILE_PATH is same as SRC_FILE_PATH: %s", src_path );
        return 1;
    }

    if ( ! (flags & F_ALLOW_OVERWRITE)  && _stati64( dst_path, &dst_stat) == 0 ){
        fprintf( stderr, "Destination path is already exists: %s", dst_path );
        return 1;
    }

    src = fopen( src_path, "rb" );
    if( ! src ){
        fprintf( stderr, "Failed to open SRC_FILE_PATH: %s", src_path );
        return 1;
    }

    dst = fopen( dst_path, "wb" );
    if( ! dst ){
        fprintf( stderr, "Failed to open DST_FILE_PATH: %s", dst_path );
        return 1;
    }

    if( _fstati64( fileno( src ), &src_stat ) != 0 ){
        fprintf( stderr, "Failed to get fstat for SRC_FILE_PATH." );
        return 1;
    }

    //キーを取得
    //複合モードでは対象のファイルの末尾に直接記録されてるハッシュ値を読み出す。
    //暗号化モードでは生成された(あるいは指定された)キーを元にハッシュ値を算出。
    if( mode == M_OP_DECRYPT ){
        info( "Decrypt." );
        _fseeki64( src, -((__int64)sizeof( key )), SEEK_END );
        fread( key, sizeof( char ), sizeof( key ), src );
        _fseeki64( src, 0, SEEK_SET );
        file_size = src_stat.st_size - sizeof( key );
    } else if( mode == M_OP_ENCRYPT ){
        info( "Encrypt." );
        if( ! raw_key ) raw_key = keygen( (char *)key_buffer, sizeof( key_buffer ) );
        info( "Raw key: %s", raw_key );
        sha256sum( (unsigned char *)raw_key, strlen( raw_key ), key );
        file_size = src_stat.st_size;
    } else{
        fprintf( stderr, "GO DEBUG DUDE." );
        return 1;
    }
    info_hash( "Hash key: ", key, sizeof( key ) );

    // 一度に処理するチャンクのサイズと数、最後の端数を計算
    buf_len   = (size_t)( BUF_SIZE / sizeof( key ) ) * sizeof( key );
    chunks    = (size_t)( file_size / buf_len );
    final_len = file_size - buf_len * chunks;

    // データに対しハッシュ値でXOR
    info( "Input : %s", src_path );
    info( "Output: %s", dst_path );
    while( chunks-- ){
        fread( _xor_buffer, sizeof( char ), buf_len, src );
        calc_xor( _xor_buffer, buf_len, key, sizeof( key ) );
        fwrite( _xor_buffer, sizeof( char ), buf_len, dst );
    }

    if( final_len ){
        fread( _xor_buffer, sizeof( char ), final_len, src );
        calc_xor( _xor_buffer, final_len, key, sizeof( key ) );
        fwrite( _xor_buffer, sizeof( char ), final_len, dst );
    }

    //暗号化モードでは複合時用にファイル末尾にハッシュ値をそのまま書きこみ
    //複合時はこれをそのまま読みだして使う=パスワードを覚えなくていい
    if( mode == M_OP_ENCRYPT ){
        fwrite( key, sizeof( char ), sizeof( key ), dst );
    }

    fclose( src );
    fclose( dst );

    return 0;
}

int main( int argc, char *argv[] )
{
    const char *wdir = NULL;
    const char *raw_key = NULL;
    const char *ext = STR_DEFAULT_EXT;

    unsigned int mode = M_OP_UNDEF, flags = 0;

    int ret = 0, opt;
    while( ( opt = getopt( argc, argv, "edafvw:k:x:" ) ) != -1 )
    {
        switch( opt )
        {
            case 'd':
                if( mode != M_OP_UNDEF ){
                    fprintf( stderr, "The operation mode is set to multiple." );
                    return 1;
                }
                mode = M_OP_DECRYPT;
                break;
            case 'e':
                if( mode != M_OP_UNDEF ){
                    fprintf( stderr, "The operation mode is set to multiple." );
                    return 1;
                }
                mode = M_OP_ENCRYPT;
                break;
            case 'a':
                break;
            case 'f':
                flags |= F_ALLOW_OVERWRITE;
                break;
            case 'v':
                _verbose = true;
                break;
            case 'w':
                wdir = optarg;
                break;
            case 'k':
                raw_key = optarg;
                break;
            case 'x':
                if( strcmp( optarg, "" ) == 0 ){
                    ext = NULL;
                } else{
                    ext = optarg;
                }
                break;
            default:
                fprintf( stderr, "Invalid argument: %c", opt );
                return 1;
        }
    }
    if( mode == M_OP_UNDEF ) mode = M_OP_AUTO;

    if( argc < ( optind + 1 ) ){
        fprintf( stderr, "Xor deNCrypter %s [%s %s]\n", VERSION, __DATE__, __TIME__ );
        fprintf( stderr, "Usage: %s [-e | -d | -a(-a)] [-fv] [-w OUTPUT_DIR(AUTO MODE ONLY)] [-k RAW_KEY] [-x extension name for auto mode(%s)] SRC_FILE_PATH [FILE_PATH ...]", argv[0], STR_DEFAULT_EXT );
        return 1;
    } 

    srand( (unsigned int)time( NULL ) );

    if( mode == M_OP_AUTO ){
        char dst_dir[MAX_PATH];
        struct _stat64 dir_stat;

        if( wdir ){
           GetFullPathNameA( wdir, MAX_PATH, dst_dir, NULL );
            
            if( _stati64( dst_dir, &dir_stat ) != 0 || ! S_ISDIR( dir_stat.st_mode ) || access( dst_dir, W_OK ) != 0 ){
                fprintf( stderr, "Invalid output directory." );
                return 1;
            }
            wdir = dst_dir;
        }
        for( int offset = 0; optind + offset < argc ; offset++ ){
            info( "-----------------------------------------------" );
            ret += dencrypt( mode, flags, argv[optind + offset], wdir, raw_key, ext );
        }
    } else{
        ret += dencrypt( mode, flags, argv[optind + 1], argv[optind + 2], raw_key, NULL );
    }

    return ret;
}
