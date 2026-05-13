#include "xorcrypt.h"

#include <string.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#include <getopt.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "hash.h"
#include "info.h"

#include "simple_xor.h"
#include "seed_xor.h"

static unsigned char st_xnc_buffer[XNC_BUF_SIZE] __attribute__((section(".bss")));

static void _show_progress( off_t cur, off_t max )
{
    printf( "\rProgress: %3d%% [%" PRId64 " / %" PRId64 " bytes]", (int)( cur * 100 / max ), (int64_t)cur, (int64_t)max );
    fflush( stdout );
}

// パスをディレクトリとファイル名に分けて正規化
static int _get_dir_and_name_by_path( const char *src, char *dst_dir, char *dst_name, size_t max_len )
{
    char buf[PATH_MAX], *dst, *name = NULL;
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

// 終端にNULLを書きこまない
void xnc_salt_seed_gen( unsigned char *buf, size_t len )
{
    while( len-- ) *buf++ = rand() & 0xFF;
}

void xnc_create_salt( struct XncContext *xnc, unsigned char *output, size_t len )
{
    XNC_HASH_SUPPRESS_UNUSED_WARN( xnc );

    xnc_salt_seed_gen( output, len );
    hash_sha256( xnc, output, len, output );
}

int xnc_read_salt( unsigned char *output, size_t len, FILE *fp )
{
    size_t rv = 0;
    if( fseek( fp, -( len ), SEEK_END ) == 0 ){
        rv = fread( output, 1, len, fp );
    }
    return (int)( rv / len );
}

int xnc_write_salt( const unsigned char *salt, size_t len, FILE *fp )
{
    size_t rv = 0;
    if( fseek( fp, 0, SEEK_END ) == 0 ){
        rv = fwrite( salt, 1, len, fp );
    }
    return (int)( rv / len );
}

// success = return 0
int xnc_xor_conv( struct XncContext *xnc, FILE *src, off_t fsize, FILE *dst, struct XncAlgoParams *p )
{
    unsigned char *buf = st_xnc_buffer;
    off_t progress = 0;
    size_t read_bytes;
    clock_t clock_now, clock_last_notice = 0;

    if( fseek( src, 0, SEEK_SET ) != 0 || fseek( dst, 0, SEEK_SET ) != 0 ) return 0x1;

    while( progress < fsize ){
        // 進捗表示
        if( xnc->flags & XNC_F_VERBOSE && ( clock_now = clock() ) - clock_last_notice >= CLOCKS_PER_SEC ){
            _show_progress( progress, fsize );
            clock_last_notice = clock_now;
        }

        // XNC_BUF_SIZE読み出す
        // 残りがXNC_BUF_SIZE以下なら残りのサイズに合わせる
        read_bytes = fread(
            buf,
            1,
            ( fsize - progress < XNC_BUF_SIZE ) ? ( fsize - progress ) : XNC_BUF_SIZE,
            src
        );
        if( ! read_bytes ){
            einfo( "\nFailed to read source file while converting." );
            return 0x2;
        }

        // 必ず32バイト境界で読みだしたことにする
        p->xor( xnc, buf, ( read_bytes + 31 ) / 32, p->ctx );

        // 実際の読み出しサイズのみ書きこむ
        if( fwrite( buf, 1, read_bytes, dst ) != read_bytes ){
            einfo( "\nFailed to write output file while converting." );
            return 0x4;
        }
        progress += read_bytes;
    }

    if( xnc->flags & XNC_F_VERBOSE ){
        _show_progress( fsize, fsize );
        printf( "\n" );
    }

    return 0;
}

static int parse_args( struct XncContext *xnc, int argc, char *argv[] )
{
    int mdchk = 0, opt;
    while( ( opt = getopt( argc, argv, "edfvo:x:a:p:n" ) ) != -1 ){
        switch( opt ){
            case 'd':
                xnc->mode = XNC_DECODE;
                mdchk++; //エラーチェック用
                break;
            case 'e':
                xnc->mode = XNC_ENCODE;
                mdchk++; //エラーチェック用
                break;
            case 'a':
                for( int i = 0; optarg[i] != '\0'; i++ ) optarg[i] = tolower( optarg[i] );
                xnc->algo.name = optarg;
                break;
            case 'p': xnc->passwd.string = optarg;   break;
            case 'o': xnc->outdir = optarg;          break;
            case 'f': xnc->flags |= XNC_F_OVERWRITE; break;
            case 'v': xnc->flags |= XNC_F_VERBOSE;   break;
            case 'x':
                if( optarg[0] != '\0' ) xnc->ext = optarg;
                break;
            case 'n':
                xnc->flags |= XNC_F_NO_STRETCH;
                break;
            default:
                einfof( "Invalid argument: %c\n", opt );
                return -1;
        }
    }

    // モード選択に矛盾がないかチェック
    if( mdchk == 0 ){
        xnc->flags |= XNC_F_AUTODETECT;
    } else if( mdchk > 1 ){
        einfo( "Multiple modes specified.\n" );
        return -1;
    }

    // 拡張子が未設定ならデフォルト値
    if( ! xnc->ext ) xnc->ext = XNC_DEFAULT_EXT;

    // パスワードが空文字列ならなし
    if( xnc->passwd.string ){
        if( xnc->passwd.string[0] == '\0' ){
            xnc->passwd.length = 0;
            xnc->passwd.string = NULL;
        } else{
            xnc->passwd.length = strlen( xnc->passwd.string );
            if( xnc->passwd.length > XNC_MAX_PASSWD ){
                xnc->passwd.length = XNC_MAX_PASSWD;
            }
        }
    }

    // 変換アルゴリズムを特定
    if( ! xnc->algo.name || strcmp( xnc->algo.name, "xor" ) == 0 ){
        xnc->algo.name = "xor";
        xnc->algo.func = simple_xor;
    } else if( strcmp( xnc->algo.name, "seed-xor" ) == 0 ){
        xnc->algo.name = "seed-xor";
        xnc->algo.func = seed_xor;
    } else{
        einfo( "Invalid algorithm specified.\n" );
        return -1;
    }

    // 引数が足りなければ失敗
    if( argc < ( optind + 1 ) ) return -1;

    return optind;
}

int main( int argc, char *argv[] )
{
    int rv = 0, args_offset, store_len;
    char src_path[PATH_MAX], dst_path[PATH_MAX];
    char path_dir[PATH_MAX], path_file[PATH_MAX];
    char *dot, *outdir;
    FILE *src = NULL, *dst = NULL;
    off_t src_size;

    struct XncContext xnc = { 0 };
    
    hash_init( &xnc );

    args_offset = parse_args( &xnc, argc, argv );
    if( args_offset < 0 ){
        char *name;
        if( _get_dir_and_name_by_path( argv[0], path_dir, path_file, PATH_MAX ) ){
            name = path_file;
        } else{
            name = XNC_NAME;
        }
        einfof( "Xor deNCrypter %s", XNC_VERSION );
        einfof( "Usage: %s [-ednfv] [-a xor|seed-xor] [-p passwd] [-o dir] [-x ext] file [file ...]", name );
        return 1;
    }

    xnc.buf = st_xnc_buffer;

    srand( (unsigned int)time( NULL ) ^ ( (unsigned int)clock() << 16 ) );

    for( int offset = args_offset; offset < argc ; offset++ ){
        src = NULL;
        dst = NULL;
        if( ! _get_dir_and_name_by_path( argv[offset], path_dir, path_file, PATH_MAX ) ){
            einfof( "Failed to parse source path strings: %s", argv[offset] );
            goto NEXT;
        }

        if( path_file[0] == '\0' ){
            einfo( "Empty source file name specified." );
            goto NEXT;
        }

        store_len = snprintf( src_path, PATH_MAX, "%s/%s", path_dir, path_file );
        if( store_len >= PATH_MAX ){
            einfo( "Source file path is too long." );
            goto NEXT;
        }

        outdir = xnc.outdir ? xnc.outdir : path_dir;

        info( &xnc, "-----------------------------------------------" );
        infof( &xnc, "Source file: %s", src_path );

        // 末尾が ".xnc" (xnc.ext) だったら'.'の位置を保存
        dot = strrchr( path_file, '.' );
        if( dot && strcasecmp( dot + 1, xnc.ext ) != 0 ){
            dot = NULL;
        }

        // 動作モードを確定
        if( xnc.flags & XNC_F_AUTODETECT ){
            xnc.mode = dot ? XNC_DECODE : XNC_ENCODE;
        }

        src = fopen( src_path, "rb" );
        if( ! src ){
            einfof( "Failed to open source file: %s", src_path );
            goto NEXT;
        }

        // ファイルサイズを取得
        if( fseek( src, 0, SEEK_END ) < 0 )    goto NEXT;
        if( ( src_size = ftello( src ) ) < 0 ) goto NEXT;

        // 処理に必要な出力パスを取得
        switch( xnc.mode ){
            case XNC_ENCODE:
                store_len = snprintf( dst_path, PATH_MAX, "%s/%s.%s", outdir, path_file, xnc.ext );
                if( store_len >= PATH_MAX ){
                    einfo( "Filename too long." );
                    goto NEXT;
                }
                break;
            case XNC_DECODE:
                if( dot ) *dot = '\0';

                // ハッシュサイズ+1バイトでもデータがない場合はxncファイルではない
                if( src_size < XNC_HASH_SIZE + 1 ){
                    einfo( "File is too small. Skipped.");
                    goto NEXT;
                }

                store_len = snprintf( dst_path, PATH_MAX, "%s/%s", outdir, path_file );
                if( store_len >= PATH_MAX ){
                    einfo( "Filename too long." );
                    goto NEXT;
                }
                break;
        }

        // エラーチェック
        if( strcasecmp( src_path, dst_path ) == 0 ){
            einfo( "Source and output paths are the same. Skipped." );
            goto NEXT;
        }

        infof( &xnc, "Output file: %s", dst_path );
        if( access( dst_path, F_OK ) == 0 && ! ( xnc.flags & XNC_F_OVERWRITE ) ){
            einfof( "Output path already exists: %s", dst_path );
            goto NEXT;
        }

        
        // 変換
        if( src_size > 0 ){
            dst = fopen( dst_path, "wb" );
            if( ! dst ){
                einfof( "Failed to open output file: %s", dst_path );
                goto NEXT;
            }

            infof( &xnc, "Processing %s ...", xnc.algo.name );
            if(
                xnc.algo.func( &xnc, src, src_size, dst ) != 0 ||
                ferror( src ) ||
                ferror( dst )
            ){
                fclose( dst );
                remove( dst_path );
                goto NEXT;
            }
            fclose( dst );
        } else{
            einfo( "Source file is empty. Skipped." );
        }

        fclose( src );

        continue;

        NEXT:
            einfo( "Some error occurred. Skipped.");
            rv |= 1;
            if( src ) fclose( src );
    }

    hash_destroy( &xnc );

    return rv;
}
