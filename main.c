#include <string.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "info.h"
#include "simple_xor.h"
#include "seed_xor.h"

#define MEMORY_ALIGN_ADDR( align, addr ) ( ( (uintptr_t)( addr ) + ( align ) - 1 ) & ( ~( (uintptr_t)( align ) - 1 ) ) )

struct xnc_file_id {
    uint64_t vid;
    uint64_t fid;
};

// ワイルドカード展開 (Mingw用)
#if defined(_WIN32) && (defined(__MINGW32__) || defined(__MINGW64__))
int _dowildcard = 1;
#endif

static struct Xnc xnc;

#ifdef _WIN32
#include <sysinfoapi.h>
#else
#include <unistd.h>
#endif

static int _get_cpu_cores()
{
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
#else
    return (int)(sysconf(_SC_NPROCESSORS_ONLN));
#endif
}

static int _get_file_uid( const char *path, struct xnc_file_id *id )
{
#ifdef _WIN32
    HANDLE h;
    BY_HANDLE_FILE_INFORMATION fi;

    h = CreateFileA( path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if( h == INVALID_HANDLE_VALUE ) return 0;

    GetFileInformationByHandle( h, &fi );
    id->vid = (uint64_t)fi.dwVolumeSerialNumber;
    id->fid = (uint64_t)(( (uint64_t)fi.nFileIndexHigh << 32 ) | fi.nFileIndexLow);
    CloseHandle( h );

    return 1;
#else
    struct stat st;
    if( stat( path, &st ) != 0 ) return 0;

    id->vid = (uint64_t)st.st_dev;
    id->fid = (uint64_t)st.st_ino;

    return 1;
#endif
}

/* George Marsaglia の Xorshift RNG */
static uint32_t xorshift32( uint32_t *state )
{
	uint32_t x = *state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return ( *state = x );
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

static void _usage( char *path )
{
    char path_dir[PATH_MAX], path_file[PATH_MAX], *name;
    if( _get_dir_and_name_by_path( path, path_dir, path_file, PATH_MAX ) ){
        name = path_file;
    } else{
        name = XNC_NAME;
    }
    einfof( "Xor deNCrypter %s", XNC_VERSION );
    einfof( "Usage: %s [-ednfv] [-a xor|seed-xor] [-p passwd] [-o dir] [-x ext] file [file ...]", name );
}

char *xnc_get_mode_name( enum XncMode mode )
{
    static char *mode_str[] = { "DECODE", "ENCODE" };
    return mode_str[mode];
}

// 終端にNULLを書きこまない
void xnc_salt_seed_gen( uint32_t *xorshift32_seed, unsigned char *buf, size_t len )
{
    while( len-- ) *buf++ = xorshift32( xorshift32_seed ) & 0xFF;
}

void xnc_create_salt( struct XncHash *hs, uint32_t *xorshift32_seed, unsigned char *output, size_t len )
{
    xnc_salt_seed_gen( xorshift32_seed, output, len );
    hash_sha256( hs, output, len, output );
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

static int parse_args( struct Xnc *xnc, int argc, char *argv[] )
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
        xnc->algo.name       = "xor";
        xnc->algo.fn_init    = simple_xor_init;
        xnc->algo.fn_destroy = simple_xor_finish;
        xnc->algo.fn_xor     = simple_xor_work;
    } else if( strcmp( xnc->algo.name, "seed-xor" ) == 0 ){
        xnc->algo.name       = "seed-xor";
        xnc->algo.fn_init    = seed_xor_init;
        xnc->algo.fn_destroy = seed_xor_finish;
        xnc->algo.fn_xor     = seed_xor_work;
    } else{
        einfo( "Unknown algorithm specified.\n" );
        return -1;
    }

    // 引数が足りなければ失敗
    if( argc < ( optind + 1 ) ) return -1;

    return optind;
}

int thread_read( void *argp )
{
    const struct Xnc *xnc = argp;
    struct XncJob *job;
    off_t read;

    while( rqueue_pop( xnc->read, &job, sizeof( job ) ) == 0 ){
        if( ! job ) break;

        read = ( job->fsrc.size - job->fsrc.cur_offset < XNC_BUF_SIZE ) ?
            job->fsrc.size - job->fsrc.cur_offset : XNC_BUF_SIZE;

        job->fsrc.read_bytes = fread( job->buf, 1, read, job->fsrc.fh );
        job->fsrc.cur_offset += job->fsrc.read_bytes;
        if( job->fsrc.read_bytes < XNC_BUF_SIZE && ferror( job->fsrc.fh ) ){
            char *err = "Failed to read source file.";
            queue_try_push( xnc->error, err, strlen( err ) + 1 );
            job->rv = 0x80001001;
            rqueue_push( xnc->idle, &job, sizeof( job ) );
        }

        rqueue_push( xnc->work, &job, sizeof( job ) );
    }

    return 0;
}

int thread_write( void *argp )
{
    const struct Xnc *xnc = argp;
    struct XncJob *job;

    while( rqueue_pop( xnc->write, &job, sizeof( job ) ) == 0 ){
        if( ! job ) break;

        if( fwrite( job->buf, 1, job->fsrc.read_bytes, job->fdst.fh ) != job->fsrc.read_bytes ){
            char *err = "Failed to write output file.";
            queue_try_push( xnc->error, err, strlen( err ) + 1 );
            job->rv = 0x80001002;
            rqueue_push( xnc->idle, &job, sizeof( job ) );
        }

        atomic_store( &(job->progress), (int)( job->fsrc.cur_offset * 100ULL / job->fsrc.size ) );
        
        if( job->fsrc.cur_offset < job->fsrc.size ){
            rqueue_push( xnc->read, &job, sizeof( job ) );
        } else{
            rqueue_push( xnc->idle, &job, sizeof( job ) );
        }
    }

    return 0;

}

int thread_worker( void *argp )
{
    const struct Xnc *xnc = argp;
    struct XncJob *job;

    while( rqueue_pop( xnc->work, &job, sizeof( job ) ) == 0 ){
        if( ! job ) break;

        job->rv = xnc->algo.fn_xor( job->hs, job->buf, ( job->fsrc.read_bytes + 31 ) / 32, job->algo_ctx );
        rqueue_push( xnc->write, &job, sizeof( job ) );
    }

    return 0;
}

static int prepare_to_job( struct Xnc *xnc, struct XncJob *job, char *file )
{
    int store_len;
    char src_path[PATH_MAX];
    char *outdir, *dot, *err;
    struct stat st;

    char path_dir[PATH_MAX], path_file[PATH_MAX];

    if( ! _get_dir_and_name_by_path( file, path_dir, path_file, PATH_MAX ) ){
        err = "Failed to parse input file path: %s";
        queue_try_push( xnc->error, err, strlen( err ) + 1 );
        goto NEXT;
    }

    if( path_file[0] == '\0' ){
        err = "Empty source file name specified.";
        queue_try_push( xnc->error, err, strlen( err ) + 1 );
        goto NEXT;
    }

    store_len = snprintf( src_path, PATH_MAX, "%s/%s", path_dir, path_file );
    if( store_len >= PATH_MAX ){
        err = "Source file path is too long.";
        queue_try_push( xnc->error, err, strlen( err ) + 1 );
        goto NEXT;
    }

    outdir = xnc->outdir ? xnc->outdir : path_dir;

    // 末尾が ".xnc" (xnc.ext) だったら'.'の位置を保存
    dot = strrchr( path_file, '.' );
    if( dot && strcasecmp( dot + 1, xnc->ext ) != 0 ){
        dot = NULL;
    }

    // 動作モードを確定
    if( xnc->flags & XNC_F_AUTODETECT ){
        job->mode = dot ? XNC_DECODE : XNC_ENCODE;
    } else{
        job->mode = xnc->mode;
    }

    if( stat( src_path, &st ) != 0 || ! S_ISREG( st.st_mode ) ){
        goto SKIP;
    }
    job->fsrc.size = st.st_size;

    job->fsrc.fh = fopen( src_path, "rb" );
    if( ! job->fsrc.fh ){
        err = "Failed to open source file: %s";
        queue_try_push( xnc->error, err, strlen( err ) + 1 );
        goto NEXT;
    }

    // 処理に必要な出力パスを取得
    switch( job->mode ){
        case XNC_ENCODE:
            store_len = snprintf( job->fdst.path, PATH_MAX, "%s/%s.%s", outdir, path_file, xnc->ext );
            if( store_len >= PATH_MAX ){
                err = "Filename too long.";
                queue_try_push( xnc->error, err, strlen( err ) + 1 );
                goto NEXT;
            }
            break;
        case XNC_DECODE:
            if( dot ) *dot = '\0';
            // ハッシュサイズ+1バイトでもデータがない場合はxncファイルではない
            if( job->fsrc.size < XNC_HASH_SIZE + 1 ){
                err = "File is too small. Skipped.";
                queue_try_push( xnc->error, err, strlen( err ) + 1 );
                goto NEXT;
            }
            store_len = snprintf( job->fdst.path, PATH_MAX, "%s/%s", outdir, path_file );
            if( store_len >= PATH_MAX ){
                err = "Filename too long.";
                queue_try_push( xnc->error, err, strlen( err ) + 1 );
                goto NEXT;
            }
            break;
    }

    // エラーチェック
    if( strcasecmp( src_path, job->fdst.path ) == 0 ){
        err = "Source and output paths are the same. Skipped.";
        queue_try_push( xnc->error, err, strlen( err ) + 1 );
        goto NEXT;
    }

    if( access( job->fdst.path, F_OK ) == 0 ){
        struct xnc_file_id fuid;
        if( ! _get_file_uid( job->fdst.path, &fuid ) ){
            err = "Failed to get output file id.";
            queue_try_push( xnc->error, err, strlen( err ) + 1 );
            goto NEXT;
        }
        for( unsigned int i = 0; i < xnc->id_cnt; i++ ){
            if( memcmp( &fuid, xnc->ids + i, sizeof( fuid ) ) == 0 ){
                err = "Output file already exists as input file. Skipped.";
                queue_try_push( xnc->error, err, strlen( err ) + 1 );
                goto NEXT;
            }
        }
        if( ! ( xnc->flags & XNC_F_OVERWRITE ) ){
            err = "Output path already exists.";
            queue_try_push( xnc->error, err, strlen( err ) + 1 );
            goto NEXT;
        }
    }
    
    // 変換
    if( job->fsrc.size > 0 ){
        job->fdst.fh = fopen( job->fdst.path, "wb" );
        if( ! job->fdst.fh ){
            err = "Failed to open output file: %s";
            queue_try_push( xnc->error, err, strlen( err ) + 1 );
            goto NEXT;
        }
    } else{
        goto NEXT;
    }

    // jobを初期化
    job->fsrc.cur_offset = 0;
    job->fsrc.read_bytes = 0;
    job->rv = 0;
    atomic_store( &(job->progress), 0 );
    
    return 0;

    NEXT:
        if( job->fsrc.fh ) fclose( job->fsrc.fh );
        return 1;
    
    SKIP:
        return -1;
}

static int finish_job( struct XncJob *job )
{
    if( job->rv == 0 ){
        fclose( job->fdst.fh );
    } else{
        fclose( job->fdst.fh );
        remove( job->fdst.path );
    }
    fclose( job->fsrc.fh );
    return job->rv;
}

int main( int argc, char *argv[] )
{
    int rv = 0, args_offset, slot = 0, inprogress = 0, lnoff = 0;
    char **file;

    struct {
        ThrwCtx *list;
        int max;
    } thr;

    struct {
        struct XncJob *slots;
        int max;
    } jobs;

    // 引数を処理
    args_offset = parse_args( &xnc, argc, argv );
    if( args_offset < 0 ){
        _usage( argv[0] );
        return 1;
    }

    // 衝突検知用のファイル識別子リストを作成
    xnc.id_cnt = argc - args_offset;
    xnc.ids = malloc( sizeof( struct xnc_file_id ) * xnc.id_cnt );
    if( ! xnc.ids ){
        einfo( "Failed to allocate file id table." );
        return 1;
    }
    for( unsigned int i = 0; i < xnc.id_cnt; i++ ){
        if( ! _get_file_uid( argv[args_offset + i], xnc.ids + i ) ){
            einfof( "No such file or directory: \"%s\"", argv[args_offset + i] );
            return 1;
        }
    }

    // ファイルリストの先頭を取得
    file = argv + args_offset;

    // スレッドとジョブのテーブルを確保
    jobs.max   = _get_cpu_cores();
    thr.max    = jobs.max + 2;

    // ジョブコンテキストテーブルを確保
    jobs.slots = calloc( jobs.max, sizeof( struct XncJob ) );
    if( ! jobs.slots ){
        einfo( "Failed to allocate jobs table." );
        return 1;
    }

    // スレッドコンテキストを確保
    thr.list = malloc( sizeof( ThrwCtx ) * thr.max );
    if( ! thr.list ){
        einfo( "Failed to allocate threads context." );
        return 1;
    }

    // ジョブ用の作業バッファを確保
    xnc.buf_addr = malloc( XNC_BUF_SIZE * jobs.max + XNC_BUF_ALIGN );
    if( ! xnc.buf_addr ){
        einfo( "Failed to allocate working buffer." );
        return 1;
    }

    // ジョブ用作業領域をアラインを揃えて設定
    // ジョブ用ハッシュコンテキストを初期化
    // ジョブ用簡易乱数シード初期化
    jobs.slots[0].buf        = (unsigned char *)MEMORY_ALIGN_ADDR( XNC_BUF_ALIGN, xnc.buf_addr );
    jobs.slots[0].hs         = hash_init();
    jobs.slots[0].xorshift32 = (uint32_t)time(NULL); 
    if( jobs.slots[0].xorshift32 == 0 ) jobs.slots[0].xorshift32 = 1;
    for( int i = 1; i < jobs.max; i++ ){
        jobs.slots[i].buf        = jobs.slots[i - 1].buf + XNC_BUF_SIZE;
        jobs.slots[i].hs         = hash_init();
        jobs.slots[i].xorshift32 = ( ( jobs.slots[0].xorshift32 << 16 ) | ( jobs.slots[0].xorshift32 >>16 ) ) ^ (uint32_t)i;
        if( jobs.slots[i].xorshift32 == 0 ) jobs.slots[i].xorshift32 = i + 1;
    }

    // I/Oスレッドとワーカースレッドを生成
    if(
        ! thrw_new( thread_read,  (void *)&xnc, thr.list ) ||
        ! thrw_new( thread_write, (void *)&xnc, thr.list + 1 )
    ){
        einfo( "Failed to initialize I/O thread." );
        return 1;
    }
    for( int i = 2; i < thr.max; i++ ){
        if( ! thrw_new( thread_worker, (void *)&xnc, thr.list + i ) ){
            einfo( "Failed to initialize workerthread." );
            return 1;
        }
    }
    
    // キュー
    if(
        ! ( xnc.read  = rqueue_new( sizeof( void* ), jobs.max ) ) ||
        ! ( xnc.work  = rqueue_new( sizeof( void* ), jobs.max ) ) ||
        ! ( xnc.write = rqueue_new( sizeof( void* ), jobs.max ) ) ||
        ! ( xnc.idle  = rqueue_new( sizeof( void* ), jobs.max ) ) ||
        ! ( xnc.error = queue_new( 10 ) )
    ){
        einfo( "Failed to allocate queue." );
        return 1;
    }

    // 進捗表示準備
   // if( xnc.flags & XNC_F_VERBOSE ) printf( "\n" );

    // ジョブを使えるだけ使う
    while( *file && slot < jobs.max ){
        void *err;
        struct XncJob *j = jobs.slots + slot;

        if( prepare_to_job( &xnc, j, *file ) == 0 ){
            xnc.algo.fn_init( &xnc, j );
            fseek( j->fsrc.fh, 0, SEEK_SET );
            if( rqueue_push( xnc.read, &j, sizeof( j ) ) == 0 ){
                inprogress++;
                slot++;
            }
        }

        while( ( err = queue_try_pop( xnc.error ) ) ){
            char *errmsg = (char *)err;
            printf( "%s\n", errmsg );
            queue_giveback( err );
        }
        
        file++;
    }

    // ジョブが終わったら新しいジョブを設定してキュー
    lnoff = 0;
    while( *file || inprogress ){
        struct XncJob *j;
        void *err;
        //スレッドからの終了通知を待つ
        if( rqueue_timed_pop( xnc.idle, &j, sizeof( j ), 1000 ) == 0 ){
            // ジョブ1つ完了
            inprogress--;

            xnc.algo.fn_destroy( &xnc, j );

            if( finish_job( j ) != 0 ){
                err = strrchr( j->fdst.path, '/' ) + 1;
                queue_try_push( xnc.error, err, strlen( err ) + 1 );
            }

            if( *file ){
                if( prepare_to_job( &xnc, j, *file ) == 0 ){
                    xnc.algo.fn_init( &xnc, j );
                    fseek( j->fsrc.fh, 0, SEEK_SET );
                    if( rqueue_push( xnc.read, &j, sizeof( j ) ) == 0 ){
                        inprogress++;
                    }
                }
                file++;
            }
        }

        // 進捗表示
        if( xnc.flags & XNC_F_VERBOSE ){
            char str[128], *path;
            size_t pos = 0, filled, left;
            int progress;

            if( lnoff ){
                pos = snprintf( str, sizeof( str ), "\x1b[%dA", lnoff );
                write( STDOUT_FILENO, str, pos );
            }

            for( int i = 0; i < jobs.max; i++ ){
                progress = atomic_load( &(jobs.slots[i].progress) );
                filled = progress * XNC_PROGBAR_LEN / 100;
                left  = progress == 100 ? 0 : XNC_PROGBAR_LEN - filled - 1;
                pos = snprintf( str, sizeof( str ), "\x1b[2K%s %2d [\x1b[32m", xnc_get_mode_name( jobs.slots[i].mode ), i );
                memset( str + pos, '=', filled );
                pos += filled;

                if( progress < 100 ) str[pos++] = '>';
                
                memset( str + pos, ' ', left );
                pos += left;

                if( strlen( jobs.slots[i].fdst.path ) > 32 ){
                    path = jobs.slots[i].fdst.path + strlen( jobs.slots[i].fdst.path ) - 32;
                } else{
                    path = jobs.slots[i].fdst.path;
                }
                pos += snprintf( str + pos, sizeof( str ) - pos,"\x1b[0m] %3d%% %-32.32s\n", progress, path );
                write( STDOUT_FILENO, str, pos );
            }
            lnoff = jobs.max;
        }
        
        while( ( err = queue_try_pop( xnc.error ) ) ){
            char *errmsg = (char *)err;
            write( STDERR_FILENO, errmsg, strlen( errmsg ) );
            write( STDERR_FILENO, "\n", 1 );
            queue_giveback( err );
            lnoff++;
        }
    }

    // 子スレッドはキューからNULLを受け取ると終了するので、スレッドの数だけNULLをキューに入れる
    {
        struct XncJob *j = NULL;
        rqueue_push( xnc.read,  &j, sizeof( j ) );
        rqueue_push( xnc.write, &j, sizeof( j ) );
        for( int i = 0; i < jobs.max; i++ ){
            rqueue_push( xnc.work,  &j, sizeof( j ) );
        }
    }

    // スレッドの終了を待ってから後片付け
    for( int i = 0; i < thr.max; i++ ){
        thrw_wait_for_exit( thr.list + i );
        thrw_destroy( thr.list + i );
    }

    rqueue_destroy( xnc.read );
    rqueue_destroy( xnc.write );
    rqueue_destroy( xnc.work );
    rqueue_destroy( xnc.idle );
    queue_destroy( xnc.error );

    for( int i = 0; i < jobs.max; i++ ) hash_destroy( jobs.slots[i].hs );
    free( thr.list );
    free( jobs.slots );
    free( xnc.buf_addr );
    free( xnc.ids );

    return rv;
}
