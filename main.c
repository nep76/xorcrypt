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
    einfof( "Usage: %s [-ednfv] [-o dir] [-x ext] [-p passwd] [-a xor|seed-xor] file [file ...]", name );
}

char *xnc_get_mode_name( struct XncJob *job )
{
    static char *mode_str[] = { "DECODE", "ENCODE" };
    return mode_str[job->mode];
}

void xnc_set_algo_ctx( struct XncJob *job, void *ctx )
{
    job->algo_ctx = ctx;
}

/* George Marsaglia の Xorshift RNG */
static uint64_t _xorshift64( uint64_t *state )
{
	uint64_t x = *state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	return ( *state = x * RNG_WEYL_CONST64 );
}

// 終端にNULLを書きこまない
void xnc_salt_seed_gen( uint64_t *xorshift_seed, unsigned char *buf, size_t len )
{
    while( len-- ) *buf++ = _xorshift64( xorshift_seed ) & 0xFF;
}

void xnc_create_salt( struct XncJob *job, unsigned char *output, size_t len )
{
    xnc_salt_seed_gen( &job->xorshift, output, len );
    hash_sha256( job->hs, output, len, output );
}

int xnc_read_salt( struct XncJob *job, unsigned char *output, size_t len )
{
    size_t rv = 0;
    if( fseek( job->fsrc.fh, -( len ), SEEK_END ) == 0 ){
        if( ( rv = fread( output, len, 1, job->fsrc.fh ) ) ) job->fsrc.size -= len;
    }
    return rv;
}

int xnc_write_salt( struct XncJob *job, const unsigned char *salt, size_t len )
{
    size_t rv = 0;
    if( fseek( job->fdst.fh, 0, SEEK_END ) == 0 ){
        rv = fwrite( salt, len, 1, job->fdst.fh );
    }
    return rv;
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
            job->rv = -1;
            qinfof_try_push( xnc->error, "Failed to read input file: %s", "" );
            rqueue_push( xnc->idle, &job, sizeof( job ) );
            continue;
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
            char *file = strrchr( job->fdst.path, '/' );
            if( ! file ) file = job->fdst.path;
            qinfof_try_push( xnc->error, "Failed to write output file: %s", file );
            rqueue_push( xnc->idle, &job, sizeof( job ) );
            continue;
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
        if( job->rv == 0 ){
            rqueue_push( xnc->write, &job, sizeof( job ) );
        } else{
            qinfof_try_push( xnc->error, "Failed to %s job (code %x): %s", xnc->algo.name, job->rv, job->fdst.path );
            rqueue_push( xnc->idle, &job, sizeof( job ) );
        }
    }

    return 0;
}

static int prepare_to_job( struct Xnc *xnc, struct XncJob *job, char *file )
{
    int store_len;
    char src_path[PATH_MAX];
    char *outdir, *dot;
    struct stat st;

    char path_dir[PATH_MAX], path_file[PATH_MAX];

    if( ! _get_dir_and_name_by_path( file, path_dir, path_file, PATH_MAX ) ){
        qinfof_try_push( xnc->error, "Failed to parse input path: %s", file );
        goto SKIP;
    }

    if( path_file[0] == '\0' ){
        qinfof_try_push( xnc->error, "Input path is directory: %s", path_dir );
        goto SKIP;
    }

    store_len = snprintf( src_path, PATH_MAX, "%s/%s", path_dir, path_file );
    if( store_len >= PATH_MAX ){
        qinfof_try_push( xnc->error, "Input file path is too long: %s", path_file );
        goto SKIP;
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
        qinfof_try_push( xnc->error, "Failed to open input file: %s", src_path );
        goto NEXT;
    }

    // 処理に必要な出力パスを取得
    switch( job->mode ){
        case XNC_ENCODE:
            store_len = snprintf( job->fdst.path, PATH_MAX, "%s/%s.%s", outdir, path_file, xnc->ext );
            if( store_len >= PATH_MAX ){
                qinfo_try_push( xnc->error, "Filename too long." );
                goto NEXT;
            }
            break;
        case XNC_DECODE:
            if( dot ) *dot = '\0';
            // ハッシュサイズ+1バイトでもデータがない場合はxncファイルではない
            if( job->fsrc.size < XNC_HASH_SIZE + 1 ){
                qinfo_try_push( xnc->error, "File is too small. Skipped." );
                goto NEXT;
            }
            store_len = snprintf( job->fdst.path, PATH_MAX, "%s/%s", outdir, path_file );
            if( store_len >= PATH_MAX ){
                qinfo_try_push( xnc->error, "Filename too long." );
                goto NEXT;
            }
            break;
    }

    // エラーチェック
    if( strcasecmp( src_path, job->fdst.path ) == 0 ){
        qinfo_try_push( xnc->error, "Source and output paths are the same. Skipped." );
        goto NEXT;
    }

    if( access( job->fdst.path, F_OK ) == 0 ){
        struct xnc_file_id fuid;
        if( ! _get_file_uid( job->fdst.path, &fuid ) ){
            qinfo_try_push( xnc->error, "Failed to get output file id." );
            goto NEXT;
        }
        for( int i = 0; i < xnc->id_cnt; i++ ){
            if( memcmp( &fuid, xnc->ids + i, sizeof( fuid ) ) == 0 ){
                qinfof_try_push( xnc->error, "Output file already exists as input file: %s", job->fdst.path );
                goto NEXT;
            }
        }
        if( ! ( xnc->flags & XNC_F_OVERWRITE ) ){
            qinfo_try_push( xnc->error, "Output path already exists." );
            goto NEXT;
        }
    }
    
    // 変換
    if( job->fsrc.size > 0 ){
        job->fdst.fh = fopen( job->fdst.path, "wb" );
        if( ! job->fdst.fh ){
            qinfof_try_push( xnc->error, "Failed to open output file: %s", job->fdst.path );
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
    for( int i = 0; i < xnc.id_cnt; i++ ){
        if( ! _get_file_uid( argv[args_offset + i], xnc.ids + i ) ){
            einfof( "No such file or directory: \"%s\"", argv[args_offset + i] );
            return 1;
        }
    }

    // ファイルリストの先頭を取得
    file = argv + args_offset;
    
    // スレッドとジョブのテーブルを確保
    jobs.max = _get_cpu_cores();
    if( jobs.max > xnc.id_cnt ) jobs.max = xnc.id_cnt;

    thr.max  = jobs.max + 2;

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
    jobs.slots[0].buf      = (unsigned char *)MEMORY_ALIGN_ADDR( XNC_BUF_ALIGN, xnc.buf_addr );
    jobs.slots[0].xorshift = ((uint64_t)time(NULL) << 32 ) ^ (uint64_t)clock();
    for( int i = 0; i < jobs.max; i++ ){
        jobs.slots[i].buf        = jobs.slots[0].buf + ( XNC_BUF_SIZE * i );
        jobs.slots[i].hs         = hash_init();
        jobs.slots[i].xorshift   = jobs.slots[0].xorshift ^ ( RNG_WEYL_CONST64 * ( (uint64_t)i + 1 ) );
        if( jobs.slots[i].xorshift == 0 ) jobs.slots[i].xorshift = i + 1;

        // 偏りを紛らわすために5回くらい回す
        for( int j = 0; j < 5; j++ ) _xorshift64( &jobs.slots[i].xorshift );
    }

    // キューを作成
    if(
        ! ( xnc.read  = rqueue_new( sizeof( void* ), jobs.max ) ) ||
        ! ( xnc.work  = rqueue_new( sizeof( void* ), jobs.max ) ) ||
        ! ( xnc.write = rqueue_new( sizeof( void* ), jobs.max ) ) ||
        ! ( xnc.idle  = rqueue_new( sizeof( void* ), jobs.max ) ) ||
        ! ( xnc.error = rqueue_new( XNC_ERRBUF_SIZE, 5 ) )
    ){
        einfo( "Failed to allocate rqueue." );
        return 1;
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
    
    // 進捗表示準備
   fflush( stdout );
   fflush( stderr );

    // ジョブを使えるだけ使う
    while( *file && slot < jobs.max ){
        struct XncJob *j = jobs.slots + slot;
        char errmsg[XNC_ERRBUF_SIZE];

        if( prepare_to_job( &xnc, j, *file ) == 0 ){
            if( ( j->rv = xnc.algo.fn_init( &xnc, j ) ) == 0 ){
                fseek( j->fsrc.fh, 0, SEEK_SET );
                if( rqueue_push( xnc.read, &j, sizeof( j ) ) == 0 ){
                    inprogress++;
                    slot++;
                }
            } else{
                finish_job( j );
                qinfof_try_push( xnc.error, "Failed to %s init (code %x): %s", xnc.algo.name, j->rv, *file );
            }
        }

        while( rqueue_try_pop( xnc.error, errmsg, sizeof( errmsg ) ) == 0 ){
            write( STDERR_FILENO, errmsg, strlen( errmsg ) );
        }
        
        file++;
    }

    // ジョブが終わったら新しいジョブを設定してキュー
    lnoff = 0;
    while( *file || inprogress ){
        struct XncJob *j;
        char errmsg[XNC_ERRBUF_SIZE];

        //スレッドからの終了通知を待つ
        if( rqueue_timed_pop( xnc.idle, &j, sizeof( j ), 1000 ) == 0 ){
            // ジョブ1つ完了
            inprogress--;

            xnc.algo.fn_destroy( &xnc, j );

            finish_job( j );

            if( *file ){
                if( prepare_to_job( &xnc, j, *file ) == 0 ){
                    if( ( j->rv = xnc.algo.fn_init( &xnc, j ) ) == 0 ){
                        fseek( j->fsrc.fh, 0, SEEK_SET );
                        if( rqueue_push( xnc.read, &j, sizeof( j ) ) == 0 ){
                            inprogress++;
                        }
                    }
                } else{
                    finish_job( j );
                    qinfof_try_push( xnc.error, "Failed to %s init (code %x): %s", xnc.algo.name, j->rv, *file );
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
                pos = snprintf( str, sizeof( str ), "\x1b[2K%s %2d [\x1b[32m", xnc_get_mode_name( jobs.slots + i ), i );
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
        
        while( rqueue_try_pop( xnc.error, errmsg, sizeof( errmsg ) ) == 0 ){
            write( STDERR_FILENO, errmsg, strlen( errmsg ) );
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
    rqueue_destroy( xnc.error );

    for( int i = 0; i < jobs.max; i++ ) hash_destroy( jobs.slots[i].hs );
    free( thr.list );
    free( jobs.slots );
    free( xnc.buf_addr );
    free( xnc.ids );

    return rv;
}
