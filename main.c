#include "xorcrypt.h"
#include <getopt.h>

static unsigned char st_xnc_buffer[XNC_BUF_SIZE];

int simple_xor( struct XncContext *xnc, FILE *src, uint64_t src_size, FILE *dst );
int seed_xor( struct XncContext *xnc, FILE *src, uint64_t src_size, FILE *dst );

void _info( FILE *stream, const char *format, ... )
{
    va_list ap;
    va_start( ap, format );
    vfprintf( stream, format, ap );
    va_end( ap );
    fputc( '\n', stream );
}


void _dumpbin( const char *label, const char *fmt, const unsigned char *bytes, size_t len )
{
    if( label ) printf( "%s: ", label );
    for( int i = 0; i < len; i++ ){
        printf( "%c", bytes[i] );
    }
    fputc( '\n' ,stdout );
}

// パスをディレクトリとファイル名に分けて正規化
static int get_dir_and_name_by_path( const char *src, char *dst_dir, char *dst_name, size_t max_len )
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

static void hashgen_init( struct XncContext *xnc )
{
    DWORD result = 0;
    NTSTATUS rv = 0;

    rv |= BCryptOpenAlgorithmProvider( &(xnc->hash.sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, 0 );
    rv |= BCryptGetProperty( xnc->hash.sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(xnc->hash.sha256.hashobj_size), sizeof( DWORD ), &result, 0 );
    xnc->hash.sha256.hashobj = malloc( xnc->hash.sha256.hashobj_size );
    if( ! xnc->hash.sha256.hashobj ){
        rv |= 1;
    }

    rv |= BCryptOpenAlgorithmProvider( &(xnc->hash.hmac_sha256.h_alg), BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG );
    rv |= BCryptGetProperty( xnc->hash.hmac_sha256.h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&(xnc->hash.hmac_sha256.hashobj_size), sizeof( DWORD ), &result, 0 );
    xnc->hash.hmac_sha256.hashobj = malloc( xnc->hash.hmac_sha256.hashobj_size );
    if( ! xnc->hash.hmac_sha256.hashobj ){
        rv |= 1;
    } 

    if( rv != 0 ){
        einfo( "Failed to initialize SHA256 provider. aborting." );
        exit( 1 );
    }
}

static void hashgen_destroy( struct XncContext *xnc )
{
    // initは失敗するとexit()するのでここにくるなら初期化できているはず
    BCryptCloseAlgorithmProvider( xnc->hash.sha256.h_alg, 0 );
    free( xnc->hash.sha256.hashobj );

    BCryptCloseAlgorithmProvider( xnc->hash.hmac_sha256.h_alg, 0 );
    free( xnc->hash.hmac_sha256.hashobj );

    memset( &xnc->hash, 0, sizeof( xnc->hash ) );
}

// 終端にNULLを書きこまない
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

// 終端にNULLを書きこまない
static void keygen( unsigned char *buf, size_t len )
{
    const char *charset = XNC_CHAR_SET;
    int cnum = strlen( charset );

    for( int i = 0; i < len; i++ ){
        buf[i] = charset[rand() % cnum];
    }
}

static int xor_conv( struct XncContext *xnc, FILE *src, uint64_t fsize, FILE *dst, struct XncAlgoParams *p )
{
    unsigned char *buf = st_xnc_buffer;
    uint64_t progress = 0;
    size_t read_bytes;
    clock_t clock_now, clock_last_notice = 0;

    fseek64( src, 0, SEEK_SET );
    fseek64( dst, 0, SEEK_SET );

    while( progress < fsize ){
        if( xnc->flags & XNC_F_VERBOSE && ( clock_now = clock() ) - clock_last_notice >= CLOCKS_PER_SEC ){
            printf( "\rProgress: %3d%% [%" PRIu64 " / %" PRIu64 " bytes]", (int)( progress * 100 / fsize ), progress, fsize );
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
        p->fn_xor( xnc, buf, ( read_bytes + 31 ) / 32, p->ctx );

        // 実際の読み出しサイズのみ書きこむ
        if( fwrite( buf, sizeof( char ), read_bytes, dst ) != read_bytes ){
            einfo( "\nFailed to write output file in coverting." );
            return 0;
        }
        progress += read_bytes;
    }

    if( xnc->flags & XNC_F_VERBOSE ){
        printf( "\rProgress: 100%% [%" PRIu64 " / %" PRIu64 " bytes]", progress, fsize );
        fflush( stdout );
    }
    printf( "\n" );

    return 1;
}

static int parse_args( struct XncContext *xnc, int argc, char *argv[] )
{
    int mdchk = 0, opt;
    while( ( opt = getopt( argc, argv, "edfvo:x:a:p:" ) ) != -1 ){
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
                if( strcmp( optarg, "xor" ) == 0 ){
                    xnc->algo.func = simple_xor;
                } else if( strcmp( optarg, "seed-xor" ) == 0 ){
                    xnc->algo.func = seed_xor;
                } else{
                    einfo( "Invalid algorithm specified.\n" );
                    return -1;
                }
                xnc->algo.name = optarg;
                break;
            case 'p': xnc->passwd = optarg;          break;
            case 'o': xnc->outdir = optarg;          break;
            case 'f': xnc->flags |= XNC_F_OVERWRITE; break;
            case 'v': xnc->flags |= XNC_F_VERBOSE;   break;
            case 'x':
                if( optarg[0] != '\0' ) xnc->ext = optarg;
                break;
            default:
                einfof( "Invalid argument: %c\n", opt );
                return -1;
        }
    }

    if( mdchk == 0 ){
        xnc->flags |= XNC_F_AUTODETECT;
    } else if( mdchk > 1 ){
        einfo( "Multiple modes specified.\n" );
        return -1;
    }

    if( xnc->passwd && xnc->passwd[0] == '\0' ) xnc->passwd = NULL;

    if( argc < ( optind + 1 ) ){
        einfof( "Xor deNCrypter %s", XNC_VERSION );
        einfof( "Usage: %s [-edfv] [-a xor|seed-xor] [-p passwd] [-o dir] [-x ext] file [file ...]", XNC_NAME );
        return -1;
    }

    return optind;
}

int _algo_simple_xor( struct XncContext *xnc, unsigned char *restrict buf, size_t blocks, void *ctx )
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

int _algo_seed_xor( struct XncContext *xnc, unsigned char *restrict buf, size_t blocks, void *ctx )
{
    struct XncSeedXor *c = (struct XncSeedXor *)ctx;
    unsigned char ks[XNC_HASH_SIZE];
    struct XncSeedXorMsg msg;

    for( size_t i = 0; i < blocks; i++ ){
        msg.label_be = xnc_be32( XNC_SEED_KS );
        msg.cnt_be   = xnc_be64( c->cnt );
        sha256hmac( xnc, (unsigned char *)&msg, sizeof( msg ), c->state, sizeof( c->state ), ks );

        for( int j = 0; j < XNC_HASH_SIZE; j++ ){
            buf[j] ^= ks[j];
        }
        buf += XNC_HASH_SIZE;

        c->cnt++;
        msg.label_be = xnc_be32( XNC_SEED_STATE );
        msg.cnt_be   = xnc_be64( c->cnt );
        sha256hmac( xnc, (unsigned char *)&msg, sizeof( msg ), c->state, sizeof( c->state ), c->state ); 
    }
    return 1;
}

int simple_xor( struct XncContext *xnc, FILE *src, uint64_t src_size, FILE *dst )
{
    struct XncAlgoParams p;
    struct XncSimpleXor c;
    unsigned char hash[XNC_HASH_SIZE];

    p.fn_xor = _algo_simple_xor;
    p.ctx = &c;

    switch( xnc->mode ){
        case XNC_ENCODE:
            keygen( c.salt, sizeof( c.salt ) );
            sha256( xnc, c.salt, sizeof( c.salt ), hash );
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
    if( xnc->passwd ){
        size_t pass_len = strlen( xnc->passwd );

        struct {
            char hash[XNC_HASH_SIZE];
            char passwd[XNC_MAX_PASSWD];
        } __attribute__((packed)) seed;

        memcpy( (void *)seed.hash, hash, sizeof( seed.hash ) );
        memcpy( (void *)seed.passwd, xnc->passwd, pass_len );
        sha256( xnc, (unsigned char *)&seed, sizeof( seed.hash ) + pass_len, c.hash );
    } else{
        memcpy( c.hash, hash, sizeof( hash ) );
    }

    dumphash( xnc, "Hash", (unsigned char *)c.hash, sizeof( c.hash ) );
    
    // 変換
    xor_conv( xnc, src, src_size, dst, &p );

    if( xnc->mode == XNC_ENCODE ){
        info( xnc, "Added decode key.");
        fwrite( hash, sizeof( char ), sizeof( hash ), dst );
    }

    return 1;
}

int seed_xor( struct XncContext *xnc, FILE *src, uint64_t src_size, FILE *dst )
{
    struct XncAlgoParams p;
    struct XncSeedXor c;
    unsigned char salt[XNC_SALT_SIZE];

    p.fn_xor = _algo_seed_xor;
    p.ctx = &c;
    c.cnt = 0;

    switch( xnc->mode ){
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
        if( xnc->passwd ){
            pass_len = strlen( xnc->passwd );
            memcpy( strech.passwd, xnc->passwd, pass_len );
        }
        sha256( xnc, (unsigned char *)&strech, ( sizeof( strech ) - sizeof( strech.passwd ) ) + pass_len, strech.state );
        for( ; i < XNC_STRECH_TIMES; i++ ){
            strech.i_be = xnc_be32( i );
            sha256hmac(
                xnc,
                (unsigned char *)&strech,
                sizeof( strech ) - sizeof( strech.passwd ) + pass_len,
                strech.state,
                sizeof( strech.state),
                strech.state
            );
        }

        msg.label_be = label_be;
        msg.cnt_be = xnc_be64( c.cnt );
        sha256hmac( xnc, (unsigned char *)&msg, sizeof( msg ), strech.state, sizeof( strech.state ), c.state );
    }

    dumpkey( xnc, "Key", (unsigned char *)salt, sizeof( salt ) );
    xor_conv( xnc, src, src_size, dst, &p );

    if( xnc->mode == XNC_ENCODE ){
        info( xnc, "Added decode key.");
        fwrite( salt, sizeof( char ), sizeof( salt ), dst );
    }

    return 1;
}

int main( int argc, char *argv[] )
{
    int rv = 0, args_offset, store_len;
    char src_path[MAX_PATH_LEN], dst_path[MAX_PATH_LEN];
    char path_dir[MAX_PATH_LEN], path_file[MAX_PATH_LEN];
    char *dot, *outdir;
    FILE *src = NULL, *dst = NULL;
    int64_t src_size;

    struct XncContext xnc = { 0 };
    
    hashgen_init( &xnc );

    args_offset = parse_args( &xnc, argc, argv );
    if( args_offset < 0 ) return 1;

    xnc.buf = st_xnc_buffer;

    info( &xnc, "-----------------------------------------------" );
    infof( &xnc, "XOR Algorithm: %s", xnc.algo.name );

    srand( (unsigned int)time( NULL ) ^ ( (unsigned int)clock() << 16 ) );

    for( int offset = args_offset; offset < argc ; offset++ ){
        if( ! get_dir_and_name_by_path( argv[offset], path_dir, path_file, MAX_PATH_LEN ) ){
            einfof( "Failed to parse source path strings: %s", argv[offset] );
            goto NEXT;
        }

        if( path_file[0] == '\0' ){
            einfo( "Empty source file name specified." );
            goto NEXT;
        }

        store_len = snprintf( src_path, MAX_PATH_LEN, "%s/%s", path_dir, path_file );
        if( store_len >= MAX_PATH_LEN ){
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
        fseek64( src, 0, SEEK_END );
        src_size = ftell64( src );

        // 処理に必要な出力パスを取得
        if( xnc.mode == XNC_ENCODE ){
            store_len = snprintf( dst_path, MAX_PATH_LEN, "%s/%s.%s", outdir, path_file, xnc.ext );
            if( store_len >= MAX_PATH_LEN ){
                einfo( "Filename too long." );
                goto NEXT;
            }
        } else if( xnc.mode == XNC_DECODE ){
            if( dot ) *dot = '\0';

            if( src_size < XNC_HASH_SIZE ){
                einfo( "File size is too small. skipped.");
                goto NEXT;
            }

            store_len = snprintf( dst_path, MAX_PATH_LEN, "%s/%s", outdir, path_file );
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

        infof( &xnc, "Output file: %s", dst_path );
        if( access( dst_path, F_OK ) == 0 && ! ( xnc.flags & XNC_F_OVERWRITE ) ){
            einfof( "Output path is already exists: %s", dst_path );
            goto NEXT;
        }

        dst = fopen( dst_path, "wb" );
        if( ! dst ){
            einfof( "Failed to open output file: %s", dst_path );
            goto NEXT;
        }

        // 変換
        info( &xnc, "Processing..." );
        xnc.algo.func( &xnc, src, src_size, dst );

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

    hashgen_destroy( &xnc );

    return rv;
}
