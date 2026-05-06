# xorcrypt
ファイルに対してランダムなバイト列で全体を簡易的にスクランブルするツールです。
コンテンツに対する機械的な解析や自動スキャンを回避することを目的としています。

**このツールは暗号化はしません。  
セキュリティ目的では絶対に使用しないでください。**

名前に`crypt`と入っていますがあくまでスクランブル（難読化）するだけであり暗号化ではありません。

このような用途では暗号化が用いられることが多いですが、暗号化はパスワードを失うとデータを復号できなくなるというリスクがあります。自動解析への対策としては強力な暗号化を使うまでもないため、このツールはパスワードを必要とせずに簡易的にデータをスクランブルします。仕組みも単純なため、ツール自体がなくても比較的容易に復元可能です。そのため、仕組みを知っていれば第三者でも復元できます。

## Build
```sh
gcc -O3 -s xorcrypt.c -o xorcrypt.exe -lbcrypt
```

## Usage
```text
Usage: xorcrypt [-edfv] [-o dir] [-x ext] [-a xor|seed-xor] [-p passwd ] file [file ...]
```
* `-e`: 指定されたファイルを難読化するスクランブルモードを強制  
（無指定で自動判別）
* `-d`: 指定されたファイルを復元する復元モードを強制  
（無指定で自動判別）
* `-f`: 出力先ファイルが既に存在していても上書きすることを許可
* `-v`: 処理経過の詳細表示モード
* `-o`: 出力先ディレクトリ  （デフォルトはカレントディレクトリ）
* `-x`: スクランブルしたファイルまたは自動判別に使用する拡張子（デフォルトはxnc）
* `-a`: XOR変換アルゴリズム
  - xor: 単純変換モード（デフォルト）
  - seed-xor: 限定的用途（[seed-xor](#seed-xor)参照）
* `-p`: パスワード（実質`-a seed-xor`専用 Noteを参照）
* `file ...`: 変換対象のファイル

複数のjpgをC:/Users/user/secretに変換して出力する例:
```sh
#-fvで詳細表示にしつつ、出力先ファイルが既に存在しても上書き
xorcrypt -fv -o "C:/Users/user/secret" mydata1.jpg mydata2.jpg ...
```
これでsecretディレクトリ内にxncファイルが生成されます。
```text
mydata1.jpg.xnc
mydata2.jpg.xnc
...
```
このxncファイルを同様にxorcrpytにもう一度渡すとそのまま元のファイルに復元できます。

Windowsの右クリックの「送る」から使うことを想定しているので入力ファイルをまとめて渡す形式です。

> [!Note]
> * スクランブルモードは自動的に指定拡張子を付与し、複合モードは指定拡張子を外す動作をします。これは自動判別に関わらず行われるので通常は`-e`や`-d`を指定せずに自動判別モードで使用してください。
> * パスワード(`-p`)は実質的に`-a seed-xor`専用のオプションです。通常用途でパスワードを設定しても複合時にパスワードを必要としないアルゴリズムなので意味をなさず、パスワードなしで復元できてしまいます。

## How it works
1. ランダムに生成した文字列からSHA-256ハッシュ値(32バイト)を生成
1. ファイル全体を生成したハッシュ値を循環させてXOR演算
1. 最後にハッシュ値をファイルの末尾に書きこむ

> [!IMPORTANT]
> 復元キーがファイルに含まれているので暗号にはなり得ません。
> 繰り返しになりますが**セキュリティ目的では絶対に使用しないでください。**

## Recovery
構造上、複雑な計算を行っていないためこのツールを失っても復元は難しくありません。
1. バイナリエディタなどで末尾の32バイトを取り出す（これが復元キーです）
1. この32バイトでファイルの先頭から32バイトずつXOR演算を末尾まで繰り返す
1. 終端が32バイトに満たない場合は、ハッシュ値の先頭部分を必要な長さだけ使用する

> [!NOTE]
> 暗号化はパスワードを失うとデータも完全に失われてしまいますが、これはファイル自体にキーが含まれているためそのリスクを回避できます。
> あくまで機械的な解析に対するものであってデータを保護するものではないので可搬性を重視してこの設計になっています。

## seed-xor
`seed-xor`は`-a`オプションで指定できるもう一つの変換アルゴリズムでSHA256を用いた自作の簡易ストリーム暗号のようなものです。冒頭で「*`crypt`と名前がついているが暗号化はしない*」と説明しましたが、このモードは一応暗号的な処理を行っています。
興味本位で作ったものなの当然安全性は保障されていません。使用はおすすめしません。

<details>
<summary>詳細</summary>

このアルゴリズムは構造上、パスワード(`-p`)の有無で結果の意味合いが変化します。
#### パスワードを使用する場合
一般的な暗号と同様にパスワードを指定して暗号化するものです。パスワードを失うと復号できず、データは失われます。
#### パスワードを使用しない場合
暗号としての保護能力はなくなり、単純XOR(`xor`モード)の上位版のような結果になります。
SHA256の拡散効果で単純XORよりもパターンが隠ぺいされやすく、機械的なスキャンに対してはわずかに強度があがりますが実用上の差はほぼありません。また単純XORよりも復元処理が複雑になりツールがほぼ必須となります。

また、自作アルゴリズムであるため本ツール以外に実装が存在せず代替手段がありません。

### Algorithm
まずパスワードとランダムに生成された32文字のソルトで初期のSHA256ハッシュを生成します。
このsaltはファイルの末尾にそのまま書きこまれます。
```text
initial state = SHA256( salt || password )
```
この`state`を元に鍵伸長を行います。
```text
for( 0...100000 )
    state = SHA256( state || i || salt || password )
```
以後は`state`から生成した`keystream`を使ってデータをXORしていきますが、鍵長(36バイト)毎にこれを更新します。
```text
count = file-size / key-length
label1 = 0xC0DECAFE
label2 = 0x00C0FFEE
...
if( ( file-size % key-length ) == 0 )
    state     = SHA256( label1 || count || state )
    keystream = SHA256( label2 || count || state )
    count = count + 1
```
パスワードが未設定だとこのうちの`password`が空になるため、ランダム32文字の`salt`だけで処理が行われ結果的にスクランブル（難読化）として動作します。

### Recovery
復号するための概念的なCコードを書いておきます。fseekとかftellみたいなのは実際にはファイルサイズや環境に合わせて_fseeki64とかfseeko_とかに読み替えてください。

1. まずファイルの末尾に記録されている32文字の`salt`を取り出します。これはハッシュ値ではなくコード内の`XNC_CHAR_SET`内の文字列からランダムに生成されたASCII文字列で「`7iO%v]Lt&lv@ihd}>XS&]LIlj+xrbu-b`」のようなデータになっています。
1. 取り出した文字列と設定したパスワードを結合してSHA256にでハッシュ値を生成します。
```c
#define HASH_LEN   32
#define SALT_LEN   32
#define PASSWD_MAX 64
// 内部状態として使うハッシュ値の保存先
static unsigned char state[HASH_LEN];

...

char *passwd = "YOUR_PASSWORD";

// xncファイルの末尾からsaltを取り出す
char salt[32];
FILE *src = fopen( "./scrambled_file.txt.xnc", "rb" );
fseek( src, -(SALT_LEN), SEEC_END );
fread( src, 1, SALT_LEN, salt );

// seed: ( salt || passwd )
char seed[SALT_LEN + PASSWD_MAX]; //salt + passwdが入るサイズ
size_t passwd_length = strlen( passwd );
memcpy( (void *)seed, salt, SALT_LEN );
memcpy( (void *)seed + SALT_LEN, passwd, passwd_length );

// seedを渡してstateにハッシュ値を得る
sha256( seed, SALT_LEN + password_length, state );
```

3. この`state`を100000回SHA256に渡して鍵伸長（もどき）をします。この時のseedは`state || i || salt || passwd`で回します。
```c
// seed: ( state || [PLACEHOLDER 32bit] || salt || passwd )
char seed[HASH_LEN + sizeof( uint32_t ) + SALT_LEN + PASSWD_MAX];
uint32_t i;
memcpy( (void *)seed, state, HASH_LEN );
memcpy( (void *)seed + HASH_LEN + sizeof( i ), salt, 32 );
memcpy( (void *)seed + HASH_LEN + sizeof( i ) + SALT_LEN, passwd, passwd_length );

// 100000回SHA256を繰り返す
for( i = 0; i < 100000; i ++ ){
    // seedの[placeholder]にループカウンタを入れる
    memcpy( (void *)seed + HASH_LEN, &i, sizeof( i ) );

    // seedを渡してstateにハッシュ値を得る
    sha256( (void *)seed, HASH_LEN + sizeof( i ) + SALT_LEN + passwd_length, state );
}
```
1. この`state`を元に`SHA256( label(32bit) || counter(64bit) || state)`で`keystream`を生成してファイルにXORしていきます。ただし、32バイト処理毎これらを更新します。
```c
#define LABEL_STATE 0xC0DECAFE
#define LABEL_KS    0x00C0FFEE

void state_update(
    const unsigned char *src_state,
    const uint64_t counter,
    unsigned char *dst_state,
    unsigned char *dst_ks
){
    // seed: ( label 32bit || counter 64bit || state )
    unsigned char seed[sizeof( uint32_t ) + sizeof( uint64_t ) + HASH_LEN];
    uint32_t label;
    unsigned char hash[HASH_LEN];

    // state更新用のseedを作る
    label = LABEL_STATE;
    memcpy( (void *)seed, &label, sizeof( label ) );
    memcpy( (void *)seed + sizeof( label ), &counter, sizeof( counter ) );
    memcpy( (void *)seed + sizeof( label ) + sizeof( counter ), src_state, HASH_LEN );

    // stateを更新
    sha256( (void *)seed, sizeof( seed ), dst_state );

    // seedのlabelを書き換えてkeystream更新用のseedを作る
    label = LABEL_KS;
    memcpy( (void *)seed, &label, sizeof( uint32_t ) );

    // keystreamを更新
    sha256( (void *)seed, sizeof( seed ), dst_ks );
}

void seed_xor(
    unsigned char *buf,
    size_t length,
    uint64_t offset
){
    unsigned char ks[HASH_LEN];
    uint64_t counter;
    int h_off;

    for( size_t i = 0; i < length; i++ ){
        // ファイル読み出し位置からハッシュのどのバイトを使うかオフセットを計算
        h_off = ( offset + i ) % HASH_LEN;

        // h_offが0、またはi = 0の時はstate更新
        //   h_off == 0: ハッシュの32バイトを使い切ったので
    }
}

...

unsigned char buf[2048]; // バッファサイズは自由
uint64_t filesize, readbytes, processed = 0;

// ファイルサイズ取得
fseek( src, 0, SEEK_END );
filesize = ftell( src );

// XOR開始
fseek( src, 0, SEEK_SET );
while( processed < filesize ){
    readbytes = fread( buf, 1, sizeof( buf ), src );
    seed_xor( buf, read_bytes, processed );
    fwrite( buf, 1, read_bytes, dst );
}





</details>
