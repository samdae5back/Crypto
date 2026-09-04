# 移植性

LiberaCrypt では、移植性を単に複数のプラットフォームでビルドできたという事実ではなく、**正しさの一部**として扱います。

コードの結果が、明示されていない compiler、ABI、byte order、文字表現、整数表現、linker の前提に依存し、その前提が別の標準準拠環境で変わり得る場合、LiberaCrypt ではそのコードを portable とはみなしません。

## ポリシー

### 定義された整数動作を使用する

アルゴリズムや表現において bit width 自体が意味を持つ場合、内部演算には fixed-width integer type を使用します。Narrowing conversion は値の範囲が分かっている場合にのみ行い、重要な representation/range invariant はコードまたは compile-time assertion で明示することを原則とします。

Signed arithmetic は、負数の right shift のような implementation-defined な動作に偶然依存してはなりません。アルゴリズムが floor division、sign extraction、特定の bit representation を必要とする場合、その意図した演算を明示的に記述します。

### Plain `char` の signedness に依存しない

標準では、plain `char` を signed とするか unsigned とするかをプラットフォームが選択できます。そのため、正確な signed-byte mapping が必要な serialization や arithmetic では、plain `char` や implementation-defined な character conversion に頼らず、mapping を明示的に定義します。

HAETAE は具体例の一つです。decomposed low-byte serialization では signed `[-128, 127]` の範囲を byte に明示的に対応させ、plain `char` が unsigned となる AIX/Power 環境でも representation が変化しないようにしています。

### Byte order を明示する

Serialization と low-level word handling は host endianness を仮定しません。Endian-sensitive な load/store はプロジェクトの utility に隔離し、public wire format は native representation に依存せず生成します。

たとえば ChaCha20 は key、nonce、counter、output word をすべて明示的な little-endian 形式で decode/encode します。

### 可能な限り intermediate width の十分性を説明する

Fixed-width 実装では、中間演算に選んだ型の幅がなぜ十分なのか説明できることを目標とします。HAETAE の fixed-point FFT が一例で、storage、Q16 product、butterfly expression、squared magnitude、accumulation の幅は、ある一つの環境で偶然動作した幅ではなく、保守的な範囲評価から選択します。

### 不要な実装拡張を避ける

Portable baseline は、標準幅の型で実用的に実装できる場合、compiler extension や特別に広い native integer type に依存しません。たとえば Poly1305 は native 128-bit integer を要求せず、範囲を制限した 26-bit limb と `uint64_t` product を使用します。

### プラットフォーム固有処理を狭い境界に限定する

OS entropy の取得や shared-library export policy はプラットフォームごとに異ならざるを得ません。こうした違いは暗号実装全体に conditional code を広げるのではなく、明示的な boundary に隔離します。

その結果、同じ public API を保ちながら Windows DLL declaration、ELF version script、macOS exported-symbol list、Solaris mapfile、AIX `.exp` file、HP-UX export option など、各環境の native mechanism を利用できます。

## Portability レビュー・チェックリスト

コードを追加したり外部実装を適用したりする際は、少なくとも次の点を確認します。

- 結果が host endianness に依存していないか。
- plain `char` signedness に依存していないか。
- signed shift、division、overflow、conversion に implementation-defined または undefined behavior が生じ得ないか。
- intermediate range が選択した integer width に収まる根拠があるか。
- pointer arithmetic が有効な object 範囲と検証済み size の中で行われているか。
- compiler extension、native 128-bit integer、alignment、ABI、linker model を不必要に仮定していないか。
- OS-specific behavior が明示的な境界の内側に隔離されているか。
- 別の compiler や optimization level で、現在の toolchain が許容している暗黙の仮定が表面化しないか。

## 検証

CI は主に Windows/MSVC、Linux、macOS を対象とします。Unit test、KAT、warning-oriented build、sanitizer、focused portability check を用いて、単一の toolchain では見逃される可能性のある前提を検出します。

ただし、これらの環境でテストに合格したこと自体が portability の定義ではありません。特に legacy および non-mainstream Unix target を考慮する場合、上記の実装ポリシーの方がより強い要件です。

## コードスタイルへの影響

多少長い式であっても、integer width、representation、range、byte order、platform behavior を明確にできるなら、短いが暗黙的な式より優先します。
