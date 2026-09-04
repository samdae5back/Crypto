# アーキテクチャ

LiberaCrypt は、公開 operation API、具体的なアルゴリズム実装、そしてプラットフォーム依存の狭い境界を分離しています。

```text
application
    |
    v
inc/ の public header
    |
    v
src/*.c の operation/category dispatcher
    |
    v
アルゴリズム実装ディレクトリ
    |
    v
共有 arithmetic / endian / ECC / NTT / core utility
    |
    v
限定された OS / toolchain 境界
```

## Public API 層

インストールされるヘッダは `inc/` 配下のものだけです。この層では operation 指向のインターフェース、共通エラー、公開型、サイズ問い合わせ API、`LiberaCAlgID` selector を定義します。

公開名の規則は次のとおりです。

- 公開 C 関数、マクロ、定数、selector には `LIBERAC_` を使用します。
- 公開型名には `LiberaC` を使用します。
- umbrella header は `LiberaCrypt.h` です。
- 公開 CMake target は `LiberaCrypt::LiberaCrypt` です。

## Dispatch 層

`src/` 直下の entry-point source は category 単位の dispatch を実装します。この層は公開リクエストを検証し、runtime algorithm identifier を解決してから、アプリケーション側で parameter set ごとの個別ビルドを用意することなく具体的な実装を呼び出します。

Operation の境界を分けることは意図的な設計です。たとえば authenticated-encryption selector は raw block-cipher API を通しません。AAD、nonce、tag の意味はブロック暗号そのものではなく AEAD operation に属するためです。

## アルゴリズム実装

具体的な実装は、次のような category ディレクトリに置かれます。

```text
src/AsymmetricCipher/
src/AuthenticatedEncryption/
src/BlockCipher/
src/DigitalSignature/
src/HashFunction/
src/KeyAgreement/
src/KeyEncapsulation/
src/MessageAuthentication/
src/RandomNumberGeneration/
src/StreamCipher/
```

Private declaration は `inc/` から公開せず、対応する実装と同じ場所に置きます。

## 共有実装層

`src/Util/` には bignum、bit、core、ECC、endian、NTT、prime など、複数の実装で共有する内部機能があります。これは第二の public API ではなく、内部 building block です。

Constant-time byte comparison や overflow を考慮した buffer-overlap 検証のように、セキュリティ上重要なロジックの重複を減らせる場合は共有 helper を優先します。

## プラットフォーム境界

暗号アルゴリズムのコードは、外部 cryptographic runtime に依存しないことを目標とします。プラットフォーム固有の処理は、OS entropy の取得や shared-library symbol export など、必要不可欠な狭い領域に限定します。

公開 symbol の基準 allowlist は `cmake/liberacrypt_exports.txt` です。ビルドは Windows DLL declaration、ELF version script、macOS exported-symbol list、Solaris mapfile、AIX export file、HP-UX linker export option など、各プラットフォームの native mechanism を使って同じ公開 API を出力します。

## この構造を採用する理由

このアーキテクチャは、次の三つの関心事を分離するために設計されています。

1. **呼び出し側が何をしたいか** — 暗号化、認証、鍵導出、署名、encapsulation など。
2. **どの具体的なアルゴリズム / parameter set で実行するか** — 必要に応じて runtime に選択。
3. **ホスト環境で実装がどのように移植性と安全性を保つか** — プラットフォーム上の仮定を public API に漏らさず内部で扱う。

この分離により、portability、constant-time behavior、アルゴリズム最適化を発展させながら、public interface を不必要に増やさずに済みます。
