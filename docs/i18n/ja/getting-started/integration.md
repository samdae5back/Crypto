# LiberaCrypt の統合

## 公開 API を include する

インストールされた target は public include directory を公開します。アプリケーションは通常 umbrella header を include します。

```c
#include <LiberaCrypt.h>
```

公開 C 関数、macro、constant、algorithm selector は `LIBERAC_` prefix を使用します。公開 type 名は `LiberaC` prefix を使用します。

## Runtime-selected algorithm

LiberaCrypt は対応するパラメータセットを一つのライブラリにまとめてコンパイルします。runtime dispatch をサポートする API は、パラメータごとの別ビルドではなく `LiberaCAlgID` selector を受け取ります。

たとえば block-cipher 操作は最後の algorithm argument で具体的な AES mode を選択します。

```c
LiberaCError error = LIBERAC_BLOCK_CIPHER_ENCRYPT(
    ciphertext, sizeof(ciphertext),
    plaintext, sizeof(plaintext),
    key, sizeof(key),
    initial_counter, sizeof(initial_counter),
    LIBERAC_ALG_AES_256_CTR);
```

完全な selector set は `inc/Def.h` に宣言され、`LiberaCrypt.h` から利用できます。

dispatcher model と family boundary については [API 概要](../../api/overview.md) と [アルゴリズム選択](../../api/algorithm-selection.md) を参照してください。

## 公開実装と内部実装

`inc/` の header だけがサポート対象の public API を構成します。private declaration は `src/` 以下で各実装とともに保持されます。アプリケーションは internal header を include したり internal symbol に直接 link したりしないでください。

shared-library export は文書化された public API に制限されます。platform-specific export mechanism は consumer に露出せず build system が処理します。

## 暗号学的な責任

ライブラリは API レベルのサイズ、identifier、多くのアルゴリズム固有パラメータ制約を検証しますが、アプリケーションのプロトコル自体を選択することはできません。caller は key management、nonce uniqueness、password policy、protocol-level algorithm restriction、そして interoperability 要件で legacy primitive を許容するかどうかに責任を負います。

low-level primitive を直接統合する前に [セキュリティ上の考慮事項](../../security/security-considerations.md) を読んでください。
