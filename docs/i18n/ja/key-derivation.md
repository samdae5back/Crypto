# 鍵導出

LiberaCrypt の key-derivation layer は公開 HMAC layer の上に直接構築されています。そのため hash selection は引き続き runtime-dispatch で行われ、hash ごとの KDF 実装を複製する必要はありません。

## HKDF

`LIBERAC_HKDF_EXTRACT`、`LIBERAC_HKDF_EXPAND`、`LIBERAC_HKDF` API は RFC 5869 を実装します。`LIBERAC_HKDF_PRK_SIZE` は選択された HMAC digest size を返します。

対応 selector は `LIBERAC_HMAC` が受け付けるものと同じ固定出力 SHA-1、SHA-2、SHA-3 identifier です。SHAKE と LSH は拒否されます。SHA-1 は新しい protocol design のためではなく legacy interoperability のために保持されています。

実装は RFC の制限と意味論に従います。

- 省略または長さ 0 の salt は `HashLen` 個の zero octet として扱います。
- `HKDF-Expand` は少なくとも `HashLen` octet の PRK を要求します。
- 出力は `255 * HashLen` octet に制限されます。
- temporary PRK、block state、動的に確保した message workspace は解放前に明示的に消去します。

Known-answer test は RFC 5869 Appendix A の test case 1 と 3 を使用し、SHA-256、明示的な salt/info、default salt、zero-length info、分離された Extract/Expand 呼び出し、combined API をカバーします。

Reference: <https://www.rfc-editor.org/rfc/rfc5869>

## PBKDF2-HMAC

`LIBERAC_PBKDF2_HMAC` は PKCS #5 / RFC 8018 で定義された PBKDF2 を実装し、既存 HMAC 実装を PRF として使用します。API は runtime hash selector、正の 64-bit iteration count、caller-supplied output buffer を受け取ります。

実装は次を行います。

- PBKDF2 block number を要求される 4-byte big-endian integer としてエンコードします。
- block-count 制限を通じて `(2^32 - 1) * HashLen` derived-key 上限を強制します。
- protocol compatibility と vector test のため空の password と salt を許容しますが、deployment policy は caller に委ねます。
- 文書化されていない in-place behavior に依存せず output/input overlap を拒否します。
- すべての終了経路で intermediate `U_j` 値と XOR accumulator を消去します。

RFC 8018 は SHA-1 および SHA-2 family の HMAC に対する標準 PBKDF2 PRF identifier を定義します。LiberaCrypt は generic API を通じて固定出力 SHA-3 HMAC selector も追加で許可します。PBKDF2 parameter を serialize する、または特定 profile に従うアプリケーションは、その profile が許可する PRF だけを選ぶ責任があります。

Known-answer coverage には iteration count 1、2、4096 の RFC 6070 PBKDF2-HMAC-SHA1 vector と、RFC 7914 の 64-byte PBKDF2-HMAC-SHA256 vector が含まれます。小さな SHA3-256 case は LiberaCrypt の generic runtime-dispatch extension に対する regression coverage を提供します。

References:

- <https://www.rfc-editor.org/rfc/rfc8018>
- <https://www.rfc-editor.org/rfc/rfc6070>
- <https://www.rfc-editor.org/rfc/rfc7914>
- <https://csrc.nist.gov/pubs/sp/800/132/final>

## Portability と最適化の注記

最初の KDF 実装は、すでに検証された HMAC API を小さく監査しやすい形で組み合わせることを意図的に優先します。C11 とライブラリ内部機能のみを使用し、明示的な big-endian byte encoding を行い、host endianness や word width を仮定しません。

HKDF は `T(n-1) || info || n` を保持できる一つの temporary buffer を確保し、PBKDF2 は `salt || INT(i)` 用の一つの buffer を確保します。allocation size は `size_t` overflow を検査し、allocation failure は `LIBERAC_ERROR_ALLOCATION_FAILED` で報告します。

PBKDF2 は現在、各 PRF 呼び出しごとに公開 one-shot HMAC operation を呼びます。単純で分かりやすい一方、毎 iteration で HMAC key normalization と ipad/opad setup が繰り返されます。将来、内部 reusable prepared-HMAC state を追加し、public KDF API や derived byte を変更せず benchmark できます。この変更は初期 correctness milestone ではなく、測定された throughput optimization として扱うべきです。
