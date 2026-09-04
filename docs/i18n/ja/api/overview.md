# API 概要

LiberaCrypt は操作指向の少数の API ファミリを公開し、具体的なアルゴリズムは `LiberaCAlgID` によって実行時に選択します。

API は実装ディレクトリではなく暗号操作ごとに意図的に構成されています。これにより、特定の操作にだけ意味を持つパラメータが無関係な呼び出しへ混入するのを防ぎます。

## ファミリ境界

- **ブロック暗号** — 認証なしの AES ECB/CBC/CTR と 3-key Triple-DES ECB/CBC。
- **ストリーム暗号** — 単独の ChaCha20。
- **認証付き暗号** — AES-GCM、AES-CCM、ChaCha20-Poly1305。
- **ハッシュ / XOF** — SHA-1、SHA-2、SHA-3、SHAKE、LSH を一つの runtime-selected hash interface で提供。
- **メッセージ認証** — HMAC、CMAC、GMAC、Poly1305。
- **鍵導出** — HKDF と PBKDF2-HMAC。
- **乱数生成** — OS random bytes と stateful CTR_DRBG。
- **非対称暗号/署名/鍵共有/KEM** — 適用可能な場合は runtime-selected parameter set を使う操作固有インターフェース。

AES-GCM と AES-CCM は raw block-cipher API では意図的に受け付けません。nonce、AAD、authentication tag の意味論は authenticated-encryption interface に属するためです。同様に、単独の ChaCha20 と ChaCha20-Poly1305 も分離されています。後者は Poly1305 鍵導出のために counter 0 を予約し、AEAD 固有の nonce/tag ルールを持つからです。

## One-shot と incremental 操作

ストリーミングが自然に有用な操作では、one-shot helper に加えて incremental state machine を公開します。最も明確な例はハッシュで、one-shot 操作も incremental caller が使うものと同じ init/update/finalize/squeeze 経路の上に実装されています。

これにより、同じ暗号状態遷移に対して別々の実装を保守する必要がありません。

## サイズとパラメータの問い合わせ

鍵、ciphertext、signature、nonce、tag などのサイズ helper も同じ runtime algorithm identifier を使用します。公開 helper が存在する場合、アプリケーションはパラメータ表を重複してハードコードせず、問い合わせまたは検証を行ってください。

## エラー処理

公開 API は `LiberaCError` を返します。不正な algorithm identifier、不正な長さ、認証失敗など、拒否された要求は明示的に報告されます。セキュリティ上重要な操作では、未認証または失敗した中間結果を成功した出力として露出する危険がある場合、部分的に生成された plaintext や output を消去します。

## 関数レベルのリファレンス

Markdown 文書は意図された使い方と設計境界を説明します。関数シグネチャ、引数、宣言、戻り値についての権威ある関数レベルのリファレンスは、公開ヘッダから生成される Doxygen 文書です。
