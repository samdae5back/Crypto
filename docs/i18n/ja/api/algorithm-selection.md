# アルゴリズム選択

LiberaCrypt は `LiberaCAlgID` を通じて具体的なアルゴリズムとパラメータセットを実行時に選択します。selector は通常、操作指向 API の最後の引数として渡されます。

selector があるからといってアルゴリズム固有のルールがなくなるわけではありません。各 API ファミリは、選択されたアルゴリズムに属する制約を個別に検証します。

## ブロック暗号とストリーム暗号

認証なし block-cipher dispatcher は次を受け付けます。

- AES-128、AES-192、AES-256 の ECB、CBC、CTR モード。
- レガシー相互運用のための 3-key Triple-DES EDE の ECB、CBC モード。

ECB と CBC は入力長がブロック境界に揃っている必要があり、padding は caller が処理します。CTR は任意のバイト長を受け付けます。

AES-GCM と AES-CCM は block-cipher dispatcher では拒否され、authenticated-encryption API を通して使用する必要があります。

単独の ChaCha20 は 32-byte key、32-bit initial counter、12-byte nonce を使う RFC 8439 の構成に従います。同じ key/nonce pair を再利用してはならず、同じ pair に対する counter range が重複してもいけません。

## 認証付き暗号

AES-GCM、AES-CCM、ChaCha20-Poly1305 は AEAD dispatcher を使用します。

| ファミリ | Nonce 長 | Tag 長 |
| --- | --- | --- |
| AES-GCM | 0 でない任意長; 12 byte 推奨 | 4、8、または 12〜16 byte |
| AES-CCM | 7〜13 byte | 4〜16 byte の偶数長 |
| ChaCha20-Poly1305 | 正確に 12 byte | 正確に 16 byte |

`LIBERAC_AEAD_KEY_SIZE()`、`LIBERAC_AEAD_NONCE_LENGTH_VALID()`、`LIBERAC_AEAD_TAG_LENGTH_VALID()` を使うと、操作前に選択された構成を検証できます。

認証失敗時は `LIBERAC_ERROR_AUTHENTICATION_FAILED` を返します。復号経路は、未認証の plaintext が成功出力として露出しないよう設計されています。

## ハッシュと XOF

ハッシュファミリには次が含まれます。

- レガシー互換用の SHA-1。
- SHA-224、SHA-256、SHA-384、SHA-512、SHA-512/224、SHA-512/256。
- SHA3-224、SHA3-256、SHA3-384、SHA3-512、SHAKE128、SHAKE256。
- LSH-256-224、LSH-256-256、LSH-512-224、LSH-512-256、LSH-512-384、LSH-512-512。

固定出力ハッシュは標準 digest size を要求します。SHAKE は caller が出力長を選び、finalize 後の repeated squeeze をサポートします。

## メッセージ認証

- HMAC は固定出力 SHA-1、SHA-2、SHA-3 identifier を受け付けます。
- CMAC は CMAC に適した AES-128/192/256 と 3-key Triple-DES EDE selector を受け付けます。
- GMAC は AES-GCM selector と GCM tag-length rule を使います。
- Poly1305 は Poly1305 selector、正確に 32-byte の one-time key、完全な 16-byte tag のみを受け付けます。

検証 API は共通の constant-time byte-equality helper を使い、認証失敗を明示的に報告します。

## 鍵導出

HKDF と PBKDF2-HMAC は同じ runtime-selected HMAC layer を使用します。どちらも、それを利用するプロトコルの制約のもとで固定出力 SHA-1、SHA-2、SHA-3 HMAC selector をサポートします。

標準、長さ制限、overlap rule、保持されている test vector については [鍵導出](../../key-derivation.md) を参照してください。

## CTR_DRBG

stateful CTR_DRBG API は AES-128/192/256 と legacy 3-key TDEA configuration をサポートし、それぞれ `Block_Cipher_df` あり/なしの variant を提供します。AES configuration が現代的な既定値で、TDEA selector は過去の標準との互換性および test-vector 再現のために存在します。

## 公開鍵および耐量子ファミリ

現在のファミリには RSA、ElGamal、ECDH、X25519、ECDSA、Ed25519、ML-KEM、NTRU+、SMAUG-T、ML-DSA、AIMer、HAETAE、SLH-DSA が含まれます。runtime dispatch をサポートするファミリでは、パラメータごとの別ビルドは不要です。

公開 size-query API がある場合、鍵、ciphertext、signature のサイズをハードコードせず、その helper を使用してください。
