# アルゴリズム・ファミリ

このページは、LiberaCrypt が公開するアルゴリズムを一覧するための案内です。各アルゴリズムの標準仕様や、生成される公開 API リファレンスの代わりになるものではありません。

| ファミリ | 実装 |
| --- | --- |
| ブロック暗号 | AES-128/192/256; 3-key Triple-DES EDE |
| ストリーム暗号 | ChaCha20 |
| 認証付き暗号 | AES-GCM, AES-CCM, ChaCha20-Poly1305 |
| ハッシュ / XOF | SHA-1, SHA-2, SHA-3, SHAKE, LSH |
| メッセージ認証 | HMAC, CMAC, GMAC, Poly1305 |
| 鍵導出 | HKDF, PBKDF2-HMAC |
| 乱数生成 | OS random bytes, CTR_DRBG |
| 公開鍵暗号 | RSAES-OAEP, raw RSA primitive, ElGamal |
| 鍵共有 | NIST P-256/P-384/P-521 上の ECDH, X25519 |
| デジタル署名 | RSASSA-PSS, ECDSA, Ed25519, ML-DSA, SLH-DSA, AIMer, HAETAE |
| 鍵カプセル化 | ML-KEM-512/768/1024, NTRU+768/864/1152, SMAUG-T-128/192/256 |
| ユーティリティ算術 | Bignum, 素数生成, ECC および共通算術 helper |

## 対称暗号と AEAD

認証なしのブロック/ストリーム暗号と認証付き暗号は、意図的に別の API ファミリとして分離されています。新しいアプリケーション・プロトコルでは、認証なし暗号と認証を独自に組み合わせるより、通常は認証付き暗号方式を優先してください。

## ハッシュ、MAC、KDF

ハッシュ、メッセージ認証、鍵導出 API は同じ runtime-selection model を共有しますが、操作固有のパラメータ検証は分離されています。HKDF と PBKDF2-HMAC の詳細は [鍵導出](../../key-derivation.md) を参照してください。

## 古典的な公開鍵アルゴリズム

RSA 暗号化には RSAES-OAEP、RSA 署名には RSASSA-PSS を使用してください。raw textbook RSA は primitive レベルのテストや互換性のために残されていますが、アプリケーションが安全な暗号化方式または署名方式として扱ってはいけません。

ECDH と ECDSA は NIST P-256、P-384、P-521 をサポートします。X25519 と Ed25519 は NIST 曲線 API のパラメータ選択として表現せず、それぞれ専用のエンコーディングとインターフェースを使用します。

## 耐量子アルゴリズム

LiberaCrypt は portable C backend を通じて複数の KEM および署名ファミリを提供します。vendored component は upstream の notice と license を保持します。provenance、固定 revision、package hash についてはリポジトリ直下の `THIRD_PARTY_NOTICES.md` を参照してください。

## レガシー互換性

SHA-1 と Triple-DES/TDEA は相互運用性および過去の標準との互換性のために保持されています。新しいプロトコルの既定値としては推奨されません。[レガシーおよび互換性アルゴリズム](../../security/legacy-algorithms.md) を参照してください。
