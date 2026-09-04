# テストと検証

LiberaCrypt は unit test、known-answer test(KAT)、compatibility regression、public-header check、sanitizer/warning build、focused benchmark/validation workflow を組み合わせて使用します。

## 一般的なテスト範囲

`LIBERAC_BUILD_TESTS` を有効にすると、生成されるテストセットは次の領域を含みます。

- public-header isolation;
- operation-level key generation、encryption/decryption、encapsulation/decapsulation、signing/verification;
- 対応パラメータ全体の block-cipher および AEAD known-answer/round-trip case;
- SHA-1、SHA-2、SHA-3、SHAKE、LSH vector;
- HMAC、CMAC、GMAC、Poly1305 の生成/検証動作;
- HKDF と PBKDF2-HMAC の標準 vector、境界処理、overlap rejection、invalid argument;
- AES と legacy TDEA CTR_DRBG vector および lifecycle behavior;
- 対応する post-quantum KEM/signature parameter set の operation test と KAT;
- Ed25519 standard vector と negative test;
- RSA OAEP/PSS regression と interoperability-oriented validation;
- 現在保持される KAT set と併用する HAETAE compatibility vector。

## KAT の乱数境界

PQC KAT executable は vector 再現のため test-only deterministic initialization を使用します。通常の shared/static LiberaCrypt target はこの KAT control interface を公開せず、通常運用の乱数は引き続き OS entropy path から取得します。

この分離により、deterministic test plumbing が production public API の一部になることを防ぎます。

## Cross-toolchain 検証

mainline CI は Windows、Linux、macOS でビルドします。コンポーネント固有の検証や benchmark stage には focused workflow を使用できます。

portability はこの matrix だけで定義されるものではありません。warning-oriented build、sanitizer、明示的な range/representation reasoning、non-mainstream platform への配慮も [Portability](../../design/portability.md) に記載された portability policy の一部です。

## 開発用 oracle

外部実装は開発時に、保持された vector や randomized interoperability case を cross-check するために使用できます。component provenance で明示的に別記されない限り、それらは test/development oracle であり LiberaCrypt の runtime dependency ではありません。

## ドキュメントのみの変更

文書だけを変更し、source code、build configuration、generated API declaration、test vector、workflow behavior を変更しない場合、cryptographic build/test の実行は不要です。ただし broken link、古い名称、現在の codebase と一致しない記述がないかは引き続き確認してください。
