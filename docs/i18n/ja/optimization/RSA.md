# Portable RSAES-OAEP と RSASSA-PSS

LiberaCrypt は PKCS #1 v2.2 scheme の RSAES-OAEP と RSASSA-PSS を managed RSA key object と raw RSA primitive の上に実装します。実装は [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html) に従い、OS2IP/I2OSP width、MGF1 counter encoding、OAEP message bound、PSS の `emBits = modBits - 1` rule、single-octet `0xbc` trailer を含みます。

## 公開 API とエンコーディング

`LIBERAC_RSA_PUBLIC_MODULUS_SIZE` と `LIBERAC_RSA_PRIVATE_MODULUS_SIZE` は固定 RSA octet width `k` を返します。`LIBERAC_RSA_OAEP_MAX_MESSAGE_SIZE` は modulus と hash が OAEP を許す場合 `k - 2*hLen - 2` を返します。

RSA key は scheme-independent です。そのため `LIBERAC_RSA_KEYGEN` は raw、OAEP、PSS RSA identifier を受け付けながら同じ `N`、`E`、`D` material を生成します。生成される public exponent は引き続き 65537 です。OAEP と PSS byte output は固定で `k` byte であり、この API は ASN.1 key や AlgorithmIdentifier encoding を追加しません。

scheme は SHA-1 と固定出力 SHA-2 family を受け付けます。SHA-1 は legacy interoperability のために保持されます。SHA-3、SHAKE、LSH identifier は拒否されます。実装済み PKCS #1 parameter set の外側に encoding profile を暗黙生成しないためです。Hash と MGF1 は常に同じ selector を使用します。

## MGF1

MGF1 は 0 から始まる counter に対して `mgfSeed || I2OSP(counter, 4)` を hash します。実装は incremental public hash API を使用し、counter を明示的に big-endian で encoding し、RFC block-count limit を検査し、各 digest を target region に直接 XOR します。seed/counter を結合した buffer を確保せず、host byte order に依存しません。

## RSAES-OAEP

暗号化は次を構成します。

`EM = 0x00 || maskedSeed || maskedDB`

ここで `DB = Hash(label) || PS || 0x01 || message` です。label は空でも構いませんが、その hash は常に存在します。新しい `hLen`-byte seed は OS random source から直接取得します。plaintext length が `k - 2*hLen - 2` を超える場合、encoding write の前に拒否します。

復号は正確に `k` byte の ciphertext と、最大 plaintext を保持できる output buffer を要求します。fixed-schedule private operation の後、seed と data block を unmask し、label hash を byte mismatch で early exit せず比較し、padding/delimiter region 全体を scan します。scan は mask で最初の `0x01` を追跡し、nonzero padding byte、missing delimiter、label mismatch、nonzero leading byte があっても早期 return しません。

`[0, N)` の外側にあるすべての ciphertext representative とすべての OAEP-format failure は `LIBERAC_ERROR_AUTHENTICATION_FAILED` に統一されます。maximum output region は private operation 前とすべての failure path で clear され、報告される message length は 0 に reset されます。undersized destination のような public argument error は区別され、caller が attacker-controlled ciphertext を処理する前に buffer contract を修正できます。

## RSASSA-PSS

signing は message を hash し、明示された数の random salt byte を取得し、`M' = 0x00...00 (8 bytes) || mHash || salt` を構成して `emBits = bit_length(N) - 1` で data block を encoding します。未使用 high bit は private operation 前に clear します。

verification は正確に `k` byte の signature と caller の正確な salt-length policy を要求します。digest-length sentinel は `hLen` に解決され、auto-detect mode ではありません。verification は recovered representative width、unused high bit、trailer byte、正確な zero-padding length、delimiter、recomputed hash を検査します。mismatch は `LIBERAC_ERROR_SIGNATURE_INVALID` を返します。

## Exponentiation schedule

private operation は既存の modulus-width Montgomery ladder-like schedule を使用します。各 modulus-width exponent bit で square と multiply candidate の両方を計算し mask で選択します。private exponent は完全な modulus limb width で格納されます。

OAEP encryption は confidential plaintext を含む randomized encoding から始まります。public exponent 自体は secret ではありませんが、一般の variable-time public bignum path を使うと encoded-base-dependent Montgomery reduction が残り得ます。そのため OAEP path は次の特性を持つ別 helper を使います。

- full fixed-width encoded base を early exit なしで load/compare する。
- masked Montgomery final subtraction を使う。
- public exponent bit に対してのみ branch する。
- fixed-width intermediate allocation を clear する。

PSS verification と保持された raw public primitive は public value を扱うため、より高速な variable-time sliding-window path を引き続き使用します。

実装は source-level fixed-schedule claim のみを行います。ISO C は同じ物理 instruction latency、compiler transformation、cache behavior、platform-wide side-channel resistance を保証できません。現在の実装は CRT recombination ではなく full-width RSA exponentiation を行います。

## 検証

focused RSA test は固定 2048-bit RSA key と OpenSSL 3.0.13 で生成した interoperability artifact を使用します。

- SHA-256 と MGF1-SHA-256 の RSAES-OAEP が期待した plaintext に復号される。
- SHA-256、MGF1-SHA-256、32-byte salt の RSASSA-PSS が検証される。
- 新しい OAEP encrypt/decrypt と PSS sign/verify round trip が成功する。
- OAEP encryption の繰り返しで独立に randomized された ciphertext が生成される。
- wrong label、malformed ciphertext、wrong message、wrong salt length、modified signature、non-exact wire length が失敗する。
- OAEP failure は output length を reset し、maximum plaintext region を clear のままにする。
- overlap、capacity、unsupported-hash、algorithm-selector contract を検査する。

RSA workflow は Ubuntu、macOS、Windows でこの target を build/run し、Ubuntu では同じ test を AddressSanitizer と UndefinedBehaviorSanitizer でも実行します。別の Ubuntu job は新しい 2048-bit OpenSSL key を生成し、modulus/private exponent を LiberaCrypt に import して双方向を確認します。OpenSSL encrypt/sign → LiberaCrypt decrypt/verify、その後 LiberaCrypt encrypt/sign → OpenSSL decrypt/verify です。通常の full test matrix は最終 merge gate のままです。
