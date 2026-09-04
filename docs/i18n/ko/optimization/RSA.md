# Portable RSAES-OAEP 및 RSASSA-PSS

LiberaCrypt는 PKCS #1 v2.2 scheme인 RSAES-OAEP와 RSASSA-PSS를 managed RSA key object와 raw RSA primitive 위에 구현합니다. 구현은 [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html)을 따르며 OS2IP/I2OSP width, MGF1 counter encoding, OAEP message bound, PSS의 `emBits = modBits - 1` 규칙, single-octet `0xbc` trailer를 포함합니다.

## 공개 API와 인코딩

`LIBERAC_RSA_PUBLIC_MODULUS_SIZE`와 `LIBERAC_RSA_PRIVATE_MODULUS_SIZE`는 고정 RSA octet width `k`를 반환합니다. `LIBERAC_RSA_OAEP_MAX_MESSAGE_SIZE`는 modulus와 hash가 OAEP를 허용할 때 `k - 2*hLen - 2`를 반환합니다.

RSA key는 scheme-independent합니다. 따라서 `LIBERAC_RSA_KEYGEN`은 raw, OAEP, PSS RSA identifier를 모두 허용하면서 동일한 `N`, `E`, `D` material을 생성합니다. 생성되는 public exponent는 계속 65537입니다. OAEP와 PSS byte output은 항상 `k` byte이며, 이 API는 ASN.1 key 또는 AlgorithmIdentifier encoding을 추가하지 않습니다.

scheme은 SHA-1과 고정 출력 SHA-2 계열을 허용합니다. SHA-1은 레거시 상호운용성을 위해 유지됩니다. SHA-3, SHAKE, LSH identifier는 거부됩니다. API가 구현된 PKCS #1 parameter set 밖의 encoding profile을 암묵적으로 만들지 않기 위함입니다. Hash와 MGF1은 항상 동일한 selector를 사용합니다.

## MGF1

MGF1은 0부터 시작하는 counter에 대해 `mgfSeed || I2OSP(counter, 4)`를 hash합니다. 구현은 incremental public hash API를 사용하고 counter를 명시적으로 big-endian으로 encoding하며 RFC block-count limit을 검사하고 각 digest를 target region에 직접 XOR합니다. seed/counter를 합친 buffer를 따로 할당하지 않으며 host byte order에 의존하지 않습니다.

## RSAES-OAEP

암호화는 다음을 구성합니다.

`EM = 0x00 || maskedSeed || maskedDB`

여기서 `DB = Hash(label) || PS || 0x01 || message`입니다. label은 비어 있을 수 있지만 그 hash는 항상 포함됩니다. 새로운 `hLen`-byte seed는 운영체제 random source에서 직접 얻습니다. plaintext length가 `k - 2*hLen - 2`를 초과하면 encoding write를 수행하기 전에 거부합니다.

복호화는 정확히 `k` byte ciphertext와 최대 plaintext를 담을 수 있는 output buffer를 요구합니다. fixed-schedule private operation 이후 seed와 data block을 unmask하고, label hash를 byte mismatch에서 early exit하지 않고 비교하며, 전체 padding/delimiter region을 scan합니다. scan은 mask로 첫 `0x01`을 추적하고 nonzero padding byte, missing delimiter, label mismatch, nonzero leading byte가 있어도 조기에 반환하지 않습니다.

`[0, N)` 범위를 벗어난 모든 ciphertext representative와 모든 OAEP format failure는 `LIBERAC_ERROR_AUTHENTICATION_FAILED`로 통합됩니다. maximum output region은 private operation 전에 지우고 모든 실패 경로에서도 다시 지우며, 보고되는 message length는 0으로 reset합니다. undersized destination 같은 public argument error는 별도로 유지해서 caller가 attacker-controlled ciphertext를 처리하기 전에 buffer contract를 수정할 수 있게 합니다.

## RSASSA-PSS

signing은 message를 hash하고 명시된 개수의 random salt byte를 얻어 `M' = 0x00...00 (8 bytes) || mHash || salt`를 구성한 뒤 `emBits = bit_length(N) - 1`에서 data block을 encoding합니다. 사용되지 않는 high bit는 private operation 전에 clear합니다.

verification은 정확히 `k` byte signature와 caller가 지정한 정확한 salt-length policy를 요구합니다. digest-length sentinel은 `hLen`으로 해석되며 auto-detect mode가 아닙니다. verification은 복원된 representative width, unused high bit, trailer byte, 정확한 zero-padding length, delimiter, recomputed hash를 검사합니다. mismatch는 `LIBERAC_ERROR_SIGNATURE_INVALID`를 반환합니다.

## Exponentiation schedule

private operation은 기존 modulus-width Montgomery ladder-like schedule을 사용합니다. modulus-width exponent bit마다 square와 multiply candidate를 모두 계산하고 mask로 선택합니다. private exponent는 완전한 modulus limb width로 저장됩니다.

OAEP encryption은 confidential plaintext를 포함한 randomized encoding에서 시작합니다. public exponent 자체는 secret이 아니지만, 일반 variable-time public bignum path를 사용하면 encoded-base-dependent Montgomery reduction이 남을 수 있습니다. 따라서 OAEP path는 다음 특성을 갖는 별도 helper를 사용합니다.

- 전체 fixed-width encoded base를 early exit 없이 load하고 compare합니다.
- masked Montgomery final subtraction을 사용합니다.
- public exponent bit에 대해서만 branch합니다.
- fixed-width intermediate allocation을 지웁니다.

PSS verification과 보존된 raw public primitive는 public value를 다루므로 더 빠른 variable-time sliding-window path를 계속 사용합니다.

구현은 source-level fixed-schedule claim만 합니다. ISO C는 동일한 물리적 instruction latency, compiler transformation, cache behavior, platform-wide side-channel resistance를 보장할 수 없습니다. 현재 구현은 CRT recombination이 아니라 full-width RSA exponentiation을 수행합니다.

## 검증

focused RSA test는 고정 2048-bit RSA key와 OpenSSL 3.0.13에서 생성한 interoperability artifact를 사용합니다.

- SHA-256 및 MGF1-SHA-256을 사용한 RSAES-OAEP가 예상 plaintext로 복호화됩니다.
- SHA-256, MGF1-SHA-256, 32-byte salt를 사용한 RSASSA-PSS가 검증됩니다.
- 새로운 OAEP encrypt/decrypt 및 PSS sign/verify round trip이 성공합니다.
- 반복 OAEP encryption은 서로 독립적으로 randomized된 ciphertext를 생성합니다.
- wrong label, malformed ciphertext, wrong message, wrong salt length, modified signature, non-exact wire length가 실패합니다.
- OAEP failure는 output length를 reset하고 최대 plaintext region을 clear된 상태로 남깁니다.
- overlap, capacity, unsupported-hash, algorithm-selector contract도 검사합니다.

RSA workflow는 Ubuntu, macOS, Windows에서 이 target을 빌드하고 실행하며 Ubuntu에서는 같은 test를 AddressSanitizer와 UndefinedBehaviorSanitizer로도 실행합니다. 별도의 Ubuntu job은 새로운 2048-bit OpenSSL key를 생성하고 modulus/private exponent를 LiberaCrypt에 import한 뒤 양방향을 검사합니다. OpenSSL encrypt/sign → LiberaCrypt decrypt/verify, 그리고 LiberaCrypt encrypt/sign → OpenSSL decrypt/verify입니다. 일반 full test matrix는 최종 merge gate로 유지됩니다.
