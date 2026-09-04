# Portable short-Weierstrass ECC 산술

이 계층은 공개 P-256, P-384, P-521 ECDH 및 ECDSA 구현이 공통으로 사용하는 prime-field와 point arithmetic을 제공합니다. key-agreement와 signature API는 `KeyAgreement.h`, `DigitalSignature.h`를 통해 제공되며 lower-level field, point, scalar interface는 내부 구현으로 유지됩니다.

production arithmetic은 의도적으로 scalar-multiplication policy를 두 개만 노출합니다. public scalar용 optimized variable-time path와 secret scalar용 fixed-schedule path입니다. textbook affine 구현은 correctness oracle과 benchmark baseline으로 test tree에만 남겨두며 LiberaCrypt library에는 link되지 않습니다.

## 지원 domain parameter

내장 parameter record는 NIST SP 800-186의 NIST P-256, P-384, P-521 curve를 다룹니다. 모두 `a = -3`인 prime field 위의 short-Weierstrass curve입니다. SEC 1 point-at-infinity, compressed, uncompressed encoding은 decoder의 명시적인 infinity policy 아래에서 허용됩니다.

X25519는 의도적으로 이 구조로 표현하지 않습니다. Montgomery curve, byte order, clamping, ladder rule은 별도 backend를 사용하며 이를 short-Weierstrass의 또 다른 parameter choice처럼 취급하지 않습니다.

## 산술 표현

- 고정 최대 storage: little-endian 32-bit limb 17개(P-521까지 충분).
- Field representation: curve별 `R`, `R^2`, `-p^-1 mod 2^32` 상수를 사용하는 Montgomery residue.
- Group-order scalar representation: `n` modulo의 별도 Montgomery domain과 curve별 상수. portable word arithmetic은 공유하지만 field-modulus 값을 재사용하지 않습니다.
- Multiplication: portable full-width schoolbook multiplication 뒤에 word-by-word Montgomery reduction.
- Inversion: `p - 2`에 대한 fixed-exponent powering.
- Square root: `(p + 1) / 4`에 대한 fixed-exponent powering. 세 field prime 모두 modulo 4에서 3입니다.

구현은 `unsigned __int128`, compiler intrinsic, assembly, VLA, host-endian cast를 의도적으로 피합니다. 따라서 동일한 source를 MSVC와 legacy 32-bit-oriented C toolchain에서도 사용할 수 있습니다. architecture-specific 또는 64-bit-limb backend는 target-specific measurement로 정당화되는 경우 나중에 같은 internal interface 뒤에 추가할 수 있습니다.

이 작은 고정 폭에서는 Karatsuba를 추가하지 않고 schoolbook multiplication을 유지합니다. Karatsuba는 자동으로 이득이라고 가정하지 않고 benchmark-driven option으로 남깁니다. 추가 temporary와 carry handling 비용이 특히 32-bit/older target에서 8, 12, 17 limb 정도의 작은 폭에서는 절감 효과보다 클 수 있기 때문입니다.

## Point-operation 경로

### Test-only textbook reference oracle

`tests/ECC/Reference.c`는 direct formula를 사용하는 affine double-and-add를 구현합니다. scalar bit와 exceptional case에서 branch하고 각 affine addition/doubling마다 field inversion을 수행합니다. 이 구현은 독립적인 correctness oracle과 benchmark baseline만을 위해 존재합니다. production source API의 일부가 아니며 LiberaCrypt에 link되지 않습니다.

### Public optimized variable-time path

`ecc_scalar_vartime.c`는 Jacobian coordinate와 고정 four-bit window를 사용합니다. 16개의 public-point multiple을 precompute하고 leading zero window를 skip하며 direct public table index를 사용합니다. 마지막 inversion 한 번으로 결과를 affine form으로 변환합니다. 이 path는 ECDSA verification component처럼 public scalar만을 대상으로 합니다.

window width는 의도적으로 작게 유지합니다. fixed maximum structure에서 16개의 Jacobian point는 최대 약 3.3 KiB이고, 더 큰 window는 legacy environment에서 stack/table pressure를 높입니다. 다른 width는 same-target benchmark를 근거로 선택해야 합니다.

### Secret fixed-schedule path

`ecc_scalar_secret.c`는 fixed encoded scalar width를 검증하고 curve의 정확한 scalar bit count 전체에 대해 Montgomery ladder를 수행합니다. 모든 bit마다 complete-behaviour Jacobian addition 1회, Jacobian doubling 1회, masked conditional swap 2회를 수행합니다. scalar-indexed table을 사용하지 않고 scalar bit에서 branch하지 않습니다. ladder state는 변환 후 명시적으로 지웁니다.

`ecc_projective.c`는 exceptional behavior가 caller branch에 의존하지 않게 합니다. generic Jacobian addition과 doubling candidate를 모두 계산한 뒤 equal point, opposite point, 한쪽 input의 infinity에 대해 올바른 결과를 mask-select합니다. 따라서 generic addition formula 자체가 수학적으로 complete unified formula는 아니더라도 operation boundary에서는 *complete-behaviour*를 제공합니다.

기존 bignum policy와 마찬가지로 이는 보편적인 물리 constant-time 보장이 아니라 fixed source-level schedule로 설명합니다. ISO C는 모든 compiler/processor에서 동일한 instruction 또는 arithmetic latency를 강제할 수 없으며, power, EM, speculative, fault, compiler-introduced side channel 저항성을 주장하지 않습니다.

## ECDH 통합

`src/KeyAgreement/ecdh.c`는 private-key operation에 fixed-schedule secret-scalar path만 사용합니다. private key는 `1 <= d < n` 범위의 fixed-width big-endian scalar이며, key generation은 OS에서 균등 random candidate를 얻고 unused high bit를 mask한 뒤 group order에 대해 rejection-sample합니다.

generated public key는 uncompressed SEC 1 point입니다. agreement는 compressed/uncompressed SEC 1 peer point를 모두 허용하고, common decoder를 통해 infinity와 invalid curve point를 거부하며, `dQ`의 fixed-width big-endian x-coordinate를 반환합니다. 지원되는 NIST curve는 cofactor가 1이므로 accepted finite on-curve peer point는 prime-order group에 속합니다.

raw x-coordinate는 ECDH 내부에서 KDF를 거치지 않습니다. public API는 이를 HKDF 같은 protocol-appropriate KDF에 입력해야 하는 key-agreement material로 문서화합니다.

## ECDSA 통합

`src/DigitalSignature/ECDSA/ecdsa.c`는 P-256, P-384, P-521의 ECDSA를 지원합니다. private key는 fixed-width big-endian scalar이고 generated public key는 uncompressed SEC 1 point이며 verification은 compressed point도 허용합니다. signature는 ASN.1 DER 대신 fixed-width raw `r || s` encoding을 사용하며 signing은 low-s normalization을 적용하지 않습니다.

message hash는 ECDSA left-truncation 및 conditional reduction rule로 변환합니다. public API는 선택 curve의 security strength 이상 collision strength를 갖는 fixed-output SHA-2/SHA-3를 허용합니다. per-message nonce는 선택한 message hash를 HMAC으로 사용하는 RFC 6979를 따릅니다. 16개의 nonce candidate를 고정 batch로 생성하고 첫 valid candidate를 mask-select하여 normal signing path에서 scalar-dependent early exit를 피합니다.

private-key public derivation과 nonce-point multiplication은 fixed-schedule secret-scalar ladder를 사용합니다. group order modulo 산술은 전용 scalar Montgomery domain을 사용하며 `n - 2` fixed-exponent inversion도 포함합니다. verification은 public value만 다루므로 `uG`, `vQ`에 four-bit variable-time multiplication path를 사용합니다.

## X25519 backend

`src/KeyAgreement/x25519.c`는 RFC 7748을 16개의 little-endian radix-2^16 limb로 별도 구현합니다. product는 portable `uint64_t`에 accumulate되고 reduction은 `2^256 = 38 (mod 2^255 - 19)`를 사용합니다. `unsigned __int128` 및 target-specific intrinsic 없이 동일 source를 MSVC와 portability-oriented build matrix에서 사용할 수 있습니다.

scalar input은 내부에서 copy하고 clamp합니다. Montgomery ladder는 masked conditional swap으로 scalar bit 255개 전부를 scan하며 inversion은 고정 공개 exponent를 사용합니다. peer u-coordinate는 high input bit masking과 non-canonical encoding을 field prime modulo로 reduce하는 동작을 포함한 RFC 7748 decoding rule을 따릅니다. shared-secret derivation은 all-zero result를 거부하여 caller가 low-order peer input을 조용히 받아들이지 않도록 합니다.

## 인코딩 및 검증

SEC 1 decoder는 다음을 거부합니다.

- 잘못된 길이 또는 지원하지 않는 prefix;
- non-canonical coordinate (`x >= p` 또는 `y >= p`);
- right-hand side가 quadratic residue가 아닌 compressed point;
- curve equation을 만족하지 않는 point;
- caller가 명시적으로 허용하지 않은 infinity.

secret scalar validation은 fixed encoded width를 scan하고 argument/length validation 이후 scalar-dependent early return 없이 `1 <= k < n` 검사를 결합합니다. optimized public path는 timing이 명시적으로 secret-safe하지 않으므로 더 짧은 encoding을 허용하고 leading zero byte를 trim할 수 있습니다. reference oracle도 유사한 단순 variable-time semantics를 사용하지만 test에서만 존재합니다.

## 검증

focused ECC arithmetic test는 다음을 다룹니다.

- P-256, P-384, P-521에서 standard generator가 on-curve finite point로 accept됨;
- SEC 1 compressed/uncompressed generator round trip;
- 세 curve 모두의 독립적인 `2G` affine coordinate를 test-only textbook reference result와 비교;
- zero, `n - 1`, `n`에서 scalar validity boundary;
- 모든 지원 order에 대한 scalar Montgomery multiplication, modular addition, fixed-exponent inversion, canonical import, one-step reduced import;
- scalar 1과 2에 대해 test-only affine oracle, four-bit windowed Jacobian, fixed-schedule ladder multiplication 간 일치;
- curve별 96개의 non-zero scalar 값에서 test oracle과 두 production multiplication path의 deterministic differential comparison.

public key-agreement test는 RFC 7748 Alice/Bob X25519 vector, 세 NIST curve의 bilateral ECDH agreement, compressed SEC 1 peer key, invalid zero ECDH scalar, X25519 all-zero rejection, OS-random key-generation round trip도 다룹니다. ECDSA test는 RFC 6979 P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 vector, SHA-3 key-generation/sign/verify round trip, deterministic repeatability, compressed public key, malformed key/signature, output clearing, buffer/overlap validation을 포함합니다.

ECC validation workflow는 hosted Ubuntu, macOS, Windows runner에서 focused arithmetic 및 ECDSA test를 build/run하고 Ubuntu ASan/UBSan run도 추가합니다. 일반 repository CI는 같은 세 OS에서 public key-agreement와 ECDSA test를 빌드합니다.

## Benchmarking

repository benchmark는 test/benchmark target이기도 하므로 textbook oracle을 production library에 추가하지 않고 link할 수 있습니다. 세 curve에서 test-only reference baseline과 두 production path의 multiplication당 median CPU microseconds를 출력합니다. scalar는 의도적으로 full-width이고 group order에 가깝게 선택하여 작은 scalar 때문에 public implementation이 인위적으로 빨라 보이지 않도록 합니다. affine reference path는 timing sample마다 한 번 측정하고 더 빠른 Jacobian path는 timer noise를 줄이기 위해 반복 연산을 사용합니다.

benchmark는 모든 processor에 대한 performance promise가 아니라 comparative evidence입니다. hosted-runner result는 더 공격적인 field representation, 큰 window, Karatsuba, architecture-specific backend를 선택하기 전에 pull request와 함께 보존되어야 합니다.
