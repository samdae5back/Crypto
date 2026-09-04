# 키 파생

LiberaCrypt의 key-derivation 계층은 공개 HMAC 계층 위에 직접 구현되어 있습니다. 따라서 hash selection은 계속 runtime-dispatch 방식으로 동작하고, hash별 KDF 구현을 따로 복제할 필요가 없습니다.

## HKDF

`LIBERAC_HKDF_EXTRACT`, `LIBERAC_HKDF_EXPAND`, `LIBERAC_HKDF` API는 RFC 5869를 구현합니다. `LIBERAC_HKDF_PRK_SIZE`는 선택된 HMAC digest 크기를 반환합니다.

지원되는 selector는 `LIBERAC_HMAC`이 허용하는 것과 동일한 고정 출력 SHA-1, SHA-2, SHA-3 식별자입니다. SHAKE와 LSH는 거부됩니다. SHA-1은 새로운 프로토콜 설계가 아니라 레거시 상호운용성을 위해 유지됩니다.

구현은 RFC의 제한과 의미론을 따릅니다.

- 생략되거나 길이가 0인 salt는 `HashLen`개의 zero octet으로 처리합니다.
- `HKDF-Expand`는 최소 `HashLen` octet 길이의 PRK를 요구합니다.
- 출력은 최대 `255 * HashLen` octet으로 제한됩니다.
- 임시 PRK, block state, 동적으로 할당한 message workspace는 해제 전에 명시적으로 지웁니다.

Known-answer test는 RFC 5869 Appendix A의 test case 1과 3을 사용합니다. SHA-256, 명시적인 salt/info, default salt, zero-length info, 분리된 Extract/Expand 호출, combined API를 모두 다룹니다.

Reference: <https://www.rfc-editor.org/rfc/rfc5869>

## PBKDF2-HMAC

`LIBERAC_PBKDF2_HMAC`은 PKCS #5 / RFC 8018에 정의된 PBKDF2를 구현하며 기존 HMAC 구현을 PRF로 사용합니다. API는 runtime hash selector, 양의 64-bit iteration count, caller가 제공하는 output buffer를 받습니다.

구현은 다음을 보장합니다.

- PBKDF2 block number를 요구되는 4-byte big-endian integer로 인코딩합니다.
- block-count 제한을 통해 `(2^32 - 1) * HashLen` derived-key 상한을 강제합니다.
- protocol compatibility와 vector test를 위해 빈 password와 salt를 허용하지만 deployment policy는 caller가 결정합니다.
- 문서화되지 않은 in-place 동작에 의존하지 않고 output/input overlap을 거부합니다.
- 모든 종료 경로에서 intermediate `U_j` 값과 XOR accumulator를 지웁니다.

RFC 8018은 SHA-1과 SHA-2 계열 HMAC에 대해 표준 PBKDF2 PRF identifier를 정의합니다. LiberaCrypt는 generic API를 통해 고정 출력 SHA-3 HMAC selector도 추가로 허용합니다. PBKDF2 parameter를 serialize하거나 특정 profile을 따라야 하는 애플리케이션은 해당 profile이 허용하는 PRF만 선택할 책임이 있습니다.

Known-answer coverage에는 iteration count 1, 2, 4096을 사용하는 RFC 6070 PBKDF2-HMAC-SHA1 vector와 RFC 7914의 64-byte PBKDF2-HMAC-SHA256 vector가 포함됩니다. 작은 SHA3-256 case는 LiberaCrypt의 generic runtime-dispatch 확장에 대한 regression coverage를 제공합니다.

References:

- <https://www.rfc-editor.org/rfc/rfc8018>
- <https://www.rfc-editor.org/rfc/rfc6070>
- <https://www.rfc-editor.org/rfc/rfc7914>
- <https://csrc.nist.gov/pubs/sp/800/132/final>

## Portability 및 최적화 참고사항

첫 KDF 구현은 이미 테스트된 HMAC API를 작고 감사하기 쉬운 형태로 조합하는 것을 의도적으로 우선합니다. C11 및 라이브러리 내부 기능만 사용하고 명시적인 big-endian byte encoding을 적용하며, host endianness나 word width를 가정하지 않습니다.

HKDF는 `T(n-1) || info || n`을 담을 수 있는 하나의 임시 buffer를 할당하고, PBKDF2는 `salt || INT(i)`를 위한 하나의 buffer를 할당합니다. allocation size는 `size_t` overflow 여부를 검사하고 allocation failure는 `LIBERAC_ERROR_ALLOCATION_FAILED`로 보고합니다.

PBKDF2는 현재 모든 PRF 호출마다 공개 one-shot HMAC 연산을 호출합니다. 단순하고 명확한 대신 매 iteration마다 HMAC key normalization과 ipad/opad setup이 반복됩니다. 향후 내부 reusable prepared-HMAC state를 추가하고 public KDF API나 derived byte를 바꾸지 않은 채 benchmark할 수 있습니다. 이러한 변경은 초기 correctness milestone의 일부가 아니라 측정된 throughput optimization으로 취급해야 합니다.
