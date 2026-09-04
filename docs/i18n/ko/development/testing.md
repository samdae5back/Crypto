# 테스트와 검증

LiberaCrypt는 unit test, known-answer test(KAT), compatibility regression, public-header check, sanitizer/warning build, 그리고 focused benchmark/validation workflow를 함께 사용합니다.

## 일반 테스트 범위

`LIBERAC_BUILD_TESTS`가 활성화되면 생성되는 테스트 세트는 다음과 같은 영역을 포함합니다.

- public-header isolation;
- operation-level key generation, encryption/decryption, encapsulation/decapsulation, signing/verification;
- 지원되는 파라미터 선택 전반의 block-cipher 및 AEAD known-answer/round-trip case;
- SHA-1, SHA-2, SHA-3, SHAKE, LSH vector;
- HMAC, CMAC, GMAC, Poly1305 생성/검증 동작;
- HKDF와 PBKDF2-HMAC 표준 벡터, 경계 처리, overlap 거부, invalid argument;
- AES 및 legacy TDEA CTR_DRBG vector와 lifecycle 동작;
- 지원되는 post-quantum KEM/signature 파라미터 세트의 operation test와 KAT;
- Ed25519 표준 벡터와 negative test;
- RSA OAEP/PSS regression 및 interoperability-oriented validation;
- 현재 보존된 KAT 세트와 함께 사용하는 HAETAE compatibility vector.

## KAT 난수 경계

PQC KAT executable은 벡터 재현을 위해 test-only deterministic initialization을 사용합니다. 일반 shared/static LiberaCrypt target은 이 KAT control interface를 노출하지 않으며, 정상적인 운용 난수는 계속 운영체제 entropy 경로를 통해 얻습니다.

이 분리는 deterministic test plumbing이 production public API의 일부가 되는 것을 막습니다.

## Cross-toolchain 검증

mainline CI는 Windows, Linux, macOS에서 빌드합니다. 컴포넌트별 검증과 benchmark stage에는 focused workflow를 사용할 수 있습니다.

portability가 이 matrix만으로 정의되는 것은 아닙니다. warning-oriented build, sanitizer, 명시적인 range/representation reasoning, non-mainstream platform 고려 역시 [Portability](../../design/portability.md)에 설명된 portability policy의 일부입니다.

## 개발용 oracle

외부 구현은 개발 과정에서 보존된 벡터나 randomized interoperability case를 교차 검증하는 데 사용할 수 있습니다. component provenance에서 명시적으로 달리 적지 않는 한, 이러한 구현은 test/development oracle일 뿐 LiberaCrypt의 runtime dependency가 아닙니다.

## 문서-only 변경

문서만 바꾸고 source code, build configuration, generated API declaration, test vector, workflow behavior를 수정하지 않는 경우 cryptographic build/test 실행은 필요하지 않습니다. 다만 broken link, 오래된 이름, 현재 codebase와 맞지 않는 주장 여부는 여전히 검토해야 합니다.
