# 보안 고려사항

LiberaCrypt는 cryptographic primitive를 제공하고 operation-level input을 검증하지만, 프로토콜을 올바르게 사용하는 책임은 caller에게 있습니다.

## 적절한 API 계열 사용

기밀성과 무결성이 모두 필요한 새로운 애플리케이션 프로토콜에서는 authenticated-encryption API를 우선하세요. raw block/stream encryption API는 인증 암호화와 의도적으로 분리되어 있습니다.

알고리즘별 nonce, tag, key size, message size 규칙은 가능한 범위에서 해당 public API가 검증합니다. nonce uniqueness, key lifecycle, replay handling, protocol negotiation처럼 애플리케이션 전체에 걸친 요구사항은 라이브러리 범위를 벗어납니다.

## 인증 실패

인증 및 검증 실패는 명시적으로 반환됩니다. caller는 authentication failure를 hard failure로 취급해야 하며, 검증이 실패한 뒤 데이터를 신뢰된 것으로 처리해서는 안 됩니다.

## 키 파생과 난수

key-derivation API는 문서화된 표준과 제한을 구현합니다. 적절한 입력, password policy, work factor, protocol-specific restriction을 선택하는 책임은 애플리케이션에 있습니다.

random-byte 및 DRBG API는 올바른 lifecycle과 parameter 사용에 의존합니다. legacy configuration은 호환성을 위해 존재하며 새로운 프로토콜에서 자동으로 선택해서는 안 됩니다.

## 공개키 primitive

raw mathematical primitive보다 고수준의 표준화된 encoding과 scheme을 우선해야 합니다. raw primitive는 테스트와 호환성에 유용한 경우 남아 있지만 그 자체로 안전한 application protocol을 정의하지는 않습니다.

## 레거시 알고리즘

일부 알고리즘은 새로운 설계에 대한 권장이 아니라 오래된 시스템과의 상호운용성을 위해 포함됩니다. [레거시 및 호환성 알고리즘](legacy-algorithms.md)을 참고하세요.

## Side channel

선택된 secret-dependent arithmetic은 전용 fixed-width timing-oriented path를 사용합니다. 이것이 라이브러리의 모든 연산, compiler output, host environment, 전체 application이 모든 side channel에서 안전하다는 뜻은 아닙니다. 구현 경계는 [Constant-time 정책](../../design/constant-time.md)을 참고하세요.

## Secret lifetime

구현은 더 이상 필요하지 않은 많은 민감한 temporary buffer와 internal state를 지웁니다. 이는 잔존 데이터를 줄이지만 애플리케이션, compiler, 운영체제, 하드웨어가 다른 위치에 만든 복사본까지 통제할 수는 없습니다.

## 프로토콜 책임

primitive library는 주변 시스템의 security goal을 추론할 수 없습니다. protocol selection, key management, message framing, domain separation, negotiation policy, replay handling, 전체 deployment의 threat model은 애플리케이션의 책임입니다.
