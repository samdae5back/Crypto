# API 개요

LiberaCrypt는 연산 중심의 소수 API 계열을 제공하고, 구체적인 알고리즘은 `LiberaCAlgID`를 통해 런타임에 선택합니다.

API는 구현 디렉터리가 아니라 암호학적 연산을 기준으로 의도적으로 구성되어 있습니다. 이를 통해 특정 연산에만 의미가 있는 파라미터가 관계없는 호출에 섞이지 않도록 합니다.

## API 계열의 경계

- **블록 암호** — 인증되지 않은 AES ECB/CBC/CTR 및 3-key Triple-DES ECB/CBC.
- **스트림 암호** — 독립형 ChaCha20.
- **인증 암호화** — AES-GCM, AES-CCM, ChaCha20-Poly1305.
- **해시 / XOF** — SHA-1, SHA-2, SHA-3, SHAKE, LSH를 하나의 런타임 선택 해시 인터페이스로 제공.
- **메시지 인증** — HMAC, CMAC, GMAC, Poly1305.
- **키 파생** — HKDF, PBKDF2-HMAC.
- **난수 생성** — OS 난수 바이트와 상태를 갖는 CTR_DRBG.
- **비대칭 암호화/서명/키 합의/KEM** — 적용 가능한 경우 런타임 선택 파라미터 세트를 사용하는 연산별 인터페이스.

AES-GCM과 AES-CCM은 raw block-cipher API에서 의도적으로 허용하지 않습니다. 이들의 nonce, AAD, authentication tag 의미론은 인증 암호화 인터페이스에 속하기 때문입니다. 마찬가지로 독립형 ChaCha20과 ChaCha20-Poly1305도 분리되어 있습니다. 후자는 Poly1305 키 파생을 위해 counter 0을 예약하고 AEAD 고유의 nonce/tag 규칙을 적용하기 때문입니다.

## One-shot과 incremental 연산

스트리밍이 자연스럽게 유용한 연산에서는 one-shot helper와 함께 incremental state machine도 제공합니다. 가장 명확한 예는 해시입니다. one-shot 연산 역시 incremental caller가 사용하는 것과 동일한 init/update/finalize/squeeze 경로 위에 구현되어 있습니다.

이렇게 함으로써 동일한 암호 상태 전이를 위한 별도의 구현을 중복해서 유지하지 않습니다.

## 크기 및 파라미터 질의

키, ciphertext, signature, nonce, tag 등 관련 크기 helper 역시 동일한 런타임 알고리즘 식별자를 사용합니다. 공개 helper가 존재하는 경우 애플리케이션이 파라미터 표를 직접 중복 구현하기보다 크기를 질의하거나 검증해야 합니다.

## 오류 처리

공개 API는 `LiberaCError`를 반환합니다. 잘못된 알고리즘 식별자, 잘못된 길이, 인증 실패 등 거부된 요청은 명시적으로 보고됩니다. 보안 민감 연산에서는 인증되지 않았거나 실패한 중간 결과가 정상 출력처럼 노출되는 것이 위험한 경우 부분적으로 생성된 plaintext 또는 output을 지웁니다.

## 함수 단위 레퍼런스

Markdown 문서는 의도된 사용법과 설계 경계를 설명합니다. 함수 시그니처, 인자, 선언, 반환값에 대한 권위 있는 함수 단위 레퍼런스는 공개 헤더에서 생성되는 Doxygen 문서입니다.
