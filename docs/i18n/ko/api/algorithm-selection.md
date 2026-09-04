# 알고리즘 선택

LiberaCrypt는 `LiberaCAlgID`를 통해 구체적인 알고리즘과 파라미터 세트를 런타임에 선택합니다. 이 selector는 보통 연산 중심 API의 마지막 인자로 전달됩니다.

selector가 있다고 해서 알고리즘별 규칙이 사라지는 것은 아닙니다. 각 API 계열은 선택된 알고리즘에 속하는 제약을 별도로 검증합니다.

## 블록 및 스트림 암호화

인증되지 않은 block-cipher dispatcher는 다음을 허용합니다.

- AES-128, AES-192, AES-256의 ECB, CBC, CTR 모드.
- 레거시 상호운용성을 위한 3-key Triple-DES EDE의 ECB, CBC 모드.

ECB와 CBC는 입력 길이가 블록 경계에 맞아야 하며 padding은 caller가 처리합니다. CTR은 임의의 바이트 길이를 허용합니다.

AES-GCM과 AES-CCM은 block-cipher dispatcher에서 거부되며 반드시 authenticated-encryption API를 통해 사용해야 합니다.

독립형 ChaCha20은 32바이트 키, 32비트 초기 counter, 12바이트 nonce를 사용하는 RFC 8439 구성을 따릅니다. 같은 key/nonce 쌍을 재사용해서는 안 되며, 같은 쌍에 대한 counter 범위가 서로 겹쳐서도 안 됩니다.

## 인증 암호화

AES-GCM, AES-CCM, ChaCha20-Poly1305는 AEAD dispatcher를 사용합니다.

| 계열 | Nonce 길이 | Tag 길이 |
| --- | --- | --- |
| AES-GCM | 0이 아닌 임의 길이; 12바이트 권장 | 4, 8, 또는 12~16바이트 |
| AES-CCM | 7~13바이트 | 4~16바이트의 짝수 길이 |
| ChaCha20-Poly1305 | 정확히 12바이트 | 정확히 16바이트 |

`LIBERAC_AEAD_KEY_SIZE()`, `LIBERAC_AEAD_NONCE_LENGTH_VALID()`, `LIBERAC_AEAD_TAG_LENGTH_VALID()`를 사용하면 연산 전에 선택된 설정을 검증할 수 있습니다.

인증 실패 시 `LIBERAC_ERROR_AUTHENTICATION_FAILED`를 반환합니다. 복호화 경로는 인증되지 않은 plaintext가 성공한 출력처럼 노출되지 않도록 설계되어 있습니다.

## 해시와 XOF

해시 계열에는 다음이 포함됩니다.

- 레거시 호환성을 위한 SHA-1.
- SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256.
- SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256.
- LSH-256-224, LSH-256-256, LSH-512-224, LSH-512-256, LSH-512-384, LSH-512-512.

고정 출력 해시는 표준 digest 크기를 요구합니다. SHAKE는 caller가 출력 길이를 선택하며 finalize 이후 반복 squeeze를 지원합니다.

## 메시지 인증

- HMAC은 고정 출력 SHA-1, SHA-2, SHA-3 식별자를 허용합니다.
- CMAC은 CMAC에 적합한 AES-128/192/256 및 3-key Triple-DES EDE selector를 허용합니다.
- GMAC은 AES-GCM selector와 GCM tag 길이 규칙을 사용합니다.
- Poly1305는 Poly1305 selector, 정확히 32바이트의 one-time key, 완전한 16바이트 tag만 허용합니다.

검증 API는 공용 constant-time byte equality helper를 사용하고 인증 실패를 명시적으로 보고합니다.

## 키 파생

HKDF와 PBKDF2-HMAC은 동일한 런타임 선택 HMAC 계층을 사용합니다. 두 계열 모두 이를 사용하는 프로토콜의 제약 아래에서 고정 출력 SHA-1, SHA-2, SHA-3 HMAC selector를 지원합니다.

표준, 길이 제한, overlap 규칙, 보존된 테스트 벡터는 [키 파생](../../key-derivation.md)을 참고하세요.

## CTR_DRBG

상태를 갖는 CTR_DRBG API는 AES-128/192/256과 레거시 3-key TDEA 구성을 지원하며, 각각 `Block_Cipher_df` 사용/미사용 variant가 있습니다. AES 구성이 현대적인 기본값이고, TDEA selector는 과거 표준과의 호환성 및 test-vector 재현을 위해 존재합니다.

## 공개키 및 양자내성 계열

현재 계열에는 RSA, ElGamal, ECDH, X25519, ECDSA, Ed25519, ML-KEM, NTRU+, SMAUG-T, ML-DSA, AIMer, HAETAE, SLH-DSA가 포함됩니다. 런타임 dispatch를 지원하는 계열은 파라미터별 별도 빌드가 필요하지 않습니다.

공개 size-query API가 존재하는 경우 키, ciphertext, signature 크기를 하드코딩하지 말고 해당 helper를 사용하세요.
