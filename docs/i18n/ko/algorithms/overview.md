# 알고리즘 계열

이 페이지는 LiberaCrypt가 제공하는 알고리즘을 한눈에 보기 위한 안내서입니다. 각 알고리즘의 표준 문서나 생성된 공개 API 레퍼런스를 대신하지는 않습니다.

| 계열 | 구현 |
| --- | --- |
| 블록 암호 | AES-128/192/256; 3-key Triple-DES EDE |
| 스트림 암호 | ChaCha20 |
| 인증 암호화 | AES-GCM, AES-CCM, ChaCha20-Poly1305 |
| 해시 / XOF | SHA-1, SHA-2, SHA-3, SHAKE, LSH |
| 메시지 인증 | HMAC, CMAC, GMAC, Poly1305 |
| 키 파생 | HKDF, PBKDF2-HMAC |
| 난수 생성 | OS 난수 바이트, CTR_DRBG |
| 공개키 암호화 | RSAES-OAEP, raw RSA primitive, ElGamal |
| 키 합의 | NIST P-256/P-384/P-521 기반 ECDH, X25519 |
| 전자서명 | RSASSA-PSS, ECDSA, Ed25519, ML-DSA, SLH-DSA, AIMer, HAETAE |
| 키 캡슐화 | ML-KEM-512/768/1024, NTRU+768/864/1152, SMAUG-T-128/192/256 |
| 유틸리티 산술 | Bignum, 소수 생성, ECC 및 공용 산술 헬퍼 |

## 대칭키 암호화와 AEAD

인증되지 않은 블록/스트림 암호화와 인증 암호화는 의도적으로 서로 다른 API 계열로 분리되어 있습니다. 새로운 애플리케이션 프로토콜에서는 인증되지 않은 암호화와 인증을 임의로 조합하기보다 일반적으로 인증 암호화 구성을 우선하는 것이 좋습니다.

## 해시, MAC, KDF

해시, 메시지 인증, 키 파생 API는 동일한 런타임 선택 모델을 사용하되 연산별 파라미터 검증은 분리해 둡니다. HKDF와 PBKDF2-HMAC은 [키 파생](../../key-derivation.md) 문서에 더 자세히 설명되어 있습니다.

## 전통적 공개키 알고리즘

RSA 암호화에는 RSAES-OAEP를, RSA 서명에는 RSASSA-PSS를 사용해야 합니다. raw textbook RSA는 primitive 수준의 테스트와 호환성을 위해 남아 있지만, 애플리케이션이 이를 안전한 암호화 또는 서명 방식으로 취급해서는 안 됩니다.

ECDH와 ECDSA는 NIST P-256, P-384, P-521 곡선을 지원합니다. X25519와 Ed25519는 NIST 곡선 API의 파라미터 선택으로 표현하지 않고 각각의 전용 인코딩과 인터페이스를 사용합니다.

## 양자내성 알고리즘

LiberaCrypt는 portable C backend를 통해 여러 KEM 및 서명 계열을 제공합니다. vendored component는 각 upstream notice와 license를 그대로 유지합니다. provenance와 고정된 revision 또는 package hash는 저장소 최상위의 `THIRD_PARTY_NOTICES.md`를 참고하세요.

## 레거시 호환성

SHA-1과 Triple-DES/TDEA는 상호운용성과 과거 표준과의 호환성을 위해 유지됩니다. 새로운 프로토콜의 기본값으로는 권장하지 않습니다. [레거시 및 호환성 알고리즘](../../security/legacy-algorithms.md)을 참고하세요.
