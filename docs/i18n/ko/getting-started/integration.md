# LiberaCrypt 통합

## 공개 API 포함

설치된 target은 public include directory를 노출합니다. 애플리케이션은 보통 umbrella header를 포함합니다.

```c
#include <LiberaCrypt.h>
```

공개 C 함수, macro, constant, algorithm selector는 `LIBERAC_` prefix를 사용합니다. 공개 type 이름은 `LiberaC` prefix를 사용합니다.

## 런타임 선택 알고리즘

LiberaCrypt는 지원되는 파라미터 세트를 하나의 라이브러리에 함께 컴파일합니다. runtime dispatch를 지원하는 API는 파라미터별 별도 빌드 대신 `LiberaCAlgID` selector를 받습니다.

예를 들어 block-cipher 연산은 마지막 알고리즘 인자를 통해 구체적인 AES 모드를 선택합니다.

```c
LiberaCError error = LIBERAC_BLOCK_CIPHER_ENCRYPT(
    ciphertext, sizeof(ciphertext),
    plaintext, sizeof(plaintext),
    key, sizeof(key),
    initial_counter, sizeof(initial_counter),
    LIBERAC_ALG_AES_256_CTR);
```

전체 selector 집합은 `inc/Def.h`에 선언되어 있고 `LiberaCrypt.h`를 통해 사용할 수 있습니다.

dispatcher model과 API 계열의 경계는 [API 개요](../../api/overview.md)와 [알고리즘 선택](../../api/algorithm-selection.md)을 참고하세요.

## 공개 구현과 내부 구현

`inc/`의 header만 지원되는 public API를 구성합니다. private declaration은 `src/` 아래에서 각 구현과 함께 유지됩니다. 애플리케이션은 internal header를 include하거나 internal symbol에 직접 link해서는 안 됩니다.

shared-library export는 문서화된 public API로 제한됩니다. 플랫폼별 export mechanism은 consumer에 노출하지 않고 build system이 처리합니다.

## 암호학적 책임

라이브러리는 API 수준의 크기, 식별자, 많은 알고리즘별 파라미터 제약을 검증하지만 애플리케이션의 프로토콜 자체를 대신 선택할 수는 없습니다. caller는 key management, nonce uniqueness, password policy, protocol-level algorithm restriction, 그리고 interoperability 요구사항에서 legacy primitive를 허용할지 여부에 대한 책임을 집니다.

low-level primitive를 직접 통합하기 전에 [보안 고려사항](../../security/security-considerations.md)을 읽으세요.
