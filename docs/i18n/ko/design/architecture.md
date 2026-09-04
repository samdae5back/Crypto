# 아키텍처

LiberaCrypt는 공개 operation API, 구체적인 알고리즘 구현, 그리고 플랫폼에 종속되는 좁은 경계를 서로 분리합니다.

```text
application
    |
    v
inc/의 public header
    |
    v
src/*.c의 operation/category dispatcher
    |
    v
알고리즘 구현 디렉터리
    |
    v
공통 arithmetic / endian / ECC / NTT / core utility
    |
    v
좁은 OS 및 toolchain 경계
```

## Public API 계층

설치되는 헤더는 `inc/` 아래의 파일뿐입니다. 이 계층은 operation 중심의 인터페이스, 공통 오류, 공개 타입, 크기 조회 API, `LiberaCAlgID` selector를 정의합니다.

공개 이름 규칙은 다음과 같습니다.

- 공개 C 함수, 매크로, 상수, selector에는 `LIBERAC_`를 사용합니다.
- 공개 타입 이름에는 `LiberaC`를 사용합니다.
- umbrella header는 `LiberaCrypt.h`입니다.
- 외부에 제공되는 CMake target은 `LiberaCrypt::LiberaCrypt`입니다.

## Dispatch 계층

`src/` 바로 아래의 entry-point source는 category 단위의 dispatch를 구현합니다. 이 계층은 공개 요청을 검증하고, runtime algorithm identifier를 해석한 뒤, 애플리케이션이 parameter set별로 별도 빌드를 사용하지 않아도 구체적인 구현을 호출할 수 있도록 합니다.

Operation 경계를 명확히 나누는 것은 의도적인 설계입니다. 예를 들어 authenticated-encryption selector는 raw block-cipher API를 통해 처리하지 않습니다. AAD, nonce, tag의 의미는 블록 암호화가 아니라 AEAD operation에 속하기 때문입니다.

## 알고리즘 구현

구체적인 구현은 다음과 같은 category 디렉터리에 위치합니다.

```text
src/AsymmetricCipher/
src/AuthenticatedEncryption/
src/BlockCipher/
src/DigitalSignature/
src/HashFunction/
src/KeyAgreement/
src/KeyEncapsulation/
src/MessageAuthentication/
src/RandomNumberGeneration/
src/StreamCipher/
```

Private declaration은 `inc/`를 통해 노출하지 않고 해당 구현과 함께 둡니다.

## 공통 구현 계층

`src/Util/`에는 bignum, bit, core, ECC, endian, NTT, prime 등 여러 구현에서 공유하는 내부 기능이 들어 있습니다. 이 계층은 두 번째 public API가 아니라 내부 building block입니다.

Constant-time byte comparison이나 overflow를 고려한 buffer-overlap 검증처럼 보안에 민감한 로직의 중복을 줄일 수 있을 때는 공통 helper를 우선합니다.

## 플랫폼 경계

암호 알고리즘 코드는 외부 cryptographic runtime에 의존하지 않는 것을 목표로 합니다. 플랫폼별 차이는 운영체제 entropy 획득이나 shared-library symbol export처럼 불가피한 좁은 영역에 한정합니다.

공개 symbol의 기준 allowlist는 `cmake/liberacrypt_exports.txt`입니다. 빌드 시스템은 Windows DLL declaration, ELF version script, macOS exported-symbol list, Solaris mapfile, AIX export file, HP-UX linker export option 등 각 플랫폼의 native mechanism을 사용해 같은 공개 API를 내보냅니다.

## 이 구조를 사용하는 이유

이 아키텍처는 다음 세 가지 관심사를 분리하기 위해 설계되었습니다.

1. **호출자가 무엇을 하려는가** — 암호화, 인증, 키 유도, 서명, encapsulation 등.
2. **어떤 구체적인 알고리즘/parameter set으로 수행하는가** — 필요한 경우 runtime에 선택.
3. **호스트 환경에서 구현이 어떻게 이식성과 안전성을 유지하는가** — 플랫폼 가정을 public API에 노출하지 않고 내부에서 처리.

이 구분을 통해 portability, constant-time behavior, 알고리즘 최적화를 발전시키면서도 public interface 수를 불필요하게 늘리지 않을 수 있습니다.
