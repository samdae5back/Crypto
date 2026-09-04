# 이식성

LiberaCrypt에서 이식성은 단순히 여러 플랫폼에서 빌드에 성공했다는 의미가 아니라 **정확성의 일부**로 취급합니다.

어떤 코드의 결과가 명시되지 않은 compiler, ABI, byte order, 문자 표현, 정수 표현, linker 동작에 의존하고 그 가정이 다른 표준 준수 환경에서 달라질 수 있다면, LiberaCrypt에서는 그 코드를 portable하다고 보지 않습니다.

## 정책

### 정의된 정수 동작만 사용

알고리즘이나 표현에서 bit width 자체가 의미를 가지는 경우 내부 연산은 fixed-width integer type을 사용합니다. Narrowing conversion은 값의 범위를 알고 있는 경우에만 수행하며, 중요한 representation/range invariant는 코드나 compile-time assertion으로 명시하는 것을 원칙으로 합니다.

Signed arithmetic은 음수의 right shift처럼 implementation-defined인 동작에 우연히 의존해서는 안 됩니다. 알고리즘에서 floor division, sign extraction, 특정 bit representation이 필요하다면 의도한 연산을 명시적으로 구현합니다.

### Plain `char`의 signedness에 의존하지 않음

표준은 plain `char`가 signed인지 unsigned인지 플랫폼이 선택할 수 있도록 허용합니다. 따라서 정확한 signed-byte mapping이 필요한 serialization이나 arithmetic은 plain `char` 또는 implementation-defined character conversion에 기대지 않고 mapping을 직접 정의합니다.

HAETAE가 구체적인 예입니다. decomposed low-byte serialization은 signed `[-128, 127]` 범위를 명시적으로 byte와 대응시켜, plain `char`가 unsigned인 AIX/Power 환경에서도 representation이 달라지지 않도록 합니다.

### Byte order를 명시적으로 처리

Serialization과 low-level word handling은 host endianness를 가정하지 않습니다. Endian-sensitive load/store는 프로젝트 utility에 격리하고, public wire format은 native representation과 무관하게 생성합니다.

예를 들어 ChaCha20은 key, nonce, counter, output word를 모두 명시적으로 little-endian으로 decode/encode합니다.

### 가능한 경우 intermediate width의 충분성을 설명

Fixed-width 구현이라면 중간 연산에 사용한 타입의 폭이 왜 충분한지 설명할 수 있어야 합니다. HAETAE의 fixed-point FFT가 한 예로, storage, Q16 product, butterfly expression, squared magnitude, accumulation에 사용하는 폭을 한 플랫폼에서 우연히 동작한 크기가 아니라 보수적인 범위 추정에 따라 정합니다.

### 불필요한 구현 확장을 피함

Portable baseline은 표준 폭으로 실용적인 구현이 가능한 경우 compiler extension이나 비정상적으로 넓은 native integer type에 의존하지 않습니다. 예를 들어 Poly1305는 native 128-bit integer를 요구하는 대신 범위를 제한한 26-bit limb와 `uint64_t` product를 사용합니다.

### 플랫폼별 처리는 좁은 경계에 한정

운영체제 entropy 획득이나 shared-library export policy는 플랫폼별로 달라질 수밖에 없습니다. 이러한 차이는 암호 구현 전체에 conditional code를 퍼뜨리지 않고 명시적인 boundary에 격리합니다.

그 결과 같은 public API를 유지하면서 Windows DLL declaration, ELF version script, macOS exported-symbol list, Solaris mapfile, AIX `.exp` file, HP-UX export option 등 각 환경의 native mechanism을 사용할 수 있습니다.

## Portability 검토 체크리스트

코드를 추가하거나 외부 구현을 적용할 때 최소한 다음 항목을 검토합니다.

- 결과가 host endianness에 의존하는가?
- plain `char` signedness에 의존하는가?
- signed shift, division, overflow, conversion에 implementation-defined 또는 undefined behavior가 존재할 수 있는가?
- intermediate range가 선택한 integer width 안에 들어간다는 근거가 있는가?
- pointer arithmetic이 유효한 object 범위와 검증된 size 안에서 이루어지는가?
- compiler extension, native 128-bit integer, alignment, ABI, linker model을 불필요하게 가정하고 있지는 않은가?
- OS-specific behavior가 명시적인 경계 뒤에 격리되어 있는가?
- 다른 compiler나 optimization level에서 현재 toolchain이 묵인하는 가정이 드러날 수 있는가?

## 검증

CI는 주로 Windows/MSVC, Linux, macOS 환경을 다룹니다. Unit test, KAT, warning-oriented build, sanitizer, focused portability check를 이용해 단일 toolchain에서는 드러나지 않을 수 있는 가정을 찾습니다.

하지만 이 환경들에서 테스트를 통과했다는 사실 자체가 portability의 정의는 아닙니다. 특히 legacy 및 non-mainstream Unix target을 고려할 때는 위 구현 정책이 더 강한 요구사항입니다.

## 코드 스타일에 미치는 영향

조금 더 긴 표현이라도 integer width, representation, range, byte order, platform behavior를 명확하게 만든다면 짧지만 암묵적인 표현보다 우선합니다.
