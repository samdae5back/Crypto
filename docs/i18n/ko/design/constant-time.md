# Constant-time 정책

LiberaCrypt는 모든 산술 primitive를 `_ct`와 `_vartime` variant로 중복 구현하지 않습니다. secret-dependent loop count, branch, table index, normalization, operand length가 비밀 정보를 노출할 수 있는 지점에서 timing-sensitive behavior를 분리합니다.

일반 bignum 계층은 ordinary/public data에 최적화된 상태로 유지하고, 더 강한 timing behavior가 필요한 call site에서는 전용 fixed-width secret path를 사용합니다.

## Public exponentiation과 secret exponentiation

public/non-secret exponentiation은 adaptive sliding window, odd-power precomputation, direct table lookup, zero-bit skipping, trivial-value early exit 같은 variable-time 최적화를 사용할 수 있습니다.

secret exponentiation은 fixed-width Montgomery path를 사용합니다.

- secret exponent의 significant length가 아니라 공개된 modulus 전체 폭을 스캔합니다.
- 예정된 각 bit마다 필요한 square/multiply candidate를 계산합니다.
- secret-dependent table index나 multiply branch 대신 mask로 결과를 선택합니다.
- secret residue를 fixed-width Montgomery storage에 유지합니다.
- secret result에는 fixed-count normalization을 사용합니다.
- 반환 전에 secret temporary storage를 지웁니다.

RSA private operation과 ElGamal secret exponentiation이 이 정책을 사용합니다.

## Secret storage 경계

일반 `LiberaCBignum`은 이미 significant `LENGTH`를 표현합니다. 기존 variable-length object를 fixed-width secret storage로 변환하는 과정은 그 기존 표현에 대해 진정한 constant-schedule이라고 부를 수 없습니다.

따라서 LiberaCrypt는 fixed-width secret storage로의 promotion을 명시적인 경계로 취급합니다. RSA `D`, ElGamal `X` 같은 persistent secret은 생성될 때 promotion되고, 이후의 secret copy와 serialization은 caller가 선택한 공개된 전체 폭을 순회할 수 있습니다.

이 구분은 실제로는 secret object의 significant length를 따라가면서 helper에 constant-time이라는 이름을 붙이는 일을 피하기 위한 것입니다.

## 기타 산술

- public data에 대해서는 generic add/subtract, reduction, compare, normalization, serialization이 variable-time이어도 됩니다.
- fixed-width secret helper는 사용되지 않는 중복 산술 스택을 유지하는 대신 실제 secret call site가 필요로 할 때 추가합니다.
- secret modular arithmetic은 secret residue를 generic division-style remainder path로 보내기보다 fixed-width Montgomery representation을 우선합니다.
- prime generation과 Miller-Rabin은 의도적으로 variable-time입니다. candidate와 witness의 control flow는 persistent secret exponent state로 취급하지 않습니다.

## 인증 비교

authentication-tag 검증은 알고리즘별 early-exit 비교 루프 대신 공용 constant-time byte-equality helper를 사용합니다.

## 주장 범위

constant-time 구현 작업은 선택된 software timing side channel을 줄이기 위한 것입니다. 라이브러리의 모든 연산, compiler output, 운영체제, 하드웨어, 전체 애플리케이션이 모든 attacker model에서 side-channel resistant하다는 주장은 아닙니다.

새로운 constant-time 주장을 추가할 때는 다음을 명확히 해야 합니다.

1. 어떤 값이 secret인지;
2. 어떤 공개된 width 또는 iteration bound가 schedule을 고정하는지;
3. 어떤 branch, memory index, loop count에서 secret dependence를 제거했는지;
4. variable-length generic helper로 조용히 fallback하지 않았음을 어떻게 검증했는지.
