# 최적화 기록

최적화 문서는 기반 암호 표준이나 wire format의 변경이 아니라 구현 선택의 근거를 기록합니다.

*reference-shaped baseline*은 표준 pseudocode를 직접 옮긴 구현이나 LiberaCrypt의 초기 단순 구현을 뜻합니다. 문서에서 명시적으로 밝히지 않는 한 공식 upstream 또는 NIST 구현을 benchmark baseline으로 사용했다는 뜻은 아닙니다.

## 컴포넌트별 기록

- [Bignum](Bignum.md) — public-data와 secret-data 산술 경로, exponentiation, Montgomery 작업, 측정된 단계.
- [ECC](ECC.md) — elliptic-curve arithmetic 구현 및 최적화 단계.
- [Ed25519](Ed25519.md) — Ed25519 전용 산술과 구현 선택.
- [RSA](RSA.md) — RSA 산술 및 OAEP/PSS 관련 구현 작업.
- [ML-KEM](ML-KEM.md) — ML-KEM 구현/최적화 기록과 최종 선택 경로.
- [ML-KEM Barrett 실험](ML-KEM-Barrett.md) — Barrett-only, hybrid Montgomery, full-Montgomery 접근의 집중 비교.

## 공용 및 레거시 작업

모든 개선이 순수 throughput 최적화인 것은 아닙니다. LiberaCrypt는 cache behavior, memory traffic, code size, 중복 구현 제거, timing behavior, portability를 위한 측정되거나 근거 있는 변경도 수행합니다.

예시는 다음과 같습니다.

- SHA-1은 circular message schedule을 사용하고 각 complete streaming block을 context staging buffer에 복사하지 않고 직접 처리할 수 있습니다.
- Triple-DES는 secret-indexed S-box table access를 피하고 fixed-index Boolean 구현을 유지합니다. hot permutation 작업은 generic bit-by-bit table walk와 중복 intermediate permutation을 피하도록 재구성되었습니다.
- AES portable 구현은 secret-derived table indexing 대신 algebraic S-box/inverse-S-box path를 사용합니다.
- SHA-2 및 LSH streaming path는 partial context block을 비운 뒤 complete input block을 직접 처리합니다.
- one-shot hash API는 padding/finalization logic을 중복 구현하지 않고 동일한 incremental state machine을 재사용합니다.
- 공용 constant-time byte equality와 overflow-aware overlap helper가 알고리즘 계열별 중복 security-sensitive loop를 대체합니다.
- portable PQC integration은 backend가 허용하는 경우 불필요한 parameter-specialized compilation보다 하나의 runtime-dispatched library build를 우선합니다.

재현 가능한 benchmark가 보존되어 있지 않은 경우 구현을 재구성했다는 이유만으로 throughput 향상을 주장해서는 안 됩니다.

## ML-KEM reduction 결정

프로젝트는 Ubuntu, Windows, macOS runner에서 Barrett-only, hybrid Montgomery, full-Montgomery ML-KEM 구현을 비교했습니다. 보존된 비교에서 hybrid Montgomery는 전체적으로 Barrett-only보다 느렸고 full Montgomery는 테스트한 runner에서 더 큰 regression을 보였습니다. 따라서 default portable ML-KEM path는 Barrett reduction을 유지합니다.

집중된 methodology와 runner별 측정값은 저장소 landing page가 아니라 [ML-KEM Barrett 실험](ML-KEM-Barrett.md)에 둡니다.

## 새로운 최적화 작업의 문서 형식

새로운 컴포넌트 기록은 적용 가능한 경우 다음 구조를 따르는 것이 좋습니다.

1. **Baseline implementation** — 변경 전 코드가 무엇을 했는지.
2. **Optimization goal** — throughput, allocation, memory traffic, code size, portability, timing behavior, maintainability 중 무엇이 목표인지.
3. **Implementation changes** — 구체적인 transformation.
4. **Correctness and timing constraints** — 최적화가 보존해야 하는 invariant.
5. **Portability considerations** — integer width, representation, compiler behavior, architecture에 대한 가정.
6. **Benchmark methodology** — hardware/runner, compiler, build flag, repetition, comparison baseline.
7. **Results** — 일반성을 과장하지 않은 보존된 측정값.
8. **Final decision** — 선택된 구현이 default path에 남는 이유.

이 형식은 시도한 최적화가 최종적으로 기각된 경우에도 engineering reasoning을 보존하기 위한 것입니다.
