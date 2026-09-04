# ML-KEM 최적화 기록

## 상태와 범위

이 문서는 LiberaCrypt의 original FIPS 203 ML-KEM 구현에 대한 첫 번째 focused optimization pass를 기록합니다. 동일한 runtime-dispatched source가 계속 ML-KEM-512, ML-KEM-768, ML-KEM-1024를 모두 구현합니다.

이번 pass의 우선순위는 다음과 같습니다.

- ISO C portability와 하나의 runtime-selected implementation 유지;
- architecture-specific intrinsic 또는 assembly 회피;
- secret-indexed table이나 secret-dependent control flow 추가 금지;
- FIPS 203 encoding, rejection-sampling order, API behavior, failure handling 보존;
- NTT arithmetic representation을 바꾸거나 더 복잡한 reduction scheme을 도입하기 전에 구조적으로 큰 이득을 먼저 취함.

재현 가능한 benchmark가 보존되기 전에는 이 문서에서 throughput 수치를 주장하지 않습니다. 아래 operation-count와 loop-count 감소는 source transformation에서 직접 도출되는 경우에만 기술합니다.

## Baseline 관찰

최적화 전 구현에는 눈에 띄는 portable hot path가 네 곳 있었습니다.

1. `ByteEncode`와 `ByteDecode`가 encoded coefficient의 각 bit를 하나씩 순회했습니다. 흔한 10-, 11-, 12-bit polynomial encoding에서는 polynomial마다 수천 개의 작은 loop iteration이 생깁니다.
2. `SampleNTT`가 rejection-sampling candidate 두 개마다 SHAKE128에서 3 byte만 요청했습니다. underlying XOF는 byte stream이므로 작은 request는 stream 생성에 필요한 Keccak work를 줄이지 않으면서 helper/loop overhead만 늘립니다.
3. K-PKE decryption이 `k`개의 secret/ciphertext polynomial pair를 각각 NTT domain에서 곱하고 각 product를 독립적으로 inverse-transform한 뒤에야 coefficient-domain polynomial을 더했습니다.
4. NTT path가 7-bit bit reversal을 division/modulo loop로 매번 다시 계산했고, `Multiply_NTT`는 모든 two-coefficient product를 별도의 helper call로 처리했습니다.

inner NTT butterfly와 base multiplication에는 여전히 많은 일반 `% 3329` 연산이 있습니다. 이 reduction 교체는 의도적으로 뒤로 미룹니다. transform 전반의 coefficient range/representation invariant를 바꾸므로 proof와 validation 비용이 더 크기 때문입니다.

## 1. Packed bit-reservoir encoding/decoding

### Baseline / 문제

`ByteEncode`와 `ByteDecode`는 coefficient bit를 하나씩 처리하고 inner loop 안에서 byte/bit position을 반복 계산했습니다.

### 변경

두 함수 모두 `uint32_t` little-endian bit reservoir를 사용합니다. coefficient를 현재 bit offset에 append하고 8 bit 이상이 준비되는 즉시 whole byte를 emit/consume합니다.

전체 encoded size는 변하지 않습니다. 256 coefficient × public `bit_width`이며 모든 지원 width는 최대 12 bit입니다. 새 coefficient를 append하기 직전 reservoir에는 8 bit 미만만 남으므로 meaningful bit는 최대 19개입니다. 따라서 32-bit unsigned reservoir면 충분합니다.

### Correctness

이전 loop는 coefficient bit를 증가하는 bit order로 emit/consume했습니다. reservoir도 정확히 같은 concatenation과 extraction을 수행하며, 단지 한 번의 C operation에서 여러 bit를 처리합니다. 12-bit decoding에서는 기존 modulo `q` reduction을 유지하고, 더 작은 width에서는 기존 power-of-two modulus semantics를 유지합니다.

### 보안 영향

loop count와 shift는 coefficient value가 아니라 public encoding width에 의존합니다. secret-indexed memory access나 coefficient-dependent branch를 추가하지 않습니다.

### Portability 영향

reservoir는 type-punning이나 native-endian word load가 아니라 fixed-width unsigned arithmetic과 byte access를 사용합니다. `mlkem_power_of_two`도 small validated result를 `int`로 다시 변환하기 전에 unsigned fixed-width left shift를 사용합니다.

### 예상 효과

모든 ML-KEM polynomial serialization/deserialization에서 bit-at-a-time inner loop를 제거합니다. 가장 큰 이득은 10-, 11-, 12-bit encoding에서 예상됩니다. 아직 측정 speedup은 주장하지 않습니다.

## 2. SHAKE128 rate-block matrix sampling

### Baseline / 문제

`SampleNTT`는 한 번에 3 byte를 squeeze하고 12-bit candidate 두 개를 parse한 뒤 256개의 accepted coefficient를 얻을 때까지 반복했습니다.

### 변경

sampler는 이제 한 번에 168-byte SHAKE128 rate block을 squeeze하고 동일한 연속 3-byte group으로 parse합니다. 168은 3으로 나누어떨어지므로 candidate group이 local buffer boundary를 가로지르지 않습니다.

### Correctness

SHAKE128은 하나의 연속 output byte stream을 제공합니다. 연속 squeeze의 크기를 바꾸어도 stream 자체는 바뀌지 않습니다. 따라서 `[0..2], [3..5], ...` group으로 byte를 parse하면 기존과 같은 candidate를 같은 순서로 동일한 `< 3329` rejection test에 제공합니다.

### 보안 영향

matrix generation은 public matrix seed에서 파생됩니다. FIPS 203이 요구하는 기존 standard rejection sampler 외에 secret-dependent index/branch를 추가하지 않습니다.

### Portability / memory 영향

최적화는 byte array와 기존 portable SHAKE API만 사용합니다. `SampleNTT`에 168-byte automatic buffer 하나를 추가하는데, 기존 heap workspace보다 작고 architecture-specific vector code를 피합니다.

### 예상 효과

sampled matrix polynomial 하나당 XOF squeeze helper 호출 횟수가 candidate pair마다 한 번 수준에서 소수의 full-rate request로 감소합니다. Keccak output stream과 필요한 permutation 횟수는 바뀌지 않습니다. 절감되는 것은 cryptographic round가 아니라 주변 helper/byte-loop overhead입니다. 아직 benchmark 수치는 주장하지 않습니다.

## 3. K-PKE decryption inner product의 inverse NTT 1회화

### Baseline / 문제

기존 K-PKE decryption은 vector component마다 다음을 계산했습니다.

```text
InvNTT(s_i_hat * u_i_hat)
```

그리고 resulting coefficient-domain polynomial을 accumulate했습니다. 즉 `k`번 inverse NTT를 수행했습니다.

### 변경

이제 product를 먼저 NTT domain에서 accumulate한 뒤 inverse NTT를 한 번만 수행합니다.

```text
InvNTT(sum_i (s_i_hat * u_i_hat))
```

### Correctness

inverse NTT는 ML-KEM coefficient ring 위에서 linear하므로:

```text
sum_i InvNTT(x_i) = InvNTT(sum_i x_i).
```

pointwise base multiplication과 addition은 계속 modulo `q`에서 수행됩니다. sum에 대한 linear inverse transform의 위치만 바뀝니다.

### 보안 영향

loop count는 계속 public parameter `k`입니다. secret-dependent branch, table lookup, early exit를 추가하지 않습니다. 오히려 transform schedule은 더 짧아지고 여전히 parameter-determined입니다.

### Portability 영향

기존 NTT implementation을 이용한 algebraic reordering일 뿐이므로 새로운 integer-width, endian, alignment, compiler assumption을 추가하지 않습니다.

### 예상 효과

K-PKE decryption마다 정확히 `k - 1`개의 inverse NTT call을 제거합니다.

| Parameter set | 이전 inverse NTT | 현재 inverse NTT | 제거 |
| --- | ---: | ---: | ---: |
| ML-KEM-512 (`k = 2`) | 2 | 1 | 1 |
| ML-KEM-768 (`k = 3`) | 3 | 1 | 2 |
| ML-KEM-1024 (`k = 4`) | 4 | 1 | 3 |

첫 pass 변경 중 가장 명확한 deterministic operation-count reduction이며 decapsulation에 가장 직접적인 영향을 줄 것으로 예상됩니다.

## 4. 작은 NTT helper cleanup

### Baseline / 문제

hot NTT path는 7-bit index를 뒤집기 위해 2로 반복 division/modulo하고 7-element temporary array를 사용했습니다. `Multiply_NTT`도 모든 pair마다 out-of-line basic multiplication helper를 호출했습니다.

### 변경

internal transform code는 이제 fixed unsigned mask/shift operation으로 7 bit를 reverse합니다. `Multiply_NTT`가 사용하는 base two-coefficient multiplication은 local `static inline` helper로 사용할 수 있습니다. 기존 `bit_rev`와 `Multiply_basic` entry point는 다른 internal user와의 source-level compatibility를 위해 유지합니다.

### Correctness

mask/shift network는 low 7 bit의 직접 permutation이며 ML-KEM transform range 안의 index에만 사용됩니다. base multiplication equation은 바뀌지 않습니다.

### 보안 및 portability 영향

bit reversal은 fixed instruction-shaped source sequence를 갖고 unsigned arithmetic만 사용합니다. secret data로 index되는 lookup table을 추가하지 않으며 compiler extension도 필요하지 않습니다.

### 예상 효과

NTT와 base multiplication 전반에서 반복되던 작은 arithmetic/helper overhead를 제거합니다. inverse-NTT elimination과 packing change보다 secondary improvement로 예상합니다.

## 검증

저장소에는 이미 세 parameter set 모두에 대한 ML-KEM unit coverage가 있습니다. successful key generation/encapsulation/decapsulation, implicit-rejection behavior, non-canonical public key, embedded-public-key hash validation, output clearing, overlap rejection을 포함합니다. 또한 ML-KEM-512, ML-KEM-768, ML-KEM-1024 KAT target이 있습니다.

이 optimization branch의 acceptance evidence는 다음과 같습니다.

1. 세 parameter set 모두에서 기존 unit suite 통과;
2. 세 ML-KEM KAT suite가 byte-for-byte 통과;
3. Linux, Windows, macOS의 일반 CI build/test matrix가 green 유지;
4. numerical speedup을 광고하기 전에 reproducible local benchmark 보존;
5. 이후 reduction rewrite에는 더 엄격한 overflow/range review 및 가능한 sanitizer/differential coverage 적용.

개발 중 packed codec은 지원 width 전반에서 byte-for-byte round-trip/equivalence를 확인했고, 7-bit reversal은 128개 input 전부를 확인했으며, inverse-NTT reordering은 `k = 2, 3, 4`에 대해 이전 algebraic ordering과 비교했습니다. 이러한 check는 repository KAT/CI evidence를 보완하지만 대체하지 않습니다.

## Benchmark 계획

ML-KEM-512/768/1024 각각에 대해 key generation, encapsulation, decapsulation을 따로 benchmark합니다. compiler/version, optimization flag, host CPU/OS, warm-up policy, iteration count, median 같은 robust statistic을 기록합니다. 같은 build/host에서 pre-optimization main commit과 이 branch를 비교합니다. hosted-runner variance를 통제할 수 없으므로 CI-host timing을 published performance claim으로 사용해서는 안 됩니다.

## Deferred optimization: modular reduction 및 NTT representation

남아 있는 가장 큰 arithmetic question은 NTT butterfly와 base multiplication의 빈번한 일반 `% MLKEM_Q`를 bounded Montgomery/Barrett-style reduction과 더 타이트한 coefficient-range invariant로 교체할지 여부입니다.

이는 추가 micro-cleanup보다 큰 throughput opportunity일 가능성이 높지만 arithmetic representation/range argument를 바꾸므로 low-risk pass에는 의도적으로 포함하지 않습니다. portable version은 AVX2/NEON이나 secret-dependent behavior 없이 ISO C로 작성할 수 있지만 explicit range proof, KAT, strict warning/sanitizer build, before/after benchmark 이후에만 채택해야 합니다.

권장 순서:

1. 이번 first-pass branch를 benchmark하고 남은 profile을 확인;
2. NTT/base reduction이 여전히 dominant하면 별도 commit/branch에서 portable bounded reduction path 구현;
3. 새 path가 독립 validation을 받을 때까지 현재 simple arithmetic을 comparison baseline으로 유지;
4. architecture-specific AVX2/NEON backend는 portable implementation의 대체가 아니라 별도의 future layer로 고려.

별도의 memory trade-off도 남아 있습니다. 현재 구현은 maximum-sized heap workspace를 사용하고 full matrix를 materialize합니다. on-the-fly matrix generation 또는 tighter parameter-sized workspace는 memory를 줄일 수 있지만 추가 SHAKE work, allocator behavior, code complexity, zeroization consideration과 trade할 수 있습니다. 이 문제는 현재 throughput pass에 섞지 말고 독립적으로 측정해야 합니다.
