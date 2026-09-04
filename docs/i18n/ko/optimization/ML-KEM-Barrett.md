# ML-KEM portable Barrett reduction

## 범위

이 문서는 두 번째 portable ML-KEM 산술 최적화 pass를 기록합니다. 이미 merge된 hot-path optimization에서 시작하며, portable NTT 구현이 사용하는 ordinary-domain modular arithmetic만 변경합니다. Montgomery representation은 별도의 측정 가능한 변경으로 의도적으로 미룹니다.

목표는 다음과 같습니다.

- `q = 3329`에서 모든 NTT coefficient를 canonical `[0, q)` 범위로 유지;
- NTT butterfly와 base multiplication에서 일반 signed `% 3329` 연산 제거;
- fixed-width unsigned ISO C arithmetic만 사용;
- secret-dependent table index 또는 source-level branch 방지;
- reduction bound와 correctness argument를 명시적으로 기록.

재현 가능한 benchmark가 보존되기 전에는 numerical speedup을 주장하지 않습니다. compiler는 constant division을 strength-reduce할 수 있고, 64-bit reciprocal multiply 비용은 32-bit와 64-bit target에서 다를 수 있습니다. division/remainder operation과 cleanup loop의 deterministic source-level 감소는 measured throughput과 별도로 기록합니다.

## Canonical coefficient invariant

최적화된 transform은 모든 butterfly boundary에서 다음 invariant를 유지합니다.

```text
0 <= coefficient < q
```

canonical `a`, `b`에 대해:

```text
0 <= a + b < 2q
0 <= a + q - b < 2q
```

따라서 modular addition과 subtraction은 고정된 형태의 conditional correction 한 번만 필요합니다. 이 연산들에는 일반 reduction이 필요하지 않습니다.

twiddle multiplication은 다음 범위를 가집니다.

```text
0 <= z * a <= (q - 1)^2 = 11,075,584.
```

현재 base multiplication이 reduce하는 가장 큰 값은 이러한 bounded term 두 개의 합입니다.

```text
2 * (q - 1)^2 = 22,151,168.
```

이는 `2^31`과 `2^32`보다 훨씬 작습니다. 그럼에도 구현은 unsigned fixed-width intermediate를 사용하므로 signed overflow와 negative-remainder semantics가 proof에 포함되지 않습니다.

## Barrett 구성

다음과 같이 둡니다.

```text
B  = 2^32
q  = 3329
mu = floor(B / q) = 1,290,167.
```

임의의 `uint32_t` 값 `x`에 대해 다음을 정의합니다.

```text
qhat = floor(x * mu / B)
r    = x - qhat * q.
```

다음이 성립하므로:

```text
B/q - 1 < mu <= B/q
```

그리고 `0 <= x < B`이므로 `x/B`를 곱하면:

```text
x/q - x/B < x*mu/B <= x/q.
```

`0 <= x/B < 1`이므로 floor를 취했을 때 `qhat`은 다음 둘 중 하나입니다.

```text
floor(x/q)
```

또는 정확히 그보다 1 작습니다. 따라서:

```text
0 <= r < 2q.
```

마지막으로 `q`를 한 번 빼고 subtraction이 underflow했을 때 조건부로 복원하면 modulo `q`에 대한 congruence를 유지하면서 `[0, q)`의 유일한 representative를 얻습니다.

구현은 `x * mu`를 `uint64_t`로 계산하고 32비트 오른쪽 shift한 뒤 `uint32_t`에서 final correction을 수행합니다. LiberaCrypt는 이미 다른 곳에서 정확한 64-bit unsigned arithmetic을 요구하고 사용하므로 새로운 integer width requirement를 추가하지 않습니다.

## Fixed-shape final correction

입력이 `[0, 2q)`에 있다고 알려진 경우 `uint32_t`에서 다음을 계산합니다.

```text
reduced = value - q
mask    = 0 - (reduced >> 31)
result  = reduced + (q & mask)
```

`value >= q`이면 `reduced`는 `[0, q)`에 있고 high bit는 0입니다. `value < q`이면 unsigned subtraction이 `2^32`에 가까운 값으로 wrap하며, `q < 2^31`이므로 high bit가 1입니다. 이때 mask가 정확히 `q` 하나를 복원합니다.

source에는 coefficient-dependent `if` 문이 없습니다. LiberaCrypt의 다른 부분과 마찬가지로 이는 모든 compiler/processor에 대한 보편적인 물리적 constant-time 보장이 아니라 constant-schedule source construction으로 설명합니다.

## NTT 동등성

이전 forward butterfly는 다음과 동등했습니다.

```text
t = z*b mod q
b = a-t mod q
a = a+t mod q
```

중간에 음수 C remainder가 생길 수 있고 마지막에 normalization pass를 수행했습니다. 새로운 형태는 동일한 residue class를 계산하되 해당 butterfly에서 두 출력을 즉시 canonicalize합니다.

```text
t = Barrett(z*b)
b = canonical_sub(a, t)
a = canonical_add(a, t)
```

inverse butterfly도 다음을:

```text
z * (b-a) mod q
```

다음으로 바꿉니다.

```text
z * canonical_sub(b, a) mod q.
```

`canonical_sub(b,a) == b-a (mod q)`이므로 ring element는 바뀌지 않습니다. `3303 = 128^-1 mod q`를 곱하는 마지막 연산 역시 동일한 ordinary-domain Barrett helper로 reduce하므로 Montgomery factor가 도입되지 않습니다.

## Base multiplication 동등성

다음 연산에 대해:

```text
(a0 + a1 X)(b0 + b1 X) mod (X^2 - r)
```

구현은 여전히 다음을 계산합니다.

```text
c0 = a0*b0 + a1*b1*r mod q
c1 = a0*b1 + a1*b0   mod q.
```

`a1*b1`은 `r`을 곱하기 전에 먼저 canonical residue로 reduce됩니다. intermediate를 congruent residue로 바꾸어도 modulo `q` 최종 결과는 달라지지 않습니다. 최종 wide value는 `2(q-1)^2` 이하이므로 위의 32-bit Barrett input bound를 그대로 적용할 수 있습니다.

## 보안 영향

이 최적화는 `Z_q`의 동일한 element에 대한 integer representative만 변경합니다. ML-KEM parameter, NTT root, wire encoding, rejection sampling, key/ciphertext format, decapsulation rejection logic은 바뀌지 않습니다.

모든 transform loop bound와 twiddle index는 계속 public이며 parameter로 결정됩니다. 새로운 reduction helper는 secret-indexed lookup이나 source-level coefficient-dependent branch를 추가하지 않습니다.

## Portability 영향

이전 구현은 butterfly 내부에서 음수가 될 수 있는 값에 signed `% q`를 사용하고 마지막에 negative representative를 보정했습니다. 새 구현은 NTT 전체에서 arithmetic을 non-negative canonical 상태로 유지하고, 정의된 wrap/shift semantics를 갖는 `uint32_t`/`uint64_t` 연산을 사용합니다. 따라서 hot transform path에서 negative remainder handling에 대한 의존을 제거하며 signed right shift, type punning, alignment assumption, native-endian word load, compiler intrinsic, SIMD, assembly를 사용하지 않습니다.

주요 performance caveat는 의미론이 아니라 architecture에 관한 것입니다. 일부 32-bit target에서는 64-bit reciprocal multiplication이 native 64-bit target보다 비쌀 수 있습니다. 따라서 explicit Barrett multiply가 각 대표 platform에서 throughput 이점이 있는지는 benchmark로 판단해야 합니다. canonical add/sub transformation은 butterfly addition/subtraction에서 일반 reduction을 제거하므로 이와 독립적으로 유용합니다.

## Repository CI 전 수행한 검증

reduction formula는 0부터 현재 ML-KEM wide intermediate 최대값까지 모든 값에 대해 일반 integer `% 3329`와 기계적으로 비교했습니다.

```text
0 .. 22,151,168
```

mismatch는 없었습니다.

canonical addition과 subtraction은 다음 모든 pair에 대해 수학적 modulo 결과와 exhaustive하게 비교했습니다.

```text
a, b in [0, 3329).
```

old/new forward/inverse NTT formula도 1,000개의 random canonical 256-coefficient polynomial에서 비교했으며 mismatch가 없었습니다.

이 development check는 repository evidence를 보완하지만 대체하지 않습니다. acceptance에는 기존 ML-KEM-512/768/1024 KAT와 unit test, 그리고 일반 Linux/Windows/macOS CI build matrix가 계속 필요합니다.

## Montgomery를 별도로 유지하는 이유

Montgomery reduction 역시 `q = 3329`에 대해 수학적으로 유효하지만 `REDC(x)`는 `x * R^-1 mod q`를 계산합니다. 따라서 twiddle과 transform scaling factor를 적절한 Montgomery domain에서 추적하지 않고 ordinary `% q` 대신 바로 대입하면 잘못된 결과가 됩니다.

이번 Barrett pass는 모든 table과 coefficient를 기존 ordinary representation에 그대로 둡니다. 향후 Montgomery pass는 explicit domain invariant, 변환된 twiddle constant, forward/inverse scaling proof, KAT validation, before/after benchmark를 갖는 별도 commit이어야 합니다. 이렇게 분리하면 이후 performance comparison과 regression diagnosis가 훨씬 명확해집니다.
