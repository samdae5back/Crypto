# Bignum 최적화 기록

이 문서는 LiberaCrypt의 2단계 arbitrary-precision arithmetic 최적화에 대한 통합 engineering record입니다.

## 한눈에 보기

| Stage | Baseline | 채택된 변경 | 측정 결과 |
|---|---|---|---|
| Stage 1 | bit-at-a-time generic reduction, repeated-doubling `R^2`, shifted CIOS | normalized base-2^32 remainder, direct `R^2`, integrated-shift CIOS | `mod` 약 **49x-83x**, `mod-mul` 약 **26x-55x** 빨라짐; CIOS 자체는 **0.7%-17.1%** 빨라짐 |
| Stage 2 | allocate/replace 방식 add/sub/mul/square, 기존 schoolbook/square loop | 안전한 output reuse, 더 타이트한 schoolbook carry 처리, doubled-cross square accumulation 1회 | add/sub 약 **38%-66%**, square **15%-62%** 빨라짐; generic mul은 더 작고 혼합된 **-2%-18%** 변화 |
| Stage 3 | Stage-2 schoolbook multiplication | 동일 폭 operand에 대해 **96 limbs / 3072 bits 이상**에서 측정 기반 one-level portable Karatsuba dispatch | 최종 production path의 3072-bit 결과: **+6.0% Linux, +25.2% macOS, +12.5% Windows**; 더 큰 크기에서는 이득 증가 |

아래 모든 performance claim은 **같은 run 안의 pairwise comparison**입니다. reference와 candidate는 동일한 hosted runner에서 동일한 deterministic input으로 실행됩니다. 서로 다른 workflow run의 absolute timing을 합쳐 인위적인 cumulative speedup을 만들지 않습니다.

portable baseline은 계속 32-bit limb와 32x32-to-64 arithmetic입니다. 이 단계들은 `__uint128_t`, compiler intrinsic, assembly, host-endian word cast를 요구하지 않습니다.

## 보안 경계

일반 bignum 계층은 의도적으로 performance-oriented variable-time입니다. secret-sensitive protocol arithmetic은 fixed-width constant-schedule path에 남습니다.

- Stage 1은 CIOS accumulation machinery를 공유하지만 secret path는 fixed loop count와 masked final reduction을 유지합니다.
- Stage 2는 generic add/sub/mul/square path를 변경하지만 fixed-width secret exponentiation schedule을 대체하지 않습니다.
- Stage 3은 generic multiplication API에만 dispatch합니다. fixed-width secret Montgomery arithmetic은 Karatsuba를 거치지 않습니다.
- Stage-3 Karatsuba workspace는 free 전에 secure zeroize됩니다. 모든 사용 sub-buffer가 arithmetic helper에서 완전히 초기화됨을 확인한 뒤 중복 initialization pass만 제거했으며 final zeroization은 유지합니다.

---

# Stage 1 - public reduction 및 Montgomery core

## 변경 내용

Stage 1 이전의 `crypto_bignum_mod()`는 dividend를 bit 단위로 scan했습니다. temporary remainder를 shift하고 한 bit를 append한 뒤 compare하고 조건부 subtract했습니다. Stage 1은 이를 다음으로 대체했습니다.

1. normalized base-2^32 long-division remainder;
2. `2^(64n)`을 한 번 reduce해서 직접 구성하는 Montgomery `R^2`;
3. integrated-shift CIOS Montgomery multiplication;
4. public/secret final-reduction policy 분리는 그대로 유지.

정확한 pre-Stage-1 formulation은 benchmark reference로만 남아 있습니다.

## Benchmark 결과

### Generic remainder - 기존 bitwise reducer 대비 speedup

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 83.4x | 55.5x | 71.8x |
| 3072 | 69.5x | 48.6x | 60.0x |
| 4096 | 81.3x | 51.9x | 66.9x |

### Multiply then reduce - 기존 경로 대비 speedup

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 55.3x | 32.3x | 44.2x |
| 3072 | 46.3x | 25.8x | 37.7x |
| 4096 | 52.8x | 30.3x | 42.6x |

### Montgomery `R^2` setup - repeated doubling 대비 speedup

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 78.0x | 47.0x | 62.8x |
| 3072 | 67.4x | 41.7x | 57.1x |
| 4096 | 78.0x | 49.2x | 60.7x |

### Raw CIOS core - integrated shift 적용 후 percent faster

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 4.1% | 3.4% | 8.1% |
| 3072 | 0.7% | 9.9% | 17.1% |
| 4096 | 4.5% | 11.9% | 15.0% |

Stage 1의 지배적인 개선은 작은 CIOS loop optimization이 아니라 algorithmic reduction/setup 변경입니다.

## 검증 기록

- 최종 정확 benchmark run: `33740787602`
- 검증된 head: `3c929f18ff207f9d7aa7357e8380632d856cbe62`
- artifact:
  - `bignum-stage1-accurate-Linux`
  - `bignum-stage1-accurate-macOS`
  - `bignum-stage1-accurate-Windows`

동일 Stage-1 head는 merge 전에 complete CI matrix, RSA validation, ECC validation, Bignum Validation, sanitizer check를 모두 통과했습니다.

---

# Stage 2 - output reuse 및 multiply/square inner loop

## 변경 내용

Stage 2는 Stage 1 이후 남은 allocator와 inner-loop overhead를 대상으로 합니다.

1. add/sub가 destination capacity를 재사용하며 safe same-index alias도 지원;
2. non-aliased multiplication이 destination capacity 재사용;
3. schoolbook multiplication은 정확한 최대 product width를 사용하고 각 row의 final carry를 직접 기록;
4. squaring은 각 doubled cross product를 portable base-2^32 piece로 한 번만 accumulate;
5. non-aliased square operation이 destination capacity 재사용.

파괴적인 multiply/square alias는 temporary를 유지합니다. `bignum_reserve()`도 나중에 private material을 담을 수 있는 speculative capacity를 남기지 않고 exact-size growth를 유지합니다.

## Benchmark 결과

Stage 2는 정확한 Stage-1 add/sub/mul/square 구현과 비교합니다.

### 1024/2048/3072/4096-bit case 전반의 개선 범위

| Operation | Linux | macOS | Windows |
|---|---:|---:|---:|
| `add` | +47.1% to +59.4% | +46.1% to +66.1% | +40.7% to +55.6% |
| `sub` | +45.4% to +60.1% | +43.7% to +65.5% | +38.5% to +50.0% |
| `mul` | +2.8% to +18.1% | +3.2% to +10.1% | -2.0% to +10.7% |
| `square` | +54.8% to +61.8% | +15.3% to +27.5% | +41.8% to +53.9% |

Windows 3072-bit multiplication의 작은 regression(`-2.0%`)도 숨기지 않고 기록에 남깁니다. Stage 2의 가장 강하고 일관된 이득은 linear operation의 output reuse와 square-specific rewrite입니다.

### 대표 4096-bit raw timing

| Operation | Linux | macOS | Windows |
|---|---:|---:|---:|
| `add` | 0.516 -> 0.273 us (+47.1%) | 0.479 -> 0.258 us (+46.1%) | 0.540 -> 0.320 us (+40.7%) |
| `sub` | 0.560 -> 0.306 us (+45.4%) | 0.471 -> 0.265 us (+43.7%) | 0.520 -> 0.320 us (+38.5%) |
| `mul` | 11.700 -> 11.369 us (+2.8%) | 24.191 -> 23.056 us (+4.7%) | 20.600 -> 18.400 us (+10.7%) |
| `square` | 50.926 -> 20.101 us (+60.5%) | 47.180 -> 39.960 us (+15.3%) | 50.200 -> 29.200 us (+41.8%) |

## 검증 기록

- 최종 accurate benchmark run: `33800902324`
- 검증된 code head: `293d736b22d807b554d8688dbd23849a97d7cfde`
- artifact:
  - `bignum-stage2-accurate-Linux`
  - `bignum-stage2-accurate-macOS`
  - `bignum-stage2-accurate-Windows`

Stage 2는 merge 전에 complete CI, RSA validation, ECC validation, dedicated Bignum Validation, Ubuntu ASan/UBSan check를 통과했습니다.

---

# Stage 3 - 측정 기반 Karatsuba dispatch

## 의사결정 과정

Stage 3은 Karatsuba의 asymptotic complexity가 좋아 보인다는 이유로 바로 추가하지 않고 의도적으로 benchmark-first 방식으로 진행했습니다.

experimental benchmark는 512-8192-bit operand에서 Stage-2 schoolbook multiplication과 portable one-level Karatsuba split을 비교했습니다. reusable scratch와 one-shot allocation을 모두 측정했습니다. 실험 결과 작은 operand에서는 Karatsuba가 정당화되지 않았고, 3072 bit 이상에서는 Linux, macOS, Windows 전부에서 유망했습니다.

그 뒤 production implementation을 추가하고 다시 측정했습니다. 실제 dispatch, per-call workspace allocation, secure workspace zeroization을 모두 포함하기 때문에 이 두 번째 측정 결과가 최종 threshold를 결정합니다.

## 채택된 구현

`crypto_bignum_mul()`은 이제 다음을 사용합니다.

- 96 limb 미만 operand: **Stage-2 schoolbook**;
- 동일 폭 operand가 **96 limbs / 3072 bits 이상**: **one-level Karatsuba**;
- 측정된 Karatsuba domain 밖의 unbalanced operand: Stage-2 schoolbook;
- Karatsuba workspace allocation을 완료할 수 없을 경우 안전한 fallback으로 Stage-2 schoolbook.

원래 Stage-2 multiplication 구현은 중복하거나 재작성하지 않고 내부 `crypto_bignum_mul_stage2()` baseline/fallback으로 유지합니다. generic `crypto_bignum_mod_mul()`은 reduction 전에 production multiplication dispatch를 거치므로 적용 가능한 public/general modular multiplication도 Stage-3 이득을 받을 수 있습니다.

## 최종 production benchmark

양의 percentage는 같은 process 안에서 최종 Stage-3 production dispatch가 정확한 Stage-2 schoolbook reference보다 빠르다는 뜻입니다.

### Production threshold 이상에서의 개선

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 3072 | **+6.0%** | **+25.2%** | **+12.5%** |
| 4096 | **+13.1%** | **+30.9%** | **+17.9%** |
| 6144 | **+18.5%** | **+29.5%** | **+16.0%** |
| 8192 | **+17.2%** | **+28.1%** | **+15.4%** |

### Raw timing (`Stage 2 -> Stage 3`, multiplication당 microseconds)

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 3072 | 7.140 -> 6.710 | 12.348 -> 9.239 | 12.000 -> 10.500 |
| 4096 | 13.178 -> 11.454 | 23.107 -> 15.973 | 23.333 -> 19.167 |
| 6144 | 28.607 -> 23.310 | 55.987 -> 39.452 | 41.667 -> 35.000 |
| 8192 | 50.320 -> 41.657 | 102.397 -> 73.626 | 74.286 -> 62.857 |

따라서 threshold는 최종 production 측정에서도 유지됩니다. **allocation과 secure zeroization 비용까지 포함해도 3072 bit에서 세 hosted OS 모두 빨라집니다.** operand가 더 커질수록 margin도 커집니다.

threshold 아래에서는 production dispatcher가 Stage-2 function을 선택합니다. 반복 측정의 작은 차이는 별도 산술 구현 차이가 아니라 runner/timer noise입니다.

## Stage-3 검증 기록

최종 production code head:

- `b8752b6608708fedd618180e51f6146eb6f4bf75`

Validation:

- Bignum Validation run `33818440244`: Linux/macOS/Windows complete test suite, 세 OS runner의 최종 production benchmark, Ubuntu ASan/UBSan;
- RSA validation run `33818440271`;
- ECC validation run `33818440257`;
- general CI run `33818440245`.

최종 benchmark artifact:

- `bignum-stage3-production-Linux`
- `bignum-stage3-production-macOS`
- `bignum-stage3-production-Windows`

benchmark는 timing 전에 1-160개의 equal-width limb 범위에서 production dispatcher를 정확한 Stage-2 multiplier와 differential-check하고 destructive left/right alias case도 검증합니다.

---

# 최적화 이력 읽기

의도된 stage snapshot은 다음과 같습니다.

| Tag | 의미 |
|---|---|
| `bignum-stage0-baseline` | Stage 1 직전 repository |
| `bignum-stage1-reduction-montgomery` | 채택된 Stage-1 reduction/Montgomery 구현 |
| `bignum-stage2-mul-square` | 채택된 Stage-2 output-reuse/mul/square 구현 |
| `bignum-stage3-karatsuba` | 채택된 Stage-3 production Karatsuba dispatch |

정확한 historical source comparison에는 tag를, 측정 근거에는 benchmark artifact를 사용하세요. 서로 다른 stage의 speedup ratio를 곱해서는 안 됩니다. Stage 1, Stage 2, Stage 3은 서로 다른 operation을 측정했고 별도의 hosted-runner job에서 실행되었습니다.
