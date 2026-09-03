# Bignum optimization record

This document is the consolidated engineering record for LiberaCrypt's second-stage
arbitrary-precision arithmetic optimization.

The short version is:

- **Stage 1** removed the largest generic modular-arithmetic bottleneck. The new
  word-based reducer is roughly **49x–83x faster for direct remainder** and
  **26x–55x faster for multiply-then-reduce** in the measured 2048–4096-bit cases.
- **Stage 2** removes avoidable output allocation and tightens the portable
  multiplication/squaring loops. At 4096 bits, add/sub improve by roughly
  **38%–47%**, squaring by **15%–61%**, while generic multiplication improves
  modestly and is intentionally kept simple.
- **Stage 3** finds a useful portable Karatsuba crossover. The conservative
  one-shot benchmark is faster on all three hosted runners from **3072 bits**
  upward, making **96 32-bit limbs / 3072 bits** the initial production threshold
  candidate.

All measured values below are **same-run pairwise comparisons**: the old/reference
path and new path execute on the same hosted runner with the same deterministic
inputs. Absolute microsecond values from different workflow runs are not combined
into a cumulative speedup claim.

The portable baseline remains 32-bit limbs with 32x32-to-64 arithmetic. No
`__uint128_t`, compiler intrinsics, assembly, or host-endian word casts are
required by the measured candidates.

## At a glance

| Stage | Baseline | Change / candidate | Measured outcome |
|---|---|---|---|
| 1 | bit-at-a-time generic reduction, repeated-doubling `R^2`, shifted CIOS | normalized base-2^32 remainder, direct `R^2`, integrated-shift CIOS | very large reduction/setup win; smaller CIOS-core win |
| 2 | allocate/replace add/sub/mul/square and older inner loops | safe output reuse, tight schoolbook carry handling, single doubled-cross square accumulation | large add/sub/square win; small-to-moderate multiply win |
| 3 | Stage-2 schoolbook multiplication | one-level portable Karatsuba | stable useful crossover at 3072 bits and above |

## Security boundary

The generic bignum layer is intentionally performance-oriented and variable-time.

Secret-sensitive operations remain on the fixed-width constant-schedule path.
Stage 1 shares only the CIOS accumulation machinery and public-modulus `R^2`
setup; the secret path still keeps fixed loop counts and masked final reduction.
Stage 2 changes the generic add/sub/mul/square paths and does **not** replace the
fixed-width secret exponentiation schedule. Stage 3 is likewise evaluated for
the generic multiplication path rather than silently routing fixed-width secret
arithmetic through a variable-time Karatsuba implementation.

---

# Stage 1 — public reduction and Montgomery core

## What changed

Before Stage 1, `crypto_bignum_mod()` scanned the dividend one bit at a time:
shift the temporary remainder, append one bit, compare, and conditionally
subtract. This was simple but extremely expensive for large operands.

Stage 1 replaced that path with:

1. **Normalized base-2^32 long-division remainder.**
2. **Direct Montgomery `R^2` construction** by reducing `2^(64n)` once instead
   of performing `64n` allocation-heavy doublings.
3. **Integrated-shift CIOS Montgomery multiplication**, removing the `n+1` limb
   move after every outer iteration.
4. Separate public and secret final-reduction policies remain intact.

The exact pre-Stage-1 algorithms are retained only in the benchmark as reference
implementations.

## Benchmark result

### Generic remainder — speedup over original bitwise reducer

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 83.4× | 55.5× | 71.8× |
| 3072 | 69.5× | 48.6× | 60.0× |
| 4096 | 81.3× | 51.9× | 66.9× |

### Multiply then reduce — speedup over original path

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 55.3× | 32.3× | 44.2× |
| 3072 | 46.3× | 25.8× | 37.7× |
| 4096 | 52.8× | 30.3× | 42.6× |

### Montgomery `R^2` setup — speedup over repeated doubling

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 78.0× | 47.0× | 62.8× |
| 3072 | 67.4× | 41.7× | 57.1× |
| 4096 | 78.0× | 49.2× | 60.7× |

### Raw CIOS core — percent faster after integrated shift

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 2048 | 4.1% | 3.4% | 8.1% |
| 3072 | 0.7% | 9.9% | 17.1% |
| 4096 | 4.5% | 11.9% | 15.0% |

The main Stage-1 win is therefore **algorithmic reduction/setup work**, not just
loop tuning. The CIOS rewrite is useful but accounts for a much smaller share of
the total improvement.

## Validation

Before timing, the benchmark checks:

- normalized remainder vs the exact old bitwise reducer;
- multiply-then-reduce through both paths;
- direct `R^2` vs repeated-doubling `R^2`;
- complete `n+1`-limb CIOS candidates from old and new formulations;
- 80 deterministic randomized reduction cases.

Final accurate benchmark workflow:

- run: `33740787602`
- head: `3c929f18ff207f9d7aa7357e8380632d856cbe62`
- artifacts:
  - `bignum-stage1-accurate-Linux`
  - `bignum-stage1-accurate-macOS`
  - `bignum-stage1-accurate-Windows`

The same head also passed the complete CI matrix, RSA validation, ECC validation,
and the dedicated Bignum Validation workflow before Stage 1 was merged.

---

# Stage 2 — output reuse and multiply/square inner loops

## What changed

Stage 2 targets allocator and inner-loop overhead left after Stage 1:

1. **Add/sub output reuse.** Same-index dependencies make these operations
   naturally alias-safe, so existing destination capacity is reused.
2. **Non-aliased multiply output reuse.** Destructive aliases keep a temporary.
3. **Tighter schoolbook multiplication.** The result uses the exact maximum
   width and each row's final carry is written directly.
4. **Single doubled-cross square accumulation.** `2*a[i]*a[j]` is represented
   portably in base 2^32 and accumulated once instead of calling the generic
   product accumulator twice.
5. **Non-aliased square output reuse.**

`bignum_reserve()` deliberately keeps exact-size growth. A global geometric
growth policy could retain unnecessary capacity in objects that may later hold
private material, so Stage 2 prefers reusing capacity that already exists.

## Benchmark result

Stage 2 compares against the exact Stage-1 add/sub/mul/square implementations.
Those generic operations were not changed by Stage 1, so for these operations
the Stage-1 reference is also the relevant pre-Stage-2/original-style baseline.

### Improvement range across 1024/2048/3072/4096-bit cases

| Operation | Linux | macOS | Windows |
|---|---:|---:|---:|
| `add` | +47.1% to +59.4% | +46.1% to +66.1% | +40.7% to +55.6% |
| `sub` | +45.4% to +60.1% | +43.7% to +65.5% | +38.5% to +50.0% |
| `mul` | +2.8% to +18.1% | +3.2% to +10.1% | -2.0% to +10.7% |
| `square` | +54.8% to +61.8% | +15.3% to +27.5% | +41.8% to +53.9% |

A small Windows multiplication regression appeared at 3072 bits (`-2.0%`), while
4096-bit Windows multiplication improved by `+10.7%`. This is why Stage 2 does
not claim a universal large multiplication speedup; the strong, consistent gains
are output reuse for linear operations and the square-specific rewrite.

### Representative 4096-bit raw timings

| Operation | Linux | macOS | Windows |
|---|---:|---:|---:|
| `add` | 0.516 → 0.273 μs (+47.1%) | 0.479 → 0.258 μs (+46.1%) | 0.540 → 0.320 μs (+40.7%) |
| `sub` | 0.560 → 0.306 μs (+45.4%) | 0.471 → 0.265 μs (+43.7%) | 0.520 → 0.320 μs (+38.5%) |
| `mul` | 11.700 → 11.369 μs (+2.8%) | 24.191 → 23.056 μs (+4.7%) | 20.600 → 18.400 μs (+10.7%) |
| `square` | 50.926 → 20.101 μs (+60.5%) | 47.180 → 39.960 μs (+15.3%) | 50.200 → 29.200 μs (+41.8%) |

Positive percentages mean the Stage-2 path is faster.

## Validation

`Stage2Benchmark.c` retains the exact Stage-1 allocating implementations as
benchmark-only references. It runs 120 deterministic randomized cases over
1–80 limbs and also validates in-place alias behavior before timing.

Final accurate benchmark workflow:

- run: `33800902324`
- head: `293d736b22d807b554d8688dbd23849a97d7cfde`
- artifacts:
  - `bignum-stage2-accurate-Linux`
  - `bignum-stage2-accurate-macOS`
  - `bignum-stage2-accurate-Windows`

That head passed the complete CI, RSA validation, ECC validation, dedicated
Bignum Validation, and Ubuntu ASan/UBSan unit-test run.

---

# Stage 3 — measured large-operand multiplication

Stage 3 is intentionally separated from Stage 2. The candidate is a portable,
one-level Karatsuba split with Stage-2 schoolbook multiplication as the leaf.

The acceptance rule is benchmark-driven:

- keep schoolbook for small operands;
- test 512 through 8192 bits;
- require differential correctness before timing;
- adopt a threshold only if the crossover is useful and reproducible across
  Linux, macOS, and Windows;
- otherwise retain Stage-2 schoolbook and record the rejected experiment.

## Benchmark result

Two Karatsuba measurements are retained:

- `one-level-karatsuba`: scratch storage is prepared outside the timed loop. This
  isolates arithmetic and assembly cost.
- `one-level-karatsuba-oneshot`: scratch is allocated and freed for every call.
  This is the more conservative comparison against the current stateless generic
  multiplication API.

The table below uses the **one-shot** result. Positive numbers mean Karatsuba is
faster than the production Stage-2 schoolbook multiplier.

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 512 | -49.6% | -92.0% | -33.3% |
| 1024 | -14.2% | -11.1% | +0.0% |
| 1536 | -3.1% | -26.6% | +20.0% |
| 2048 | +3.1% | +5.7% | +17.6% |
| 3072 | +7.8% | +36.4% | +21.1% |
| 4096 | +18.9% | +34.6% | +23.8% |
| 6144 | +21.7% | +32.9% | +21.7% |
| 8192 | +17.2% | +19.5% | +20.8% |

The crossover is not stable below 2048 bits. At 2048 bits the result is already
positive in this one-shot measurement, but the margin is small on Linux/macOS
and the scratch-reuse measurement is still slower on macOS. Starting at
**3072 bits (96 32-bit limbs)**, both the practical one-shot measurements and
the reusable-scratch arithmetic measurements show a useful cross-platform win.

Representative one-shot gains:

| Bits | Linux | macOS | Windows |
|---:|---:|---:|---:|
| 3072 | +7.8% | +36.4% | +21.1% |
| 4096 | +18.9% | +34.6% | +23.8% |
| 6144 | +21.7% | +32.9% | +21.7% |
| 8192 | +17.2% | +19.5% | +20.8% |

## Stage-3 conclusion

The benchmark establishes a reproducible portable crossover. The engineering
decision is therefore:

- **keep Stage-2 schoolbook multiplication below 96 limbs;**
- **use 96 limbs / 3072 bits as the initial production Karatsuba threshold
  candidate;**
- keep the implementation one-level and portable unless later measurements
  justify recursive Karatsuba or architecture-specific backends;
- re-run the full validation/benchmark matrix after the production dispatch is
  introduced before calling Stage 3 complete.

This document deliberately says **threshold candidate** rather than claiming the
benchmark-only Karatsuba code is already the production implementation. The
current Stage-3 branch establishes the evidence needed for adoption; production
dispatch still requires its own validation on the final code path.

## Validation

The Stage-3 benchmark performs 120 deterministic randomized differential
comparisons over 4–160 limbs before timing.

Final accurate benchmark workflow for the measurement branch:

- run: `33801007748`
- head: `a560a27882fad64ec2db58e16a889048e5de7a10`
- artifacts:
  - `bignum-stage3-accurate-Linux`
  - `bignum-stage3-accurate-macOS`
  - `bignum-stage3-accurate-Windows`

## Reading the numbers correctly

These tables are deliberately pairwise:

- Stage 1 compares original reduction/Montgomery setup vs Stage 1.
- Stage 2 compares the Stage-1 generic arithmetic baseline vs Stage 2.
- Stage 3 compares Stage-2 schoolbook multiplication vs the Karatsuba candidate.

Do not multiply percentages from separate workflow runs to manufacture a single
"original to Stage 3" number. Different stages benchmark different operations,
and hosted-runner absolute timings can vary between runs. The correct claims are
the same-run ratios shown above.
