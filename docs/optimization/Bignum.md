# Bignum optimization record

This document records the second-stage optimization work for LiberaCrypt's
shared arbitrary-precision arithmetic. The general bignum layer remains
performance-oriented and variable-time. Secret-sensitive protocol operations
continue to use fixed-width constant-schedule helpers where their control flow
or memory access must not depend on secret values.

The portable baseline remains 32-bit limbs with 32x32-to-64 arithmetic. No
`__uint128_t`, compiler intrinsics, assembly, or host-endian word casts are
required by the changes recorded here.

## Stage 1 — public reduction and Montgomery core

### Baseline

Before this stage, `crypto_bignum_mod()` implemented generic remainder by
scanning the dividend one bit at a time. For every bit it shifted a temporary
remainder left, appended the next input bit, compared against the modulus, and
allocated/subtracted a new bignum when reduction was needed. Consequently a
large `multiply -> mod` path performed work proportional to the dividend bit
count with substantial repeated temporary allocation.

The optimized public and fixed-width secret Montgomery engines already used
CIOS Montgomery multiplication, but each outer iteration completed the logical
division by one radix limb by copying `n + 1` temporary limbs down by one
position. Montgomery `R^2` setup was also built through `64*n` repeated bignum
doublings and conditional subtractions.

### Accepted implementation

1. **Normalized word remainder.** Generic variable-time remainder now uses a
   base-2^32 normalized long-division remainder algorithm. The divisor is
   normalized so its high bit is set, one quotient digit is estimated per input
   limb, the estimate is corrected when necessary, and only the remainder is
   retained. A one-limb modulus still uses the existing `uint64_t`/`uint32_t`
   remainder path. The implementation uses only fixed-width ISO C integer
   arithmetic.
2. **Direct `R^2` construction.** Montgomery setup constructs the public integer
   `2^(64*n)` directly and reduces it once with the word reducer, rather than
   performing `64*n` allocation-heavy doublings. This setup depends only on the
   public modulus and does not enter a secret-dependent schedule.
3. **Shift-free CIOS core.** The common Montgomery multiply core folds the
   logical radix-limb shift into reduction write-back: reduced limb `j` is
   written directly to slot `j-1`. This removes the per-outer-iteration
   `n + 1`-limb copy.
4. **Separate final-reduction policy is preserved.** The public Montgomery path
   retains its public-data compare/branch and early exit. The secret
   fixed-width path still computes `candidate - modulus` and mask-selects the
   reduced or unreduced candidate with fixed loop counts. Sharing the CIOS
   accumulation core therefore does not collapse the public/secret timing
   boundary.

The older bit-at-a-time remainder, repeated-doubling `R^2` setup, and
shift-after-each-round CIOS formulation are retained only inside the bignum
benchmark as same-build comparison baselines; they are not linked into the
library.

### Correctness and portability argument

The normalized reducer is the usual base-2^32 long-division remainder
construction. Normalization preserves the quotient and scales the remainder by
an exact power of two; the final right shift reverses that scaling. Quotient
estimation uses at most two high dividend limbs and the normalized high divisor
limb, and the correction/add-back step handles an overestimate without relying
on signed overflow.

The shift-free CIOS formulation performs the same multiply and Montgomery
reduction recurrence as the prior implementation. It changes only where the
post-reduction words are stored. The benchmark checks the complete unreduced
`n + 1`-limb candidate from both formulations before timing them.

All arithmetic uses `uint32_t`, `uint64_t`, and `size_t`. No signed right shift,
plain-`char` signedness, host byte order, native 128-bit integer, or
architecture-specific instruction is assumed.

### Validation and benchmark method

`benchmarks/Bignum/Benchmark.c` performs differential checks before printing any
measurements:

- normalized remainder versus the exact pre-stage bitwise reducer;
- `multiply -> remainder` through both reduction paths;
- direct `R^2` setup versus the exact repeated-doubling setup;
- shift-free CIOS candidate versus the exact shift-after-each-round CIOS
  candidate;
- 80 additional deterministic randomized remainder cases from 64 through
  1024 bits.

The benchmark then reports median CPU microseconds per operation over five
samples for 2048-, 3072-, and 4096-bit moduli. It measures:

- a two-modulus-width remainder;
- modular multiplication;
- Montgomery `R^2` setup;
- the raw Montgomery CIOS core.

The `Bignum Validation` workflow builds a static library, runs the complete test
suite, runs the benchmark on Ubuntu, macOS, and Windows, uploads each CSV, and
runs the unit-test label under ASan/UBSan on Ubuntu. Hosted-runner measurements
are comparative evidence for these exact revisions; they are not universal
architecture claims.

### Hosted benchmark result

Results are populated from the final validated pull-request head after the
Ubuntu, macOS, and Windows benchmark jobs complete.

## Stage 2 — allocation/workspace and multiply/square tuning

Planned after Stage 1 is validated. This stage will benchmark allocation reuse,
capacity growth, reusable arithmetic scratch storage, and the schoolbook
multiply/square inner loops as a separate pull request so Stage 1 numbers remain
attributable to reduction and Montgomery changes only.

## Stage 3 — measured large-operand multiplication

Karatsuba or another large-operand multiplication path will be considered only
after Stage 2. The schoolbook baseline remains the default unless a reproducible
crossover appears at operand sizes that matter to LiberaCrypt's RSA, ElGamal,
and prime-generation workloads. A rejected optimization is still recorded with
its benchmark evidence rather than being retained for algorithm-count reasons.
