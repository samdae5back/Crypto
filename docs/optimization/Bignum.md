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

Results are populated from the final validated Stage-1 pull-request head after
the Ubuntu, macOS, and Windows benchmark jobs complete.

## Stage 2 — output reuse and multiplication/squaring inner loops

### Baseline

The general add, subtract, and multiply routines always constructed a fresh
`LiberaCBignum`, even when the caller's output already owned enough capacity.
The result replaced the previous object only after the operation completed.
This made every repeated non-aliased operation pay allocator, copy/zeroization,
and free costs solely to preserve alias safety.

Schoolbook multiplication also reserved `a_length + b_length + 1` limbs and
entered a carry-propagation loop after each input row. For ordinary base-2^32
schoolbook multiplication, no earlier row can have written the limb immediately
above the current row, so the final row carry can be stored there directly and
the product needs at most `a_length + b_length` limbs.

The Stage-1 dedicated square path already computed each cross multiplication
once, but added the resulting `a[i] * a[j]` twice through the generic
64-bit-product accumulator. This repeated helper and carry-propagation overhead
for every symmetric cross term.

### Accepted implementation

1. **Alias-safe add/subtract output reuse.** Addition and subtraction read both
   source limbs at an index before overwriting that same output index. They can
   therefore reuse the destination buffer even when `out == a`, `out == b`, or
   both. Capacity grows only when required; stale previously significant limbs
   above a shorter result are explicitly zeroized.
2. **Non-aliased multiply output reuse.** Multiplication reuses destination
   capacity when `out` is distinct from both inputs. Aliased multiplication
   still uses a temporary because source limbs participate in several output
   columns. This keeps the API's existing alias behavior while avoiding the
   common unnecessary result allocation.
3. **Tighter schoolbook row completion.** The portable multiplication loop
   reserves exactly the maximum mathematical product width and writes each
   row's final carry directly to limb `i + b_length`, removing the old
   propagation loop and extra result limb.
4. **Single doubled-cross accumulation for squaring.** A cross product is split
   into portable base-2^32 pieces representing the potentially 65-bit value
   `2 * a[i] * a[j]`, then accumulated once. This retains 32x32-to-64-only
   portability and removes the second generic product-add pass.
5. **Square destination reuse.** A non-aliased destination keeps its allocation
   across repeated squares. `out == a` intentionally retains the temporary
   path because squaring needs input limbs after earlier output columns have
   been produced.

`bignum_reserve()` itself deliberately keeps exact-size growth in this stage.
A global geometric growth policy would retain excess capacity in bignums that
may hold private material before promotion to a fixed-width secret path. The
measurable hot-path win targeted here comes from reusing already sufficient
capacity rather than retaining speculative unused capacity. Likewise, a new
persistent generic scratch-object API is not introduced: RSA/ElGamal secret
exponentiation already uses fixed-width contiguous Montgomery workspaces, and
there is no repeated generic multiplication/reduction caller that presently
justifies another stateful arithmetic context.

### Security and portability boundary

These changes apply to the existing general performance-oriented bignum
operations. They do not replace or relax the fixed-width constant-schedule
Montgomery exponentiation state. Aliased operations retain behavior explicitly:
add/subtract are proven safe in-place by their same-index dependency, while
multiply/square use a temporary when source destruction would change later
input reads.

Only `uint32_t` and `uint64_t` arithmetic is used. Doubling a 64-bit cross
product is represented as up to three base-2^32 pieces rather than overflowing a
`uint64_t` or depending on `__uint128_t`.

### Validation and benchmark method

`benchmarks/Bignum/Stage2Benchmark.c` keeps the exact Stage-1 allocating
add/subtract/multiply/square routines as benchmark-only references. Before any
timing it runs 120 deterministic randomized cases covering 1 through 80 limbs
and compares every optimized result against its Stage-1 counterpart. It also
checks in-place add, subtract, multiply, and square behavior.

For 1024-, 2048-, 3072-, and 4096-bit operands, the benchmark reports median
CPU microseconds over five samples for:

- repeated addition: Stage-1 allocate/replace vs reused destination;
- repeated subtraction: Stage-1 allocate/replace vs reused destination;
- multiplication: Stage-1 allocation/extra-limb/carry-loop path vs Stage-2
  reuse/tight row completion;
- squaring: Stage-1 double product-add vs Stage-2 single doubled-cross add.

The Stage-2 pull request runs the complete test suite and this exact benchmark
on Ubuntu, macOS, and Windows, plus unit tests under ASan/UBSan on Ubuntu.

### Hosted benchmark result

Results are populated from the final validated Stage-2 pull-request head.

## Stage 3 — measured large-operand multiplication

### Candidate and acceptance rule

The first candidate is deliberately the smallest portable Karatsuba extension:
one top-level split with the accepted Stage-2 schoolbook multiplier as each
leaf. For equal `n`-limb inputs it computes `z0`, `z2`, and
`(a0+a1)(b0+b1)` and assembles the usual Karatsuba cross term. The candidate
uses only 32-bit limbs and 32x32-to-64 products, with one reusable scratch block
allocated outside the timed multiplication loop.

This one-level form reduces the leading limb-multiplication count from roughly
`n^2` to roughly `3n^2/4` without introducing recursive call/scratch complexity.
It is therefore an intentionally conservative gate: if this form cannot beat
the Stage-2 schoolbook path at realistic RSA/ElGamal sizes, a more complex
portable recursive implementation is not justified by source-level operation
counts alone.

Production adoption requires a reproducible crossover rather than one isolated
runner win. In particular:

- compare 512, 1024, 1536, 2048, 3072, 4096, 6144, and 8192 bits;
- require differential correctness before timing;
- prefer a threshold that is beneficial on Ubuntu, macOS, and Windows rather
  than architecture-specific tuning hidden in the portable backend;
- retain schoolbook multiplication below the measured threshold;
- if no stable crossover exists in sizes relevant to the library, keep the
  Stage-2 schoolbook implementation and record Karatsuba as evaluated/rejected.

### Validation and benchmark method

`benchmarks/Bignum/Stage3Benchmark.c` compares the production Stage-2
schoolbook multiplier against a benchmark-only one-level Karatsuba candidate.
The benchmark first runs 120 deterministic randomized comparisons from 4
through 160 limbs. Timed cases reuse both destination capacity and Karatsuba
scratch so the comparison measures arithmetic/assembly cost rather than
per-call allocator noise.

The Stage-3 pull request runs the complete test suite and the crossover
benchmark on Ubuntu, macOS, and Windows, plus the unit-test label under
ASan/UBSan on Ubuntu.

### Hosted benchmark result and decision

Results and the production adoption/rejection decision are populated from the
final validated Stage-3 benchmark head. If Karatsuba is adopted, the threshold
and a second validation run of the production dispatch are recorded here before
merge.
