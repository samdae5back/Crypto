# ML-KEM optimization record

## Status and scope

This document records the first focused optimization pass over LiberaCrypt's
original FIPS 203 ML-KEM implementation.  The same runtime-dispatched source
continues to implement ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

The priorities for this pass are:

- preserve ISO C portability and the single runtime-selected implementation;
- avoid architecture-specific intrinsics or assembly;
- do not add secret-indexed tables or secret-dependent control flow;
- preserve FIPS 203 encodings, rejection-sampling order, API behavior, and
  failure handling;
- take structurally large wins before changing the NTT arithmetic
  representation or introducing a more complicated reduction scheme.

No throughput number is claimed in this document until a reproducible benchmark
has been retained.  Operation-count and loop-count reductions below are stated
only where they follow directly from the source transformation.

## Baseline observations

The pre-optimization implementation had four conspicuous portable hot paths:

1. `ByteEncode` and `ByteDecode` walked every encoded coefficient one bit at a
   time.  For the common 10-, 11-, and 12-bit polynomial encodings this creates
   thousands of small loop iterations per polynomial.
2. `SampleNTT` requested only three bytes from SHAKE128 for each pair of
   rejection-sampling candidates.  The underlying XOF is a byte stream, so the
   small requests add helper/loop overhead without changing the Keccak work
   needed to generate the stream.
3. K-PKE decryption multiplied each of the `k` secret/ciphertext polynomial
   pairs in the NTT domain, inverse-transformed each product independently, and
   only then added the coefficient-domain polynomials.
4. The NTT path recomputed each 7-bit bit reversal with division/modulo loops,
   and `Multiply_NTT` routed every two-coefficient product through a separate
   helper call.

The inner NTT butterflies and base multiplication still contain many general
`% 3329` operations.  Replacing those reductions is intentionally deferred;
that change has higher proof and validation cost because it changes coefficient
range/representation invariants throughout the transform.

## 1. Packed bit-reservoir encoding and decoding

### Baseline / observed problem

`ByteEncode` and `ByteDecode` processed each coefficient bit individually and
recomputed byte/bit positions inside the inner loop.

### Change

Both functions now use a `uint32_t` little-endian bit reservoir.  Coefficients
are appended at the current bit offset and whole bytes are emitted or consumed
as soon as at least eight bits are available.

The total encoded size is unchanged: 256 coefficients times the public
`bit_width`, and every supported width is at most 12 bits.  Immediately before a
new coefficient is appended, fewer than eight bits remain in the reservoir, so
at most 19 meaningful bits are present.  A 32-bit unsigned reservoir therefore
has ample range.

### Correctness

The previous loop emitted or consumed coefficient bits in increasing bit order.
The reservoir performs exactly the same concatenation and extraction; it merely
processes several bits per C operation.  For 12-bit decoding the existing
reduction modulo `q` is retained, and for smaller widths the existing power-of-
two modulus semantics are retained.

### Security implications

Loop counts and shifts depend on the public encoding width, not on coefficient
values.  No secret-indexed memory access or coefficient-dependent branch is
introduced.

### Portability implications

The reservoir uses fixed-width unsigned arithmetic and byte accesses rather
than type-punning or native-endian word loads.  `mlkem_power_of_two` also uses an
unsigned fixed-width left shift before converting the small, validated result
back to `int`.

### Expected effect

This removes the bit-at-a-time inner loop from every ML-KEM polynomial
serialization/deserialization.  The largest benefit is expected on 10-, 11-,
and 12-bit encodings.  A measured speedup is intentionally not stated yet.

## 2. SHAKE128 rate-block matrix sampling

### Baseline / observed problem

`SampleNTT` squeezed three bytes at a time, parsed two 12-bit candidates, and
repeated until 256 accepted coefficients were obtained.

### Change

The sampler now squeezes one 168-byte SHAKE128 rate block at a time and parses
that block in the same consecutive three-byte groups.  Since 168 is divisible
by three, no candidate group straddles a local buffer boundary.

### Correctness

SHAKE128 exposes one continuous output byte stream.  Changing the size of each
successive squeeze does not change that stream.  Parsing bytes in groups
`[0..2], [3..5], ...` therefore presents the same candidates, in the same order,
to the same `< 3329` rejection test.

### Security implications

Matrix generation is derived from the public matrix seed.  The change does not
introduce secret-dependent indices or branches beyond the standard rejection
sampler already required by FIPS 203.

### Portability / memory implications

The optimization uses only a byte array and the existing portable SHAKE API.  It
adds a 168-byte automatic buffer to `SampleNTT`; this is deliberately small
relative to the existing heap workspaces and avoids architecture-specific
vector code.

### Expected effect

The number of XOF squeeze helper invocations per sampled matrix polynomial falls
from approximately one per candidate pair to a small number of full-rate
requests.  The Keccak output stream and its required permutations are unchanged;
the saving is surrounding helper/byte-loop overhead, not fewer cryptographic
rounds.  No benchmark figure is claimed yet.

## 3. One inverse NTT for the K-PKE decryption inner product

### Baseline / observed problem

K-PKE decryption previously computed, for each vector component,

```text
InvNTT(s_i_hat * u_i_hat)
```

and accumulated the resulting coefficient-domain polynomials.  This performed
`k` inverse NTTs.

### Change

The products are now accumulated in the NTT domain first, followed by one
inverse NTT:

```text
InvNTT(sum_i (s_i_hat * u_i_hat))
```

### Correctness

The inverse NTT is linear over the ML-KEM coefficient ring, so

```text
sum_i InvNTT(x_i) = InvNTT(sum_i x_i).
```

The pointwise base multiplications and additions remain modulo `q`; only the
position of the linear inverse transform relative to the sum changes.

### Security implications

The loop count remains the public parameter `k`.  No secret-dependent branch,
table lookup, or early exit is added.  In fact, the transform schedule becomes
strictly shorter and still parameter-determined.

### Portability implications

This is an algebraic reordering using the existing NTT implementation; no new
integer-width, endian, alignment, or compiler assumptions are introduced.

### Expected effect

This removes exactly `k - 1` inverse NTT calls from each K-PKE decryption:

| Parameter set | Previous inverse NTTs | Current inverse NTTs | Removed |
| --- | ---: | ---: | ---: |
| ML-KEM-512 (`k = 2`) | 2 | 1 | 1 |
| ML-KEM-768 (`k = 3`) | 3 | 1 | 2 |
| ML-KEM-1024 (`k = 4`) | 4 | 1 | 3 |

Among the first-pass changes, this is the clearest deterministic operation-count
reduction and is expected to matter most directly to decapsulation.

## 4. Small NTT helper cleanup

### Baseline / observed problem

The hot NTT paths reversed seven-bit indices by repeatedly dividing/modding by
two and using a temporary seven-element array.  `Multiply_NTT` also invoked the
out-of-line basic multiplication helper for every pair.

### Change

Internal transform code now reverses seven bits with fixed unsigned mask/shift
operations.  The base two-coefficient multiplication used by `Multiply_NTT` is
available as a local `static inline` helper.  The existing `bit_rev` and
`Multiply_basic` entry points are retained for source-level compatibility with
other internal users.

### Correctness

The mask/shift network is a direct permutation of the low seven bits and is used
only for indices in the ML-KEM transform range.  Base multiplication equations
are unchanged.

### Security and portability implications

The bit reversal has a fixed instruction-shaped source sequence and uses
unsigned arithmetic only.  No lookup table indexed by secret data is added, and
no compiler extension is required.

### Expected effect

This removes small arithmetic/helper overhead repeated throughout NTT and base
multiplication.  It is expected to be a secondary improvement compared with the
inverse-NTT elimination and packing changes.

## Validation

The repository already contains ML-KEM unit coverage for all three parameter
sets, including successful key generation/encapsulation/decapsulation,
implicit-rejection behavior, non-canonical public keys, embedded-public-key
hash validation, output clearing, and overlap rejection.  It also contains KAT
targets for ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

For this optimization branch the required acceptance evidence is:

1. the existing unit suite passes for all three parameter sets;
2. all three ML-KEM KAT suites pass byte-for-byte;
3. the normal CI build/test matrix remains green on Linux, Windows, and macOS;
4. a reproducible local benchmark is retained before any numerical speedup is
   advertised;
5. any later reduction rewrite receives stricter overflow/range review plus
   sanitizer and differential coverage where available.

During development, the packed codec was also checked for byte-for-byte
round-trip/equivalence across supported widths, the seven-bit reversal was
checked across all 128 inputs, and the inverse-NTT reordering was checked against
the previous algebraic ordering for `k = 2, 3, 4`.  These checks supplement, but
do not replace, the repository KAT/CI evidence.

## Benchmark plan

Benchmark key generation, encapsulation, and decapsulation separately for
ML-KEM-512/768/1024.  Record compiler and version, optimization flags, host CPU
and OS, warm-up policy, iteration count, and a robust statistic such as the
median.  Compare the pre-optimization main commit with this branch using the
same build and host.  CI-host timings should not be used as published performance
claims because hosted-runner variance is not controlled.

## Deferred optimization: modular reduction and NTT representation

The largest remaining arithmetic question is whether to replace frequent
general `% MLKEM_Q` operations in NTT butterflies and base multiplication with
bounded Montgomery/Barrett-style reduction and tighter coefficient-range
invariants.

This is likely to offer a larger remaining throughput opportunity than further
micro-cleanups, but it is deliberately not part of the low-risk pass because it
changes the arithmetic representation/range argument.  A portable version can
still be written in ISO C without AVX2/NEON and without secret-dependent
behavior, but it should be accepted only after explicit range proofs, KATs,
strict warning/sanitizer builds, and before/after benchmarks.

Recommended sequence:

1. benchmark this first-pass branch and identify the remaining profile;
2. if NTT/base reduction is still dominant, implement a portable bounded
   reduction path on a separate commit/branch;
3. retain the current simple arithmetic as the comparison baseline until the
   new path has independent validation;
4. consider architecture-specific AVX2/NEON backends only as a separate future
   layer, not as a replacement for the portable implementation.

A separate memory trade-off also remains: the implementation currently uses
maximum-sized heap workspaces and materializes the full matrix.  On-the-fly
matrix generation or tighter parameter-sized workspaces could reduce memory,
but may trade additional SHAKE work, allocator behavior, code complexity, and
zeroization considerations.  That trade-off should be measured independently
rather than mixed into the current throughput pass.
