# ML-KEM portable Barrett reduction

## Scope

This note records the second portable ML-KEM arithmetic optimization pass.  It
starts from the already-merged hot-path optimization and changes only the
ordinary-domain modular arithmetic used by the portable NTT implementation.
Montgomery representation is intentionally deferred to a separate measured
change.

The goals are:

- keep every NTT coefficient canonical in `[0, q)` with `q = 3329`;
- remove general signed `% 3329` operations from NTT butterflies and base
  multiplication;
- use only fixed-width unsigned ISO C arithmetic;
- avoid secret-dependent table indices or source-level branches;
- make the reduction bounds and correctness argument explicit.

No numerical speedup is claimed until a reproducible benchmark is retained.
Compilers can strength-reduce division by a constant, and a 64-bit reciprocal
multiply may have different costs on 32-bit and 64-bit targets.  The deterministic
source-level reductions in division/remainder operations and cleanup loops are
recorded separately from measured throughput.

## Canonical coefficient invariant

The optimized transform maintains the invariant

```text
0 <= coefficient < q
```

at every butterfly boundary.

For canonical `a` and `b`:

```text
0 <= a + b < 2q
0 <= a + q - b < 2q
```

so modular addition and subtraction need only one fixed-shape conditional
correction.  No general reduction is required for those operations.

A twiddle multiplication has

```text
0 <= z * a <= (q - 1)^2 = 11,075,584.
```

The largest value reduced by the current base multiplication is the sum of two
such bounded terms:

```text
2 * (q - 1)^2 = 22,151,168.
```

This is far below both `2^31` and `2^32`.  The implementation nevertheless uses
unsigned fixed-width intermediates so signed overflow and negative-remainder
semantics are not part of the proof.

## Barrett construction

Let

```text
B  = 2^32
q  = 3329
mu = floor(B / q) = 1,290,167.
```

For any `uint32_t` value `x`, define

```text
qhat = floor(x * mu / B)
r    = x - qhat * q.
```

Because

```text
B/q - 1 < mu <= B/q
```

and `0 <= x < B`, multiplication by `x/B` gives

```text
x/q - x/B < x*mu/B <= x/q.
```

Since `0 <= x/B < 1`, taking floors shows that `qhat` is either

```text
floor(x/q)
```

or exactly one less.  Therefore

```text
0 <= r < 2q.
```

One final subtraction of `q`, conditionally restored when the subtraction
underflows, produces the unique representative in `[0, q)` while preserving
congruence modulo `q`.

The implementation computes `x * mu` in `uint64_t`, shifts right by 32, and
performs the final correction in `uint32_t`.  LiberaCrypt already requires and
uses exact 64-bit unsigned arithmetic elsewhere, so this adds no new integer
width requirement.

## Fixed-shape final correction

For an input known to lie in `[0, 2q)`, compute in `uint32_t`:

```text
reduced = value - q
mask    = 0 - (reduced >> 31)
result  = reduced + (q & mask)
```

If `value >= q`, `reduced` lies in `[0, q)` and its high bit is zero.  If
`value < q`, unsigned subtraction wraps to a value near `2^32`, whose high bit
is one because `q < 2^31`; the mask then restores exactly one `q`.

The source contains no coefficient-dependent `if` statement.  As elsewhere in
LiberaCrypt, this is described as a constant-schedule source construction rather
than a universal physical constant-time guarantee for every compiler/processor.

## NTT equivalence

The previous forward butterfly was equivalent to

```text
t = z*b mod q
b = a-t mod q
a = a+t mod q
```

with possibly negative C remainders followed by a final normalization pass.
The new form computes the same residue classes but canonicalizes both outputs at
that butterfly immediately:

```text
t = Barrett(z*b)
b = canonical_sub(a, t)
a = canonical_add(a, t)
```

The inverse butterfly similarly replaces

```text
z * (b-a) mod q
```

with

```text
z * canonical_sub(b, a) mod q.
```

Since `canonical_sub(b,a) == b-a (mod q)`, the ring element is unchanged.
The final multiplication by `3303 = 128^-1 mod q` is also reduced with the same
ordinary-domain Barrett helper, so no Montgomery factor is introduced.

## Base multiplication equivalence

For

```text
(a0 + a1 X)(b0 + b1 X) mod (X^2 - r)
```

the implementation still computes

```text
c0 = a0*b0 + a1*b1*r mod q
c1 = a0*b1 + a1*b0   mod q.
```

`a1*b1` is first reduced to its canonical residue before multiplication by `r`.
Replacing an intermediate by a congruent residue does not change the final
result modulo `q`.  The final wide values are bounded by `2(q-1)^2`, so the
32-bit Barrett input bound above applies directly.

## Security implications

The optimization changes only integer representatives of the same elements in
`Z_q`.  It does not change ML-KEM parameters, NTT roots, wire encodings,
rejection sampling, key/ciphertext formats, or decapsulation rejection logic.

All transform loop bounds and twiddle indices remain public and
parameter-determined.  The new reduction helpers add no secret-indexed lookup
and no source-level coefficient-dependent branch.

## Portability implications

The previous implementation used signed `% q` on values that could be negative
inside butterflies, then repaired negative representatives at the end.  The new
implementation keeps arithmetic non-negative and canonical throughout the NTT
and uses `uint32_t`/`uint64_t` operations with defined wrap and shift semantics.
It therefore removes dependence on negative remainder handling from the hot
transform path and does not use signed right shift, type punning, alignment
assumptions, native-endian word loads, compiler intrinsics, SIMD, or assembly.

The main performance caveat is architectural rather than semantic: on some
32-bit targets a 64-bit reciprocal multiplication can be more expensive than on
native 64-bit targets.  Benchmarking must therefore determine whether the
explicit Barrett multiply is a throughput win on each representative platform.
The canonical add/sub transformation remains useful independently because it
removes general reduction from butterfly additions and subtractions.

## Validation performed before repository CI

The reduction formula was mechanically compared with ordinary integer `% 3329`
for every value from zero through the maximum current ML-KEM wide intermediate:

```text
0 .. 22,151,168
```

with no mismatch.

Canonical addition and subtraction were exhaustively compared with mathematical
modulo for every pair

```text
a, b in [0, 3329).
```

The old and new forward/inverse NTT formulas were also compared on 1,000 random
canonical 256-coefficient polynomials with no mismatch.

These development checks supplement rather than replace repository evidence.
Acceptance still requires the existing ML-KEM-512/768/1024 KATs and unit tests,
plus the normal Linux/Windows/macOS CI build matrix.

## Why Montgomery remains separate

Montgomery reduction is also mathematically valid for `q = 3329`, but
`REDC(x)` computes `x * R^-1 mod q`.  Substituting it directly for ordinary `% q`
would therefore be wrong unless twiddles and transform scaling factors are
tracked in the appropriate Montgomery domain.

This Barrett pass intentionally leaves every table and coefficient in the
existing ordinary representation.  A future Montgomery pass should be a
separate commit with an explicit domain invariant, converted twiddle constants,
forward/inverse scaling proof, KAT validation, and before/after benchmark.  This
separation makes any later performance comparison and regression diagnosis much
clearer.
