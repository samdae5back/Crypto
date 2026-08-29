# ML-KEM Montgomery reduction record

## Scope

This document records the Montgomery-reduction follow-up to the portable
Barrett/canonical-coefficient ML-KEM optimization.

The implementation deliberately does **not** move ML-KEM polynomials into a
persistent Montgomery domain.  Polynomial coefficients remain ordinary
canonical representatives in `[0, q)` at every public/internal boundary.  The
Montgomery reducer is used where one multiplication operand is a fixed public
constant: NTT twiddle multiplication and the inverse-NTT scaling constant.

Variable-by-variable base multiplication remains on the ordinary-domain Barrett
path because converting an operand to Montgomery form for each such product
would add conversion work and complicate representation tracking without a
measured benefit.

## Constants

ML-KEM uses

```text
q = 3329
R = 2^16 = 65536
```

Since `q` is odd,

```text
gcd(q, R) = 1.
```

For this modulus:

```text
-q^{-1} mod R = 3327
R mod q         = 2285
```

The implementation stores these values as fixed-width unsigned constants and
uses only unsigned multiplication, masking, addition, and right shift in REDC.
It does not depend on implementation-defined right shift of negative signed
integers.

## REDC construction

For a non-negative integer `x < qR`, define

```text
m = x * (-q^{-1}) mod R
```

and

```text
t = (x + m*q) / R.
```

Because

```text
m*q == -x (mod R),
```

`x + m*q` is exactly divisible by `R`.

Modulo `q`,

```text
t*R == x (mod q),
```

so

```text
t == x*R^{-1} (mod q).
```

The implementation computes `mod R` by masking the low 16 bits because
`R = 2^16`.

## Output-range proof

The multiplier satisfies

```text
0 <= m < R.
```

For `0 <= x < qR`,

```text
0 <= x + m*q < qR + Rq = 2qR,
```

therefore

```text
0 <= t < 2q.
```

The existing fixed-shape one-step canonical reducer therefore maps `t` into
`[0, q)`.

The actual ML-KEM use is substantially narrower.  Both the ordinary coefficient
and its Montgomery-form fixed constant are canonical and below `q`, so the REDC
input is at most

```text
(q - 1)^2 = 11,075,584.
```

This is far below

```text
qR = 218,169,344.
```

The intermediate numerator also fits comfortably in `uint32_t`:

```text
x + m*q
< (q - 1)^2 + (R - 1)q
< 2^32.
```

Thus neither the REDC precondition nor the C integer-width bound is approached.

## Ordinary-domain fixed-constant multiplication

For an ordinary constant `c`, the implementation first computes

```text
c_mont = cR mod q.
```

This conversion uses the already-validated ordinary-domain Barrett reducer.
For an ordinary coefficient `a`, it then computes

```text
REDC(a * c_mont).
```

Since `c_mont == cR (mod q)`,

```text
REDC(a * c_mont)
== a*cR*R^{-1}
== a*c
(mod q).
```

The REDC result is canonicalized, so the output remains an ordinary coefficient
in `[0, q)`.  No persistent Montgomery representation crosses a butterfly or
function boundary.

## NTT use

### Forward NTT

Each twiddle `z` is converted once per butterfly group:

```text
z_mont = zR mod q.
```

Every coefficient in the group uses

```text
product = REDC(coefficient * z_mont),
```

which is exactly `z * coefficient mod q` in the ordinary domain.  The existing
canonical add/sub helpers then preserve the `[0, q)` invariant.

This replaces one Barrett wide reduction per twiddle multiplication with one
Montgomery REDC.  The one-time twiddle conversion remains an ordinary Barrett
operation and is shared by every butterfly in that group.

### Inverse NTT

The same fixed-constant method replaces inverse twiddle multiplications.

The final multiplication by `3303 = 128^{-1} mod q` also uses Montgomery
constant multiplication.  The value `3303R mod q` is derived at runtime once
for the full polynomial, then reused for all 256 coefficients.  The inverse NTT
therefore retains exactly the same ordinary-domain output as before.

## Base multiplication remains Barrett

`Multiply_NTT` has two variable polynomial operands.  A direct Montgomery REDC
of their ordinary product would return

```text
a*b*R^{-1} mod q,
```

not the ordinary product.  Correcting that scale would require either persistent
Montgomery-domain polynomial state or extra conversions.

The current design intentionally avoids that representation change.  The
Barrett path already has a direct range proof for the base products and leaves
all outputs ordinary/canonical.  A future full-domain Montgomery design should
only be considered if profiling shows a measured benefit large enough to
justify the additional representation invariant and conversion logic.

## Security implications

The change does not introduce secret-indexed tables, secret-dependent loop
counts, or early exits.  REDC uses a fixed source-level sequence of unsigned
operations, and its final canonical correction uses the same fixed-shape mask
selection as the Barrett pass.

As elsewhere in LiberaCrypt, this is described as a **constant-schedule** source
construction rather than as a universal physical constant-time claim for every
compiler and processor.

## Portability implications

The implementation uses:

- `uint32_t` and `uint64_t` only;
- unsigned wrap semantics defined by ISO C;
- a 16-bit mask instead of signed remainder tricks;
- unsigned right shift only;
- no type punning, alignment assumptions, SIMD, compiler intrinsics, or
  architecture-specific assembly.

The bounds above show that the REDC numerator fits in `uint32_t`; no reliance on
signed overflow or implementation-defined narrowing is required.

## Validation

The preceding Barrett-only branch passed the complete GitHub Actions build and
CTest suite on Ubuntu, macOS, and Windows before this Montgomery follow-up was
added.

Before repository CI, the Montgomery fixed-constant identity was exhaustively
checked for every pair

```text
a, c in [0, 3329)
```

against ordinary modular multiplication:

```text
REDC(a * (cR mod q)) == (a*c) mod q.
```

The Montgomery branch must additionally pass the existing ML-KEM-512,
ML-KEM-768, and ML-KEM-1024 KATs and the complete cross-platform CI suite before
it is considered ready to merge.

## Performance claim policy

No numerical speedup is claimed until the Barrett-only commit and the
Barrett-plus-Montgomery commit are benchmarked reproducibly on the same host.

The expected structural benefit is that each fixed twiddle multiplication uses
16-bit-radix REDC instead of the 32-bit reciprocal Barrett reduction, while the
Barrett conversion of a twiddle is paid once per butterfly group rather than
once per coefficient.  Compiler lowering can materially affect the actual
result, so this remains an expected effect until measured.
