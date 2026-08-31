# Elliptic-curve arithmetic infrastructure

This directory documents the internal short-Weierstrass arithmetic layer used by
future ECDH and ECDSA implementations.  It is deliberately not a public ABI yet:
the first consumer will define the key formats, validation policy, and operation
surface rather than exposing low-level point objects directly.

## Scope

The implementation supports the NIST prime curves P-256, P-384, and P-521.
Each has cofactor one and coefficient `a = -3`.  Domain parameters are stored in
`src/Util/ECC/ecc_curves.c` and follow NIST SP 800-186.

The common layer contains:

- fixed-width prime-field arithmetic,
- affine and Jacobian point representations,
- point addition and doubling,
- three explicitly separated scalar-multiplication paths,
- scalar range validation,
- curve-equation validation, and
- SEC 1 compressed, uncompressed, and infinity point encoding/decoding.

No external ECC implementation was copied.  The affine formulas, Jacobian
formulas, Montgomery arithmetic, and SEC 1 conversion logic are implemented
from their mathematical specifications.

## Field representation

Field elements use 32-bit little-endian limbs internally, with a maximum of 17
limbs for P-521.  This keeps the baseline compatible with the legacy 32-bit
targets supported by LiberaCrypt and does not require `__uint128_t`, assembly,
or platform intrinsics.

Values remain in Montgomery form while arithmetic is in progress.  Import
rejects non-canonical integers `x >= p`; export performs one Montgomery
conversion.  Addition, subtraction, multiplication, reduction, selection,
inversion, and square-root exponentiation all use loop bounds determined only
by the selected public curve.  Inversion and square-root exponentiation use
a four-bit window whose digits come only from the public, fixed curve exponent;
the table contents depend on the field input, but its accessed index does not.

The generic LiberaCrypt bignum layer remains unchanged.  ECC uses its own
fixed-width field representation because curve fields have known widths and
because calling generic division-based reduction would make the secret-scalar
schedule depend on variable-length bignum behavior.

## Point and scalar paths

### Affine reference path

`crypto_ec_scalar_multiply_reference` is the straightforward binary
double-and-add construction using textbook affine addition and doubling.
Affine operations perform a field inversion for each non-trivial addition or
doubling.  The implementation is intentionally simple and structurally
different from the optimized path, which makes it useful for differential
tests and review.

This path branches on scalar bits and intermediate point cases.  It must not be
used with private scalars.

### Optimized public-data path

`crypto_ec_scalar_multiply_vartime` uses Jacobian coordinates, a four-bit
window, direct public table indexing, and public-data exceptional-case
branches.  Jacobian coordinates defer inversion until the final affine
conversion.  A separate variable-time addition routine avoids computing an
unused doubling candidate during ordinary additions.

This path is intended for public scalars or verification-side calculations.
It must not be used for ECDH private keys or ECDSA nonces.

The four-bit window is a conservative single-shot choice: its 16-entry table is
small, portable, and inexpensive to build for a point that may change on every
call.  Larger fixed-base tables and curve-specific comb methods are better
introduced with the ECDSA/ECDH consumers that can own and reuse such contexts.

### Secret-scalar path

`crypto_ec_scalar_multiply_ct` scans exactly `scalar_bytes * 8` bits and uses a
Montgomery-ladder invariant.  Every bit performs:

1. a masked point swap,
2. one complete-behavior Jacobian addition,
3. one Jacobian doubling, and
4. a second masked point swap.

The complete-behavior addition computes the ordinary addition result, the
doubling result, and infinity handling, then resolves exceptional cases with
masks.  Scalar bits do not control a branch or a table index.  The final
Jacobian-to-affine inversion uses a fixed exponentiation schedule.

`crypto_ec_scalar_is_valid_ct` separately checks `1 <= k < n` using the fixed
curve width.  Protocol code is expected to call it before secret scalar
multiplication.

“Constant-time” here means a fixed software operation and memory-access
schedule with respect to the scalar and field values.  ISO C cannot guarantee
identical physical timing on every compiler, processor, cache hierarchy, or
speculative-execution environment.  Consumers must retain the project-wide
compiler review and side-channel testing requirements.

## Point encoding and validation

The decoder accepts SEC 1:

- `0x04 || X || Y` uncompressed points,
- `0x02/0x03 || X` compressed points, and
- `0x00` only when the caller explicitly allows the point at infinity.

Coordinates must be canonical field integers and decoded non-infinity points
must satisfy `y^2 = x^3 - 3x + b`.  Compressed points recover `y` with
`(p + 1) / 4` exponentiation; all three supported primes are congruent to
three modulo four.  The requested parity bit selects between the two roots.

Future ECDH public-key decoding must set `allow_infinity` to zero.  Since the
supported curves have cofactor one, a canonical non-infinity point satisfying
the curve equation is in the prime-order group.

## Validation

`tests/ECC/UnitTest.c` covers all three curves with:

- published generator coordinates and known `2G` values,
- differential comparison of affine, windowed, and ladder multiplication,
- zero, one, `n - 1`, and `n` scalar boundaries,
- `nG = infinity`,
- addition, doubling, inverse-point, and infinity edge cases,
- compressed and uncompressed round trips,
- non-canonical coordinates, non-residue compressed inputs, malformed tags,
  lengths, and forbidden infinity encodings, and
- in-place aliasing of scalar-multiplication outputs.

During development, the windowed and ladder paths were additionally compared
against an independent Python big-integer affine oracle for 100 random scalars
per curve.

## Benchmarking

Build the non-gating benchmark with:

```sh
cmake -S . -B build \
  -DBUILD_SHARED_LIBS=OFF \
  -DLIBERAC_BUILD_TESTS=OFF \
  -DLIBERAC_BUILD_BENCHMARKS=ON \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --target crypto_ecc_benchmark
./build/crypto_ecc_benchmark
```

The benchmark uses the same high-Hamming-weight scalar `n - 1`, includes the
final affine conversion, dynamically increases the iteration count until the
timer interval is useful, and prints nanoseconds per scalar multiplication.
It compares:

- affine binary reference,
- Jacobian four-bit variable-time window, and
- fixed-schedule Jacobian ladder.

The reference-to-window comparison measures optimization benefit.  The ladder
is reported separately because it provides a stronger side-channel schedule
and is not a drop-in performance alternative to the public-data path.  Hosted
Ubuntu, macOS, and Windows results are uploaded by
`.github/workflows/ecc-benchmark.yml`; hosted-runner numbers are comparative
rather than stable machine benchmarks.

## Deliberately deferred optimizations

The common portable baseline does not yet use:

- NIST-prime-specific Solinas reduction,
- 64-bit or `__uint128_t` field backends,
- assembly or SIMD,
- reusable fixed-base precomputation,
- endomorphisms, or
- architecture-specific inversion chains.

Those techniques should be isolated behind independently tested backends.
They should replace the portable path only after differential testing,
side-channel review, and per-platform benchmarks show a material benefit.

## References

- NIST SP 800-186, *Recommendations for Discrete Logarithm-based
  Cryptography: Elliptic Curve Domain Parameters*, February 2023.
- Standards for Efficient Cryptography Group, *SEC 1: Elliptic Curve
  Cryptography*, Version 2.0.
- J. Renes, C. Costello, and L. Batina, *Complete addition formulas for prime
  order elliptic curves*, EUROCRYPT 2016 / IACR ePrint 2015/1060.
