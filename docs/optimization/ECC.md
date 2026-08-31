# Portable short-Weierstrass ECC arithmetic

This layer provides the common prime-field and point arithmetic needed by the
planned ECDH and ECDSA implementations. It is internal-only in this change: no
new public key-agreement or signature API is exported yet.

## Supported domain parameters

The built-in parameter records cover the NIST P-256, P-384, and P-521 curves
from NIST SP 800-186. They are short-Weierstrass curves over prime fields with
`a = -3`. SEC 1 point-at-infinity, compressed, and uncompressed encodings are
accepted under the decoder's explicit infinity policy.

X25519 is intentionally not represented by this structure. Its Montgomery
curve, byte-order, clamping, and ladder rules need a separate backend rather
than pretending it is another short-Weierstrass parameter choice.

## Arithmetic representation

- Fixed maximum storage: 17 little-endian 32-bit limbs (enough for P-521).
- Field representation: Montgomery residues with curve-specific `R`, `R^2`,
  and `-p^-1 mod 2^32` constants.
- Multiplication: portable full-width schoolbook multiplication followed by a
  word-by-word Montgomery reduction.
- Inversion: fixed-exponent powering to `p - 2`.
- Square root: fixed-exponent powering to `(p + 1) / 4`; all three field primes
  are congruent to 3 modulo 4.

The implementation deliberately avoids `unsigned __int128`, compiler
intrinsics, assembly, VLAs, and host-endian casts. This keeps the same source
usable with MSVC and legacy 32-bit-oriented C toolchains. Architecture-specific
or 64-bit-limb backends can be added later behind the same internal interface
if target-specific measurements justify them.

Schoolbook multiplication is retained instead of adding Karatsuba at these
small fixed widths. Karatsuba remains a benchmark-driven option, not an assumed
win: its extra temporaries and carry handling may cost more than it saves for
8, 12, and 17 limbs, particularly on 32-bit and older targets.

## Point-operation paths

### Textbook reference path

`ecc_reference.c` implements affine double-and-add using the direct formulas.
It branches on scalar bits and exceptional cases, and each affine addition or
doubling performs a field inversion. This path is intentionally simple and is
used as an independent correctness oracle and benchmark baseline. It must not
process secret scalars in production.

### Public, optimized variable-time path

`ecc_scalar_vartime.c` uses Jacobian coordinates and a fixed four-bit window.
It precomputes the sixteen public-point multiples, skips leading zero windows,
and uses a direct public table index. One final inversion converts the result
to affine form. This path is intended only for public scalars, such as ECDSA
verification components.

The window width is deliberately modest. Sixteen Jacobian points are at most
about 3.3 KiB with the fixed maximum structure, while larger windows increase
stack/table pressure on legacy environments. A different width should be
selected only from same-target benchmarks.

### Secret fixed-schedule path

`ecc_scalar_secret.c` validates a fixed encoded scalar width and executes a
Montgomery ladder over exactly the curve's scalar bit count. Every bit performs
one complete-behaviour Jacobian addition, one Jacobian doubling, and two masked
conditional swaps. It does not use a scalar-indexed table or branch on a scalar
bit. Ladder states are explicitly erased after conversion.

`ecc_projective.c` makes exceptional behaviour independent of a caller branch:
it evaluates the generic Jacobian addition and the doubling candidate, then
mask-selects the correct result for equal points, opposite points, and either
input at infinity. The formulas are therefore *complete-behaviour* at the
operation boundary even though the generic addition formula itself is not a
mathematically complete unified formula.

As with the existing bignum policy, this is described as a fixed source-level
schedule rather than a universal physical constant-time guarantee. ISO C cannot
force every compiler and processor to give identical instruction or arithmetic
latency, nor does this change claim resistance to power, EM, speculative,
fault, or compiler-introduced side channels.

## Encoding and validation

The SEC 1 decoder rejects:

- wrong lengths or unsupported prefixes;
- non-canonical coordinates (`x >= p` or `y >= p`);
- compressed points whose right-hand side is not a quadratic residue;
- points that do not satisfy the curve equation; and
- infinity unless the caller explicitly permits it.

Secret scalar validation scans the fixed encoded width and combines the checks
for `1 <= k < n` without scalar-dependent early return after argument/length
validation. Public/reference multiplication accepts shorter encodings and may
trim leading zero bytes because its timing is explicitly not secret-safe.

## Validation

The focused tests include:

- field import/export and arithmetic checked against independently generated
  Python big-integer results;
- independent coordinates for `2G`, `3G`, and `7G` on all three curves;
- equality, inverse, infinity, aliasing, and zero-scalar point cases;
- `1`, `n - 1`, and `n` scalar boundaries;
- cross-checks among affine reference, windowed Jacobian, and ladder paths;
- SEC 1 compressed/uncompressed round trips and malformed encodings; and
- independently generated full-width scalar and field differential vectors.

The repository benchmark prints median CPU microseconds per multiplication for
all three paths and curves. It is a comparative microbenchmark, not a promise
for every processor. The hosted Ubuntu, macOS, and Windows results should be
retained with the pull request before choosing any more aggressive field or
window optimization.
