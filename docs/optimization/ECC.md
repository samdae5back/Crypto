# Portable short-Weierstrass ECC arithmetic

This layer provides the common prime-field and point arithmetic used by the
public P-256, P-384, and P-521 ECDH implementation and planned ECDSA support.
The key-agreement API is exposed through `KeyAgreement.h`; the lower-level
field, point, and scalar-multiplication interfaces remain internal.

The production arithmetic intentionally exposes only two scalar-multiplication
policies: an optimized variable-time path for public scalars and a fixed-schedule
path for secret scalars. The textbook affine implementation is retained only in
the test tree as a correctness oracle and benchmark baseline; it is not linked
into the LiberaCrypt library.

## Supported domain parameters

The built-in parameter records cover the NIST P-256, P-384, and P-521 curves
from NIST SP 800-186. They are short-Weierstrass curves over prime fields with
`a = -3`. SEC 1 point-at-infinity, compressed, and uncompressed encodings are
accepted under the decoder's explicit infinity policy.

X25519 is intentionally not represented by this structure. Its Montgomery
curve, byte-order, clamping, and ladder rules use a separate backend rather
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

### Test-only textbook reference oracle

`tests/ECC/Reference.c` implements affine double-and-add using the direct
formulas. It branches on scalar bits and exceptional cases, and each affine
addition or doubling performs a field inversion. This implementation exists
only to provide an independent correctness oracle and benchmark baseline. It is
not part of the production source API and is not linked into LiberaCrypt.

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

## ECDH integration

`src/KeyAgreement/ecdh.c` uses only the fixed-schedule secret-scalar path for
private-key operations. Private keys are fixed-width big-endian scalars in
`1 <= d < n`; key generation obtains uniformly random candidates from the OS,
masks unused high bits, and rejection-samples against the group order.

Generated public keys are uncompressed SEC 1 points. Agreement accepts either
compressed or uncompressed SEC 1 peer points, rejects infinity and invalid
curve points through the common decoder, and returns the fixed-width big-endian
x-coordinate of `dQ`. Because the supported NIST curves have cofactor one, an
accepted finite on-curve peer point is in the prime-order group.

The raw x-coordinate is deliberately not passed through a KDF inside ECDH. The
public API documents it as key-agreement material that should be fed into a
protocol-appropriate KDF such as HKDF.

## X25519 backend

`src/KeyAgreement/x25519.c` implements RFC 7748 separately with sixteen
little-endian radix-2^16 limbs. Products accumulate in portable `uint64_t`
values; reduction uses `2^256 = 38 (mod 2^255 - 19)`. This avoids
`unsigned __int128` and target-specific intrinsics, keeping the same source
usable with MSVC and the portability-oriented build matrix.

Scalar inputs are copied and clamped internally. The Montgomery ladder scans
all 255 scalar bits with masked conditional swaps, and inversion uses a fixed
public exponent. Peer u-coordinates use RFC 7748 decoding rules, including
masking the high input bit and reducing non-canonical encodings modulo the field
prime. Shared-secret derivation rejects the all-zero result so callers do not
silently accept a low-order peer input.

## Encoding and validation

The SEC 1 decoder rejects:

- wrong lengths or unsupported prefixes;
- non-canonical coordinates (`x >= p` or `y >= p`);
- compressed points whose right-hand side is not a quadratic residue;
- points that do not satisfy the curve equation; and
- infinity unless the caller explicitly permits it.

Secret scalar validation scans the fixed encoded width and combines the checks
for `1 <= k < n` without scalar-dependent early return after argument/length
validation. The optimized public path accepts shorter encodings and may trim
leading zero bytes because its timing is explicitly not secret-safe. The
reference oracle follows similarly simple variable-time semantics, but only in
tests.

## Validation

The focused ECC arithmetic tests cover:

- the standard generator being accepted as an on-curve finite point for
  P-256, P-384, and P-521;
- SEC 1 compressed and uncompressed generator round trips;
- independent `2G` affine coordinates for all three curves, checked against
  the test-only textbook reference result;
- scalar validity boundaries at zero, `n - 1`, and `n`;
- agreement among the test-only affine oracle, four-bit windowed Jacobian, and
  fixed-schedule ladder multiplication for scalar 1 and scalar 2; and
- deterministic differential comparisons of the test oracle and both
  production multiplication paths over 96 non-zero scalar values per curve.

The public key-agreement tests additionally cover RFC 7748 Alice/Bob X25519
vectors, bilateral ECDH agreement on all three NIST curves, compressed SEC 1
peer keys, invalid zero ECDH scalars, X25519 all-zero rejection, and OS-random
key-generation round trips.

The ECC validation workflow builds and runs the focused arithmetic tests on
hosted Ubuntu, macOS, and Windows runners and adds an Ubuntu ASan/UBSan run. The
normal repository CI builds the public key-agreement tests across the same three
operating systems.

## Benchmarking

The repository benchmark is also a test/benchmark target, so it may link the
textbook oracle without adding that code to the production library. It prints
median CPU microseconds per multiplication for the test-only reference baseline
and both production paths on all three curves. The scalar is deliberately
full-width and close to the group order so the public implementation cannot
look artificially fast from a tiny scalar. The affine reference path is sampled
once per timing sample, while the faster Jacobian paths use repeated operations
to reduce timer noise.

The benchmark is comparative evidence, not a performance promise for every
processor. Hosted-runner results should be retained with the pull request before
choosing more aggressive field representations, larger windows, Karatsuba, or
architecture-specific backends.
