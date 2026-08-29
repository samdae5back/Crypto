# ML-KEM full Montgomery-domain optimization

## Scope

This experiment extends the validated Barrett-only and hybrid-Montgomery ML-KEM
implementations by keeping all internal NTT-domain polynomials in Montgomery
representation.

The external FIPS 203 representation is unchanged. Serialized public/private
keys and ciphertexts continue to contain ordinary canonical residues. The
Montgomery domain exists only between explicit internal conversion boundaries.

The three implementations retained for measurement are:

1. Barrett-only: ordinary canonical NTT coefficients with Barrett multiplication.
2. Hybrid Montgomery: ordinary canonical NTT coefficients; only fixed twiddle
   products use Montgomery REDC.
3. Full Montgomery: NTT-domain coefficients, sampled matrices, decoded NTT keys,
   pointwise products, and NTT-domain accumulators are represented as `aR mod q`.

## Constants

For ML-KEM:

```text
q = 3329
R = 2^16 = 65536
-q^{-1} mod R = 3327
R mod q = 2285
R^2 mod q = 1353
```

`q` is odd, so `gcd(q,R)=1` and Montgomery representation is a bijection on
`Z_q`.

## Domain invariant

The full-domain implementation uses the following strict contracts:

```text
coefficient-domain polynomial before NTT: ordinary [0,q)
NTT() output:                         Montgomery [0,q), representing aR
SampleNTT output:                    ordinary NTT coefficient
SampleNTT after explicit conversion: Montgomery NTT coefficient
serialized NTT public/private key:   ordinary [0,q)
decoded NTT public/private key:      ordinary, then explicitly converted
Multiply_NTT input/output:           Montgomery NTT coefficients
NTT_inv input:                       Montgomery NTT coefficients
NTT_inv output:                      ordinary coefficient-domain polynomial
```

No function is expected to infer a domain from a value. The conversion points
are explicit in K-PKE.

## Ordinary to Montgomery conversion

A naive conversion can compute `aR mod q` with ordinary modular reduction. The
full implementation instead uses the standard Montgomery identity

```text
REDC(a * R^2 mod q) = aR mod q.
```

Because `R^2 mod q = 1353`, for `0 <= a < q` the REDC input is at most

```text
(q-1) * 1353 = 4,502,?  (well below qR).
```

More directly, `(q-1)*1353 = 4,502,?` remains far below the REDC precondition
`qR = 218,169,344`; the implementation uses `uint32_t` throughout this product.

The exact numeric bound is not performance-critical; the important invariant is
`a < q` and `1353 < q`, hence the product is below `(q-1)^2`.

## Montgomery to ordinary conversion

For a canonical Montgomery coefficient `aR mod q`,

```text
REDC(aR) = a mod q.
```

Key generation converts secret/public NTT coefficients back to ordinary form
immediately before 12-bit serialization. Public/private key decoding performs
the inverse conversion immediately after decoding.

## Pre-scaled zeta table

Every FIPS 203 twiddle `z` is stored internally as

```text
z_M = zR mod q.
```

The table is derived mechanically from the existing LiberaCrypt zeta table; it
does not change the root sequence or bit-reversal order.

For Montgomery coefficients `a_M = aR`,

```text
MontMul(z_M, a_M)
= REDC((zR)(aR))
= zaR mod q,
```

so the result remains in Montgomery domain. Unlike the hybrid implementation,
there is no per-butterfly conversion of the twiddle.

## Forward NTT

`NTT()` accepts ordinary coefficient-domain input. Each input coefficient is
converted once to Montgomery representation using `REDC(a*R^2)`. Every
subsequent butterfly operation stays in Montgomery domain:

```text
t = MontMul(z_M, b_M)
a'_M = a_M + t mod q
b'_M = a_M - t mod q.
```

Addition and subtraction preserve the common factor `R` and the existing
canonical add/sub helpers keep representatives in `[0,q)`.

Thus the NTT output represents exactly

```text
R * NTT(a) mod q.
```

## Base multiplication

For two Montgomery NTT coefficients,

```text
MontMul(aR, bR) = abR mod q.
```

The quadratic base product therefore remains entirely in Montgomery domain.
For the twisted term with Montgomery `r_M = rR`:

```text
u_M = MontMul(a1_M, b1_M) = a1*b1*R
MontMul(u_M, r_M)          = a1*b1*r*R.
```

All additions then preserve the same Montgomery factor. This removes the
Barrett wide-reduction path from variable-by-variable NTT base multiplication,
which is the principal difference from the hybrid design.

## Inverse NTT and scale removal

`NTT_inv()` accepts Montgomery NTT coefficients and keeps butterflies in
Montgomery representation. Immediately before return, each coefficient still
contains the common `R` factor.

The inverse normalization constant is ordinary

```text
3303 = 128^{-1} mod q.
```

Therefore a single REDC operation performs both normalization and domain exit:

```text
REDC((xR) * 3303)
= x * 3303 mod q.
```

The output is the same ordinary coefficient-domain polynomial produced by the
Barrett/hybrid implementations. No separate Montgomery-to-ordinary pass is
needed after inverse NTT.

## Matrix and key boundaries

`SampleNTT` is intentionally kept specification-shaped and continues to emit
ordinary NTT coefficients. K-PKE converts a sampled matrix polynomial once,
immediately after sampling, and then reuses it in Montgomery form.

FIPS 203 public/private NTT key coefficients are serialized as ordinary
residues. Key generation converts internal Montgomery NTT coefficients back to
ordinary form immediately before `ByteEncode`. Encryption/decryption convert
such decoded NTT coefficients into Montgomery representation immediately after
`ByteDecode`.

This keeps the wire format and validation semantics unchanged.

## Range and overflow argument

Every canonical Montgomery representative lies in `[0,q)`, just like an
ordinary canonical residue. Consequently every Montgomery multiply has

```text
0 <= a*b <= (q-1)^2 = 11,075,584.
```

This is far below

```text
qR = 218,169,344,
```

which is the REDC input precondition used by the reducer. For
`m < R`, the REDC numerator obeys

```text
value + m*q < (q-1)^2 + (R-1)q < 2^32.
```

Thus the current `uint32_t` numerator cannot overflow. Addition/subtraction
inputs remain below `2q` and use the already-validated fixed-shape canonical
correction.

## Security implications

Montgomery representation is a bijective representation of the same `Z_q`
elements and does not change ML-KEM parameters, encodings, sampling, rejection
logic, or algebra.

All conversion counts, transform loop counts, and zeta indices are determined by
public parameters. The implementation introduces no secret-indexed lookup,
secret-dependent early exit, or source-level secret-dependent branch.

As elsewhere in LiberaCrypt, the source is described as constant-schedule rather
than claiming universal physical constant time on every compiler/CPU.

## Portability implications

The implementation uses fixed-width unsigned integer arithmetic only for the
reduction core. It does not require SIMD, compiler intrinsics, unaligned loads,
native-endian word interpretation, signed right shift, or assembly.

The pre-scaled table contains ordinary integer constants below `q`; no platform
representation assumption is involved.

## Validation requirements

Before the full-domain implementation is accepted:

1. ML-KEM-512/768/1024 official repository KATs must pass unchanged.
2. The complete unit/negative/overlap/failure-path suite must pass.
3. Linux, macOS, and Windows CI must all build and test successfully.
4. The resulting public keys, private keys, ciphertexts, and shared secrets must
   therefore remain byte-for-byte compatible with the existing vectors.
5. Performance must be measured against both the Barrett-only and hybrid
   implementations on the same runner for each OS.

## Benchmark design

The benchmark workflow builds three fixed revisions independently on each of:

- Ubuntu GitHub Actions runner
- macOS GitHub Actions runner
- Windows GitHub Actions runner

Each runner measures Barrett-only, hybrid Montgomery, and full Montgomery using
the same deterministic benchmark source. To reduce simple run-order bias, each
binary is run three times in rotated order and the reported value is the median
of those three per-binary medians.

The benchmark reports KeyGen, Encaps, and Decaps separately for ML-KEM-512,
ML-KEM-768, and ML-KEM-1024. Hosted-runner results are useful comparative
evidence but are not treated as stable absolute throughput numbers.
