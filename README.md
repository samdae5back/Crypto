# LiberaCrypt

**Free cryptography, everywhere.**

LiberaCrypt is a **portability-first C11 cryptography library** providing classical and post-quantum cryptographic primitives through a consistent runtime-selected API.

> **Portable by construction.** LiberaCrypt avoids relying on undefined, implementation-defined, or platform-specific behavior that merely happens to work on common systems.

Portability is treated as a **correctness property**, not merely as a list of supported platforms. The implementation is written to avoid assumptions that may hold on mainstream systems but fail across different compilers, architectures, ABIs, or legacy and non-mainstream Unix environments. Code that depends on native integer or character representation, byte order, signed shifts, compiler extensions, or other hidden platform properties is avoided or rewritten explicitly.

The cryptographic implementation remains independent of an external cryptographic runtime. Platform-specific behavior is isolated to narrow system boundaries such as entropy acquisition and shared-library symbol export.

## Design goals

- **Portability first** — ISO C11, fixed-width arithmetic, explicit range reasoning, byte-order handling, and well-defined integer behavior.
- **Broad platform compatibility** — avoid assumptions that become problematic across different compilers, architectures, ABIs, and legacy or non-mainstream Unix systems.
- **Minimal platform dependence** — keep OS-specific behavior at explicit boundaries rather than throughout cryptographic code.
- **Consistent API** — compile supported parameter sets into one library and select algorithms at runtime through `LiberaCAlgID`.
- **Free software** — original LiberaCrypt source is released under `AGPL-3.0-only`.

## Cryptographic primitives

LiberaCrypt includes classical and post-quantum cryptographic algorithms,
including AES, Triple-DES, ChaCha20, Poly1305, ChaCha20-Poly1305,
SHA-1/SHA-2/SHA-3/SHAKE, HMAC, CMAC, GMAC, HKDF, PBKDF2-HMAC, CTR_DRBG,
RSA, ElGamal, ECDH, X25519, ECDSA, Ed25519, ML-KEM, ML-DSA, SLH-DSA,
NTRU+, SMAUG-T, AIMer, and HAETAE.

## Project principles

- **Simplicity** — keep public interfaces small and consistent, avoid needless
  configuration, and make common cryptographic operations straightforward to
  integrate.
- **Portability** — prefer ISO C, fixed-width types, explicit range reasoning,
  and well-defined integer behavior so the same code can be built reliably on
  very different compilers, architectures, and operating systems.
- **Environment independence** — avoid unnecessary dependencies on a particular
  cryptographic runtime, system library, compiler extension, character
  signedness, byte order, or implementation-defined arithmetic behavior.
- **Software freedom** — LiberaCrypt is developed as free software. Users should
  be able to study, modify, and redistribute the project under its license. The
  project's original source is released under `AGPL-3.0-only`; separately
  identified bundled components retain their upstream licenses.

LiberaCrypt uses `LIBERAC_` for public C functions, macros, constants, and
algorithm selectors, `LiberaC` for public type names, `LiberaCrypt.h` as its
umbrella header, and the `LiberaCrypt::LiberaCrypt` CMake target.

> Security note: use RSAES-OAEP for RSA encryption and RSASSA-PSS for RSA
> signatures. The raw textbook RSA entry points remain available for primitive
> tests and compatibility, but applications must not treat raw RSA as a secure
> encryption or signature scheme.

## Portability considerations

Portability in LiberaCrypt is treated as a correctness property rather than only
a list of supported platforms. Code that happens to work on one compiler or
machine is not considered portable if its result depends on implementation-
defined integer behavior, native character signedness, byte order, or linker
conventions.

Examples of portability work in the current codebase include:

- **Fixed-width arithmetic and explicit range reasoning.** Internal arithmetic
  uses `uint32_t`, `int32_t`, `uint64_t`, `int64_t`, and `size_t` where their
  width or role matters. Narrowing conversions are made only where the value
  range is known, with compile-time assertions used for important invariants.
- **No dependency on plain `char` signedness.** AIX/Power environments may use
  unsigned plain `char`. HAETAE's decomposed low-byte serialization therefore
  defines the signed `[-128, 127]` to byte mapping and its inverse explicitly
  instead of relying on a cast through implementation-defined `signed char`
  behavior.
- **Portable signed division and shifts.** Arithmetic that originally relied on
  right-shifting negative signed integers was rewritten around explicit floor
  division and unsigned sign-bit extraction. This removes assumptions about the
  implementation's signed right-shift behavior in HAETAE Montgomery/Barrett
  reduction and fixed-point FFT arithmetic.
- **Range-proven fixed-point FFT widths.** HAETAE's key-generation FFT records a
  conservative bound for every real and imaginary component. FFT storage stays
  `int32_t`, Q16 products and butterfly expressions are evaluated in `int64_t`,
  and squared magnitudes and singular-value accumulation use `uint64_t`. Static
  assertions tie those choices to the algorithm parameters used by the proof.
- **Explicit byte-order handling.** Serialization and low-level word handling
  avoid assuming host endianness; endian-sensitive operations are isolated in
  project utilities rather than leaking native representation into public
  formats.
- **Portable modern symmetric arithmetic.** ChaCha20 decodes all key, nonce,
  counter, and output words explicitly in little-endian order and uses only
  defined `uint32_t` addition, rotation, and XOR. Poly1305 uses five 26-bit
  limbs with range-bounded `uint64_t` products; it needs neither native
  128-bit integers nor a generic bignum implementation.
- **Platform-specific behavior is kept at narrow boundaries.** Entropy
  acquisition is adapted to the host OS, while cryptographic algorithms remain
  independent of the operating system's cryptographic runtime.
- **ABI/export policy follows each platform's native model.** The same public API
  is exported through Windows DLL declarations, ELF version scripts, macOS
  exported-symbol lists, Solaris mapfiles, AIX `.exp` files, and HP-UX linker
  export options rather than assuming one linker model everywhere.
- **Cross-toolchain validation.** CI builds the library on Windows/MSVC, Linux,
  and macOS, while unit tests, KATs, warning-oriented builds, and sanitizers are
  used to catch assumptions that a single compiler may otherwise tolerate.

These constraints intentionally influence implementation style. A slightly more
explicit expression is preferred over a shorter one when the explicit form
makes integer width, representation, range, or platform behavior unambiguous.

## Layout

```text
inc/                              public category API headers only
src/*.c                           public category API entry points
src/AsymmetricCipher/{RSA,ElGamal}
src/AuthenticatedEncryption/ChaCha20Poly1305
src/BlockCipher/{AES,TripleDES}
src/DigitalSignature/{AIMer,ECDSA,Ed25519,HAETAE,ML-DSA,SLH-DSA}
src/HashFunction/{SHA1,SHA2,SHA3,LSH}
src/KeyAgreement/{ecdh,x25519}
src/KeyEncapsulation/{ML-KEM,NTRU-Plus,SMAUG-T}
src/MessageAuthentication/Poly1305
src/RandomNumberGeneration/{CTR_DRBG,KAT,Noise}
src/StreamCipher/ChaCha20
src/{AuthenticatedEncryption,KeyDerivation,MessageAuthentication,StreamCipher}.c
src/Util/{Bignum,Bit,Core,ECC,Endian,NTT,Prime}
cmake/                            platform export policy
tests/                            unit, KAT, and public-header tests
```

Only the headers in `inc/` are installed. Private declarations are colocated
with their implementation under the corresponding `src/` directory. Each
operational public header has a same-named entry-point source directly under
`src/`.

## Build and test

No submodule checkout or external crypto package is required.

```sh
cmake -E make_directory build
cmake -E chdir build cmake .. \
  -DBUILD_SHARED_LIBS=ON \
  -DLIBERAC_BUILD_TESTS=ON \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
cmake -E chdir build ctest -C Release --output-on-failure
```

For a static library, configure with `-DBUILD_SHARED_LIBS=OFF`. To install the
library and its public headers:

```sh
cmake -E chdir build cmake .. -DCMAKE_INSTALL_PREFIX=/your/prefix
cmake --build build --target install --config Release
```

CMake consumers can discover the installed package and link its imported target:

```cmake
find_package(LiberaCrypt CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE LiberaCrypt::LiberaCrypt)
```

Tests default to enabled for a standalone checkout and disabled when the library
is included by another project with `add_subdirectory()`. An embedding project
can enable them through the CMake cache (for example,
`-DLIBERAC_BUILD_TESTS=ON`); its top-level CMake file must also call
`enable_testing()` for root-level CTest discovery.

The target exposes the installed `inc` directory, so source files include the
umbrella header as follows:

```c
#include <LiberaCrypt.h>
```

To generate the public API reference, install Doxygen 1.12 or newer and enable
the optional documentation target:

```sh
cmake -E make_directory build-docs
cmake -E chdir build-docs cmake .. -DLIBERAC_BUILD_DOCS=ON
cmake --build build-docs --target liberacrypt_docs
```

The generated entry page is `build-docs/docs/html/index.html`. Only the public
headers in `inc/` are included in this reference.

## Runtime algorithm dispatch

Public operation names start with `LIBERAC_`. For APIs that accept an algorithm
identifier, `LiberaCAlgID` is the last argument. The complete identifier set is
in `inc/Def.h` and is available from `LiberaCrypt.h`.

### Symmetric encryption

AES and Triple-DES encryption and decryption use one API pair for all key sizes
and modes. Triple-DES is included strictly for interoperability with legacy
systems; new protocols should use an authenticated AES mode such as GCM.

AES does not define a separate master-key construction algorithm. Generate a
uniform random key with the size required by the selected identifier; round-key
expansion remains an internal implementation detail:

```c
uint8_t key[LIBERAC_AES_256_KEY_BYTES];
size_t key_length = LIBERAC_BLOCK_CIPHER_KEY_SIZE(LIBERAC_ALG_AES_256_GCM);

LiberaCError error = LIBERAC_RANDOM_BYTES(key, key_length);
```

Applications deriving keys from passwords or shared secrets must use an
appropriate key-derivation protocol instead of copying or truncating that input.

```c
uint8_t ciphertext[32];
uint8_t tag[16];

LiberaCError error = LIBERAC_BLOCK_CIPHER_ENCRYPT(
    ciphertext, sizeof(ciphertext),
    tag, sizeof(tag),
    plaintext, sizeof(plaintext),
    key, sizeof(key),
    nonce, sizeof(nonce),
    aad, sizeof(aad),
    LIBERAC_ALG_AES_256_GCM);
```

The AES dispatcher supports AES-128, AES-192, and AES-256 with ECB, CBC, CTR,
CCM, and GCM. ECB and CBC inputs must be block-aligned; padding is intentionally
left to the caller. AEAD decryption clears the plaintext output when tag
authentication fails.

The same dispatcher supports three-key Triple-DES EDE in ECB and CBC modes with
a 24-byte key and 8-byte block alignment. It does not support two-key TDEA or
single DES. DES parity bits are ignored rather than corrected or validated.

### ChaCha20, Poly1305, and ChaCha20-Poly1305

The standalone stream-cipher API implements the
[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) ChaCha20 variant with a
32-byte key, a 32-bit initial counter, and a 12-byte nonce. It accepts
arbitrary byte lengths and supports exact in-place XOR. Requests that would
wrap the 32-bit counter are rejected before output is written. A key/nonce pair
must never be reused, and counter ranges for the same pair must not overlap.

Poly1305 is exposed through the message-authentication family for protocols
that already define safe one-time-key generation. It always produces and
verifies the complete 16-byte tag from an exactly 32-byte one-time key. Direct
users must never authenticate two messages with the same Poly1305 key.

For normal application use, the standardized composition is available through
the separate AEAD dispatcher:

```c
uint8_t ciphertext[1024];
uint8_t tag[LIBERAC_CHACHA20_POLY1305_TAG_BYTES];

LiberaCError error = LIBERAC_AEAD_ENCRYPT(
    ciphertext, sizeof(ciphertext),
    tag, sizeof(tag),
    plaintext, message_length,
    key, LIBERAC_CHACHA20_POLY1305_KEY_BYTES,
    nonce, LIBERAC_CHACHA20_POLY1305_NONCE_BYTES,
    aad, aad_length,
    LIBERAC_ALG_CHACHA20_POLY1305);
```

ChaCha20-Poly1305 reserves counter zero to derive the one-time Poly1305 key and
starts payload encryption at counter one. Only the RFC 8439 12-byte nonce and
complete 16-byte tag are accepted. Decryption authenticates AAD and ciphertext
before transforming any ciphertext; a tag mismatch returns
`LIBERAC_ERROR_AUTHENTICATION_FAILED` and clears the entire plaintext output.
Exact input/output aliasing is supported, while partial overlaps and overlaps
with key, nonce, AAD, or tag storage are rejected explicitly.

### Hashes and XOFs

All fixed-output hashes and XOFs use the same hash API:

```c
uint8_t digest[LIBERAC_SHA2_256_DIGEST_BYTES];

LiberaCError error = LIBERAC_HASH(
    digest, sizeof(digest),
    message, message_length,
    LIBERAC_ALG_HASH_SHA2_256);
```

Supported hash identifiers are:

- SHA-1 (legacy compatibility only; do not use for new security designs)
- SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256
- LSH-256-224, LSH-256-256, LSH-512-224, LSH-512-256, LSH-512-384, and
  LSH-512-512
- SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256

For SHAKE, `OUTPUT_LENGTH` selects the requested XOF output length. Fixed-output
hashes require a buffer at least as large as their standard digest.

Messages can also be supplied incrementally through the same runtime-selected
interface. Finalization finishes input absorption; output is then retrieved by
the squeeze operation:

```c
LiberaCHashContext context;
uint8_t digest[LIBERAC_SHA2_256_DIGEST_BYTES];

LiberaCError error = LIBERAC_HASH_INIT(&context, LIBERAC_ALG_HASH_SHA2_256);
if (error == LIBERAC_SUCCESS)
    error = LIBERAC_HASH_UPDATE(&context, first_part, first_part_length);
if (error == LIBERAC_SUCCESS)
    error = LIBERAC_HASH_UPDATE(&context, second_part, second_part_length);
if (error == LIBERAC_SUCCESS)
    error = LIBERAC_HASH_FINALIZE(&context);
if (error == LIBERAC_SUCCESS)
    error = LIBERAC_HASH_SQUEEZE(&context, digest, sizeof(digest));
LIBERAC_HASH_CLEAR(&context);
```

Fixed-output algorithms permit one squeeze and write exactly their standard
digest size. SHAKE permits repeated squeezes; concatenating their outputs gives
the same byte stream as one request for the combined length.

### Message authentication and key derivation

Message authentication uses separate one-shot generation and verification APIs:

- HMAC accepts the fixed-output SHA-1, SHA-2, and SHA-3 identifiers. SHAKE and
  LSH identifiers are rejected. A caller may request a non-empty prefix up to
  the selected digest size.
- CMAC accepts AES-128/192/256 ECB identifiers and three-key Triple-DES EDE ECB.
  A caller may request a non-empty prefix up to the cipher block size.
- GMAC accepts AES-128/192/256 GCM identifiers and GCM tag lengths of 4, 8, or
  12 through 16 bytes. Its IV must be non-empty; a 12-byte IV follows GCM's
  direct counter construction.
- Poly1305 accepts only `LIBERAC_ALG_POLY1305`, an exactly 32-byte one-time key,
  and the complete 16-byte tag. Tag truncation is intentionally unavailable.
- `LIBERAC_HMAC_VERIFY`, `LIBERAC_CMAC_VERIFY`, `LIBERAC_GMAC_VERIFY`, and
  `LIBERAC_POLY1305_VERIFY` compare tag contents through the shared
  constant-time equality helper and return
  `LIBERAC_ERROR_AUTHENTICATION_FAILED` on mismatch.

The key-derivation APIs compose the same runtime-selected HMAC layer:

- `LIBERAC_HKDF_EXTRACT`, `LIBERAC_HKDF_EXPAND`, and `LIBERAC_HKDF`
  implement RFC 5869. An omitted salt is treated as a digest-sized all-zero
  salt, Expand requires at least one digest of PRK material, and output is
  limited to `255 * HashLen` bytes.
- `LIBERAC_PBKDF2_HMAC` accepts a positive 64-bit iteration count, encodes the
  block counter in four-byte big-endian form, and enforces the
  `(2^32 - 1) * HashLen` derived-key bound. Empty passwords and salts are
  permitted for protocol compatibility; applications remain responsible for
  password policy and work-factor selection.
- Both families accept fixed-output SHA-1, SHA-2, and SHA-3 HMAC selectors.
  Protocols that serialize standard algorithm identifiers must still restrict
  the choice to the identifiers their profile permits.

HKDF-Extract rejects PRK overlap with IKM or salt; HKDF-Expand rejects
OKM overlap with its PRK or info; and PBKDF2 rejects derived-key overlap with
password or salt. The combined HKDF keeps its intermediate PRK locally, so
already-consumed IKM/salt need not remain live during Expand. Allocation sizes
are checked for `size_t` overflow, intermediate PRKs and iteration blocks are
explicitly erased, and a partially produced output is cleared if an internal
operation fails. PBKDF2 currently invokes the public
one-shot HMAC path for every PRF call; a reusable prepared-HMAC state remains a
future measured optimization, not a claimed current speedup. The standards,
limits, and vectors are also recorded in `docs/key-derivation.md`.

### Random bytes and CTR_DRBG

`LIBERAC_RANDOM_BYTES` reads directly from the operating-system entropy source.
The stateful CTR_DRBG API follows
[NIST SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final)
and supports instantiate, reseed, generate, prediction-resistance requests,
OS-entropy helpers, and explicit state clearing. AES remains the modern default:

| Configuration | Effective key state | V | Seed | Request maximum | Reseed interval |
| --- | ---: | ---: | ---: | ---: | ---: |
| AES-128 | 16 bytes | 16 bytes | 32 bytes | 65,536 bytes | `2^48` requests |
| AES-192 | 24 bytes | 16 bytes | 40 bytes | 65,536 bytes | `2^48` requests |
| AES-256 | 32 bytes | 16 bytes | 48 bytes | 65,536 bytes | `2^48` requests |
| Three-key TDEA (**legacy compatibility**) | 21 bytes | 8 bytes | 29 bytes | 1,024 bytes | `2^32` requests |

Every configuration has `*_DF` and `*_NO_DF` identifiers. A no-DF
instantiation requires exactly the listed seed size and no nonce; DF variants
accept variable-length inputs under the standard entropy and nonce rules.
TDEA's 168-bit effective key state is stored as 21 bytes, then expanded into
three 64-bit DES engine keys with odd parity before encryption. Counter
increments always traverse the complete active V, and all block-cipher
schedules, derived seed material, temporary blocks, and failed output are
erased.

The TDEA selectors exist only to reproduce standards-era systems and
[NIST CAVP reference vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators).
They are not a recommendation for a new random-bit generator. NIST has
[withdrawn the TDEA recommendation for new protection](https://csrc.nist.gov/news/2023/nist-to-withdraw-sp-800-67-rev-2),
so new applications should use an AES CTR_DRBG configuration.

## Other supported families

- ECDH and ECDSA over NIST P-256, P-384, and P-521; X25519; and Ed25519
- ChaCha20, Poly1305, and RFC 8439 ChaCha20-Poly1305 AEAD
- HMAC with fixed-output SHA-1/SHA-2/SHA-3, AES/Triple-DES CMAC, and AES-GMAC
- HKDF and PBKDF2-HMAC with fixed-output SHA-1/SHA-2/SHA-3
- CTR_DRBG with AES-128/192/256 and legacy three-key TDEA, with and without
  `Block_Cipher_df`
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- NTRU+768, NTRU+864, and NTRU+1152
- SMAUG-T-128, SMAUG-T-192, and SMAUG-T-256
- ML-DSA-44, ML-DSA-65, and ML-DSA-87
- AIMer 128/192/256 fast and small parameter sets
- HAETAE-120, HAETAE-180, and HAETAE-260
- All twelve FIPS 205 SLH-DSA SHA2/SHAKE small/fast parameter sets
- RSAES-OAEP, RSASSA-PSS, raw RSA, and safe-prime ElGamal
- Unsigned big-number byte load/store and lifecycle operations
- Probable-prime, prime, and safe-prime generation
- Random bytes obtained directly from the operating system entropy source

Key, ciphertext, and signature size-query APIs also take the runtime
`LiberaCAlgID`, so applications do not need parameter-specific builds or
headers.

## Implementation optimization and reference comparison

The comparisons below describe implementation structure, not changes to the
standard algorithms or their wire formats. Here, a *reference-shaped baseline*
means a direct translation of the standard pseudocode or the project's initial
pre-optimization implementation; it does not mean that an official NIST
software package was benchmarked. Bundled upstream code and its exact versions
are identified in `THIRD_PARTY_NOTICES.md` and the component provenance files.

### SHA-1 and Triple-DES

| Area | Reference-shaped or initial baseline | LiberaCrypt implementation | Effect |
| --- | --- | --- | --- |
| SHA-1 message schedule | Materialize all 80 32-bit schedule words described by the compression procedure. | Keep a 16-word circular schedule and overwrite a word after its last use. | Reduces schedule storage from 320 to 64 bytes per compression call without changing the 80 rounds. |
| SHA-1 streaming input | Copy every input byte through the context's 64-byte staging buffer. | Drain an existing partial block, compress complete input blocks directly, and buffer only the final remainder. | Avoids one copy for aligned full blocks while preserving arbitrary chunk boundaries. |
| DES S-boxes and P permutation | A textbook table implementation uses secret-derived S-box indices; the first hardened LiberaCrypt revision instead scanned all 64 entries for every S-box. | Evaluate the FIPS 46-3 S/P truth functions with a fixed-index Boolean multiplexer tree. | Avoids secret-indexed table or cache access and removes the 64-entry scan. |
| DES E, IP, and FP permutations | Walk the E/IP/FP tables bit by bit, and perform IP plus FP around each of the three DES stages. | Spell E out with fixed shifts, use a 32-bit permutation network for IP/FP, and keep intermediate E-D-E stages in the IP domain. | Replaces hot generic permutation loops and cancels the two intermediate FP/IP pairs. |
| Secret lifetime | Round schedules and temporary round state remain ordinary automatic storage until return. | Explicitly clear all three round-key schedules and the reusable Boolean-round workspace after the operation. | Reduces residual key-dependent data while avoiding per-round workspace setup. |

In a same-host development microbenchmark built with GCC 13.3 and `-O3`, the
current Triple-DES path processed about 4.3 times as much data as the initial
constant-scan implementation (0.829 MB/s to 3.544 MB/s). This is a comparison
between two LiberaCrypt revisions, not a cross-library benchmark, and absolute
throughput will vary by compiler and machine.

The optimized legacy primitives were checked with SHA-1 empty-string, `abc`,
padding-boundary, and million-`a` known-answer cases; all 19 incremental hash
identifiers; standard Triple-DES vectors; and 1,000 randomized ECB/CBC cases
against OpenSSL 3.0.13. OpenSSL is only a development test oracle and is not a
build or runtime dependency. In-place CBC, invalid-argument behavior, strict
C11 `-O0`/`-O2`/`-O3` warning builds, and AddressSanitizer/
UndefinedBehaviorSanitizer runs were also exercised.

### ElGamal

| Area | Previous implementation | LiberaCrypt optimization | Effect |
| --- | --- | --- | --- |
| Safe-prime subgroup generator candidate | Form the fixed exponent `2` as a bignum and route `hseed^2 mod p` through generic modular exponentiation. | Use the shared square-specific bignum path. Symmetric cross products are computed once and accumulated twice before reduction. | Avoids generic exponentiation setup and reduces the number of wide limb multiplications for squaring. Safe-prime generation still dominates total key-generation cost. |
| Secret exponentiation | Binary square-and-multiply skipped the multiply when a secret exponent bit was zero and stopped at the secret exponent bit length. | RSA private operations and ElGamal `x`/`y` exponentiation use a fixed-width Montgomery path that always computes square and multiply candidates for every modulus-width bit and mask-selects the result. | Removes secret-bit-dependent multiply branches and secret-bit-dependent table/index selection from the exponentiation schedule. |
| Encryption twin powers | Compute `g^y mod p` and `h^y mod p` as independent exponentiations. | Use the shared `crypto_bignum_mod_exp2_ct` path for both bases with one Montgomery/R^2 setup and one fixed-width exponent scan. | Avoids duplicated Montgomery context preparation while preserving the same two exponentiation results. |
| Decryption factor | Compute `shared = c1^x mod p`, then invert it with a second full exponentiation `shared^(p-2) mod p`. | For nonzero `c1`, use Fermat's theorem to compute the inverse factor directly as `c1^(p-1-x) mod p`, then multiply by `c2`; both the derived subtraction and exponentiation use fixed-width secret paths. | Reduces the decryption path from two full modular exponentiations to one full modular exponentiation plus one modular multiplication. Invalid `c1 = 0` ciphertexts are rejected because zero has no multiplicative inverse. |

The ElGamal changes preserve the generated subgroup and valid-ciphertext
semantics. No exact speedup is claimed here until a reproducible benchmark is
retained in the repository. The decryption transformation removes one complete
modular exponentiation, while encryption shares context setup across its two
powers.

The secret exponentiation path is described as **constant-schedule** rather than
as a universal physical constant-time guarantee. Its loop count, multiplication
count, and memory indices do not depend on secret exponent bits, and stored
private exponents are padded to the public modulus limb width. ISO C, however,
cannot guarantee identical instruction latency on every processor/compiler, so
hardware-level timing claims require platform-specific validation.

### RSAES-OAEP and RSASSA-PSS

The RSA scheme layer implements RSAES-OAEP encryption and RSASSA-PSS
signatures according to [PKCS #1 v2.2 / RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html).
Both schemes use MGF1 and require the same caller-selected fixed-output hash for
the main hash and MGF1. SHA-1 is accepted only for legacy interoperability; the
fixed-output SHA-2 family, including SHA-512/224 and SHA-512/256, is supported
for current protocol profiles. SHA-3, SHAKE, and LSH selectors are rejected
rather than assigned a non-PKCS #1 encoding implicitly.

OAEP accepts an optional label, obtains a fresh seed from the operating-system
random source, and enforces the RFC bound `mLen <= k - 2*hLen - 2`. Decryption
requires an exact `k`-byte ciphertext and a destination sized for the maximum
plaintext. The leading byte, label hash, zero padding, and `0x01` delimiter are
checked with one full delimiter scan; ciphertext representatives outside the
RSA range and every OAEP-format mismatch return the same
`LIBERAC_ERROR_AUTHENTICATION_FAILED`. The maximum plaintext output region is
cleared before decoding and remains cleared on failure.

PSS uses `emBits = modBits - 1`, clears and verifies the unused high bits,
requires the `0xbc` trailer, and binds verification to an exact salt length.
`LIBERAC_RSA_PSS_SALT_LENGTH_DIGEST` selects a salt equal to the digest size
without enabling salt auto-detection. Signing accepts a destination capacity
of at least the modulus width, while verification requires an exactly
modulus-width signature; malformed encodings return
`LIBERAC_ERROR_SIGNATURE_INVALID`.

Private RSA operations reuse the modulus-width fixed-schedule Montgomery
exponentiation path. OAEP encryption additionally uses a public-exponent path
whose exponent-controlled schedule is public while base loading, multiplication,
and final reduction avoid branches or indices derived from the randomized
encoded plaintext. These are source-level schedule properties, not universal
physical constant-time claims. Raw RSA still routes public inputs through the
faster variable-time sliding-window path and remains explicitly unsuitable as a
standalone application scheme. Detailed encoding, error, and interoperability
evidence is recorded in `docs/optimization/RSA.md`.

### Short-Weierstrass ECC, ECDH, ECDSA, and X25519

The detailed ECC implementation record already existed in
`docs/optimization/ECC.md`; the summary is included here so the README remains
the central implementation index.

| Area | Reference-shaped baseline | LiberaCrypt implementation | Effect |
| --- | --- | --- | --- |
| Prime-field arithmetic | Affine point formulas and general division expose an inversion at each addition or doubling. | P-256, P-384, and P-521 use at most seventeen little-endian 32-bit limbs in curve-specific Montgomery fields. Production point operations use Jacobian coordinates and perform one final affine inversion. | Removes inversions from the scalar-multiplication loop while avoiding `unsigned __int128`, intrinsics, assembly, VLAs, and native-endian casts. |
| Public scalar multiplication | Bit-at-a-time affine double-and-add branches on public bits and repeatedly inverts. | A four-bit Jacobian window precomputes sixteen public-point multiples, skips public leading-zero windows, and directly indexes the table. | Reduces point-operation and inversion cost for public operations such as ECDSA verification; variable-time behavior is confined to public values. |
| Secret scalar multiplication | A simple double-and-add loop branches on secret bits and may stop at the scalar's significant length. | A fixed-width Montgomery ladder scans exactly the curve scalar bit count. Every bit performs one complete-behaviour Jacobian addition, one doubling, and two masked swaps; ladder state is erased afterward. | Removes secret-bit branches, secret-indexed tables, and secret-dependent loop length at the source level. |
| Exceptional point cases | Generic Jacobian formulas need caller branches for infinity, equal points, and opposite points. | Compute the generic addition and doubling candidates, then mask-select the correct result for exceptional cases. | Gives complete behaviour at the point-operation boundary without scalar-dependent exceptional-case branches. |
| ECDSA order arithmetic and nonces | Reuse field-modulus arithmetic or loop until a valid deterministic nonce appears. | Use a separate Montgomery domain modulo the group order `n`. RFC 6979 generates a fixed batch of sixteen candidates and mask-selects the first valid candidate. | Keeps field and scalar invariants separate and avoids a nonce-validity early exit in the normal signing path. |
| X25519 | Treat the Montgomery curve as another short-Weierstrass parameter choice or rely on target-specific wide arithmetic. | A separate RFC 7748 backend uses sixteen radix-2^16 limbs, portable `uint64_t` products, reduction via `2^256 = 38 mod (2^255 - 19)`, and a 255-bit masked ladder. | Preserves X25519 clamping, little-endian encoding, and ladder semantics without target extensions. |

ECDH private operations use only the secret ladder. Generated P-curve public
keys are uncompressed SEC 1 points; agreement also accepts canonical compressed
points, rejects invalid points and infinity, and returns the fixed-width raw
x-coordinate for a protocol KDF. The library intentionally does not hide a KDF
inside ECDH.

ECDSA signatures use fixed-width raw `r || s`, not ASN.1 DER, and signing does
not force low-`s` normalization. Hash conversion follows the ECDSA
left-truncation rules. Private-key derivation and signing use the secret ladder;
verification uses the public four-bit path. X25519 applies clamping internally,
accepts RFC 7748 non-canonical u-coordinate decoding semantics, and rejects an
all-zero shared result.

The production paths are compared against a test-only textbook affine oracle.
The first validated hosted benchmark was recorded in the superseded
[draft PR #26](https://github.com/samdae5back/LiberaCrypt/pull/26). It used the
exact ECC implementation head later merged through
[PR #27](https://github.com/samdae5back/LiberaCrypt/pull/27) and reported these
ratios relative to that intentionally slow affine baseline:

| Hosted runner | Four-bit public path: P-256 / P-384 / P-521 | Fixed ladder: P-256 / P-384 / P-521 |
| --- | ---: | ---: |
| Linux | 44.8x / 71.3x / 97.0x | 21.9x / 35.5x / 48.0x |
| Windows | 43.9x / 68.8x / 95.8x | 20.3x / 34.8x / 47.6x |

These ratios compare two LiberaCrypt paths at commit
`0369104b452f71e8698988fa2c33b2916de7d89d`; they are not a cross-library
benchmark or a promise for other machines. The fixed ladder is roughly twice as
slow as the public windowed path in those runs because it deliberately performs
a full operation schedule and scans rather than directly indexing its choices.

Focused coverage includes generator and SEC 1 encoding tests, scalar boundaries,
group-order arithmetic, 96 deterministic differential scalars per curve, RFC
6979 ECDSA vectors, 24 bidirectional ECDSA/OpenSSL checks, RFC 7748 X25519
vectors, compressed-key handling, negative cases, Ubuntu/macOS/Windows builds,
and ASan/UBSan. The secret-path description remains a source-level schedule
claim, not a universal physical constant-time guarantee.

### Ed25519

The Ed25519 implementation follows pure-mode RFC 8032 with 32-byte private
seeds, compressed 32-byte public keys, and 64-byte `R || S` signatures. SHA-512
is fixed by the algorithm and is not exposed as a caller-selectable parameter.

Field elements use sixteen little-endian radix-2^16 limbs over
`2^255 - 19`. Products accumulate in portable `uint64_t` storage and fold with
`2^256 = 38 (mod p)`, avoiding `unsigned __int128`, target intrinsics, assembly,
VLAs, host-endian word casts, and signed-shift assumptions. Extended Edwards
coordinates use complete addition formulas, so scalar multiplication needs no
secret-dependent exceptional-case branch or affine inversion inside its loop.

Scalar multiplication uses a four-bit fixed window. Sixteen point multiples
are precomputed, every window performs four doublings and one addition, and a
masked scan selects one of all sixteen entries. The schedule and table access
pattern therefore do not depend on private scalar digits. This is a source-level
fixed-schedule claim, not a universal hardware side-channel guarantee.

Verification rejects non-canonical point encodings, `S >= L`, the identity
public key, and public keys outside the prime-order subgroup before checking the
uncofactored RFC 8032 equation. Detailed representation, validation, and test
evidence is recorded in `docs/optimization/Ed25519.md`.

### Message authentication, key derivation, AEAD, and CTR_DRBG

| Area | Direct or reference-shaped organization | LiberaCrypt implementation | Effect |
| --- | --- | --- | --- |
| HMAC | Duplicate each supported hash inside the MAC layer or materialize whole-message concatenations. | Reuse the runtime incremental hash API for inner and outer hashing. Long-key normalization, pads, hash contexts, inner digest, and full tag are cleared on every exit. | Keeps one validated hash state machine and bounds secret temporary lifetime. |
| CMAC and GMAC | Re-expand an AES key for every authenticated block or maintain an independent GMAC implementation. | AES-CMAC prepares one AES context for the complete MAC. GMAC invokes the AES-GCM authentication path with an empty plaintext. | Reuses block-cipher and AEAD logic instead of duplicating schedules and tag rules. |
| ChaCha20 state setup | Recreate and decode the complete 16-word state for every 64-byte block. | Decode the constants, key, and nonce once per request, retain that base state, and change only the public counter between blocks. The 20 rounds are expressed as fixed `uint32_t` ARX operations. | Removes repeated byte decoding and provides a compiler-friendly scalar path without tables, intrinsics, assembly, or host-endian loads. |
| Poly1305 arithmetic | Translate the RFC pseudocode through a dynamically allocated generic bignum. | Clamp `r` while decoding five 26-bit limbs, accumulate products in `uint64_t`, reduce with fixed carries, and mask-select the final canonical residue. | Avoids allocation, secret-indexed memory, native 128-bit types, and a data-dependent final subtraction; the largest multiplication sum stays below the documented 64-bit bound. |
| ChaCha20-Poly1305 composition | Allocate and concatenate `AAD || pad || ciphertext || pad || lengths` before authenticating. | Feed each component directly into the internal incremental Poly1305 state, derive the one-time key from counter zero, and use counter one for payload. | Keeps temporary storage fixed-size regardless of message length and follows the RFC byte encoding explicitly. |
| Tag verification | Family-specific early-exit byte comparisons. | HMAC, CMAC, GMAC, Poly1305, GCM, CCM, ChaCha20-Poly1305, and authenticated PQC paths share the constant-time byte-equality helper. | Avoids first-difference exits and reduces duplicate security-sensitive comparison code. |
| HKDF and PBKDF2 | Hash-specific KDF copies and unchecked concatenation sizes. | Compose runtime HMAC, encode counters explicitly in big-endian bytes, check `size_t` and standard output bounds, reject unsafe overlap at each component boundary, clear intermediate secrets, and clear partial output after internal failure. | One portable KDF implementation across accepted hashes with explicit failure and memory rules. |
| GCM authentication | A GHASH lookup table indexed by intermediate data. | Multiply in GF(2^128) with a fixed 128-bit serial loop, masks, and no secret-indexed table. GCM verifies the tag before releasing plaintext. | Favors portable cache behaviour and authentication-before-decryption over table-driven throughput. |
| CCM authentication | Release decrypted plaintext before CBC-MAC validation. | Decrypt to the caller buffer, compute and compare the expected CBC-MAC tag, then erase the complete plaintext region on any failure. | Prevents unauthenticated plaintext from remaining available after the API returns an error. |
| CTR_DRBG block-cipher work | Expand the AES or TDEA key for every generated block. | Reuse one expanded block-cipher context across each update, generate, BCC, or derivation-function pass. TDEA's 21-byte effective key is expanded to a parity-bearing 24-byte engine key only at this boundary. | Removes repeated per-block key setup, keeps parity representation outside DRBG state, and preserves SP 800-90A state transitions. |

AES-GCM accepts the standard 96-bit-IV fast path and hashes other non-empty IV
lengths. Its tag and counter length bounds are checked before processing.
AES-CCM enforces nonce lengths from 7 through 13 bytes, even tag lengths from 4
through 16 bytes, and the message bound implied by its encoded `q` value.
Both modes reuse a single AES key schedule for the complete operation and clear
authentication state and keystream blocks before returning.

The ChaCha20 and Poly1305 paths use only fixed-width unsigned arithmetic and
explicit little-endian serialization. For Poly1305, clamped `r` limbs are below
`2^26`; after adding an input limb, each accumulator limb is below `2^27 + 1`.
The five-term products, including the limbs multiplied by five for reduction,
therefore remain below `2^59`, leaving margin in `uint64_t`. Secret base state,
keystream blocks, one-time keys, accumulators, tags, and failed plaintext are
explicitly erased when their lifetime ends. These are source-level fixed-
schedule and memory-access properties, not a universal hardware timing claim.

Validation includes the RFC 8439 ChaCha20 block and multi-block cipher vectors,
the primary Poly1305 vector, Appendix A.3 carry/final-reduction boundary cases,
and the complete ChaCha20-Poly1305 AEAD vector. Unit coverage exercises empty,
partial-block, multi-block, in-place, counter-exhaustion, invalid-size,
overlap, and authentication-failure behavior. During development, 250
randomized Poly1305 cases and 250 randomized ChaCha20-Poly1305 cases were also
checked against `cryptography` 46.0.0 backed by OpenSSL 3.5.3. The focused
tests pass strict C11 conversion/sign/shadow warnings and ASan/UBSan. No
throughput ratio is claimed until a reproducible cross-platform benchmark is
retained in the repository.

CTR_DRBG supports AES-128/192/256 and legacy three-key TDEA with and without
`Block_Cipher_df`, explicit instantiate/reseed/generate state transitions,
algorithm-specific request and reseed limits, optional additional input,
OS-entropy instantiation/reseed helpers, and an explicit context clear
operation. TDEA's 8-byte counter and 29-byte seed share the same bounded
implementation as AES without assuming a 16-byte block. NIST CAVP vectors cover
TDEA DF, no-DF, reseed, internal state, and returned bits; the existing AES KAT
remains unchanged. Development additionally cross-checked randomized TDEA
state transitions against an independent Python/TripleDES reference. No speed
ratio is claimed for the schedule reuse or other table-free choices.

### ML-KEM portable hot paths

The first ML-KEM optimization pass is fully recorded in
`docs/optimization/ML-KEM.md`. Its structural changes precede the separately
measured Barrett/Montgomery selection below.

| Area | Initial path | Current portable path | Deterministic effect |
| --- | --- | --- | --- |
| Polynomial packing | Encode and decode each coefficient one bit at a time while recomputing byte/bit positions. | Use a `uint32_t` little-endian bit reservoir and emit or consume complete bytes as they become available. | Removes the bit-at-a-time inner loop while preserving every FIPS 203 encoded byte. |
| Matrix sampling | Request three SHAKE128 bytes for each pair of 12-bit rejection candidates. | Squeeze one 168-byte SHAKE128 rate block and parse the same consecutive three-byte groups. | Preserves the XOF stream and candidate order while reducing squeeze-helper calls; it does not claim fewer Keccak rounds. |
| K-PKE decryption inner product | Inverse-transform each of the `k` pointwise products, then add in coefficient space. | Add all products in the NTT domain and perform one inverse NTT, using transform linearity. | Removes exactly 1, 2, and 3 inverse NTT calls for ML-KEM-512, -768, and -1024 respectively. |
| NTT helper overhead | Reverse seven-bit indices with division/modulo loops and call a separate two-coefficient multiplication helper for every pair. | Use a fixed unsigned mask/shift reversal and a local `static inline` base-multiplication helper. | Removes repeated small-loop and call overhead without adding lookup tables or extensions. |

All loop choices depend only on public parameters or the standard public matrix
rejection sampler. The packed codec, bit reversal, and inverse-NTT reordering
were checked for equivalence during development, then accepted through all
three ML-KEM KAT suites, unit tests, and the multi-OS CI matrix. No numerical
speedup is assigned to this pass because the repository retains operation-count
evidence rather than a controlled same-host timing comparison.

### ML-KEM modular reduction selection

The portable ML-KEM NTT keeps coefficients canonical in `[0, q)` for
`q = 3329`. The selected implementation uses fixed-width unsigned Barrett
reduction for multiplication and one-step canonical correction for bounded
addition/subtraction. The range and correctness argument is recorded in
`docs/optimization/ML-KEM-Barrett.md`.

Montgomery reduction was also implemented in two forms and validated before the
final selection:

- **Barrett-only**: commit `e931f90debf742df4c3f16b4b7a0c7c955943bd5`.
- **Hybrid Montgomery**: commit `c5e0ff5e6371b4c7a2553d0c3e2c08292b9f8faf`,
  keeping ordinary NTT coefficients while using Montgomery REDC for fixed
  twiddle/scaling products.
- **Full Montgomery domain**: commit
  `ffabc6e708113f7ba486a8a050ed89bcd92aed8b`, keeping internal NTT-domain
  polynomials as `aR mod q`, including pointwise base multiplication.

All three approaches were correctness-tested before comparison; the full
Montgomery experiment passed the complete repository Build + Test suite on
Ubuntu, Windows, and macOS, including the ML-KEM KATs. The performance workflow
then built all three fixed revisions independently on each GitHub Actions runner,
ran them three times in rotated order, and compared the median of the per-run
medians for ML-KEM-512/768/1024 KeyGen, Encaps, and Decaps. The numbers below are
percentage changes relative to Barrett-only; positive would mean faster and
negative means slower.

| Runner | Parameter set | Hybrid KeyGen / Encaps / Decaps | Full Montgomery KeyGen / Encaps / Decaps |
| --- | --- | ---: | ---: |
| Ubuntu | ML-KEM-512 | -1.86% / -1.64% / -2.15% | -4.67% / -3.38% / -3.81% |
| Ubuntu | ML-KEM-768 | -2.11% / -2.10% / -2.23% | -6.47% / -4.63% / -5.05% |
| Ubuntu | ML-KEM-1024 | -1.97% / -1.74% / -2.03% | -7.12% / -5.77% / -6.24% |
| Windows | ML-KEM-512 | -2.52% / -1.87% / -2.42% | -5.87% / -5.74% / -5.61% |
| Windows | ML-KEM-768 | -2.48% / -1.45% / -2.09% | -7.10% / -7.25% / -6.92% |
| Windows | ML-KEM-1024 | -2.58% / -1.74% / -1.66% | -8.17% / -7.29% / -7.28% |
| macOS | ML-KEM-512 | -1.81% / -1.22% / -1.39% | -1.86% / -0.69% / -0.48% |
| macOS | ML-KEM-768 | -1.74% / -1.68% / -2.03% | -2.65% / -1.43% / -2.21% |
| macOS | ML-KEM-1024 | -0.82% / -1.23% / -1.63% | -2.31% / -1.83% / -1.30% |

Across the nine operations on each runner, hybrid Montgomery averaged **1.98%
slower on Ubuntu, 2.09% slower on Windows, and 1.50% slower on macOS** than
Barrett-only. Full Montgomery averaged **5.24% slower on Ubuntu, 6.80% slower on
Windows, and 1.64% slower on macOS**. Across all 27 measurements, hybrid and
full Montgomery were respectively **1.86% and 4.56% slower** than Barrett-only.

For that reason, Montgomery reduction is **not used in the default portable
ML-KEM path**. Full Montgomery additionally requires a stronger representation
invariant and more conversion/domain bookkeeping, so retaining it would increase
implementation and validation complexity while regressing performance on all 27
Barrett comparisons measured here. These are hosted-runner comparative results,
not a claim that Barrett must win on every architecture; a future 32-bit or
unusual target may justify reconsideration only if a same-target benchmark shows
a material advantage.

### Bignum timing and optimization policy

LiberaCrypt intentionally does **not** duplicate every bignum primitive into
`_ct` and `_vartime` variants. The default generic bignum layer is optimized for
normal/public data. A separate fixed-width secret layer is used only where a
value-dependent loop count, branch, table index, normalization step, or operand
length could expose secret information. This keeps the performance path simple
without creating two independent implementations of operations that do not need
separate timing behavior.

The current policy is:

| Operation class | Default/public path | Secret path |
| --- | --- | --- |
| Exponentiation | `crypto_bignum_mod_exp_vartime`: adaptive sliding window, odd-power precomputation, direct table lookup, zero-bit skipping, and trivial-value early exits. | `crypto_bignum_mod_exp_ct` / `crypto_bignum_mod_exp2_ct`: full modulus-width scan, one square and one multiply candidate per bit, mask selection, no secret-indexed lookup. |
| Copy / serialization | Normal `LiberaCBignum` copy and byte serialization retain variable-length behavior for ordinary data. | Secrets are first promoted once to a public fixed storage width. Subsequent fixed-width copies and BE/LE import/export use the `*_secret_fixed_ct` helpers, which traverse the complete caller-selected width and do not use secret `LENGTH` to control the loop. |
| Add/subtract | Generic arithmetic remains variable-time and may normalize or stop according to significant length. | A fixed-width secret subtraction helper is used where required, currently for ElGamal's derived `p-1-x` exponent. More fixed-width add/sub helpers should be added only when a secret call site needs them. |
| Modular multiply / reduction | Generic `crypto_bignum_mod_mul` and `crypto_bignum_mod` remain performance-oriented variable-time operations. | Secret exponentiation keeps residues in a dedicated fixed-width Montgomery layer. Montgomery multiplication, final conditional reduction, and result selection use fixed-count loops/masks rather than routing secret state through the generic division-style reduction path. |
| Compare / normalization | Early exit and significant-length normalization are allowed for public values. | Secret Montgomery results use fixed-count normalization; secret equality/compare helpers should be introduced only for call sites whose result or first-difference position is sensitive. |
| Prime testing/generation | Miller–Rabin and trial division are deliberately variable-time because candidate values and witness decisions are not treated as long-lived secret exponents. | No duplicate constant-time prime-generation stack is maintained. |

The variable-length-to-fixed-width **promotion boundary is not claimed to be
constant-schedule**: it necessarily starts from an ordinary `LiberaCBignum`
whose significant length is already represented in `LENGTH`. RSA `D` and
ElGamal `X` are promoted once during key generation; subsequent persistent-key
copies use the fixed-width CT copy helper. This distinction prevents a helper
from being labelled constant-time while still copying only `LENGTH` limbs.

For secret modular arithmetic, the preferred design is to keep values reduced
inside the fixed-width Montgomery domain rather than create a second general
purpose arbitrary-size division/remainder implementation. A standalone CT
modular inverse, GCD, or arbitrary reduction routine should be added when a
protocol actually needs it; until then, avoiding duplicate complex arithmetic
reduces maintenance and validation risk.

### Other algorithms and shared paths

Not every optimization is a throughput optimization. The following verified
changes target cache behavior, memory traffic, code size, build duplication, or
portable execution; no speedup is claimed where the project does not retain a
reproducible benchmark.

| Area | Reference or previous organization | LiberaCrypt optimization | Primary goal |
| --- | --- | --- | --- |
| AES-128/192/256 | Common compact implementations index an S-box or T-table with secret-derived bytes. | Compute the S-box and inverse S-box algebraically over GF(2^8) with a fixed operation sequence; round keys and temporary state are explicitly cleared. | Cache-timing hardening and secret-data hygiene, with portability favored over table-driven throughput. |
| SHA-2 and LSH streaming | A simple update path copies every block into context storage before compression. | After completing a partial block, pass complete input blocks directly to the compression function and copy only the remainder. | Lower memory traffic for large or block-aligned updates. |
| Generic hash API | Separate one-shot and incremental implementations can duplicate padding and state-transition logic. | Build the one-shot operation on the runtime-selected init/update/finalize/squeeze path; SHAKE retains repeated-squeeze streaming. | One validated state machine and less duplicate code across SHA-1, SHA-2, SHA-3/SHAKE, and LSH. |
| Bignum exponentiation policy | One binary exponentiation helper served both public and secret exponents. | Route public/non-secret values such as Miller–Rabin and RSA `e` through an explicitly variable-time path, and private/random exponents through the separate fixed-schedule path. | Allows aggressive public-data optimization without silently weakening secret-exponent timing behavior. |
| Public bignum exponentiation | Binary square-and-multiply processed one exponent bit at a time and performed one conditional multiply for each set bit. | Use an adaptive sliding window, precompute odd Montgomery powers, index that table directly from the public window value, skip public zero-bit work, and return early for trivial modulus/base/exponent cases. | Reduces Montgomery multiplication count for larger public exponents while confining table lookup and early-exit behavior to non-secret inputs. |
| Bignum squaring | Route `a^2` through generic schoolbook multiplication, computing both `a[i]a[j]` and `a[j]a[i]`. | Use one shared square-specific helper that computes each symmetric cross product once; ElGamal generator selection and Miller–Rabin both use it. | Roughly halves wide cross-product multiplications before modular reduction, while centralizing future square-specific tuning. |
| Bignum Montgomery exponentiation | Allocate and free the `n + 2`-limb Montgomery scratch array for every Montgomery multiplication. | Allocate one scratch array in the per-exponentiation Montgomery context, clear and reuse it for every multiply, then securely clear it when the context is released. | Removes one heap allocation/free pair from every variable-time Montgomery multiplication used by RSA and Miller–Rabin while also reducing residual intermediate data. |
| Secret bignum copy / serialization | Variable-length copies and serialization naturally follow significant length. | Fixed-width secret copy and BE/LE import/export traverse the full caller-selected public width after the secret has crossed the fixed-storage boundary. | Prevents subsequent secret copies/codecs from exposing significant limb/byte length through loop count or memory extent. |
| Secret temporary storage | Secret exponent state used ordinary variable-length bignums and generic temporaries. | Use modulus-width limb buffers for secret Montgomery state, mask-select candidate results, fixed-count output normalization, fixed-width secret subtraction for derived exponents, and explicit zeroization before release. | Reduce secret-dependent control flow, operand-length leakage in secret subtraction, and residual secret intermediates. |
| ML-KEM | Build parameter-specialized copies for ML-KEM-512/768/1024. | Compile the implementation once, select a complete FIPS 203 parameter record at the API boundary, and use maximum-sized portable work arrays. | Lower build/code duplication and one runtime-dispatched implementation; this is not a claimed cryptographic-operation speedup. |
| ML-DSA and SLH-DSA integration | Independently compile all shared support for every parameter set. | Use the pinned mldsa-native multilevel mode so shared code is emitted once, and expose all 12 SLH-DSA parameter objects from one portable backend build. | Reduce duplicated backend code and keep one library artifact for all levels. Native assembly is deliberately disabled in the current ML-DSA adapter for consistent portable builds. |
| HAETAE | The upstream-oriented arithmetic relied in places on signed right shifts, plain-`char` behavior, and implicit fixed-point widths. | Use explicit floor division and unsigned sign extraction, define signed-byte serialization, prove FFT widths, evaluate Q16 intermediates in `int64_t`, and accumulate magnitudes in `uint64_t`. | Defined behavior across compilers and architectures while preserving current and legacy KAT output. |
| AES authentication and PQC validation | AES tags, ML-KEM validation, and PQC adapters carried separate equality loops; ML-KEM and NTRU+ carried separate overlap predicates. | Share one constant-time byte-equality helper and one overflow-aware buffer-overlap helper. | Remove security-sensitive duplicate code and keep validation behavior consistent. |

These notes distinguish security, portability, and code-footprint work from
measured performance work. Algorithm outputs remain validated against the
known-answer and compatibility tests described below.

## Public ABI and Unix exports

`cmake/liberacrypt_exports.txt` is the canonical public-symbol allowlist.
Internal arithmetic, NTT, endian, hash-state, block-cipher, and backend symbols
are hidden. The shared-library build applies the allowlist with the native
platform model:

- Windows: explicit `__declspec(dllexport)` declarations
- ELF systems: a linker version script
- macOS: an exported-symbol list
- Solaris: a legacy-compatible mapfile
- AIX: an `.exp` file passed with `-bE`
- HP-UX: explicit `+e` linker entries

This keeps the exported ABI limited to the documented `LIBERAC_` functions while
allowing static builds to retain normal archive behavior. Restricted AIX exports
require CMake 3.17 or newer because that release added the supported switch for
disabling CMake's automatic all-symbol export list.

## Tests

When `LIBERAC_BUILD_TESTS` is enabled, CMake generates:

- public-header isolation checks
- operation-level unit tests for key generation, encryption/decryption,
  encapsulation/decapsulation, and signing/verification
- AES and Triple-DES known-answer tests, plus round-trip coverage for every
  supported mode and key size; an AES-GCM negative authentication case verifies
  plaintext clearing
- SHA-1, SHA-2, SHA-3, SHAKE, and LSH known-answer tests
- HMAC known-answer tests across every accepted hash, including long keys;
  AES- and Triple-DES-CMAC vectors; GMAC vectors; truncated-tag verification;
  tampering, invalid-selector, length, and buffer checks; the MAC suites were
  also cross-checked with OpenSSL 3.5.5 during development
- RFC 5869 HKDF, RFC 6070 PBKDF2-HMAC-SHA1, RFC 7914
  PBKDF2-HMAC-SHA256, and SHA3-256 runtime-dispatch cases, plus KDF boundary,
  overlap, output-clearing, and invalid-argument tests; the retained vectors and
  SHA3 dispatch case were independently cross-checked through OpenSSL HMAC
- AES and legacy TDEA CTR_DRBG known-answer, derivation-function, no-DF,
  reseed, request/reseed-limit, parity-expansion, and clear-state tests
- operation tests for every supported post-quantum KEM and signature family
- RFC 8032 Ed25519 known-answer tests, strict-encoding negative tests, and
  deterministic sign/verify round trips
- OpenSSL-generated RSAES-OAEP/SHA-256 decryption and
  RSASSA-PSS/SHA-256 verification regressions, randomized OAEP/PSS round trips,
  strict salt/label/length checks, malformed encodings, and output clearing;
  focused CI also generates a fresh OpenSSL key and cross-checks OAEP/PSS in
  both library-to-OpenSSL and OpenSSL-to-library directions
- 100-record KATs for all 9 KEM parameter sets and all 24 current signature
  parameter sets
- verification of 300 context-explicit HAETAE 1.1.2 signatures as a
  compatibility regression alongside the exact HAETAE 1.2.0 KATs

The PQC KAT executables link a test-exclusive static module. Calling its private
KAT initializer routes subsequent PQC randomness through AES-256 CTR-DRBG without
a derivation function, initialized from each vector's 48-byte seed. The normal
shared/static `LiberaCrypt` target has no KAT control API and continues to obtain
PQC randomness from the operating system. Each parameter set is a separate CTest
so the slower SLH-DSA cases can run in parallel.

## Bundled implementation notices

The portable PQC backends are vendored below their algorithm directories so a
checkout is directly buildable. Their original license and notice files are
retained next to the source. See `THIRD_PARTY_NOTICES.md` for provenance,
verified package hashes or pinned revisions, and the applicable upstream terms.

## License

Copyright (C) 2026 Myungjun Kim.

Except for the separately identified third-party components, this project's
original source code is licensed under the GNU Affero General Public License,
version 3 only (`AGPL-3.0-only`). See `LICENSE` for the complete terms.

Vendored third-party sources remain available under their respective upstream
licenses described in `THIRD_PARTY_NOTICES.md`; those notices and license grants
are not replaced by the project's AGPL license.
