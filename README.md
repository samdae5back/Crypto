# LiberaCrypt

**Free cryptography, everywhere.**

LiberaCrypt is a free-software C11 cryptography library designed around three
priorities: **simplicity, portability, and environment independence**. The goal
is to make cryptographic primitives easy to build, integrate, and use across a
wide range of systems without tying applications to a particular operating
system, compiler, architecture, or external cryptographic runtime.

The library keeps one runtime-selected API per primitive family. Every supported
parameter set is compiled into one library; callers select the algorithm and
parameter set with the final `LiberaCAlgID` argument. Algorithm implementations
use ISO C and project-local headers rather than an external cryptographic
library. Platform-specific code is kept at narrow system boundaries where it is
actually required, such as entropy acquisition (`BCryptGenRandom`, `getrandom`,
or `/dev/urandom`).

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

> Security note: the RSA interface currently exposes the raw textbook
> operation. It is useful for implementation tests, but applications must not
> treat raw RSA as a secure encryption scheme.

## Layout

```text
inc/                              public category API headers only
src/*.c                           public category API entry points
src/AsymmetricCipher/{RSA,ElGamal}
src/BlockCipher/{AES,TripleDES}
src/DigitalSignature/{AIMer,HAETAE,ML-DSA,SLH-DSA}
src/HashFunction/{SHA1,SHA2,SHA3,LSH}
src/KeyEncapsulation/{ML-KEM,NTRU-Plus,SMAUG-T}
src/RandomNumberGeneration/{CTR_DRBG,KAT,Noise}
src/Util/{Bignum,Bit,Core,Endian,NTT,Prime}
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
single DES.

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

## Other supported families

- CTR_DRBG with AES-128/192/256, with and without `Block_Cipher_df`
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- NTRU+768, NTRU+864, and NTRU+1152
- SMAUG-T-128, SMAUG-T-192, and SMAUG-T-256
- ML-DSA-44, ML-DSA-65, and ML-DSA-87
- AIMer 128/192/256 fast and small parameter sets
- HAETAE-120, HAETAE-180, and HAETAE-260
- All twelve FIPS 205 SLH-DSA SHA2/SHAKE small/fast parameter sets
- Raw RSA and safe-prime ElGamal
- Unsigned big-number byte load/store and lifecycle operations
- Probable-prime, prime, and safe-prime generation
- Random bytes obtained directly from the operating system entropy source

Key, ciphertext, and signature size-query APIs also take the runtime
`LiberaCAlgID`, so applications do not need parameter-specific builds or
headers.

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
  supported mode and key size
- SHA-1, SHA-2, SHA-3, SHAKE, and LSH known-answer tests
- CTR_DRBG known-answer and derivation-function tests
- operation tests for every supported post-quantum KEM and signature family
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
