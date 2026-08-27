# Crypto

Crypto is a portable C11 cryptography library with one runtime-selected API per
primitive family. Every supported parameter set is compiled into one library;
callers select the algorithm and parameter set with the final `AlgID` argument.

The library is self-contained. Algorithm implementations use ISO C and
project-local headers rather than an external cryptographic library. The random
byte adapter necessarily calls the host operating system entropy interface
(`BCryptGenRandom`, `getrandom`, or `/dev/urandom`).

> Security note: the RSA interface currently exposes the raw textbook
> operation. It is useful for implementation tests, but applications must not
> treat raw RSA as a secure encryption scheme.

## Layout

```text
inc/                              public category API headers only
src/*.c                           public category API entry points
src/AsymmetricCipher/{RSA,ElGamal}
src/BlockCipher/AES
src/DigitalSignature/{ML-DSA,SLH-DSA}
src/HashFunction/{SHA2,SHA3,LSH}
src/KeyEncapsulation/ML-KEM
src/RandomNumberGeneration/{CTR_DRBG,Noise}
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
cmake -S . -B build \
  -DBUILD_SHARED_LIBS=ON \
  -DCRYPTO_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

For a static library, configure with `-DBUILD_SHARED_LIBS=OFF`. To install the
library and its public headers:

```sh
cmake --install build --prefix /your/prefix
```

CMake consumers can discover the installed package and link its imported target:

```cmake
find_package(Crypto CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE Crypto::Crypto)
```

The target exposes the installed `inc` directory, so source files include the
umbrella header as follows:

```c
#include <Crypto.h>
```

## Runtime algorithm dispatch

Public operation names start with `CRYPTO_`. For APIs that accept an algorithm
identifier, `AlgID` is the last argument. The complete identifier set is in
`inc/Def.h` and is available from `Crypto.h`.

AES encryption and decryption use one API pair for all key sizes and modes:

```c
uint8_t ciphertext[32];
uint8_t tag[16];

CryptoError error = CRYPTO_BLOCK_CIPHER_ENCRYPT(
    ciphertext, sizeof(ciphertext),
    tag, sizeof(tag),
    plaintext, sizeof(plaintext),
    key, sizeof(key),
    nonce, sizeof(nonce),
    aad, sizeof(aad),
    ALG_AES_256_GCM);
```

The AES dispatcher supports AES-128, AES-192, and AES-256 with ECB, CBC, CTR,
CCM, and GCM. ECB and CBC inputs must be block-aligned; padding is intentionally
left to the caller. AEAD decryption clears the plaintext output when tag
authentication fails.

All fixed-output hashes and XOFs use the same hash API:

```c
uint8_t digest[CRYPTO_SHA2_256_DIGEST_BYTES];

CryptoError error = CRYPTO_HASH(
    digest, sizeof(digest),
    message, message_length,
    ALG_HASH_SHA2_256);
```

Supported hash identifiers are:

- SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256
- LSH-256-224, LSH-256-256, LSH-512-224, LSH-512-256, LSH-512-384, and
  LSH-512-512
- SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256

For SHAKE, `OUTPUT_LENGTH` selects the requested XOF output length. Fixed-output
hashes require a buffer at least as large as their standard digest.

## Other supported families

- CTR_DRBG with AES-128/192/256, with and without `Block_Cipher_df`
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024
- ML-DSA-44, ML-DSA-65, and ML-DSA-87
- All twelve FIPS 205 SLH-DSA SHA2/SHAKE small/fast parameter sets
- Raw RSA and safe-prime ElGamal
- Unsigned big-number byte load/store and lifecycle operations
- Probable-prime, prime, and safe-prime generation
- Random bytes obtained directly from the operating system entropy source

Key, ciphertext, and signature size-query APIs also take the runtime `AlgID`, so
applications do not need parameter-specific builds or headers.

## Public ABI and Unix exports

`cmake/crypto_exports.txt` is the canonical public-symbol allowlist. Internal
arithmetic, NTT, endian, hash-state, block-cipher, and backend symbols are hidden.
The shared-library build applies the allowlist with the native platform model:

- Windows: explicit `__declspec(dllexport)` declarations
- ELF systems: a linker version script
- macOS: an exported-symbol list
- Solaris: a legacy-compatible mapfile
- AIX: an `.exp` file passed with `-bE`
- HP-UX: explicit `+e` linker entries

This keeps the exported ABI limited to the documented `CRYPTO_` functions while
allowing static builds to retain normal archive behavior.

## Tests

When `CRYPTO_BUILD_TESTS` is enabled, CMake generates:

- public-header isolation checks
- operation-level unit tests for key generation, encryption/decryption,
  encapsulation/decapsulation, and signing/verification
- AES mode known-answer tests for every supported key size
- SHA-2, SHA-3, SHAKE, and LSH known-answer tests
- CTR_DRBG known-answer and derivation-function tests
- ML-KEM and post-quantum signature tests

## Bundled implementation notices

The portable ML-DSA and SLH-DSA backends are vendored below their algorithm
directories so a checkout is directly buildable. Their original license files
are retained next to the source. See `THIRD_PARTY_NOTICES.md` for provenance and
the upstream revisions used.

The top-level project is licensed under the terms in `LICENSE`.
