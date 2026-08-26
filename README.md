# Crypto

A portable C11 cryptography library that collects the algorithms and reusable primitives in this repository behind one CMake target and one public include directory.

> **Status:** educational/reference implementation. In particular, `ALG_RSA_RAW` is textbook/raw RSA without OAEP/PSS padding and must not be used directly as a production encryption/signature scheme.

## Layout

```text
.
├── CMakeLists.txt
├── LICENSE
├── include/                 # public API only
│   ├── CRYPTO.h
│   ├── ALGID.h
│   ├── ERROR.h
│   ├── BIGNUM.h
│   ├── PRIME.h
│   ├── RSA.h
│   ├── ELGAMAL.h
│   ├── SHA3.h
│   ├── HASH.h
│   ├── RANDOM.h
│   ├── ENDIAN.h
│   ├── NTT.h
│   └── ML_KEM.h
├── src/
│   ├── BIGNUM/
│   ├── CORE/
│   ├── ELGAMAL/
│   ├── ENDIAN/
│   ├── HASH/
│   ├── INTERNAL/
│   ├── ML_KEM/
│   ├── NTT/
│   ├── PRIME/
│   ├── RANDOM/
│   ├── RSA/
│   └── SHA3/
└── tests/
```

All implementation/internal headers live below `src/`. Public consumers should include headers only from `include/`, usually just:

```c
#include <CRYPTO.h>
```

## Build

```sh
cmake -S . -B build -DBUILD_SHARED_LIBS=ON -DCRYPTO_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

The unified target is `Crypto` (`Crypto::Crypto` inside the build) and the installed library output name is `crypto`.

To build a static library:

```sh
cmake -S . -B build-static -DBUILD_SHARED_LIBS=OFF
cmake --build build-static
```

On Windows the shared library links `bcrypt` for `BCryptGenRandom`. Linux uses `getrandom()` with `/dev/urandom` fallback. macOS and other current POSIX builds use `/dev/urandom` for random bytes. Explicit symbol-export policy for additional Unix targets is intentionally left for later.

## Algorithm identifiers

`AlgID` is an `int`-backed public type. Public algorithm-selection APIs reject unknown identifiers with `CRYPTO_ERROR_INVALID_ALG_ID`.

| Identifier | Value | Algorithm |
|---|---:|---|
| `ALG_HASH_SHA3_256` | `0x0101` | SHA3-256 |
| `ALG_HASH_SHA3_512` | `0x0102` | SHA3-512 |
| `ALG_HASH_SHAKE128` | `0x0111` | SHAKE128 |
| `ALG_HASH_SHAKE256` | `0x0112` | SHAKE256 |
| `ALG_ML_KEM_512` | `0x1001` | ML-KEM-512 |
| `ALG_ML_KEM_768` | `0x1002` | ML-KEM-768 |
| `ALG_ML_KEM_1024` | `0x1003` | ML-KEM-1024 |
| `ALG_RSA_RAW` | `0x2001` | raw RSA |
| `ALG_ELGAMAL_SAFE_PRIME` | `0x3001` | safe-prime ElGamal |
| `ALG_NTT_GENERIC` | `0x4001` | generic radix-2 cyclic NTT |

`ALGID_NAME()` returns a printable name for an identifier.

## ML-KEM dynamic dispatch

The same public API selects the ML-KEM parameter set using `AlgID`:

```c
AlgID alg = ALG_ML_KEM_768;
size_t pk_len = ML_KEM_PUBLIC_KEY_SIZE(alg);
size_t sk_len = ML_KEM_PRIVATE_KEY_SIZE(alg);
size_t ct_len = ML_KEM_CIPHERTEXT_SIZE(alg);

uint8_t *pk = malloc(pk_len);
uint8_t *sk = malloc(sk_len);
uint8_t *ct = malloc(ct_len);
uint8_t ss1[ML_KEM_SHARED_SECRET_BYTES];
uint8_t ss2[ML_KEM_SHARED_SECRET_BYTES];

CryptoError err = ML_KEM_KEYGEN(alg, pk, pk_len, sk, sk_len);
if (err == CRYPTO_SUCCESS)
    err = ML_KEM_ENCAPS(alg, pk, pk_len, ss1, ct, ct_len);
if (err == CRYPTO_SUCCESS)
    err = ML_KEM_DECAPS(alg, sk, sk_len, ct, ct_len, ss2);
```

The three ML-KEM variants are built from the same implementation sources with separate parameter definitions and private symbol namespaces, then selected by the public dispatch layer.

## Hash dispatch

```c
uint8_t digest[32];
CryptoError err = HASH(
    ALG_HASH_SHA3_256,
    (const uint8_t *)"abc", 3,
    digest, sizeof(digest));
```

For SHA3-256/512, `HASH_OUTPUT_SIZE()` returns 32/64. SHAKE is an XOF, so `HASH_OUTPUT_SIZE()` returns zero and the caller selects `OUTPUT_LENGTH`.

The lower-level `SHA3_256`, `SHA3_512`, `SHAKE128`, `SHAKE256` and incremental SHAKE context APIs are also public.

## Big numbers and primes

`BIGNUM` stores unsigned integers as dynamically allocated 32-bit limbs and is not limited by native integer width.

Byte conversion is explicit about byte order:

```c
BIGNUM n;
BIGNUM_INIT(&n);
BIGNUM_FROM_BYTES_BE(&n, input, input_len);
BIGNUM_TO_BYTES_BE(&n, output, output_len);
BIGNUM_FREE(&n);
```

The common prime module provides OS-CSPRNG-backed Miller-Rabin prime generation:

- `PRIME_IS_PROBABLE`
- `PRIME_GENERATE`
- `PRIME_GENERATE_SAFE`

RSA and ElGamal use this common prime/BigNum layer rather than native `int` arithmetic or `rand()`.

## RSA

RSA keys contain `BIGNUM` members and support large modulus sizes such as 2048 bits:

```c
RSA_PUBLIC_KEY pub;
RSA_PRIVATE_KEY priv;
RSA_PUBLIC_KEY_INIT(&pub);
RSA_PRIVATE_KEY_INIT(&priv);

CryptoError err = RSA_KEYGEN(ALG_RSA_RAW, &pub, &priv, 2048, 32);

RSA_PUBLIC_KEY_FREE(&pub);
RSA_PRIVATE_KEY_FREE(&priv);
```

`RSA_ENCRYPT` and `RSA_DECRYPT` operate on `BIGNUM` values and reject messages outside the modulus range.

## Portable integer/length types

Public lengths and buffer sizes use `size_t`. Integer values use fixed-width types (`uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`) where practical.

`include/TYPES.h` and `src/INTERNAL/crypto_types.h` prefer `<stddef.h>`/`<stdint.h>`. A fallback typedef path is provided for legacy MSVC versions that did not ship `<stdint.h>`, and the internal shim checks fixed-width type sizes at compile time.

## Error handling

Public fallible APIs use `CryptoError` from `ERROR.h` where appropriate. Errors are separated by cause, including:

- `CRYPTO_ERROR_INVALID_ARGUMENT`
- `CRYPTO_ERROR_INVALID_ALG_ID`
- `CRYPTO_ERROR_UNSUPPORTED_ALGORITHM`
- `CRYPTO_ERROR_BUFFER_TOO_SMALL`
- `CRYPTO_ERROR_ALLOCATION_FAILED`
- `CRYPTO_ERROR_RANDOM_FAILED`
- `CRYPTO_ERROR_INVALID_KEY`
- `CRYPTO_ERROR_MESSAGE_TOO_LARGE`
- `CRYPTO_ERROR_PRIME_GENERATION_FAILED`
- `CRYPTO_ERROR_ARITHMETIC`
- `CRYPTO_ERROR_INTERNAL`

Use `CRYPTO_ERROR_STRING()` for a human-readable description.

## Symbol visibility

Only public declarations marked `CRYPTO_API` are intended to be exported by shared builds.

- Windows: `__declspec(dllexport)` / `__declspec(dllimport)`
- Linux: default visibility on `CRYPTO_API`, hidden visibility for other symbols
- macOS: default visibility on `CRYPTO_API`, hidden visibility for other symbols
- Other Unix platforms: explicit export policy intentionally deferred

## License

MIT License. See [LICENSE](LICENSE).
