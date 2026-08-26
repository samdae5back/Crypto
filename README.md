# Crypto

A portable C11 cryptography library that collects the algorithms and reusable primitives in this repository behind one CMake target and one public include directory.

> **Status:** educational/reference implementation. In particular, `ALG_RSA_RAW` is textbook/raw RSA without OAEP/PSS padding and must not be used directly as a production encryption/signature scheme. The portable AES implementation is source-level cache-timing hardened by avoiding secret-indexed S-box/T-table lookups, but this is not a proof of resistance to every compiler, microarchitectural, speculative-execution, power/EM, or fault side channel. Platform hardware AES is preferable for high-assurance production use where available.

## Layout

```text
.
????? CMakeLists.txt
????? LICENSE
????? THIRD_PARTY_NOTICES.md
????? include/                 # public API only
??  ????? CRYPTO.h
??  ????? ALGID.h
??  ????? ERROR.h
??  ????? AES.h
??  ????? CTR_DRBG.h
??  ????? BIGNUM.h
??  ????? PRIME.h
??  ????? RSA.h
??  ????? ELGAMAL.h
??  ????? SHA3.h
??  ????? HASH.h
??  ????? RANDOM.h
??  ????? ENDIAN.h
??  ????? NTT.h
??  ????? ML_KEM.h
??  ????? ML_DSA.h
??  ????? SLH_DSA.h
????? src/
??  ????? AES/
??  ????? BIGNUM/
??  ????? CORE/
??  ????? DRBG/
??  ????? ELGAMAL/
??  ????? ENDIAN/
??  ????? CRYPTO_HASH/
??  ????? INTERNAL/
??  ????? ML_KEM/
??  ????? ML_DSA/
??  ????? NTT/
??  ????? PRIME/
??  ????? RANDOM/
??  ????? RSA/
??  ????? SHA3/
??  ????? SLH_DSA/
????? third_party/
??  ????? mldsa-native/        # pinned FIPS 204 backend
??  ????? slhdsa-c/            # pinned FIPS 205 backend
????? tests/
```

All implementation/internal headers live below `src/`. Public consumers should include headers only from `include/`, usually just:

```c
#include <CRYPTO.h>
```

## Build

The FIPS 204/205 signature backends are pinned Git submodules, so initialize them before configuring a fresh checkout:

```sh
git submodule update --init --recursive
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
| `ALG_HASH_SHAKE128` | `0x0111` | CRYPTO_SHAKE128 |
| `ALG_HASH_SHAKE256` | `0x0112` | CRYPTO_SHAKE256 |
| `ALG_ML_KEM_512` | `0x1001` | ML-KEM-512 |
| `ALG_ML_KEM_768` | `0x1002` | ML-KEM-768 |
| `ALG_ML_KEM_1024` | `0x1003` | ML-KEM-1024 |
| `ALG_RSA_RAW` | `0x2001` | raw RSA |
| `ALG_ELGAMAL_SAFE_PRIME` | `0x3001` | safe-prime ElGamal |
| `ALG_NTT_GENERIC` | `0x4001` | generic radix-2 cyclic NTT |
| `ALG_AES_128` | `0x5001` | AES-128 |
| `ALG_AES_192` | `0x5002` | AES-192 |
| `ALG_AES_256` | `0x5003` | AES-256 |
| `ALG_CTR_DRBG_AES_128_DF` | `0x6001` | CTR_DRBG AES-128 with Block_Cipher_df |
| `ALG_CTR_DRBG_AES_192_DF` | `0x6002` | CTR_DRBG AES-192 with Block_Cipher_df |
| `ALG_CTR_DRBG_AES_256_DF` | `0x6003` | CTR_DRBG AES-256 with Block_Cipher_df |
| `ALG_CTR_DRBG_AES_128_NO_DF` | `0x6011` | CTR_DRBG AES-128 without DF |
| `ALG_CTR_DRBG_AES_192_NO_DF` | `0x6012` | CTR_DRBG AES-192 without DF |
| `ALG_CTR_DRBG_AES_256_NO_DF` | `0x6013` | CTR_DRBG AES-256 without DF |
| `ALG_ML_DSA_44` | `0x7001` | ML-DSA-44 |
| `ALG_ML_DSA_65` | `0x7002` | ML-DSA-65 |
| `ALG_ML_DSA_87` | `0x7003` | ML-DSA-87 |
| `ALG_SLH_DSA_SHA2_128S` | `0x8001` | SLH-DSA-SHA2-128s |
| `ALG_SLH_DSA_SHA2_128F` | `0x8002` | SLH-DSA-SHA2-128f |
| `ALG_SLH_DSA_SHA2_192S` | `0x8003` | SLH-DSA-SHA2-192s |
| `ALG_SLH_DSA_SHA2_192F` | `0x8004` | SLH-DSA-SHA2-192f |
| `ALG_SLH_DSA_SHA2_256S` | `0x8005` | SLH-DSA-SHA2-256s |
| `ALG_SLH_DSA_SHA2_256F` | `0x8006` | SLH-DSA-SHA2-256f |
| `ALG_SLH_DSA_SHAKE_128S` | `0x8011` | SLH-DSA-SHAKE-128s |
| `ALG_SLH_DSA_SHAKE_128F` | `0x8012` | SLH-DSA-SHAKE-128f |
| `ALG_SLH_DSA_SHAKE_192S` | `0x8013` | SLH-DSA-SHAKE-192s |
| `ALG_SLH_DSA_SHAKE_192F` | `0x8014` | SLH-DSA-SHAKE-192f |
| `ALG_SLH_DSA_SHAKE_256S` | `0x8015` | SLH-DSA-SHAKE-256s |
| `ALG_SLH_DSA_SHAKE_256F` | `0x8016` | SLH-DSA-SHAKE-256f |

`CRYPTO_ALGID_NAME()` returns a printable name for an identifier.

## AES

AES supports 128-, 192-, and 256-bit keys through the same `AlgID`-selected API. `CRYPTO_AES_KEY_SIZE()` returns the required key size for a selected AES identifier.

Low-level context/block API:

```c
AES_CONTEXT ctx;
uint8_t out[AES_BLOCK_SIZE];

CryptoError err = CRYPTO_AES_CONTEXT_INIT(&ctx, ALG_AES_256, key, key_len);
if (err == CRYPTO_SUCCESS)
    err = CRYPTO_AES_ENCRYPT_BLOCK(&ctx, plaintext_block, out);
CRYPTO_AES_CONTEXT_CLEAR(&ctx);
```

The portable AES core deliberately does not contain byte-indexed S-box or T-tables. The S-box and inverse S-box are computed algebraically in `GF(2^8)` using a fixed operation pattern, and finite-field multiplication performs a fixed eight iterations with masking instead of secret-dependent branches. This removes the classic cache-line leakage caused by `SBOX[secret_byte]`-style accesses.

This is **cache-timing hardening**, not a claim that the implementation is universally constant-time under every compiler/CPU or resistant to all side channels. It does not by itself address power analysis, EM leakage, transient/speculative-execution effects, fault attacks, or every possible optimizer transformation. AES-NI or ARM Cryptography Extensions are preferable when a trusted platform implementation is available.

One-shot confidentiality-only modes are also provided:

- `CRYPTO_AES_ECB_ENCRYPT` / `CRYPTO_AES_ECB_DECRYPT`
- `CRYPTO_AES_CBC_ENCRYPT` / `CRYPTO_AES_CBC_DECRYPT`
- `CRYPTO_AES_CTR_CRYPT`

ECB and CBC require `INPUT_LENGTH` to be a multiple of 16 bytes and **do not add or remove padding**. CTR accepts arbitrary lengths and uses a 128-bit big-endian counter increment. CBC and CTR require the caller to provide the IV/initial counter.

For authenticated encryption, use the AEAD APIs:

- `CRYPTO_AES_GCM_ENCRYPT` / `CRYPTO_AES_GCM_DECRYPT`
- `CRYPTO_AES_CCM_ENCRYPT` / `CRYPTO_AES_CCM_DECRYPT`

GCM accepts an explicit IV and AAD. A 12-byte IV is the recommended/common fast path. CCM accepts nonce lengths from 7 through 13 bytes and even tag lengths from 4 through 16 bytes. Both APIs return ciphertext and authentication tag separately. Decryption returns `CRYPTO_ERROR_AUTHENTICATION_FAILED` if the tag does not verify and clears the caller's plaintext output range on failure.

```c
uint8_t ciphertext[plaintext_len];
uint8_t tag[16];

CryptoError err = CRYPTO_AES_GCM_ENCRYPT(
    ALG_AES_256,
    key, 32,
    nonce, nonce_len,
    aad, aad_len,
    plaintext, plaintext_len,
    ciphertext, sizeof(ciphertext),
    tag, sizeof(tag));
```

GCM authentication uses bit-serial GHASH without secret-indexed GHASH lookup tables. Authentication tags are compared over the complete requested tag length rather than exiting on the first mismatching byte.

ECB should generally be avoided. CBC/CTR provide confidentiality only and need a separate authentication construction if integrity/authenticity is required; GCM or CCM is preferable when an AEAD construction fits the protocol.

The test suite includes AES-128/192/256 FIPS-197 known-answer vectors, SP 800-38A CBC/CTR vectors, a GCM known-answer vector, RFC 3610 CCM Packet Vector #1, and negative tag-verification tests.

## CTR_DRBG

`CTR_DRBG` follows the CTR_DRBG construction from NIST SP 800-90A Rev. 1 and supports AES-128, AES-192, and AES-256. Both derivation-function and no-derivation-function variants have separate `AlgID` values.

Public operations:

- `CRYPTO_CTR_DRBG_INSTANTIATE`
- `CRYPTO_CTR_DRBG_INSTANTIATE_OS`
- `CRYPTO_CTR_DRBG_RESEED`
- `CRYPTO_CTR_DRBG_RESEED_OS`
- `CRYPTO_CTR_DRBG_GENERATE`
- `CRYPTO_CTR_DRBG_CLEAR`
- `CRYPTO_CTR_DRBG_SEED_SIZE`

Example using the OS entropy source and AES-256 with `Block_Cipher_df`:

```c
CTR_DRBG_CONTEXT drbg;
uint8_t random_bytes[64];

CryptoError err = CRYPTO_CTR_DRBG_INSTANTIATE_OS(
    &drbg,
    ALG_CTR_DRBG_AES_256_DF,
    (const uint8_t *)"application-v1", 14);

if (err == CRYPTO_SUCCESS) {
    err = CRYPTO_CTR_DRBG_GENERATE(
        &drbg,
        random_bytes, sizeof(random_bytes),
        NULL, 0,
        0);
}

CRYPTO_CTR_DRBG_CLEAR(&drbg);
```

For `*_DF`, entropy, nonce, personalization, reseed material, and additional input are conditioned with `Block_Cipher_df` as required by the construction. The direct instantiate API requires at least the selected AES security strength of entropy and sufficient combined entropy+nonce input; `CRYPTO_CTR_DRBG_INSTANTIATE_OS` obtains appropriate entropy/nonce bytes through `CRYPTO_RANDOM_BYTES`.

For `*_NO_DF`, instantiation requires a full-entropy input exactly equal to `seedlen = keylen + 128 bits`; no nonce is used. Personalization and additional input are zero-padded/XORed to `seedlen` and therefore may not exceed `seedlen`.

`CRYPTO_CTR_DRBG_GENERATE` limits one request to 65,536 bytes. The reseed interval is `2^48` requests; once exceeded, generation returns `CRYPTO_ERROR_RESEED_REQUIRED`. Setting the prediction-resistance argument requests a fresh OS-backed reseed before generation.

The DRBG counter state `V` is incremented with a fixed 16-byte loop rather than a carry-dependent early exit. The tests include a NIST CAVP AES-256 no-DF known-answer vector that checks instantiate state, generated bytes, final `Key`, final `V`, and the reseed counter, plus deterministic DF-path checks for AES-128/192/256.

## Explicit zeroization

Sensitive temporary storage is cleared through the internal helper `crypto_zeroize()` in `src/INTERNAL/secure_zero.c`. It performs writes through a `volatile uint8_t *` so the explicit clearing operation is not represented as an ordinary dead `memset` that an optimizer may simply discard.

The AES, GCM/CCM, CTR_DRBG, and post-quantum signature wrappers explicitly clear sensitive temporary material before returning or releasing storage, including:

- AES expanded round-key contexts and key-schedule temporary words
- AES encryption/decryption states, CBC chaining blocks, CTR keystream/counters
- GCM hash subkeys, `J0`, full authentication tags, GHASH temporaries and CTR state
- CCM CBC-MAC state, counter blocks, keystream and expected tags
- CTR_DRBG seed material, `Block_Cipher_df`/BCC intermediates, temporary AES contexts and generated blocks
- DRBG OS entropy/nonce buffers after instantiate or reseed
- ML-DSA key-generation seeds, signing randomness, and domain-separation temporary buffers
- SLH-DSA key-generation seed material and per-signature additional randomness
- the complete DRBG context when `CRYPTO_CTR_DRBG_CLEAR()` is called

Authentication-failure paths in GCM/CCM continue to clear the caller-visible plaintext output range.

## ML-KEM dynamic dispatch

The same public API selects the ML-KEM parameter set using `AlgID`:

```c
AlgID alg = ALG_ML_KEM_768;
size_t pk_len = CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(alg);
size_t sk_len = CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(alg);
size_t ct_len = CRYPTO_ML_KEM_CIPHERTEXT_SIZE(alg);

uint8_t *pk = malloc(pk_len);
uint8_t *sk = malloc(sk_len);
uint8_t *ct = malloc(ct_len);
uint8_t ss1[ML_KEM_SHARED_SECRET_BYTES];
uint8_t ss2[ML_KEM_SHARED_SECRET_BYTES];

CryptoError err = CRYPTO_ML_KEM_KEYGEN(alg, pk, pk_len, sk, sk_len);
if (err == CRYPTO_SUCCESS)
    err = CRYPTO_ML_KEM_ENCAPS(alg, pk, pk_len, ss1, ct, ct_len);
if (err == CRYPTO_SUCCESS)
    err = CRYPTO_ML_KEM_DECAPS(alg, sk, sk_len, ct, ct_len, ss2);
```

The three ML-KEM variants are built from the same implementation sources with separate parameter definitions and private symbol namespaces, then selected by the public dispatch layer.

## ML-DSA dynamic dispatch

ML-DSA follows FIPS 204 and exposes ML-DSA-44, ML-DSA-65, and ML-DSA-87 through one `AlgID`-selected API. Buffer sizes are queried before allocation with:

- `CRYPTO_ML_DSA_PUBLIC_KEY_SIZE`
- `CRYPTO_ML_DSA_PRIVATE_KEY_SIZE`
- `CRYPTO_ML_DSA_SIGNATURE_SIZE`

The three parameter sets use the following serialized sizes:

| Parameter set | Public key | Private key | Signature |
|---|---:|---:|---:|
| ML-DSA-44 | 1312 | 2560 | 2420 |
| ML-DSA-65 | 1952 | 4032 | 3309 |
| ML-DSA-87 | 2592 | 4896 | 4627 |

Example:

```c
AlgID alg = ALG_ML_DSA_65;
size_t pk_len = CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(alg);
size_t sk_len = CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(alg);
size_t sig_len = CRYPTO_ML_DSA_SIGNATURE_SIZE(alg);

uint8_t *pk = malloc(pk_len);
uint8_t *sk = malloc(sk_len);
uint8_t *sig = malloc(sig_len);

CryptoError err = CRYPTO_ML_DSA_KEYGEN(alg, pk, pk_len, sk, sk_len);
if (err == CRYPTO_SUCCESS)
    err = CRYPTO_ML_DSA_SIGN(alg, sk, sk_len, message, message_len,
                      context, context_len, sig, sig_len);
if (err == CRYPTO_SUCCESS)
    err = CRYPTO_ML_DSA_VERIFY(alg, pk, pk_len, message, message_len,
                        context, context_len, sig, sig_len);
```

The FIPS 204 context string may be empty and is limited to 255 bytes. Key generation and randomized signing obtain randomness through the library's `CRYPTO_RANDOM_BYTES` OS-CSPRNG abstraction. Verification failures return `CRYPTO_ERROR_SIGNATURE_INVALID`.

The backend is the pinned `mldsa-native` implementation documented in `THIRD_PARTY_NOTICES.md`. A local multi-level adapter builds the same portable source for all three parameter sets with private namespaced symbols, while the public wrapper performs `AlgID` dispatch.

## SLH-DSA dynamic dispatch

SLH-DSA follows FIPS 205. All twelve approved parameter sets are available dynamically:

- SHA2-128s / SHA2-128f
- SHA2-192s / SHA2-192f
- SHA2-256s / SHA2-256f
- SHAKE-128s / SHAKE-128f
- SHAKE-192s / SHAKE-192f
- SHAKE-256s / SHAKE-256f

Use `CRYPTO_SLH_DSA_PUBLIC_KEY_SIZE`, `CRYPTO_SLH_DSA_PRIVATE_KEY_SIZE`, and `CRYPTO_SLH_DSA_SIGNATURE_SIZE` to size buffers for the chosen `AlgID`, then call `CRYPTO_SLH_DSA_KEYGEN`, `CRYPTO_SLH_DSA_SIGN`, and `CRYPTO_SLH_DSA_VERIFY`.

| Strength/variant | Public key | Private key | Signature |
|---|---:|---:|---:|
| 128s | 32 | 64 | 7856 |
| 128f | 32 | 64 | 17088 |
| 192s | 48 | 96 | 16224 |
| 192f | 48 | 96 | 35664 |
| 256s | 64 | 128 | 29792 |
| 256f | 64 | 128 | 49856 |

SHA2 and SHAKE variants at the same strength/speed setting have the same serialized sizes. The FIPS 205 context string is limited to 255 bytes. Key-generation seeds and per-signature additional randomness are drawn through `CRYPTO_RANDOM_BYTES`; invalid signatures return `CRYPTO_ERROR_SIGNATURE_INVALID`.

The backend is the pinned portable `slhdsa-c` implementation. The test suite performs keygen/sign/verify plus tampered-signature rejection for every one of the 12 `AlgID` values.

## Hash dispatch

```c
uint8_t digest[32];
CryptoError err = CRYPTO_HASH(
    ALG_HASH_SHA3_256,
    (const uint8_t *)"abc", 3,
    digest, sizeof(digest));
```

For SHA3-256/512, `CRYPTO_HASH_OUTPUT_SIZE()` returns 32/64. SHAKE is an XOF, so `CRYPTO_HASH_OUTPUT_SIZE()` returns zero and the caller selects `OUTPUT_LENGTH`.

The lower-level `CRYPTO_SHA3_256`, `CRYPTO_SHA3_512`, `CRYPTO_SHAKE128`, `CRYPTO_SHAKE256` and incremental SHAKE context APIs are also public.

## Big numbers and primes

`BIGNUM` stores unsigned integers as dynamically allocated 32-bit limbs and is not limited by native integer width.

Byte conversion is explicit about byte order:

```c
BIGNUM n;
CRYPTO_BIGNUM_INIT(&n);
CRYPTO_BIGNUM_FROM_BYTES_BE(&n, input, input_len);
CRYPTO_BIGNUM_TO_BYTES_BE(&n, output, output_len);
CRYPTO_BIGNUM_FREE(&n);
```

The common prime module provides OS-CSPRNG-backed Miller-Rabin prime generation:

- `CRYPTO_PRIME_IS_PROBABLE`
- `CRYPTO_PRIME_GENERATE`
- `CRYPTO_PRIME_GENERATE_SAFE`

RSA and ElGamal use this common prime/BigNum layer rather than native `int` arithmetic or `rand()`.

## RSA

RSA keys contain `BIGNUM` members and support large modulus sizes such as 2048 bits:

```c
RSA_PUBLIC_KEY pub;
RSA_PRIVATE_KEY priv;
CRYPTO_RSA_PUBLIC_KEY_INIT(&pub);
CRYPTO_RSA_PRIVATE_KEY_INIT(&priv);

CryptoError err = CRYPTO_RSA_KEYGEN(ALG_RSA_RAW, &pub, &priv, 2048, 32);

CRYPTO_RSA_PUBLIC_KEY_FREE(&pub);
CRYPTO_RSA_PRIVATE_KEY_FREE(&priv);
```

`CRYPTO_RSA_ENCRYPT` and `CRYPTO_RSA_DECRYPT` operate on `BIGNUM` values and reject messages outside the modulus range.

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
- `CRYPTO_ERROR_AUTHENTICATION_FAILED`
- `CRYPTO_ERROR_RESEED_REQUIRED`
- `CRYPTO_ERROR_SIGNATURE_INVALID`

Use `CRYPTO_ERROR_STRING()` for a human-readable description.

## Symbol visibility

Only public declarations marked `CRYPTO_API` are intended to be exported by shared builds.

- Windows: `__declspec(dllexport)` / `__declspec(dllimport)`
- Linux: default visibility on `CRYPTO_API`, hidden visibility for other symbols
- macOS: default visibility on `CRYPTO_API`, hidden visibility for other symbols
- Other Unix platforms: explicit export policy intentionally deferred

## Third-party implementations

The FIPS 204/205 signature implementations are pinned as submodules rather than fetched dynamically at build time. Their exact commits and upstream license choices are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Both selected upstream projects permit MIT licensing; their original notices remain in the submodules.

## License

MIT License. See [LICENSE](LICENSE).
