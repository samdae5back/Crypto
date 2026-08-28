/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file Def.h
 * @brief Common public types, status codes, algorithm identifiers, and ABI
 *        decoration used by the LiberaCrypt library.
 *
 * Algorithm identifiers are stable runtime selectors.  Pass only an identifier
 * from the family accepted by a particular operation; for example,
 * LIBERAC_HASH() accepts the @c LIBERAC_ALG_HASH_* identifiers, while the
 * block-cipher operations accept the @c LIBERAC_ALG_AES_* and
 * @c LIBERAC_ALG_TDES_* identifiers.
 *
 * @defgroup crypto_core Core API definitions
 * @brief Types and constants shared by every public API family.
 * @{
 */
#ifndef LIBERAC_DEF_H
#define LIBERAC_DEF_H

/* Public types use only ISO C headers. */
#include <stddef.h>
#include <stdint.h>

/** @cond LIBERAC_ABI_SUPPORT */
#if defined(__cplusplus)
#define LIBERAC_BEGIN_DECLS extern "C" {
#define LIBERAC_END_DECLS }
#else
#define LIBERAC_BEGIN_DECLS
#define LIBERAC_END_DECLS
#endif

#if defined(_WIN32)
#if defined(LIBERAC_SHARED)
#if defined(LIBERAC_BUILDING_LIBRARY)
#define LIBERAC_API __declspec(dllexport)
#else
#define LIBERAC_API __declspec(dllimport)
#endif
#else
#define LIBERAC_API
#endif
#elif defined(__sun) && (defined(__SUNPRO_C) || defined(__SUNPRO_CC))
#if defined(LIBERAC_BUILDING_LIBRARY)
#define LIBERAC_API __global
#else
#define LIBERAC_API
#endif
#elif defined(__GNUC__) || defined(__clang__)
#if defined(LIBERAC_SHARED)
#define LIBERAC_API __attribute__((visibility("default")))
#else
#define LIBERAC_API
#endif
#else
/* AIX XL and HP aCC exports are restricted by generated linker export files. */
#define LIBERAC_API
#endif
/** @endcond */

/**
 * @brief Runtime algorithm selector.
 *
 * Values are defined by the @c ALG_* constants below.  An identifier belongs
 * to exactly one operation family and must be supplied as the final argument
 * of APIs that perform runtime dispatch.
 */
typedef int32_t LiberaCAlgID;

/**
 * @brief Status value returned by fallible LiberaCrypt library operations.
 *
 * @c LIBERAC_SUCCESS denotes success.  Every other defined value is negative
 * and describes the reason the operation could not be completed.
 */
typedef int32_t LiberaCError;

/**
 * @name Algorithm identifiers
 * @brief Runtime selectors for the algorithms and parameter sets implemented
 *        by the library.
 *
 * The numeric values are part of the public ABI.  Applications should use the
 * symbolic constants rather than depending on their encoded values.
 * @{
 */
enum {
    /** No algorithm selected; rejected by all cryptographic operations. */
    LIBERAC_ALG_NONE = 0,

    /** SHA-1 fixed-output hash (legacy compatibility only). */
    LIBERAC_ALG_HASH_SHA1 = 0x0001,

    /** SHA3-224 fixed-output hash. */
    LIBERAC_ALG_HASH_SHA3_224 = 0x0100,
    /** SHA3-256 fixed-output hash. */
    LIBERAC_ALG_HASH_SHA3_256 = 0x0101,
    /** SHA3-512 fixed-output hash. */
    LIBERAC_ALG_HASH_SHA3_512 = 0x0102,
    /** SHA3-384 fixed-output hash. */
    LIBERAC_ALG_HASH_SHA3_384 = 0x0103,
    /** SHAKE128 extensible-output function. */
    LIBERAC_ALG_HASH_SHAKE128 = 0x0111,
    /** SHAKE256 extensible-output function. */
    LIBERAC_ALG_HASH_SHAKE256 = 0x0112,

    /** SHA-224 fixed-output hash. */
    LIBERAC_ALG_HASH_SHA2_224 = 0x0201,
    /** SHA-256 fixed-output hash. */
    LIBERAC_ALG_HASH_SHA2_256 = 0x0202,
    /** SHA-384 fixed-output hash. */
    LIBERAC_ALG_HASH_SHA2_384 = 0x0203,
    /** SHA-512 fixed-output hash. */
    LIBERAC_ALG_HASH_SHA2_512 = 0x0204,
    /** SHA-512/224 fixed-output hash. */
    LIBERAC_ALG_HASH_SHA2_512_224 = 0x0205,
    /** SHA-512/256 fixed-output hash. */
    LIBERAC_ALG_HASH_SHA2_512_256 = 0x0206,

    /** LSH-256 with a 224-bit digest. */
    LIBERAC_ALG_HASH_LSH_256_224 = 0x0301,
    /** LSH-256 with a 256-bit digest. */
    LIBERAC_ALG_HASH_LSH_256_256 = 0x0302,
    /** LSH-512 with a 224-bit digest. */
    LIBERAC_ALG_HASH_LSH_512_224 = 0x0311,
    /** LSH-512 with a 256-bit digest. */
    LIBERAC_ALG_HASH_LSH_512_256 = 0x0312,
    /** LSH-512 with a 384-bit digest. */
    LIBERAC_ALG_HASH_LSH_512_384 = 0x0313,
    /** LSH-512 with a 512-bit digest. */
    LIBERAC_ALG_HASH_LSH_512_512 = 0x0314,

    /** ML-KEM-512 key-encapsulation parameter set. */
    LIBERAC_ALG_ML_KEM_512 = 0x1001,
    /** ML-KEM-768 key-encapsulation parameter set. */
    LIBERAC_ALG_ML_KEM_768 = 0x1002,
    /** ML-KEM-1024 key-encapsulation parameter set. */
    LIBERAC_ALG_ML_KEM_1024 = 0x1003,

    /** NTRU+768 key-encapsulation parameter set. */
    LIBERAC_ALG_NTRU_PLUS_768 = 0x1101,
    /** NTRU+864 key-encapsulation parameter set. */
    LIBERAC_ALG_NTRU_PLUS_864 = 0x1102,
    /** NTRU+1152 key-encapsulation parameter set. */
    LIBERAC_ALG_NTRU_PLUS_1152 = 0x1103,

    /** SMAUG-T 128-bit security parameter set. */
    LIBERAC_ALG_SMAUG_T_128 = 0x1201,
    /** SMAUG-T 192-bit security parameter set. */
    LIBERAC_ALG_SMAUG_T_192 = 0x1202,
    /** SMAUG-T 256-bit security parameter set. */
    LIBERAC_ALG_SMAUG_T_256 = 0x1203,

    /** Raw textbook RSA operation without padding or message encoding. */
    LIBERAC_ALG_RSA_RAW = 0x2001,
    /** ElGamal over a generated safe-prime group. */
    LIBERAC_ALG_ELGAMAL_SAFE_PRIME = 0x3001,

    /** AES-128 in electronic codebook (ECB) mode. */
    LIBERAC_ALG_AES_128_ECB = 0x00500110,
    /** AES-192 in electronic codebook (ECB) mode. */
    LIBERAC_ALG_AES_192_ECB = 0x00500118,
    /** AES-256 in electronic codebook (ECB) mode. */
    LIBERAC_ALG_AES_256_ECB = 0x00500120,
    /** AES-128 in cipher block chaining (CBC) mode. */
    LIBERAC_ALG_AES_128_CBC = 0x00500210,
    /** AES-192 in cipher block chaining (CBC) mode. */
    LIBERAC_ALG_AES_192_CBC = 0x00500218,
    /** AES-256 in cipher block chaining (CBC) mode. */
    LIBERAC_ALG_AES_256_CBC = 0x00500220,
    /** AES-128 in counter (CTR) mode. */
    LIBERAC_ALG_AES_128_CTR = 0x00500610,
    /** AES-192 in counter (CTR) mode. */
    LIBERAC_ALG_AES_192_CTR = 0x00500618,
    /** AES-256 in counter (CTR) mode. */
    LIBERAC_ALG_AES_256_CTR = 0x00500620,
    /** AES-128 in counter with CBC-MAC (CCM) mode. */
    LIBERAC_ALG_AES_128_CCM = 0x00580110,
    /** AES-192 in counter with CBC-MAC (CCM) mode. */
    LIBERAC_ALG_AES_192_CCM = 0x00580118,
    /** AES-256 in counter with CBC-MAC (CCM) mode. */
    LIBERAC_ALG_AES_256_CCM = 0x00580120,
    /** AES-128 in Galois/counter (GCM) mode. */
    LIBERAC_ALG_AES_128_GCM = 0x00580210,
    /** AES-192 in Galois/counter (GCM) mode. */
    LIBERAC_ALG_AES_192_GCM = 0x00580218,
    /** AES-256 in Galois/counter (GCM) mode. */
    LIBERAC_ALG_AES_256_GCM = 0x00580220,

    /** Three-key Triple-DES EDE in electronic codebook (ECB) mode. */
    LIBERAC_ALG_TDES_EDE3_ECB = 0x00400118,
    /** Three-key Triple-DES EDE in cipher block chaining (CBC) mode. */
    LIBERAC_ALG_TDES_EDE3_CBC = 0x00400218,

    /** AES-128 CTR_DRBG using the derivation function. */
    LIBERAC_ALG_CTR_DRBG_AES_128_DF = 0x6001,
    /** AES-192 CTR_DRBG using the derivation function. */
    LIBERAC_ALG_CTR_DRBG_AES_192_DF = 0x6002,
    /** AES-256 CTR_DRBG using the derivation function. */
    LIBERAC_ALG_CTR_DRBG_AES_256_DF = 0x6003,
    /** AES-128 CTR_DRBG without the derivation function. */
    LIBERAC_ALG_CTR_DRBG_AES_128_NO_DF = 0x6011,
    /** AES-192 CTR_DRBG without the derivation function. */
    LIBERAC_ALG_CTR_DRBG_AES_192_NO_DF = 0x6012,
    /** AES-256 CTR_DRBG without the derivation function. */
    LIBERAC_ALG_CTR_DRBG_AES_256_NO_DF = 0x6013,

    /** ML-DSA-44 digital-signature parameter set. */
    LIBERAC_ALG_ML_DSA_44 = 0x7001,
    /** ML-DSA-65 digital-signature parameter set. */
    LIBERAC_ALG_ML_DSA_65 = 0x7002,
    /** ML-DSA-87 digital-signature parameter set. */
    LIBERAC_ALG_ML_DSA_87 = 0x7003,

    /** AIMer-128f digital-signature parameter set. */
    LIBERAC_ALG_AIMER_128F = 0x7101,
    /** AIMer-128s digital-signature parameter set. */
    LIBERAC_ALG_AIMER_128S = 0x7102,
    /** AIMer-192f digital-signature parameter set. */
    LIBERAC_ALG_AIMER_192F = 0x7103,
    /** AIMer-192s digital-signature parameter set. */
    LIBERAC_ALG_AIMER_192S = 0x7104,
    /** AIMer-256f digital-signature parameter set. */
    LIBERAC_ALG_AIMER_256F = 0x7105,
    /** AIMer-256s digital-signature parameter set. */
    LIBERAC_ALG_AIMER_256S = 0x7106,

    /** HAETAE-120 digital-signature parameter set. */
    LIBERAC_ALG_HAETAE_120 = 0x7201,
    /** HAETAE-180 digital-signature parameter set. */
    LIBERAC_ALG_HAETAE_180 = 0x7202,
    /** HAETAE-260 digital-signature parameter set. */
    LIBERAC_ALG_HAETAE_260 = 0x7203,

    /** SLH-DSA-SHA2-128s digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHA2_128S = 0x8001,
    /** SLH-DSA-SHA2-128f digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHA2_128F = 0x8002,
    /** SLH-DSA-SHA2-192s digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHA2_192S = 0x8003,
    /** SLH-DSA-SHA2-192f digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHA2_192F = 0x8004,
    /** SLH-DSA-SHA2-256s digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHA2_256S = 0x8005,
    /** SLH-DSA-SHA2-256f digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHA2_256F = 0x8006,
    /** SLH-DSA-SHAKE-128s digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHAKE_128S = 0x8011,
    /** SLH-DSA-SHAKE-128f digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHAKE_128F = 0x8012,
    /** SLH-DSA-SHAKE-192s digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHAKE_192S = 0x8013,
    /** SLH-DSA-SHAKE-192f digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHAKE_192F = 0x8014,
    /** SLH-DSA-SHAKE-256s digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHAKE_256S = 0x8015,
    /** SLH-DSA-SHAKE-256f digital-signature parameter set. */
    LIBERAC_ALG_SLH_DSA_SHAKE_256F = 0x8016
};
/** @} */

/**
 * @name Status codes
 * @brief Return values used by functions whose result type is LiberaCError.
 * @{
 */
enum {
    /** Operation completed successfully. */
    LIBERAC_SUCCESS = 0,
    /** A pointer, length, mode-specific option, or state argument is invalid. */
    LIBERAC_ERROR_INVALID_ARGUMENT = -1,
    /** The supplied LiberaCAlgID is not defined for the requested operation family. */
    LIBERAC_ERROR_INVALID_ALG_ID = -2,
    /** The identifier is known but its algorithm is unavailable in this build. */
    LIBERAC_ERROR_UNSUPPORTED_ALGORITHM = -3,
    /** An output buffer is smaller than the required result. */
    LIBERAC_ERROR_BUFFER_TOO_SMALL = -4,
    /** Dynamic memory allocation failed. */
    LIBERAC_ERROR_ALLOCATION_FAILED = -5,
    /** Entropy collection or random-byte generation failed. */
    LIBERAC_ERROR_RANDOM_FAILED = -6,
    /** A key has an invalid size, representation, or value. */
    LIBERAC_ERROR_INVALID_KEY = -7,
    /** The input exceeds an algorithm-specific length limit. */
    LIBERAC_ERROR_MESSAGE_TOO_LARGE = -8,
    /** A prime could not be generated within the implementation limits. */
    LIBERAC_ERROR_PRIME_GENERATION_FAILED = -9,
    /** A big-number or modular arithmetic operation failed. */
    LIBERAC_ERROR_ARITHMETIC = -10,
    /** An invariant or an otherwise unspecified internal operation failed. */
    LIBERAC_ERROR_INTERNAL = -11,
    /** An authenticated decryption tag did not verify. */
    LIBERAC_ERROR_AUTHENTICATION_FAILED = -12,
    /** A deterministic random generator must be reseeded before further use. */
    LIBERAC_ERROR_RESEED_REQUIRED = -13,
    /** A digital signature is invalid for the supplied message and key. */
    LIBERAC_ERROR_SIGNATURE_INVALID = -14
};
/** @} */

#endif

/** @} */
