/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_DIGITAL_SIGNATURE_H
#define CRYPTO_DIGITAL_SIGNATURE_H

/**
 * @file DigitalSignature.h
 * @brief Runtime-selected ML-DSA and SLH-DSA signature APIs.
 *
 * Keys and signatures are encoded as fixed-size byte strings. Use the size
 * query functions, or the matching compile-time constants, to allocate them.
 * Signing functions implement the non-prehash variants and obtain their
 * per-signature randomness from the operating-system random source.
 *
 * @defgroup crypto_digital_signature Digital-signature API
 * @brief ML-DSA and SLH-DSA key generation, signing, and verification.
 * @{
 */

#include "Def.h"

/** @brief Maximum domain-separation context length accepted by signature APIs. */
#define CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES 255u

/** @brief ML-DSA-44 encoded public-key length in bytes. */
#define CRYPTO_ML_DSA_44_PUBLIC_KEY_BYTES 1312u
/** @brief ML-DSA-44 encoded private-key length in bytes. */
#define CRYPTO_ML_DSA_44_PRIVATE_KEY_BYTES 2560u
/** @brief ML-DSA-44 encoded signature length in bytes. */
#define CRYPTO_ML_DSA_44_SIGNATURE_BYTES 2420u
/** @brief ML-DSA-65 encoded public-key length in bytes. */
#define CRYPTO_ML_DSA_65_PUBLIC_KEY_BYTES 1952u
/** @brief ML-DSA-65 encoded private-key length in bytes. */
#define CRYPTO_ML_DSA_65_PRIVATE_KEY_BYTES 4032u
/** @brief ML-DSA-65 encoded signature length in bytes. */
#define CRYPTO_ML_DSA_65_SIGNATURE_BYTES 3309u
/** @brief ML-DSA-87 encoded public-key length in bytes. */
#define CRYPTO_ML_DSA_87_PUBLIC_KEY_BYTES 2592u
/** @brief ML-DSA-87 encoded private-key length in bytes. */
#define CRYPTO_ML_DSA_87_PRIVATE_KEY_BYTES 4896u
/** @brief ML-DSA-87 encoded signature length in bytes. */
#define CRYPTO_ML_DSA_87_SIGNATURE_BYTES 4627u

/** @brief Encoded public-key length for all SLH-DSA 128-bit parameter sets. */
#define CRYPTO_SLH_DSA_128_PUBLIC_KEY_BYTES 32u
/** @brief Encoded private-key length for all SLH-DSA 128-bit parameter sets. */
#define CRYPTO_SLH_DSA_128_PRIVATE_KEY_BYTES 64u
/** @brief Encoded signature length for SLH-DSA-128s parameter sets. */
#define CRYPTO_SLH_DSA_128S_SIGNATURE_BYTES 7856u
/** @brief Encoded signature length for SLH-DSA-128f parameter sets. */
#define CRYPTO_SLH_DSA_128F_SIGNATURE_BYTES 17088u
/** @brief Encoded public-key length for all SLH-DSA 192-bit parameter sets. */
#define CRYPTO_SLH_DSA_192_PUBLIC_KEY_BYTES 48u
/** @brief Encoded private-key length for all SLH-DSA 192-bit parameter sets. */
#define CRYPTO_SLH_DSA_192_PRIVATE_KEY_BYTES 96u
/** @brief Encoded signature length for SLH-DSA-192s parameter sets. */
#define CRYPTO_SLH_DSA_192S_SIGNATURE_BYTES 16224u
/** @brief Encoded signature length for SLH-DSA-192f parameter sets. */
#define CRYPTO_SLH_DSA_192F_SIGNATURE_BYTES 35664u
/** @brief Encoded public-key length for all SLH-DSA 256-bit parameter sets. */
#define CRYPTO_SLH_DSA_256_PUBLIC_KEY_BYTES 64u
/** @brief Encoded private-key length for all SLH-DSA 256-bit parameter sets. */
#define CRYPTO_SLH_DSA_256_PRIVATE_KEY_BYTES 128u
/** @brief Encoded signature length for SLH-DSA-256s parameter sets. */
#define CRYPTO_SLH_DSA_256S_SIGNATURE_BYTES 29792u
/** @brief Encoded signature length for SLH-DSA-256f parameter sets. */
#define CRYPTO_SLH_DSA_256F_SIGNATURE_BYTES 49856u

CRYPTO_BEGIN_DECLS

/**
 * @brief Return the encoded ML-DSA public-key size for an algorithm.
 * @param[in] ALG One of ALG_ML_DSA_44, ALG_ML_DSA_65, or ALG_ML_DSA_87.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
CRYPTO_API size_t CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(AlgID ALG);

/**
 * @brief Return the encoded ML-DSA private-key size for an algorithm.
 * @param[in] ALG One of ALG_ML_DSA_44, ALG_ML_DSA_65, or ALG_ML_DSA_87.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
CRYPTO_API size_t CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(AlgID ALG);

/**
 * @brief Return the encoded ML-DSA signature size for an algorithm.
 * @param[in] ALG One of ALG_ML_DSA_44, ALG_ML_DSA_65, or ALG_ML_DSA_87.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
CRYPTO_API size_t CRYPTO_ML_DSA_SIGNATURE_SIZE(AlgID ALG);

/**
 * @brief Generate an ML-DSA key pair using operating-system randomness.
 * @param[out] PUBLIC_KEY Buffer receiving the encoded public key.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY; must be at least
 *                              CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(ALG).
 * @param[out] PRIVATE_KEY Buffer receiving the encoded private key.
 * @param[in] PRIVATE_KEY_LENGTH Available bytes in PRIVATE_KEY; must be at
 *                               least CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(ALG).
 * @param[in] ALG ML-DSA parameter-set identifier.
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_BUFFER_TOO_SMALL for an
 *         undersized output, CRYPTO_ERROR_RANDOM_FAILED if entropy cannot be
 *         obtained, or another negative CryptoError on failure.
 * @note If generation fails after output sizes have been validated, the
 *       required portions of both output buffers are cleared.
 */
CRYPTO_API CryptoError CRYPTO_ML_DSA_KEYGEN(uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, AlgID ALG);

/**
 * @brief Sign a message with randomized, non-prehash ML-DSA.
 * @param[in] PRIVATE_KEY Encoded ML-DSA private key.
 * @param[in] PRIVATE_KEY_LENGTH Exact encoded private-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only when MESSAGE_LENGTH is zero.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Optional domain-separation context; may be null only when
 *                    CONTEXT_LENGTH is zero.
 * @param[in] CONTEXT_LENGTH Context length from 0 through
 *                           CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES.
 * @param[out] SIGNATURE Buffer receiving the fixed-size signature.
 * @param[in] SIGNATURE_LENGTH Available bytes in SIGNATURE; must be at least
 *                             CRYPTO_ML_DSA_SIGNATURE_SIZE(ALG).
 * @param[in] ALG ML-DSA parameter-set identifier matching PRIVATE_KEY.
 * @return CRYPTO_SUCCESS on success, CRYPTO_ERROR_INVALID_KEY for a private-key
 *         length mismatch, CRYPTO_ERROR_BUFFER_TOO_SMALL for an undersized
 *         signature buffer, or another negative CryptoError on failure.
 * @note The required signature region is cleared if signing fails after
 *       buffer validation.
 */
CRYPTO_API CryptoError CRYPTO_ML_DSA_SIGN(const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, AlgID ALG);

/**
 * @brief Verify a non-prehash ML-DSA signature.
 * @param[in] PUBLIC_KEY Encoded ML-DSA public key.
 * @param[in] PUBLIC_KEY_LENGTH Exact encoded public-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only when MESSAGE_LENGTH is zero.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Domain-separation context used when signing; may be null
 *                    only when CONTEXT_LENGTH is zero.
 * @param[in] CONTEXT_LENGTH Context length from 0 through
 *                           CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES.
 * @param[in] SIGNATURE Encoded signature.
 * @param[in] SIGNATURE_LENGTH Exact signature size for ALG.
 * @param[in] ALG ML-DSA parameter-set identifier matching the key and signature.
 * @return CRYPTO_SUCCESS for a valid signature,
 *         CRYPTO_ERROR_SIGNATURE_INVALID for a malformed or non-matching
 *         signature, CRYPTO_ERROR_INVALID_KEY for a public-key length mismatch,
 *         or another negative CryptoError for invalid inputs.
 */
CRYPTO_API CryptoError CRYPTO_ML_DSA_VERIFY(const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, AlgID ALG);

/**
 * @brief Return the encoded SLH-DSA public-key size for an algorithm.
 * @param[in] ALG Any ALG_SLH_DSA_SHA2_* or ALG_SLH_DSA_SHAKE_* identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
CRYPTO_API size_t CRYPTO_SLH_DSA_PUBLIC_KEY_SIZE(AlgID ALG);

/**
 * @brief Return the encoded SLH-DSA private-key size for an algorithm.
 * @param[in] ALG Any ALG_SLH_DSA_SHA2_* or ALG_SLH_DSA_SHAKE_* identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
CRYPTO_API size_t CRYPTO_SLH_DSA_PRIVATE_KEY_SIZE(AlgID ALG);

/**
 * @brief Return the encoded SLH-DSA signature size for an algorithm.
 * @param[in] ALG Any ALG_SLH_DSA_SHA2_* or ALG_SLH_DSA_SHAKE_* identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
CRYPTO_API size_t CRYPTO_SLH_DSA_SIGNATURE_SIZE(AlgID ALG);

/**
 * @brief Generate an SLH-DSA key pair using operating-system randomness.
 * @param[out] PUBLIC_KEY Buffer receiving the encoded public key.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY; must be at least
 *                              CRYPTO_SLH_DSA_PUBLIC_KEY_SIZE(ALG).
 * @param[out] PRIVATE_KEY Buffer receiving the encoded private key.
 * @param[in] PRIVATE_KEY_LENGTH Available bytes in PRIVATE_KEY; must be at
 *                               least CRYPTO_SLH_DSA_PRIVATE_KEY_SIZE(ALG).
 * @param[in] ALG Any supported SHA2- or SHAKE-based SLH-DSA parameter set.
 * @return CRYPTO_SUCCESS on success or a negative CryptoError on failure.
 * @note Validated output regions are cleared if key generation fails.
 */
CRYPTO_API CryptoError CRYPTO_SLH_DSA_KEYGEN(uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, AlgID ALG);

/**
 * @brief Sign a message with randomized, non-prehash SLH-DSA.
 * @param[in] PRIVATE_KEY Encoded SLH-DSA private key.
 * @param[in] PRIVATE_KEY_LENGTH Exact encoded private-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only when MESSAGE_LENGTH is zero.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Optional domain-separation context; may be null only when
 *                    CONTEXT_LENGTH is zero.
 * @param[in] CONTEXT_LENGTH Context length from 0 through
 *                           CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES.
 * @param[out] SIGNATURE Buffer receiving the fixed-size signature.
 * @param[in] SIGNATURE_LENGTH Available bytes in SIGNATURE; must be at least
 *                             CRYPTO_SLH_DSA_SIGNATURE_SIZE(ALG).
 * @param[in] ALG SLH-DSA parameter-set identifier matching PRIVATE_KEY.
 * @return CRYPTO_SUCCESS on success, CRYPTO_ERROR_INVALID_KEY for a private-key
 *         length mismatch, or another negative CryptoError on failure.
 * @note The required signature region is cleared if signing fails after
 *       buffer validation.
 */
CRYPTO_API CryptoError CRYPTO_SLH_DSA_SIGN(const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, AlgID ALG);

/**
 * @brief Verify a non-prehash SLH-DSA signature.
 * @param[in] PUBLIC_KEY Encoded SLH-DSA public key.
 * @param[in] PUBLIC_KEY_LENGTH Exact encoded public-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only when MESSAGE_LENGTH is zero.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Domain-separation context used when signing; may be null
 *                    only when CONTEXT_LENGTH is zero.
 * @param[in] CONTEXT_LENGTH Context length from 0 through
 *                           CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES.
 * @param[in] SIGNATURE Encoded signature.
 * @param[in] SIGNATURE_LENGTH Exact signature size for ALG.
 * @param[in] ALG SLH-DSA parameter-set identifier matching the key and signature.
 * @return CRYPTO_SUCCESS for a valid signature,
 *         CRYPTO_ERROR_SIGNATURE_INVALID for a malformed or non-matching
 *         signature, CRYPTO_ERROR_INVALID_KEY for a public-key length mismatch,
 *         or another negative CryptoError for invalid inputs.
 */
CRYPTO_API CryptoError CRYPTO_SLH_DSA_VERIFY(const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, AlgID ALG);
CRYPTO_END_DECLS

#endif

/** @} */
