/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBERAC_DIGITAL_SIGNATURE_H
#define LIBERAC_DIGITAL_SIGNATURE_H

/**
 * @file DigitalSignature.h
 * @brief Runtime-selected classical and post-quantum digital-signature APIs.
 *
 * Keys and signatures are encoded as fixed-size byte strings. Use the size
 * query functions, or the matching compile-time constants, to allocate them.
 * Post-quantum signing functions implement the non-prehash variants and
 * obtain their per-signature randomness from the operating-system random
 * source. ECDSA signs messages deterministically according to RFC 6979.
 *
 * @defgroup crypto_digital_signature Digital-signature API
 * @brief Key generation, signing, and verification for supported signatures.
 * @{
 */

#include "Def.h"

/** @brief Maximum domain-separation context length accepted by signature APIs. */
#define LIBERAC_SIGNATURE_CONTEXT_MAX_BYTES 255u

/** @brief P-256 ECDSA private-scalar length in bytes. */
#define LIBERAC_ECDSA_P256_PRIVATE_KEY_BYTES 32u
/** @brief P-256 uncompressed SEC 1 public-key length in bytes. */
#define LIBERAC_ECDSA_P256_PUBLIC_KEY_BYTES 65u
/** @brief P-256 fixed-width raw signature length in bytes. */
#define LIBERAC_ECDSA_P256_SIGNATURE_BYTES 64u

/** @brief P-384 ECDSA private-scalar length in bytes. */
#define LIBERAC_ECDSA_P384_PRIVATE_KEY_BYTES 48u
/** @brief P-384 uncompressed SEC 1 public-key length in bytes. */
#define LIBERAC_ECDSA_P384_PUBLIC_KEY_BYTES 97u
/** @brief P-384 fixed-width raw signature length in bytes. */
#define LIBERAC_ECDSA_P384_SIGNATURE_BYTES 96u

/** @brief P-521 ECDSA private-scalar length in bytes. */
#define LIBERAC_ECDSA_P521_PRIVATE_KEY_BYTES 66u
/** @brief P-521 uncompressed SEC 1 public-key length in bytes. */
#define LIBERAC_ECDSA_P521_PUBLIC_KEY_BYTES 133u
/** @brief P-521 fixed-width raw signature length in bytes. */
#define LIBERAC_ECDSA_P521_SIGNATURE_BYTES 132u

/** @brief Ed25519 private seed length in bytes. */
#define LIBERAC_ED25519_PRIVATE_KEY_BYTES 32u
/** @brief Ed25519 compressed public-key length in bytes. */
#define LIBERAC_ED25519_PUBLIC_KEY_BYTES 32u
/** @brief Ed25519 signature length in bytes. */
#define LIBERAC_ED25519_SIGNATURE_BYTES 64u

/** @brief ML-DSA-44 encoded public-key length in bytes. */
#define LIBERAC_ML_DSA_44_PUBLIC_KEY_BYTES 1312u
/** @brief ML-DSA-44 encoded private-key length in bytes. */
#define LIBERAC_ML_DSA_44_PRIVATE_KEY_BYTES 2560u
/** @brief ML-DSA-44 encoded signature length in bytes. */
#define LIBERAC_ML_DSA_44_SIGNATURE_BYTES 2420u
/** @brief ML-DSA-65 encoded public-key length in bytes. */
#define LIBERAC_ML_DSA_65_PUBLIC_KEY_BYTES 1952u
/** @brief ML-DSA-65 encoded private-key length in bytes. */
#define LIBERAC_ML_DSA_65_PRIVATE_KEY_BYTES 4032u
/** @brief ML-DSA-65 encoded signature length in bytes. */
#define LIBERAC_ML_DSA_65_SIGNATURE_BYTES 3309u
/** @brief ML-DSA-87 encoded public-key length in bytes. */
#define LIBERAC_ML_DSA_87_PUBLIC_KEY_BYTES 2592u
/** @brief ML-DSA-87 encoded private-key length in bytes. */
#define LIBERAC_ML_DSA_87_PRIVATE_KEY_BYTES 4896u
/** @brief ML-DSA-87 encoded signature length in bytes. */
#define LIBERAC_ML_DSA_87_SIGNATURE_BYTES 4627u

/** @brief AIMer-128f encoded public-key length in bytes. */
#define LIBERAC_AIMER_128F_PUBLIC_KEY_BYTES 32u
/** @brief AIMer-128f encoded private-key length in bytes. */
#define LIBERAC_AIMER_128F_PRIVATE_KEY_BYTES 48u
/** @brief AIMer-128f encoded signature length in bytes. */
#define LIBERAC_AIMER_128F_SIGNATURE_BYTES 5888u
/** @brief AIMer-128s encoded public-key length in bytes. */
#define LIBERAC_AIMER_128S_PUBLIC_KEY_BYTES 32u
/** @brief AIMer-128s encoded private-key length in bytes. */
#define LIBERAC_AIMER_128S_PRIVATE_KEY_BYTES 48u
/** @brief AIMer-128s encoded signature length in bytes. */
#define LIBERAC_AIMER_128S_SIGNATURE_BYTES 4160u
/** @brief AIMer-192f encoded public-key length in bytes. */
#define LIBERAC_AIMER_192F_PUBLIC_KEY_BYTES 48u
/** @brief AIMer-192f encoded private-key length in bytes. */
#define LIBERAC_AIMER_192F_PRIVATE_KEY_BYTES 72u
/** @brief AIMer-192f encoded signature length in bytes. */
#define LIBERAC_AIMER_192F_SIGNATURE_BYTES 13056u
/** @brief AIMer-192s encoded public-key length in bytes. */
#define LIBERAC_AIMER_192S_PUBLIC_KEY_BYTES 48u
/** @brief AIMer-192s encoded private-key length in bytes. */
#define LIBERAC_AIMER_192S_PRIVATE_KEY_BYTES 72u
/** @brief AIMer-192s encoded signature length in bytes. */
#define LIBERAC_AIMER_192S_SIGNATURE_BYTES 9120u
/** @brief AIMer-256f encoded public-key length in bytes. */
#define LIBERAC_AIMER_256F_PUBLIC_KEY_BYTES 64u
/** @brief AIMer-256f encoded private-key length in bytes. */
#define LIBERAC_AIMER_256F_PRIVATE_KEY_BYTES 96u
/** @brief AIMer-256f encoded signature length in bytes. */
#define LIBERAC_AIMER_256F_SIGNATURE_BYTES 25120u
/** @brief AIMer-256s encoded public-key length in bytes. */
#define LIBERAC_AIMER_256S_PUBLIC_KEY_BYTES 64u
/** @brief AIMer-256s encoded private-key length in bytes. */
#define LIBERAC_AIMER_256S_PRIVATE_KEY_BYTES 96u
/** @brief AIMer-256s encoded signature length in bytes. */
#define LIBERAC_AIMER_256S_SIGNATURE_BYTES 17056u

/** @brief HAETAE-120 encoded public-key length in bytes. */
#define LIBERAC_HAETAE_120_PUBLIC_KEY_BYTES 992u
/** @brief HAETAE-120 encoded private-key length in bytes. */
#define LIBERAC_HAETAE_120_PRIVATE_KEY_BYTES 1408u
/** @brief HAETAE-120 encoded signature length in bytes. */
#define LIBERAC_HAETAE_120_SIGNATURE_BYTES 1474u
/** @brief HAETAE-180 encoded public-key length in bytes. */
#define LIBERAC_HAETAE_180_PUBLIC_KEY_BYTES 1472u
/** @brief HAETAE-180 encoded private-key length in bytes. */
#define LIBERAC_HAETAE_180_PRIVATE_KEY_BYTES 2112u
/** @brief HAETAE-180 encoded signature length in bytes. */
#define LIBERAC_HAETAE_180_SIGNATURE_BYTES 2349u
/** @brief HAETAE-260 encoded public-key length in bytes. */
#define LIBERAC_HAETAE_260_PUBLIC_KEY_BYTES 2080u
/** @brief HAETAE-260 encoded private-key length in bytes. */
#define LIBERAC_HAETAE_260_PRIVATE_KEY_BYTES 2752u
/** @brief HAETAE-260 encoded signature length in bytes. */
#define LIBERAC_HAETAE_260_SIGNATURE_BYTES 2948u

/** @brief Encoded public-key length for all SLH-DSA 128-bit parameter sets. */
#define LIBERAC_SLH_DSA_128_PUBLIC_KEY_BYTES 32u
/** @brief Encoded private-key length for all SLH-DSA 128-bit parameter sets. */
#define LIBERAC_SLH_DSA_128_PRIVATE_KEY_BYTES 64u
/** @brief Encoded signature length for SLH-DSA-128s parameter sets. */
#define LIBERAC_SLH_DSA_128S_SIGNATURE_BYTES 7856u
/** @brief Encoded signature length for SLH-DSA-128f parameter sets. */
#define LIBERAC_SLH_DSA_128F_SIGNATURE_BYTES 17088u
/** @brief Encoded public-key length for all SLH-DSA 192-bit parameter sets. */
#define LIBERAC_SLH_DSA_192_PUBLIC_KEY_BYTES 48u
/** @brief Encoded private-key length for all SLH-DSA 192-bit parameter sets. */
#define LIBERAC_SLH_DSA_192_PRIVATE_KEY_BYTES 96u
/** @brief Encoded signature length for SLH-DSA-192s parameter sets. */
#define LIBERAC_SLH_DSA_192S_SIGNATURE_BYTES 16224u
/** @brief Encoded signature length for SLH-DSA-192f parameter sets. */
#define LIBERAC_SLH_DSA_192F_SIGNATURE_BYTES 35664u
/** @brief Encoded public-key length for all SLH-DSA 256-bit parameter sets. */
#define LIBERAC_SLH_DSA_256_PUBLIC_KEY_BYTES 64u
/** @brief Encoded private-key length for all SLH-DSA 256-bit parameter sets. */
#define LIBERAC_SLH_DSA_256_PRIVATE_KEY_BYTES 128u
/** @brief Encoded signature length for SLH-DSA-256s parameter sets. */
#define LIBERAC_SLH_DSA_256S_SIGNATURE_BYTES 29792u
/** @brief Encoded signature length for SLH-DSA-256f parameter sets. */
#define LIBERAC_SLH_DSA_256F_SIGNATURE_BYTES 49856u

LIBERAC_BEGIN_DECLS

/**
 * @brief Return the fixed-width ECDSA private-key size for a curve selector.
 * @param[in] ALG A LIBERAC_ALG_ECDSA_P256, _P384, or _P521 identifier.
 * @return Required bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_ECDSA_PRIVATE_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the generated ECDSA public-key size for a curve selector.
 * @param[in] ALG A LIBERAC_ALG_ECDSA_P256, _P384, or _P521 identifier.
 * @return Uncompressed SEC 1 public-key bytes, or zero if unsupported.
 * @note Verification also accepts the corresponding compressed SEC 1 point.
 */
LIBERAC_API size_t LIBERAC_ECDSA_PUBLIC_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the fixed-width raw ECDSA signature size.
 * @param[in] ALG A LIBERAC_ALG_ECDSA_P256, _P384, or _P521 identifier.
 * @return Bytes required for r || s, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_ECDSA_SIGNATURE_SIZE(LiberaCAlgID ALG);

/**
 * @brief Generate an ECDSA private scalar and public point.
 * @param[out] PUBLIC_KEY Buffer receiving an uncompressed SEC 1 point.
 * @param[in] PUBLIC_KEY_LENGTH Available public-key bytes.
 * @param[out] PRIVATE_KEY Buffer receiving a fixed-width big-endian scalar.
 * @param[in] PRIVATE_KEY_LENGTH Available private-key bytes.
 * @param[in] ALG ECDSA curve selector.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note Once output validation succeeds, an operational failure clears both
 *       required output regions.
 */
LIBERAC_API LiberaCError LIBERAC_ECDSA_KEYGEN(
    uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
    uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Derive an ECDSA public key from a supplied private scalar.
 * @param[out] PUBLIC_KEY Buffer receiving an uncompressed SEC 1 point.
 * @param[in] PUBLIC_KEY_LENGTH Available public-key bytes.
 * @param[in] PRIVATE_KEY Fixed-width big-endian scalar in 1 <= d < n.
 * @param[in] PRIVATE_KEY_LENGTH Exact private-key length for ALG.
 * @param[in] ALG ECDSA curve selector.
 * @return LIBERAC_SUCCESS on success, LIBERAC_ERROR_INVALID_KEY for an invalid
 *         scalar, or another negative LiberaCError on failure.
 */
LIBERAC_API LiberaCError LIBERAC_ECDSA_PUBLIC_FROM_PRIVATE(
    uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
    const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Generate a deterministic RFC 6979 ECDSA signature.
 *
 * The signature is the fixed-width big-endian concatenation r || s, with each
 * integer occupying LIBERAC_ECDSA_PRIVATE_KEY_SIZE(ALG) bytes. No DER wrapper
 * and no low-s normalization are applied.
 *
 * @param[in] PRIVATE_KEY Fixed-width private scalar in 1 <= d < n.
 * @param[in] PRIVATE_KEY_LENGTH Exact private-key length for ALG.
 * @param[in] MESSAGE Message bytes; may be null only when MESSAGE_LENGTH is 0.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[out] SIGNATURE Buffer receiving the fixed-width r || s encoding.
 * @param[in] SIGNATURE_LENGTH Available signature bytes.
 * @param[in] HASH_ALG Approved fixed-output SHA-2 or SHA-3 selector whose
 *                     collision strength is not below the selected curve.
 * @param[in] ALG ECDSA curve selector.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note Signing needs no per-message random source. Key generation still uses
 *       operating-system randomness.
 */
LIBERAC_API LiberaCError LIBERAC_ECDSA_SIGN(
    const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH,
    LiberaCAlgID HASH_ALG, LiberaCAlgID ALG);

/**
 * @brief Verify a fixed-width raw ECDSA signature.
 * @param[in] PUBLIC_KEY Compressed or uncompressed SEC 1 public point.
 * @param[in] PUBLIC_KEY_LENGTH Exact encoded public-key length.
 * @param[in] MESSAGE Message bytes; may be null only when MESSAGE_LENGTH is 0.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] SIGNATURE Fixed-width big-endian r || s encoding.
 * @param[in] SIGNATURE_LENGTH Exact signature length for ALG.
 * @param[in] HASH_ALG The same approved hash selector used while signing.
 * @param[in] ALG ECDSA curve selector.
 * @return LIBERAC_SUCCESS for a valid signature,
 *         LIBERAC_ERROR_SIGNATURE_INVALID for a malformed or non-matching
 *         signature, LIBERAC_ERROR_INVALID_KEY for an invalid public key, or
 *         another negative LiberaCError for invalid inputs.
 */
LIBERAC_API LiberaCError LIBERAC_ECDSA_VERIFY(
    const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH,
    LiberaCAlgID HASH_ALG, LiberaCAlgID ALG);

/**
 * @brief Return the Ed25519 private-seed size.
 * @param[in] ALG LIBERAC_ALG_ED25519.
 * @return 32 for Ed25519, or zero for an unsupported identifier.
 */
LIBERAC_API size_t LIBERAC_ED25519_PRIVATE_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the Ed25519 compressed public-key size.
 * @param[in] ALG LIBERAC_ALG_ED25519.
 * @return 32 for Ed25519, or zero for an unsupported identifier.
 */
LIBERAC_API size_t LIBERAC_ED25519_PUBLIC_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the Ed25519 signature size.
 * @param[in] ALG LIBERAC_ALG_ED25519.
 * @return 64 for Ed25519, or zero for an unsupported identifier.
 */
LIBERAC_API size_t LIBERAC_ED25519_SIGNATURE_SIZE(LiberaCAlgID ALG);

/**
 * @brief Generate an Ed25519 private seed and matching public key.
 * @param[out] PUBLIC_KEY Buffer receiving the 32-byte compressed point.
 * @param[in] PUBLIC_KEY_LENGTH Available public-key bytes.
 * @param[out] PRIVATE_KEY Buffer receiving the 32-byte private seed.
 * @param[in] PRIVATE_KEY_LENGTH Available private-key bytes.
 * @param[in] ALG LIBERAC_ALG_ED25519.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note Once output validation succeeds, an operational failure clears both
 *       required output regions.
 */
LIBERAC_API LiberaCError LIBERAC_ED25519_KEYGEN(
    uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
    uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Derive an Ed25519 public key from a private seed.
 * @param[out] PUBLIC_KEY Buffer receiving the 32-byte compressed point.
 * @param[in] PUBLIC_KEY_LENGTH Available public-key bytes.
 * @param[in] PRIVATE_KEY Exact 32-byte private seed.
 * @param[in] PRIVATE_KEY_LENGTH Private-seed length.
 * @param[in] ALG LIBERAC_ALG_ED25519.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 */
LIBERAC_API LiberaCError LIBERAC_ED25519_PUBLIC_FROM_PRIVATE(
    uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
    const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Generate a deterministic pure-mode Ed25519 signature.
 *
 * The private key is the RFC 8032 32-byte seed. Ed25519 performs its mandated
 * SHA-512 hashing internally; a caller-selectable prehash is intentionally not
 * accepted by this pure-mode API.
 *
 * @param[in] PRIVATE_KEY Exact 32-byte private seed.
 * @param[in] PRIVATE_KEY_LENGTH Private-seed length.
 * @param[in] MESSAGE Message bytes; may be NULL only when MESSAGE_LENGTH is 0.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[out] SIGNATURE Buffer receiving the 64-byte R || S signature.
 * @param[in] SIGNATURE_LENGTH Available signature bytes.
 * @param[in] ALG LIBERAC_ALG_ED25519.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 */
LIBERAC_API LiberaCError LIBERAC_ED25519_SIGN(
    const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Verify a strict pure-mode Ed25519 signature.
 *
 * Verification requires canonical point encodings, S < L, and a non-identity
 * public key in the prime-order subgroup.
 *
 * @param[in] PUBLIC_KEY Exact 32-byte compressed public key.
 * @param[in] PUBLIC_KEY_LENGTH Public-key length.
 * @param[in] MESSAGE Message bytes; may be NULL only when MESSAGE_LENGTH is 0.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] SIGNATURE Exact 64-byte R || S signature.
 * @param[in] SIGNATURE_LENGTH Signature length.
 * @param[in] ALG LIBERAC_ALG_ED25519.
 * @return LIBERAC_SUCCESS for a valid signature,
 *         LIBERAC_ERROR_SIGNATURE_INVALID for a malformed or non-matching
 *         signature, LIBERAC_ERROR_INVALID_KEY for an invalid public key, or
 *         another negative LiberaCError for invalid inputs.
 */
LIBERAC_API LiberaCError LIBERAC_ED25519_VERIFY(
    const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Return the encoded ML-DSA public-key size for an algorithm.
 * @param[in] ALG One of LIBERAC_ALG_ML_DSA_44, LIBERAC_ALG_ML_DSA_65, or LIBERAC_ALG_ML_DSA_87.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_ML_DSA_PUBLIC_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded ML-DSA private-key size for an algorithm.
 * @param[in] ALG One of LIBERAC_ALG_ML_DSA_44, LIBERAC_ALG_ML_DSA_65, or LIBERAC_ALG_ML_DSA_87.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_ML_DSA_PRIVATE_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded ML-DSA signature size for an algorithm.
 * @param[in] ALG One of LIBERAC_ALG_ML_DSA_44, LIBERAC_ALG_ML_DSA_65, or LIBERAC_ALG_ML_DSA_87.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_ML_DSA_SIGNATURE_SIZE(LiberaCAlgID ALG);

/**
 * @brief Generate an ML-DSA key pair using operating-system randomness.
 * @param[out] PUBLIC_KEY Buffer receiving the encoded public key.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY; must be at least
 *                              LIBERAC_ML_DSA_PUBLIC_KEY_SIZE(ALG).
 * @param[out] PRIVATE_KEY Buffer receiving the encoded private key.
 * @param[in] PRIVATE_KEY_LENGTH Available bytes in PRIVATE_KEY; must be at
 *                               least LIBERAC_ML_DSA_PRIVATE_KEY_SIZE(ALG).
 * @param[in] ALG ML-DSA parameter-set identifier.
 * @return LIBERAC_SUCCESS on success; LIBERAC_ERROR_BUFFER_TOO_SMALL for an
 *         undersized output, LIBERAC_ERROR_RANDOM_FAILED if entropy cannot be
 *         obtained, or another negative LiberaCError on failure.
 * @note If generation fails after output sizes have been validated, the
 *       required portions of both output buffers are cleared.
 */
LIBERAC_API LiberaCError LIBERAC_ML_DSA_KEYGEN(uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Sign a message with randomized, non-prehash ML-DSA.
 * @param[in] PRIVATE_KEY Encoded ML-DSA private key.
 * @param[in] PRIVATE_KEY_LENGTH Exact encoded private-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only when MESSAGE_LENGTH is zero.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Optional domain-separation context; may be null only when
 *                    CONTEXT_LENGTH is zero.
 * @param[in] CONTEXT_LENGTH Context length from 0 through
 *                           LIBERAC_SIGNATURE_CONTEXT_MAX_BYTES.
 * @param[out] SIGNATURE Buffer receiving the fixed-size signature.
 * @param[in] SIGNATURE_LENGTH Available bytes in SIGNATURE; must be at least
 *                             LIBERAC_ML_DSA_SIGNATURE_SIZE(ALG).
 * @param[in] ALG ML-DSA parameter-set identifier matching PRIVATE_KEY.
 * @return LIBERAC_SUCCESS on success, LIBERAC_ERROR_INVALID_KEY for a private-key
 *         length mismatch, LIBERAC_ERROR_BUFFER_TOO_SMALL for an undersized
 *         signature buffer, or another negative LiberaCError on failure.
 * @note The required signature region is cleared if signing fails after
 *       buffer validation.
 */
LIBERAC_API LiberaCError LIBERAC_ML_DSA_SIGN(const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Verify a non-prehash ML-DSA signature.
 * @param[in] PUBLIC_KEY Encoded ML-DSA public key.
 * @param[in] PUBLIC_KEY_LENGTH Exact encoded public-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only when MESSAGE_LENGTH is zero.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Domain-separation context used when signing; may be null
 *                    only when CONTEXT_LENGTH is zero.
 * @param[in] CONTEXT_LENGTH Context length from 0 through
 *                           LIBERAC_SIGNATURE_CONTEXT_MAX_BYTES.
 * @param[in] SIGNATURE Encoded signature.
 * @param[in] SIGNATURE_LENGTH Exact signature size for ALG.
 * @param[in] ALG ML-DSA parameter-set identifier matching the key and signature.
 * @return LIBERAC_SUCCESS for a valid signature,
 *         LIBERAC_ERROR_SIGNATURE_INVALID for a malformed or non-matching
 *         signature, LIBERAC_ERROR_INVALID_KEY for a public-key length mismatch,
 *         or another negative LiberaCError for invalid inputs.
 */
LIBERAC_API LiberaCError LIBERAC_ML_DSA_VERIFY(const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Return the encoded AIMer public-key size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_AIMER_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_AIMER_PUBLIC_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded AIMer private-key size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_AIMER_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_AIMER_PRIVATE_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded AIMer signature size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_AIMER_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_AIMER_SIGNATURE_SIZE(LiberaCAlgID ALG);

/**
 * @brief Generate an AIMer key pair using operating-system randomness.
 * @param[out] PUBLIC_KEY Buffer receiving the encoded public key.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY.
 * @param[out] PRIVATE_KEY Buffer receiving the encoded private key.
 * @param[in] PRIVATE_KEY_LENGTH Available bytes in PRIVATE_KEY.
 * @param[in] ALG An LIBERAC_ALG_AIMER_* parameter-set identifier.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note Validated output regions are cleared if generation fails.
 */
LIBERAC_API LiberaCError LIBERAC_AIMER_KEYGEN(uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Sign a message with randomized AIMer.
 * @param[in] PRIVATE_KEY Encoded private key selected by ALG.
 * @param[in] PRIVATE_KEY_LENGTH Exact encoded private-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only for an empty message.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Optional domain-separation context.
 * @param[in] CONTEXT_LENGTH Context length from zero through 255 bytes.
 * @param[out] SIGNATURE Buffer receiving the fixed-size signature.
 * @param[in] SIGNATURE_LENGTH Available signature bytes.
 * @param[in] ALG An LIBERAC_ALG_AIMER_* parameter-set identifier.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note The signature output is cleared if signing fails after validation.
 */
LIBERAC_API LiberaCError LIBERAC_AIMER_SIGN(const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Verify an AIMer signature.
 * @param[in] PUBLIC_KEY Encoded public key selected by ALG.
 * @param[in] PUBLIC_KEY_LENGTH Exact encoded public-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only for an empty message.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Domain-separation context used while signing.
 * @param[in] CONTEXT_LENGTH Context length from zero through 255 bytes.
 * @param[in] SIGNATURE Encoded signature.
 * @param[in] SIGNATURE_LENGTH Exact signature length selected by ALG.
 * @param[in] ALG An LIBERAC_ALG_AIMER_* parameter-set identifier.
 * @return LIBERAC_SUCCESS for a valid signature or a negative LiberaCError.
 */
LIBERAC_API LiberaCError LIBERAC_AIMER_VERIFY(const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Return the encoded HAETAE public-key size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_HAETAE_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_HAETAE_PUBLIC_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded HAETAE private-key size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_HAETAE_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_HAETAE_PRIVATE_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded HAETAE signature size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_HAETAE_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_HAETAE_SIGNATURE_SIZE(LiberaCAlgID ALG);

/**
 * @brief Generate a HAETAE key pair using operating-system randomness.
 * @param[out] PUBLIC_KEY Buffer receiving the encoded public key.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY.
 * @param[out] PRIVATE_KEY Buffer receiving the encoded private key.
 * @param[in] PRIVATE_KEY_LENGTH Available bytes in PRIVATE_KEY.
 * @param[in] ALG An LIBERAC_ALG_HAETAE_* parameter-set identifier.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note Validated output regions are cleared if generation fails.
 */
LIBERAC_API LiberaCError LIBERAC_HAETAE_KEYGEN(uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Sign a message with randomized HAETAE.
 * @param[in] PRIVATE_KEY Encoded private key selected by ALG.
 * @param[in] PRIVATE_KEY_LENGTH Exact encoded private-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only for an empty message.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Optional domain-separation context.
 * @param[in] CONTEXT_LENGTH Context length from zero through 255 bytes.
 * @param[out] SIGNATURE Buffer receiving the fixed-size signature.
 * @param[in] SIGNATURE_LENGTH Available signature bytes.
 * @param[in] ALG An LIBERAC_ALG_HAETAE_* parameter-set identifier.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note The signature output is cleared if signing fails after validation.
 */
LIBERAC_API LiberaCError LIBERAC_HAETAE_SIGN(const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Verify a HAETAE signature.
 * @param[in] PUBLIC_KEY Encoded public key selected by ALG.
 * @param[in] PUBLIC_KEY_LENGTH Exact encoded public-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only for an empty message.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Domain-separation context used while signing.
 * @param[in] CONTEXT_LENGTH Context length from zero through 255 bytes.
 * @param[in] SIGNATURE Encoded signature.
 * @param[in] SIGNATURE_LENGTH Exact signature length selected by ALG.
 * @param[in] ALG An LIBERAC_ALG_HAETAE_* parameter-set identifier.
 * @return LIBERAC_SUCCESS for a valid signature or a negative LiberaCError.
 */
LIBERAC_API LiberaCError LIBERAC_HAETAE_VERIFY(const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Return the encoded SLH-DSA public-key size for an algorithm.
 * @param[in] ALG Any LIBERAC_ALG_SLH_DSA_SHA2_* or LIBERAC_ALG_SLH_DSA_SHAKE_* identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_SLH_DSA_PUBLIC_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded SLH-DSA private-key size for an algorithm.
 * @param[in] ALG Any LIBERAC_ALG_SLH_DSA_SHA2_* or LIBERAC_ALG_SLH_DSA_SHAKE_* identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_SLH_DSA_PRIVATE_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded SLH-DSA signature size for an algorithm.
 * @param[in] ALG Any LIBERAC_ALG_SLH_DSA_SHA2_* or LIBERAC_ALG_SLH_DSA_SHAKE_* identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_SLH_DSA_SIGNATURE_SIZE(LiberaCAlgID ALG);

/**
 * @brief Generate an SLH-DSA key pair using operating-system randomness.
 * @param[out] PUBLIC_KEY Buffer receiving the encoded public key.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY; must be at least
 *                              LIBERAC_SLH_DSA_PUBLIC_KEY_SIZE(ALG).
 * @param[out] PRIVATE_KEY Buffer receiving the encoded private key.
 * @param[in] PRIVATE_KEY_LENGTH Available bytes in PRIVATE_KEY; must be at
 *                               least LIBERAC_SLH_DSA_PRIVATE_KEY_SIZE(ALG).
 * @param[in] ALG Any supported SHA2- or SHAKE-based SLH-DSA parameter set.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note Validated output regions are cleared if key generation fails.
 */
LIBERAC_API LiberaCError LIBERAC_SLH_DSA_KEYGEN(uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Sign a message with randomized, non-prehash SLH-DSA.
 * @param[in] PRIVATE_KEY Encoded SLH-DSA private key.
 * @param[in] PRIVATE_KEY_LENGTH Exact encoded private-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only when MESSAGE_LENGTH is zero.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Optional domain-separation context; may be null only when
 *                    CONTEXT_LENGTH is zero.
 * @param[in] CONTEXT_LENGTH Context length from 0 through
 *                           LIBERAC_SIGNATURE_CONTEXT_MAX_BYTES.
 * @param[out] SIGNATURE Buffer receiving the fixed-size signature.
 * @param[in] SIGNATURE_LENGTH Available bytes in SIGNATURE; must be at least
 *                             LIBERAC_SLH_DSA_SIGNATURE_SIZE(ALG).
 * @param[in] ALG SLH-DSA parameter-set identifier matching PRIVATE_KEY.
 * @return LIBERAC_SUCCESS on success, LIBERAC_ERROR_INVALID_KEY for a private-key
 *         length mismatch, or another negative LiberaCError on failure.
 * @note The required signature region is cleared if signing fails after
 *       buffer validation.
 */
LIBERAC_API LiberaCError LIBERAC_SLH_DSA_SIGN(const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Verify a non-prehash SLH-DSA signature.
 * @param[in] PUBLIC_KEY Encoded SLH-DSA public key.
 * @param[in] PUBLIC_KEY_LENGTH Exact encoded public-key size for ALG.
 * @param[in] MESSAGE Message bytes; may be null only when MESSAGE_LENGTH is zero.
 * @param[in] MESSAGE_LENGTH Message length in bytes.
 * @param[in] CONTEXT Domain-separation context used when signing; may be null
 *                    only when CONTEXT_LENGTH is zero.
 * @param[in] CONTEXT_LENGTH Context length from 0 through
 *                           LIBERAC_SIGNATURE_CONTEXT_MAX_BYTES.
 * @param[in] SIGNATURE Encoded signature.
 * @param[in] SIGNATURE_LENGTH Exact signature size for ALG.
 * @param[in] ALG SLH-DSA parameter-set identifier matching the key and signature.
 * @return LIBERAC_SUCCESS for a valid signature,
 *         LIBERAC_ERROR_SIGNATURE_INVALID for a malformed or non-matching
 *         signature, LIBERAC_ERROR_INVALID_KEY for a public-key length mismatch,
 *         or another negative LiberaCError for invalid inputs.
 */
LIBERAC_API LiberaCError LIBERAC_SLH_DSA_VERIFY(const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, const uint8_t *MESSAGE, size_t MESSAGE_LENGTH, const uint8_t *CONTEXT, size_t CONTEXT_LENGTH, const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH, LiberaCAlgID ALG);
LIBERAC_END_DECLS

#endif

/** @} */
