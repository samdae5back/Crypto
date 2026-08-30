/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file KeyDerivation.h
 * @brief Runtime-selected HKDF and PBKDF2-HMAC API.
 *
 * @defgroup crypto_key_derivation Key-derivation API
 * @brief RFC 5869 HKDF and PBKDF2-HMAC over the existing HMAC layer.
 *
 * The final LiberaCAlgID selects the HMAC hash. The accepted identifiers are
 * the same fixed-output SHA-1, SHA-2, and SHA-3 identifiers accepted by
 * LIBERAC_HMAC(). SHAKE and LSH identifiers are rejected.
 *
 * SHA-1 is provided only for legacy interoperability. New designs should use
 * a modern hash such as SHA-256, SHA-384, SHA-512, or an appropriate SHA-3
 * variant. PBKDF2 iteration counts and salt sizes are application security
 * parameters rather than library defaults; applications should follow the
 * current policy applicable to their protocol and deployment environment.
 * @{
 */
#ifndef LIBERAC_KEY_DERIVATION_H
#define LIBERAC_KEY_DERIVATION_H

#include "Def.h"

LIBERAC_BEGIN_DECLS

/**
 * @brief Return the RFC 5869 pseudorandom-key size for a supported HKDF hash.
 *
 * @param[in] ALG A fixed-output SHA-1, SHA-2, or SHA-3 identifier accepted by
 *                HMAC.
 * @return Hash output size in bytes, or zero when @p ALG is not accepted.
 */
LIBERAC_API size_t LIBERAC_HKDF_PRK_SIZE(LiberaCAlgID ALG);

/**
 * @brief Perform RFC 5869 HKDF-Extract.
 *
 * The result is exactly LIBERAC_HKDF_PRK_SIZE(@p ALG) bytes. When
 * @p SALT_LENGTH is zero, the RFC 5869 default salt of HashLen zero octets is
 * used. @p IKM may be NULL only when @p IKM_LENGTH is zero.
 *
 * @param[out] PRK Destination for the extracted pseudorandom key.
 * @param[in] PRK_CAPACITY Size of @p PRK in bytes.
 * @param[in] IKM Input keying material.
 * @param[in] IKM_LENGTH Input-keying-material length in bytes.
 * @param[in] SALT Optional salt.
 * @param[in] SALT_LENGTH Salt length in bytes; zero selects the RFC default.
 * @param[in] ALG Runtime-selected HMAC hash identifier.
 *
 * @retval LIBERAC_SUCCESS The PRK was produced.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not accepted by HMAC.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A required pointer is invalid or an
 *         output range overlaps an input range.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p PRK_CAPACITY is too small.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE A selected hash input limit was
 *         exceeded.
 */
LIBERAC_API LiberaCError LIBERAC_HKDF_EXTRACT(
    uint8_t *PRK, size_t PRK_CAPACITY,
    const uint8_t *IKM, size_t IKM_LENGTH,
    const uint8_t *SALT, size_t SALT_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Perform RFC 5869 HKDF-Expand.
 *
 * @p PRK_LENGTH must be at least HashLen. @p OKM_LENGTH may be zero and must
 * not exceed 255 * HashLen. A zero-length output may use a NULL @p OKM.
 *
 * @param[out] OKM Destination for output keying material.
 * @param[in] OKM_CAPACITY Size of @p OKM in bytes.
 * @param[in] OKM_LENGTH Requested output length in bytes.
 * @param[in] PRK Pseudorandom key, normally produced by HKDF-Extract.
 * @param[in] PRK_LENGTH PRK length in bytes; at least HashLen is required.
 * @param[in] INFO Optional context/application information.
 * @param[in] INFO_LENGTH Information length in bytes.
 * @param[in] ALG Runtime-selected HMAC hash identifier.
 *
 * @retval LIBERAC_SUCCESS The requested output was produced.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not accepted by HMAC.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer, PRK length, or overlapping
 *         range is invalid.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p OKM_CAPACITY is too small.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE The RFC 5869 output limit or a hash
 *         input-length limit was exceeded.
 * @retval LIBERAC_ERROR_ALLOCATION_FAILED Temporary workspace allocation
 *         failed.
 */
LIBERAC_API LiberaCError LIBERAC_HKDF_EXPAND(
    uint8_t *OKM, size_t OKM_CAPACITY, size_t OKM_LENGTH,
    const uint8_t *PRK, size_t PRK_LENGTH,
    const uint8_t *INFO, size_t INFO_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Perform RFC 5869 HKDF-Extract followed by HKDF-Expand.
 *
 * Parameters have the same meaning and constraints as the two component
 * operations. The intermediate PRK is held only in local temporary storage and
 * is explicitly erased before return.
 */
LIBERAC_API LiberaCError LIBERAC_HKDF(
    uint8_t *OKM, size_t OKM_CAPACITY, size_t OKM_LENGTH,
    const uint8_t *IKM, size_t IKM_LENGTH,
    const uint8_t *SALT, size_t SALT_LENGTH,
    const uint8_t *INFO, size_t INFO_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Derive a key with PBKDF2 using runtime-selected HMAC.
 *
 * This implements the PBKDF2 construction from PKCS #5/RFC 8018. The
 * iteration count must be positive and the derived-key length must be positive
 * and no more than (2^32 - 1) * HashLen. Empty passwords and salts are accepted
 * for protocol compatibility and test-vector use.
 *
 * RFC 8018 assigns standard PRF identifiers to HMAC with SHA-1 and SHA-2.
 * LiberaCrypt also permits its fixed-output SHA-3 HMAC identifiers through the
 * same generic API; applications that require a particular encoded PBKDF2
 * profile must separately ensure that their protocol permits that PRF.
 *
 * @param[out] DERIVED_KEY Destination for the derived key.
 * @param[in] DERIVED_KEY_CAPACITY Size of @p DERIVED_KEY in bytes.
 * @param[in] DERIVED_KEY_LENGTH Requested derived-key length in bytes.
 * @param[in] PASSWORD Password octets. It may be NULL only when
 *                     @p PASSWORD_LENGTH is zero.
 * @param[in] PASSWORD_LENGTH Password length in bytes.
 * @param[in] SALT Salt octets. It may be NULL only when @p SALT_LENGTH is zero.
 * @param[in] SALT_LENGTH Salt length in bytes.
 * @param[in] ITERATION_COUNT Positive PBKDF2 iteration count.
 * @param[in] ALG Runtime-selected HMAC hash identifier.
 *
 * @retval LIBERAC_SUCCESS The derived key was produced.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not accepted by HMAC.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer, length, iteration count, or
 *         overlapping range is invalid.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL The destination is too small.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE The PBKDF2 block-count limit, a
 *         temporary input length, or a hash input-length limit was exceeded.
 * @retval LIBERAC_ERROR_ALLOCATION_FAILED Temporary workspace allocation
 *         failed.
 */
LIBERAC_API LiberaCError LIBERAC_PBKDF2_HMAC(
    uint8_t *DERIVED_KEY, size_t DERIVED_KEY_CAPACITY,
    size_t DERIVED_KEY_LENGTH,
    const uint8_t *PASSWORD, size_t PASSWORD_LENGTH,
    const uint8_t *SALT, size_t SALT_LENGTH,
    uint64_t ITERATION_COUNT,
    LiberaCAlgID ALG);

LIBERAC_END_DECLS

#endif

/** @} */
