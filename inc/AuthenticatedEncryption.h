/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file AuthenticatedEncryption.h
 * @brief Runtime-selected authenticated-encryption API.
 *
 * @defgroup crypto_authenticated_encryption Authenticated-encryption API
 * @brief One-shot AES-GCM, AES-CCM, and ChaCha20-Poly1305 AEAD.
 *
 * Nonce and tag constraints are algorithm-specific and can be checked before
 * an operation with LIBERAC_AEAD_NONCE_LENGTH_VALID() and
 * LIBERAC_AEAD_TAG_LENGTH_VALID(). A nonce must never be reused with the same
 * key. Authentication failure clears the plaintext output.
 * @{
 */
#ifndef LIBERAC_AUTHENTICATED_ENCRYPTION_H
#define LIBERAC_AUTHENTICATED_ENCRYPTION_H

#include "Def.h"

/** Recommended interoperable AES-GCM nonce size, in bytes. */
#define LIBERAC_AES_GCM_RECOMMENDED_NONCE_BYTES 12u
/** Smallest AES-CCM nonce size, in bytes. */
#define LIBERAC_AES_CCM_MIN_NONCE_BYTES 7u
/** Largest AES-CCM nonce size, in bytes. */
#define LIBERAC_AES_CCM_MAX_NONCE_BYTES 13u
/** Largest authentication tag accepted by an AES AEAD mode. */
#define LIBERAC_AES_AEAD_MAX_TAG_BYTES 16u
/** ChaCha20-Poly1305 key size, in bytes. */
#define LIBERAC_CHACHA20_POLY1305_KEY_BYTES 32u
/** ChaCha20-Poly1305 nonce size, in bytes. */
#define LIBERAC_CHACHA20_POLY1305_NONCE_BYTES 12u
/** ChaCha20-Poly1305 authentication-tag size, in bytes. */
#define LIBERAC_CHACHA20_POLY1305_TAG_BYTES 16u

LIBERAC_BEGIN_DECLS

/** Return the key size for a supported AEAD identifier, or zero. */
LIBERAC_API size_t LIBERAC_AEAD_KEY_SIZE(LiberaCAlgID ALG);
/** Return nonzero exactly when @p NONCE_LENGTH is valid for @p ALG. */
LIBERAC_API int LIBERAC_AEAD_NONCE_LENGTH_VALID(
    LiberaCAlgID ALG, size_t NONCE_LENGTH);
/** Return nonzero exactly when @p TAG_LENGTH is valid for @p ALG. */
LIBERAC_API int LIBERAC_AEAD_TAG_LENGTH_VALID(
    LiberaCAlgID ALG, size_t TAG_LENGTH);

/**
 * @brief Encrypt and authenticate a message.
 *
 * @p OUTPUT may equal @p INPUT for in-place encryption. Other partial overlap
 * is rejected. The tag range must be disjoint from the message, key, nonce,
 * and AAD ranges.
 *
 * AES-GCM accepts a non-empty nonce (12 bytes is recommended) and tag lengths
 * 4, 8, or 12 through 16. AES-CCM accepts nonce lengths 7 through 13 and even
 * tag lengths 4 through 16. ChaCha20-Poly1305 requires a 12-byte nonce and a
 * 16-byte tag.
 *
 * @param[out] OUTPUT Ciphertext, or NULL for an empty plaintext.
 * @param[in] OUTPUT_CAPACITY Size of @p OUTPUT in bytes.
 * @param[out] TAG Destination for the authentication tag.
 * @param[in] TAG_CAPACITY Size of @p TAG in bytes.
 * @param[in] TAG_LENGTH Requested tag length in bytes.
 * @param[in] INPUT Plaintext, or NULL when @p INPUT_LENGTH is zero.
 * @param[in] INPUT_LENGTH Plaintext length in bytes.
 * @param[in] KEY Secret key.
 * @param[in] KEY_LENGTH Size of @p KEY in bytes.
 * @param[in] NONCE Unique nonce for this key.
 * @param[in] NONCE_LENGTH Size of @p NONCE in bytes.
 * @param[in] AAD Additional authenticated data, or NULL when empty.
 * @param[in] AAD_LENGTH Additional authenticated-data length in bytes.
 * @param[in] ALG A supported AEAD identifier.
 *
 * @retval LIBERAC_SUCCESS Encryption and authentication completed.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer, length, or overlap is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH is invalid.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL An output or tag buffer is too small.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE An algorithm length limit was exceeded.
 */
LIBERAC_API LiberaCError LIBERAC_AEAD_ENCRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    uint8_t *TAG, size_t TAG_CAPACITY, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Authenticate and decrypt a message.
 *
 * Buffer, overlap, nonce, and tag rules match LIBERAC_AEAD_ENCRYPT(). On an
 * authentication failure, @p INPUT_LENGTH bytes of @p OUTPUT are cleared,
 * including for in-place operation.
 *
 * @param[out] OUTPUT Plaintext, or NULL for an empty ciphertext.
 * @param[in] OUTPUT_CAPACITY Size of @p OUTPUT in bytes.
 * @param[in] TAG Authentication tag to verify.
 * @param[in] TAG_LENGTH Size of @p TAG in bytes.
 * @param[in] INPUT Ciphertext, or NULL when @p INPUT_LENGTH is zero.
 * @param[in] INPUT_LENGTH Ciphertext length in bytes.
 * @param[in] KEY Secret key.
 * @param[in] KEY_LENGTH Size of @p KEY in bytes.
 * @param[in] NONCE Nonce used for encryption.
 * @param[in] NONCE_LENGTH Size of @p NONCE in bytes.
 * @param[in] AAD Additional authenticated data, or NULL when empty.
 * @param[in] AAD_LENGTH Additional authenticated-data length in bytes.
 * @param[in] ALG A supported AEAD identifier.
 *
 * @retval LIBERAC_SUCCESS Authentication and decryption completed.
 * @retval LIBERAC_ERROR_AUTHENTICATION_FAILED The tag is invalid.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer, length, or overlap is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH is invalid.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p OUTPUT_CAPACITY is too small.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE An algorithm length limit was exceeded.
 */
LIBERAC_API LiberaCError LIBERAC_AEAD_DECRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    LiberaCAlgID ALG);

LIBERAC_END_DECLS
#endif

/** @} */
