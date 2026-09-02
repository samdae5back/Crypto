/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file AuthenticatedEncryption.h
 * @brief Runtime-selected authenticated-encryption API.
 *
 * @defgroup crypto_authenticated_encryption Authenticated-encryption API
 * @brief One-shot RFC 8439 ChaCha20-Poly1305 AEAD.
 *
 * The complete 16-byte authentication tag is always produced and required;
 * tag truncation is not supported. A nonce must never be reused with the same
 * key. Decryption authenticates the ciphertext and associated data before
 * releasing plaintext and clears the plaintext buffer on authentication
 * failure.
 * @{
 */
#ifndef LIBERAC_AUTHENTICATED_ENCRYPTION_H
#define LIBERAC_AUTHENTICATED_ENCRYPTION_H

#include "Def.h"

/** ChaCha20-Poly1305 key size, in bytes. */
#define LIBERAC_CHACHA20_POLY1305_KEY_BYTES 32u
/** ChaCha20-Poly1305 nonce size, in bytes. */
#define LIBERAC_CHACHA20_POLY1305_NONCE_BYTES 12u
/** ChaCha20-Poly1305 authentication-tag size, in bytes. */
#define LIBERAC_CHACHA20_POLY1305_TAG_BYTES 16u

LIBERAC_BEGIN_DECLS

/** Return the key size for a supported AEAD identifier, or zero. */
LIBERAC_API size_t LIBERAC_AEAD_KEY_SIZE(LiberaCAlgID ALG);
/** Return the nonce size for a supported AEAD identifier, or zero. */
LIBERAC_API size_t LIBERAC_AEAD_NONCE_SIZE(LiberaCAlgID ALG);
/** Return the full tag size for a supported AEAD identifier, or zero. */
LIBERAC_API size_t LIBERAC_AEAD_TAG_SIZE(LiberaCAlgID ALG);

/**
 * @brief Encrypt and authenticate a message.
 *
 * @p OUTPUT may equal @p INPUT for in-place encryption. Any other input/output
 * overlap is rejected. The output and tag ranges must be disjoint from each
 * other, from the key and nonce, and from the AAD. The complete standard tag
 * is written when @p TAG_CAPACITY is at least LIBERAC_AEAD_TAG_SIZE(@p ALG).
 *
 * @param[out] OUTPUT Ciphertext, or NULL for an empty plaintext.
 * @param[in]  OUTPUT_CAPACITY Size of @p OUTPUT in bytes.
 * @param[out] TAG Destination for the complete authentication tag.
 * @param[in]  TAG_CAPACITY Size of @p TAG in bytes.
 * @param[in]  INPUT Plaintext, or NULL when @p INPUT_LENGTH is zero.
 * @param[in]  INPUT_LENGTH Plaintext length in bytes.
 * @param[in]  KEY Secret key.
 * @param[in]  KEY_LENGTH Size of @p KEY in bytes.
 * @param[in]  NONCE Unique nonce for this key.
 * @param[in]  NONCE_LENGTH Size of @p NONCE in bytes.
 * @param[in]  AAD Additional authenticated data, or NULL when empty.
 * @param[in]  AAD_LENGTH Additional authenticated-data length in bytes.
 * @param[in]  ALG A supported AEAD identifier.
 *
 * @retval LIBERAC_SUCCESS Encryption and authentication completed.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer, nonce size, or overlap is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH is invalid.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL An output buffer is too small.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE An RFC 8439 length limit was exceeded.
 */
LIBERAC_API LiberaCError LIBERAC_AEAD_ENCRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    uint8_t *TAG, size_t TAG_CAPACITY,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Authenticate and decrypt a message.
 *
 * Buffer and overlap rules match LIBERAC_AEAD_ENCRYPT(). @p TAG_LENGTH must
 * equal LIBERAC_AEAD_TAG_SIZE(@p ALG). Authentication is performed before
 * decryption. On an authentication failure, @p INPUT_LENGTH bytes of @p OUTPUT
 * are cleared, including for in-place operation.
 *
 * @param[out] OUTPUT Plaintext, or NULL for an empty ciphertext.
 * @param[in]  OUTPUT_CAPACITY Size of @p OUTPUT in bytes.
 * @param[in]  TAG Complete authentication tag.
 * @param[in]  TAG_LENGTH Size of @p TAG in bytes.
 * @param[in]  INPUT Ciphertext, or NULL when @p INPUT_LENGTH is zero.
 * @param[in]  INPUT_LENGTH Ciphertext length in bytes.
 * @param[in]  KEY Secret key.
 * @param[in]  KEY_LENGTH Size of @p KEY in bytes.
 * @param[in]  NONCE Nonce used for encryption.
 * @param[in]  NONCE_LENGTH Size of @p NONCE in bytes.
 * @param[in]  AAD Additional authenticated data, or NULL when empty.
 * @param[in]  AAD_LENGTH Additional authenticated-data length in bytes.
 * @param[in]  ALG A supported AEAD identifier.
 *
 * @retval LIBERAC_SUCCESS Authentication and decryption completed.
 * @retval LIBERAC_ERROR_AUTHENTICATION_FAILED The tag is invalid.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer, length, or overlap is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH is invalid.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p OUTPUT_CAPACITY is too small.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE An RFC 8439 length limit was exceeded.
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
