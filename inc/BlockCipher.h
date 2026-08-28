/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file BlockCipher.h
 * @brief Runtime-selected AES and Triple-DES encryption/decryption API.
 *
 * @defgroup crypto_block_cipher Block-cipher API
 * @brief AES in ECB/CBC/CTR/CCM/GCM and three-key Triple-DES in ECB/CBC.
 *
 * Encryption and decryption preserve the input length. No padding scheme is
 * applied: AES ECB/CBC callers supply 16-byte blocks and Triple-DES ECB/CBC
 * callers supply 8-byte blocks. CCM and GCM are authenticated modes
 * and produce or consume a separate authentication tag.
 * @{
 */
#ifndef LIBERAC_BLOCK_CIPHER_H
#define LIBERAC_BLOCK_CIPHER_H

#include "Def.h"

/** AES block size and required ECB/CBC input alignment, in bytes. */
#define LIBERAC_BLOCK_CIPHER_BLOCK_BYTES 16u
/** Largest authentication tag produced or accepted by an AES AEAD mode. */
#define LIBERAC_BLOCK_CIPHER_MAX_TAG_BYTES 16u
/** AES-128 master-key size, in bytes. */
#define LIBERAC_AES_128_KEY_BYTES 16u
/** AES-192 master-key size, in bytes. */
#define LIBERAC_AES_192_KEY_BYTES 24u
/** AES-256 master-key size, in bytes. */
#define LIBERAC_AES_256_KEY_BYTES 32u
/** Three-key Triple-DES EDE master-key size, in bytes. */
#define LIBERAC_TDES_EDE3_KEY_BYTES 24u
/** Triple-DES block size and required ECB/CBC input alignment, in bytes. */
#define LIBERAC_TDES_BLOCK_BYTES 8u

LIBERAC_BEGIN_DECLS

/**
 * @brief Return the master-key size required by a block-cipher identifier.
 *
 * @param[in] ALG A supported @c LIBERAC_ALG_AES_* or @c LIBERAC_ALG_TDES_* identifier.
 *
 * @return Required key size in bytes, or zero if @p ALG is not a supported
 *         block-cipher identifier.
 *
 * @par Generating an AES master key
 * An AES master key is simply a uniformly random byte string of the size
 * returned by this function.  Generate it with LIBERAC_RANDOM_BYTES() (declared
 * by RandomNumberGeneration.h), store it as secret key material, and pass it
 * directly to the encryption/decryption operation.  The internal AES round-key
 * schedule is derived for each operation and must not be generated, stored, or
 * exposed by callers.
 * @code{.c}
 * uint8_t key[LIBERAC_AES_256_KEY_BYTES];
 * size_t key_length = LIBERAC_BLOCK_CIPHER_KEY_SIZE(LIBERAC_ALG_AES_256_GCM);
 * LiberaCError error = LIBERAC_RANDOM_BYTES(key, key_length);
 * @endcode
 */
LIBERAC_API size_t LIBERAC_BLOCK_CIPHER_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Encrypt data with a runtime-selected block cipher and mode.
 *
 * The ciphertext length is exactly @p INPUT_LENGTH.  The mode-specific
 * requirements are:
 *
 * - AES ECB: @p INPUT_LENGTH is a multiple of 16; @p IV_LENGTH,
 *   @p AAD_LENGTH, and @p TAG_LENGTH are zero.
 * - AES CBC: @p INPUT_LENGTH is a multiple of 16; the IV is exactly 16 bytes;
 *   @p AAD_LENGTH and @p TAG_LENGTH are zero.
 * - CTR: the initial counter is exactly 16 bytes; @p AAD_LENGTH and
 *   @p TAG_LENGTH are zero.  Any input length is accepted.
 * - CCM: the nonce is 7 through 13 bytes and the tag length is an even value
 *   from 4 through 16 bytes.  The nonce length also determines the maximum
 *   encodable message length.
 * - GCM: the IV is non-empty (12 bytes is the usual interoperable choice) and
 *   the tag length is 4, 8, or 12 through 16 bytes.
 * - Triple-DES ECB/CBC: @p INPUT_LENGTH is a multiple of 8; CBC uses an
 *   8-byte IV. AAD and tags are not accepted.
 *
 * A counter/nonce must never be reused with the same key in CTR, CCM, or GCM.
 * CBC IVs must be unpredictable and unique for the key.  ECB provides no
 * semantic security for repeated blocks and should only be used when a
 * protocol explicitly requires it.
 *
 * @param[out] OUTPUT Ciphertext buffer.  May be NULL only when
 *                    @p INPUT_LENGTH is zero.
 * @param[in]  OUTPUT_CAPACITY Size of @p OUTPUT in bytes; must be at least
 *                             @p INPUT_LENGTH.
 * @param[out] TAG Authentication-tag buffer for CCM/GCM.  It must hold exactly
 *                   @p TAG_LENGTH bytes.  It is ignored by non-AEAD modes when
 *                   @p TAG_LENGTH is zero.
 * @param[in]  TAG_LENGTH Requested authentication-tag length in bytes, or zero
 *                        for ECB/CBC/CTR.
 * @param[in]  INPUT Plaintext buffer.  May be NULL only when
 *                   @p INPUT_LENGTH is zero.
 * @param[in]  INPUT_LENGTH Plaintext length in bytes.
 * @param[in]  KEY Master key for the selected block cipher.
 * @param[in]  KEY_LENGTH Size of @p KEY in bytes; it must exactly match the
 *                        key size encoded by @p ALG.
 * @param[in]  IV Initialization vector, initial counter, or nonce as required
 *               by the selected mode; use NULL for ECB.
 * @param[in]  IV_LENGTH Size of @p IV in bytes, or zero for ECB.
 * @param[in]  AAD Additional authenticated data for CCM/GCM.  May be NULL when
 *                 @p AAD_LENGTH is zero and is not accepted by other modes.
 * @param[in]  AAD_LENGTH Additional authenticated-data length in bytes.
 * @param[in]  ALG A supported AES or Triple-DES identifier.
 *
 * @retval LIBERAC_SUCCESS Encryption completed successfully.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not a supported selector.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer, length, or mode-specific
 *         parameter is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH does not match @p ALG.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p OUTPUT_CAPACITY is smaller than
 *         @p INPUT_LENGTH.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE A CCM/GCM length limit was exceeded.
 */
LIBERAC_API LiberaCError LIBERAC_BLOCK_CIPHER_ENCRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Decrypt data with a runtime-selected block cipher and mode.
 *
 * Parameters and mode constraints are identical to
 * LIBERAC_BLOCK_CIPHER_ENCRYPT(), except that @p INPUT is ciphertext and
 * @p OUTPUT receives plaintext.  For CCM/GCM, authentication is verified using
 * @p TAG.  If authentication fails, the function returns
 * LIBERAC_ERROR_AUTHENTICATION_FAILED and clears @p INPUT_LENGTH bytes of the
 * plaintext output; callers must not use that output.
 *
 * @param[out] OUTPUT Plaintext buffer.  May be NULL only when
 *                    @p INPUT_LENGTH is zero.
 * @param[in]  OUTPUT_CAPACITY Size of @p OUTPUT in bytes; must be at least
 *                             @p INPUT_LENGTH.
 * @param[in]  TAG Authentication tag to verify for CCM/GCM.  It is ignored by
 *                 non-AEAD modes when @p TAG_LENGTH is zero.
 * @param[in]  TAG_LENGTH Authentication-tag length in bytes, or zero for
 *                        ECB/CBC/CTR.
 * @param[in]  INPUT Ciphertext buffer.  May be NULL only when
 *                   @p INPUT_LENGTH is zero.
 * @param[in]  INPUT_LENGTH Ciphertext length in bytes.
 * @param[in]  KEY Master key for the selected block cipher.
 * @param[in]  KEY_LENGTH Size of @p KEY in bytes; it must exactly match the
 *                        key size encoded by @p ALG.
 * @param[in]  IV Initialization vector, initial counter, or nonce as required
 *               by the selected mode; use NULL for ECB.
 * @param[in]  IV_LENGTH Size of @p IV in bytes, or zero for ECB.
 * @param[in]  AAD Additional authenticated data for CCM/GCM.  May be NULL when
 *                 @p AAD_LENGTH is zero and is not accepted by other modes.
 * @param[in]  AAD_LENGTH Additional authenticated-data length in bytes.
 * @param[in]  ALG A supported AES or Triple-DES identifier.
 *
 * @retval LIBERAC_SUCCESS Decryption and, for AEAD, authentication succeeded.
 * @retval LIBERAC_ERROR_AUTHENTICATION_FAILED The CCM/GCM tag is invalid.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not a supported selector.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer, length, or mode-specific
 *         parameter is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH does not match @p ALG.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p OUTPUT_CAPACITY is smaller than
 *         @p INPUT_LENGTH.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE A CCM/GCM length limit was exceeded.
 */
LIBERAC_API LiberaCError LIBERAC_BLOCK_CIPHER_DECRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    LiberaCAlgID ALG);

LIBERAC_END_DECLS
#endif

/** @} */
