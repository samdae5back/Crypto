/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file BlockCipher.h
 * @brief Runtime-selected AES and Triple-DES encryption/decryption API.
 *
 * @defgroup crypto_block_cipher Block-cipher API
 * @brief AES in ECB/CBC/CTR and three-key Triple-DES in ECB/CBC.
 *
 * Encryption and decryption preserve the input length. No padding scheme is
 * applied: AES ECB/CBC callers supply 16-byte blocks and Triple-DES ECB/CBC
 * callers supply 8-byte blocks. Authenticated modes such as AES-GCM and
 * AES-CCM are exposed by AuthenticatedEncryption.h instead.
 * @{
 */
#ifndef LIBERAC_BLOCK_CIPHER_H
#define LIBERAC_BLOCK_CIPHER_H

#include "Def.h"

/** AES block size and required ECB/CBC input alignment, in bytes. */
#define LIBERAC_BLOCK_CIPHER_BLOCK_BYTES 16u
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
 * @return Required key size in bytes, or zero if @p ALG is unsupported.
 *
 * An AES master key is a uniformly random byte string of the returned size.
 * The internal round-key schedule is derived for each operation.
 * @code{.c}
 * uint8_t key[LIBERAC_AES_256_KEY_BYTES];
 * size_t key_length = LIBERAC_BLOCK_CIPHER_KEY_SIZE(LIBERAC_ALG_AES_256_CTR);
 * LiberaCError error = LIBERAC_RANDOM_BYTES(key, key_length);
 * @endcode
 */
LIBERAC_API size_t LIBERAC_BLOCK_CIPHER_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Encrypt data with a runtime-selected block cipher and mode.
 *
 * The ciphertext length is exactly @p INPUT_LENGTH. AES ECB/CBC require
 * 16-byte-aligned input; Triple-DES ECB/CBC require 8-byte-aligned input.
 * ECB takes no IV. AES CBC/CTR take a 16-byte IV or initial counter, and
 * Triple-DES CBC takes an 8-byte IV. CTR accepts any input length.
 *
 * A counter must never be reused with the same key in CTR. CBC IVs must be
 * unpredictable and unique for the key. ECB should only be used when a
 * protocol explicitly requires it. Triple-DES is exposed only for legacy
 * interoperability and is unsuitable for new designs.
 *
 * @param[out] OUTPUT Ciphertext, or NULL when @p INPUT_LENGTH is zero.
 * @param[in] OUTPUT_CAPACITY Size of @p OUTPUT; at least @p INPUT_LENGTH.
 * @param[in] INPUT Plaintext, or NULL when @p INPUT_LENGTH is zero.
 * @param[in] INPUT_LENGTH Plaintext length in bytes.
 * @param[in] KEY Master key for the selected cipher.
 * @param[in] KEY_LENGTH Size of @p KEY; must exactly match @p ALG.
 * @param[in] IV IV or initial counter, or NULL for ECB.
 * @param[in] IV_LENGTH Size of @p IV, or zero for ECB.
 * @param[in] ALG A supported unauthenticated AES or Triple-DES identifier.
 *
 * @retval LIBERAC_SUCCESS Encryption completed successfully.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer or mode parameter is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH does not match @p ALG.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p OUTPUT_CAPACITY is too small.
 */
LIBERAC_API LiberaCError LIBERAC_BLOCK_CIPHER_ENCRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Decrypt data with a runtime-selected block cipher and mode.
 *
 * Parameters and mode constraints match LIBERAC_BLOCK_CIPHER_ENCRYPT(), except
 * that @p INPUT is ciphertext and @p OUTPUT receives plaintext.
 */
LIBERAC_API LiberaCError LIBERAC_BLOCK_CIPHER_DECRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    LiberaCAlgID ALG);

LIBERAC_END_DECLS
#endif

/** @} */
