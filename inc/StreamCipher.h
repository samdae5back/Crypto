/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file StreamCipher.h
 * @brief Runtime-selected stream-cipher API.
 *
 * @defgroup crypto_stream_cipher Stream-cipher API
 * @brief One-shot encryption and decryption with RFC 8439 ChaCha20.
 *
 * The supported ChaCha20 variant has a 256-bit key, a 32-bit block counter,
 * and a 96-bit nonce. Encryption and decryption are the same XOR operation.
 * A nonce must never be reused with the same key. The caller must arrange
 * unique nonces and must not use a counter range more than once for a given
 * key and nonce.
 * @{
 */
#ifndef LIBERAC_STREAM_CIPHER_H
#define LIBERAC_STREAM_CIPHER_H

#include "Def.h"

/** ChaCha20 key size, in bytes. */
#define LIBERAC_CHACHA20_KEY_BYTES 32u
/** RFC 8439 ChaCha20 nonce size, in bytes. */
#define LIBERAC_CHACHA20_NONCE_BYTES 12u
/** ChaCha20 keystream block size, in bytes. */
#define LIBERAC_CHACHA20_BLOCK_BYTES 64u

LIBERAC_BEGIN_DECLS

/**
 * @brief Return the key size required by a stream-cipher identifier.
 *
 * @param[in] ALG A supported stream-cipher identifier.
 * @return Required key size in bytes, or zero for an unsupported identifier.
 */
LIBERAC_API size_t LIBERAC_STREAM_CIPHER_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the nonce size required by a stream-cipher identifier.
 *
 * @param[in] ALG A supported stream-cipher identifier.
 * @return Required nonce size in bytes, or zero for an unsupported identifier.
 */
LIBERAC_API size_t LIBERAC_STREAM_CIPHER_NONCE_SIZE(LiberaCAlgID ALG);

/**
 * @brief XOR input with a runtime-selected stream cipher.
 *
 * @p OUTPUT may equal @p INPUT for in-place operation. Any other overlap is
 * rejected. The output must not overlap the key or nonce. Empty input is
 * accepted with NULL input and output pointers.
 *
 * RFC 8439 ChaCha20 permits at most the blocks from @p INITIAL_COUNTER through
 * `UINT32_MAX`, inclusive. A request that would wrap the counter is rejected.
 * Counter zero is permitted for the standalone cipher; protocols such as
 * ChaCha20-Poly1305 reserve it for one-time-key generation and start payload
 * encryption at counter one.
 *
 * @param[out] OUTPUT Output buffer, or NULL when @p INPUT_LENGTH is zero.
 * @param[in]  OUTPUT_CAPACITY Size of @p OUTPUT in bytes.
 * @param[in]  INPUT Input buffer, or NULL when @p INPUT_LENGTH is zero.
 * @param[in]  INPUT_LENGTH Number of bytes to transform.
 * @param[in]  KEY Secret key.
 * @param[in]  KEY_LENGTH Size of @p KEY in bytes.
 * @param[in]  NONCE Unique nonce for this key.
 * @param[in]  NONCE_LENGTH Size of @p NONCE in bytes.
 * @param[in]  INITIAL_COUNTER Initial 32-bit block counter.
 * @param[in]  ALG A supported stream-cipher identifier.
 *
 * @retval LIBERAC_SUCCESS The operation completed.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer, nonce size, or overlap is invalid.
 * @retval LIBERAC_ERROR_INVALID_KEY @p KEY_LENGTH is invalid.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL @p OUTPUT_CAPACITY is too small.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE The counter would wrap.
 */
LIBERAC_API LiberaCError LIBERAC_STREAM_CIPHER_XOR(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    uint32_t INITIAL_COUNTER,
    LiberaCAlgID ALG);

LIBERAC_END_DECLS
#endif

/** @} */
