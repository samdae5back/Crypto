/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * @file HashFunction.h
 * @brief Runtime-selected one-shot and incremental hash/XOF API.
 *
 * @defgroup crypto_hash Hash-function API
 * @brief SHA-2, SHA-3, SHAKE, and LSH through one runtime-selected API.
 * @{
 */
#ifndef LIBERAC_HASH_FUNCTION_H
#define LIBERAC_HASH_FUNCTION_H

#include "Def.h"

/** Maximum digest size among the fixed-output hash algorithms, in bytes. */
#define LIBERAC_HASH_MAX_DIGEST_BYTES 64u
/** SHA-224 digest size, in bytes. */
#define LIBERAC_SHA2_224_DIGEST_BYTES 28u
/** SHA-256 digest size, in bytes. */
#define LIBERAC_SHA2_256_DIGEST_BYTES 32u
/** SHA-384 digest size, in bytes. */
#define LIBERAC_SHA2_384_DIGEST_BYTES 48u
/** SHA-512 digest size, in bytes. */
#define LIBERAC_SHA2_512_DIGEST_BYTES 64u
/** SHA-512/224 digest size, in bytes. */
#define LIBERAC_SHA2_512_224_DIGEST_BYTES 28u
/** SHA-512/256 digest size, in bytes. */
#define LIBERAC_SHA2_512_256_DIGEST_BYTES 32u
/** LSH-256-224 digest size, in bytes. */
#define LIBERAC_LSH_256_224_DIGEST_BYTES 28u
/** LSH-256-256 digest size, in bytes. */
#define LIBERAC_LSH_256_256_DIGEST_BYTES 32u
/** LSH-512-224 digest size, in bytes. */
#define LIBERAC_LSH_512_224_DIGEST_BYTES 28u
/** LSH-512-256 digest size, in bytes. */
#define LIBERAC_LSH_512_256_DIGEST_BYTES 32u
/** LSH-512-384 digest size, in bytes. */
#define LIBERAC_LSH_512_384_DIGEST_BYTES 48u
/** LSH-512-512 digest size, in bytes. */
#define LIBERAC_LSH_512_512_DIGEST_BYTES 64u
/** SHA3-224 digest size, in bytes. */
#define LIBERAC_SHA3_224_DIGEST_BYTES 28u
/** SHA3-256 digest size, in bytes. */
#define LIBERAC_SHA3_256_DIGEST_BYTES 32u
/** SHA3-384 digest size, in bytes. */
#define LIBERAC_SHA3_384_DIGEST_BYTES 48u
/** SHA3-512 digest size, in bytes. */
#define LIBERAC_SHA3_512_DIGEST_BYTES 64u

/**
 * @brief Storage reserved for an incremental hash context, in bytes.
 *
 * The size is part of the public ABI.  Applications must use
 * LiberaCHashContext rather than interpreting this storage directly.
 */
#define LIBERAC_HASH_CONTEXT_BYTES 512u

/**
 * @brief Opaque mutable state for an incremental hash or XOF operation.
 *
 * Initialize the object with LIBERAC_HASH_INIT(), feed input with
 * LIBERAC_HASH_UPDATE(), finish absorption with LIBERAC_HASH_FINALIZE(), and
 * obtain output with LIBERAC_HASH_SQUEEZE().  Treat @c INTERNAL as private:
 * do not inspect, modify, or serialize it.  A context must not be used
 * concurrently by multiple threads.
 *
 * Even though hash state is not a key, it can contain information derived
 * from sensitive input.  Erase it with LIBERAC_HASH_CLEAR() when finished.
 */
typedef struct {
    uint8_t INTERNAL[LIBERAC_HASH_CONTEXT_BYTES]; /**< Reserved private state. */
} LiberaCHashContext;

LIBERAC_BEGIN_DECLS

/**
 * @brief Hash a complete message or produce SHAKE output in one operation.
 *
 * For a fixed-output algorithm, @p OUTPUT_LENGTH is the capacity of
 * @p OUTPUT and must be at least the corresponding @c *_DIGEST_BYTES value;
 * exactly that many digest bytes are written.  For SHAKE128 and SHAKE256,
 * @p OUTPUT_LENGTH is the requested XOF output length and every requested byte
 * is written.  Consequently, LIBERAC_HASH_MAX_DIGEST_BYTES does not limit SHAKE
 * output.
 *
 * @param[out] OUTPUT Digest or XOF output buffer.  It may be NULL only when
 *                    @p OUTPUT_LENGTH is zero; a zero-length output is useful
 *                    only for SHAKE.
 * @param[in]  OUTPUT_LENGTH Output-buffer capacity for a fixed-output hash, or
 *                           requested output length for SHAKE.
 * @param[in]  INPUT Complete input message.  It may be NULL when
 *                   @p INPUT_LENGTH is zero, which hashes the empty message.
 * @param[in]  INPUT_LENGTH Input-message length in bytes.
 * @param[in]  ALG One of the @c LIBERAC_ALG_HASH_* identifiers.
 *
 * @retval LIBERAC_SUCCESS The digest or requested XOF output was produced.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A nonzero length was paired with a
 *         NULL buffer.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not a supported hash selector.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL A fixed-output digest does not fit in
 *         @p OUTPUT.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE A SHA-224 or SHA-256 family input
 *         exceeds the format's 64-bit bit-length representation.
 */
LIBERAC_API LiberaCError LIBERAC_HASH(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Initialize an incremental hash or XOF context.
 *
 * Any supported SHA-2, SHA-3, SHAKE, or LSH identifier may be selected.  The
 * algorithm is retained in @p CONTEXT, so subsequent incremental calls do not
 * take an algorithm argument.
 *
 * @param[out] CONTEXT Destination context.  Existing contents are erased
 *                     before initialization.  If initialization fails, the
 *                     context is left cleared and unusable until a successful
 *                     call to LIBERAC_HASH_INIT().
 * @param[in] ALG One of the @c LIBERAC_ALG_HASH_* identifiers.
 *
 * @retval LIBERAC_SUCCESS The context is ready to absorb input.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT @p CONTEXT is NULL.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is not supported by the hash API.
 */
LIBERAC_API LiberaCError LIBERAC_HASH_INIT(
    LiberaCHashContext *CONTEXT,
    LiberaCAlgID ALG);

/**
 * @brief Absorb the next part of a message into an incremental hash context.
 *
 * This function may be called any number of times between
 * LIBERAC_HASH_INIT() and LIBERAC_HASH_FINALIZE().  Splitting a message into
 * arbitrary chunks produces the same result as LIBERAC_HASH().
 *
 * @param[in,out] CONTEXT Initialized context in its input-absorption phase.
 * @param[in] INPUT Next message bytes.  It may be NULL only when
 *                  @p INPUT_LENGTH is zero.
 * @param[in] INPUT_LENGTH Number of bytes to absorb.
 *
 * @retval LIBERAC_SUCCESS The complete input chunk was absorbed.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer is invalid, the context was
 *         not initialized, or absorption has already been finalized.
 * @retval LIBERAC_ERROR_MESSAGE_TOO_LARGE The accumulated SHA-2 message length
 *         cannot be represented by that algorithm's encoded bit length.  The
 *         context is unchanged and remains usable after this error.
 */
LIBERAC_API LiberaCError LIBERAC_HASH_UPDATE(
    LiberaCHashContext *CONTEXT,
    const uint8_t *INPUT, size_t INPUT_LENGTH);

/**
 * @brief Finish input absorption for an incremental hash or XOF.
 *
 * No digest bytes are written by this call.  Retrieve them with
 * LIBERAC_HASH_SQUEEZE().  Finalization must occur exactly once after
 * initialization and all updates.
 *
 * @param[in,out] CONTEXT Initialized context in its input-absorption phase.
 *
 * @retval LIBERAC_SUCCESS Padding was applied and the context is ready to
 *         produce output.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT @p CONTEXT is NULL, uninitialized, or
 *         no longer in its input-absorption phase.
 */
LIBERAC_API LiberaCError LIBERAC_HASH_FINALIZE(
    LiberaCHashContext *CONTEXT);

/**
 * @brief Retrieve a fixed digest or the next bytes of SHAKE output.
 *
 * LIBERAC_HASH_FINALIZE() must be called first.  For SHA-2, SHA-3, and LSH,
 * @p OUTPUT_LENGTH is the capacity of @p OUTPUT and must be at least the
 * selected algorithm's digest size.  Exactly one digest is written and a
 * second squeeze attempt is rejected.  Bytes beyond the digest are left
 * unchanged.
 *
 * For SHAKE128 and SHAKE256, @p OUTPUT_LENGTH is the requested output length.
 * The function may be called repeatedly; concatenating those results is
 * identical to requesting the combined length from LIBERAC_HASH().  A
 * zero-length SHAKE request may use a NULL output pointer and does not consume
 * any XOF output.
 *
 * @param[in,out] CONTEXT Finalized incremental context.
 * @param[out] OUTPUT Digest or XOF destination.  It may be NULL only for a
 *                    zero-length SHAKE request.
 * @param[in] OUTPUT_LENGTH Fixed-digest buffer capacity or requested SHAKE
 *                          output length, in bytes.
 *
 * @retval LIBERAC_SUCCESS The digest or requested XOF bytes were written.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT A pointer or context phase is invalid.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL A fixed digest does not fit in
 *         @p OUTPUT.
 */
LIBERAC_API LiberaCError LIBERAC_HASH_SQUEEZE(
    LiberaCHashContext *CONTEXT,
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH);

/**
 * @brief Securely erase an incremental hash context.
 *
 * @param[in,out] CONTEXT Context to erase.  A NULL pointer is ignored.
 * @post The context is uninitialized and must be passed to
 *       LIBERAC_HASH_INIT() before reuse.
 */
LIBERAC_API void LIBERAC_HASH_CLEAR(LiberaCHashContext *CONTEXT);
LIBERAC_END_DECLS

#endif

/** @} */
