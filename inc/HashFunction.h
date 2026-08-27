/**
 * @file HashFunction.h
 * @brief One-shot, runtime-selected hash and extensible-output API.
 *
 * @defgroup crypto_hash Hash-function API
 * @brief SHA-2, SHA-3, SHAKE, and LSH through one public operation.
 * @{
 */
#ifndef CRYPTO_HASH_FUNCTION_H
#define CRYPTO_HASH_FUNCTION_H

#include "Def.h"

/** Maximum digest size among the fixed-output hash algorithms, in bytes. */
#define CRYPTO_HASH_MAX_DIGEST_BYTES 64u
/** SHA-224 digest size, in bytes. */
#define CRYPTO_SHA2_224_DIGEST_BYTES 28u
/** SHA-256 digest size, in bytes. */
#define CRYPTO_SHA2_256_DIGEST_BYTES 32u
/** SHA-384 digest size, in bytes. */
#define CRYPTO_SHA2_384_DIGEST_BYTES 48u
/** SHA-512 digest size, in bytes. */
#define CRYPTO_SHA2_512_DIGEST_BYTES 64u
/** SHA-512/224 digest size, in bytes. */
#define CRYPTO_SHA2_512_224_DIGEST_BYTES 28u
/** SHA-512/256 digest size, in bytes. */
#define CRYPTO_SHA2_512_256_DIGEST_BYTES 32u
/** LSH-256-224 digest size, in bytes. */
#define CRYPTO_LSH_256_224_DIGEST_BYTES 28u
/** LSH-256-256 digest size, in bytes. */
#define CRYPTO_LSH_256_256_DIGEST_BYTES 32u
/** LSH-512-224 digest size, in bytes. */
#define CRYPTO_LSH_512_224_DIGEST_BYTES 28u
/** LSH-512-256 digest size, in bytes. */
#define CRYPTO_LSH_512_256_DIGEST_BYTES 32u
/** LSH-512-384 digest size, in bytes. */
#define CRYPTO_LSH_512_384_DIGEST_BYTES 48u
/** LSH-512-512 digest size, in bytes. */
#define CRYPTO_LSH_512_512_DIGEST_BYTES 64u
/** SHA3-224 digest size, in bytes. */
#define CRYPTO_SHA3_224_DIGEST_BYTES 28u
/** SHA3-256 digest size, in bytes. */
#define CRYPTO_SHA3_256_DIGEST_BYTES 32u
/** SHA3-384 digest size, in bytes. */
#define CRYPTO_SHA3_384_DIGEST_BYTES 48u
/** SHA3-512 digest size, in bytes. */
#define CRYPTO_SHA3_512_DIGEST_BYTES 64u

CRYPTO_BEGIN_DECLS

/**
 * @brief Hash a complete message or produce SHAKE output in one operation.
 *
 * For a fixed-output algorithm, @p OUTPUT_LENGTH is the capacity of
 * @p OUTPUT and must be at least the corresponding @c *_DIGEST_BYTES value;
 * exactly that many digest bytes are written.  For SHAKE128 and SHAKE256,
 * @p OUTPUT_LENGTH is the requested XOF output length and every requested byte
 * is written.  Consequently, CRYPTO_HASH_MAX_DIGEST_BYTES does not limit SHAKE
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
 * @param[in]  ALG One of the @c ALG_HASH_* identifiers.
 *
 * @retval CRYPTO_SUCCESS The digest or requested XOF output was produced.
 * @retval CRYPTO_ERROR_INVALID_ARGUMENT A nonzero length was paired with a
 *         NULL buffer.
 * @retval CRYPTO_ERROR_INVALID_ALG_ID @p ALG is not a supported hash selector.
 * @retval CRYPTO_ERROR_BUFFER_TOO_SMALL A fixed-output digest does not fit in
 *         @p OUTPUT.
 * @retval CRYPTO_ERROR_MESSAGE_TOO_LARGE A SHA-224 or SHA-256 family input
 *         exceeds the format's 64-bit bit-length representation.
 */
CRYPTO_API CryptoError CRYPTO_HASH(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    AlgID ALG);
CRYPTO_END_DECLS

#endif

/** @} */
