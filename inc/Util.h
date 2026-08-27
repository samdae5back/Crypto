#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

/**
 * @file Util.h
 * @brief Public unsigned-bignum serialization and prime-generation utilities.
 *
 * CRYPTO_BIGNUM represents a non-negative arbitrary-precision integer. Its
 * storage is managed by this library: initialize an object before first use,
 * pass it only to CRYPTO APIs, and release it when finished. Applications must
 * not directly modify the structure members.
 *
 * @defgroup crypto_util Utility API
 * @brief Managed unsigned bignums and probable-prime generation.
 * @{
 */

#include "Def.h"

/** @brief Library-managed non-negative arbitrary-precision integer. */
typedef struct {
    uint32_t *LIMBS; /**< Internal little-endian 32-bit limb storage. */
    size_t LENGTH; /**< Number of significant limbs currently in use. */
    size_t CAPACITY; /**< Number of allocated limbs. */
} CRYPTO_BIGNUM;

CRYPTO_BEGIN_DECLS

/**
 * @brief Initialize a bignum to zero without allocating storage.
 * @param[out] VALUE Object to initialize. A null pointer is ignored.
 * @note Do not call this on an object that currently owns storage; call
 *       CRYPTO_BIGNUM_FREE() first.
 */
CRYPTO_API void CRYPTO_BIGNUM_INIT(CRYPTO_BIGNUM *VALUE);

/**
 * @brief Securely clear and release a bignum's allocated storage.
 * @param[in,out] VALUE Initialized object to release. A null pointer is ignored.
 * @post VALUE represents zero and may be reused or freed again.
 */
CRYPTO_API void CRYPTO_BIGNUM_FREE(CRYPTO_BIGNUM *VALUE);

/**
 * @brief Load an unsigned integer from a big-endian byte string.
 * @param[in,out] OUTPUT Initialized bignum receiving the decoded value.
 * @param[in] BYTES Most-significant byte first; may be null when LENGTH is zero.
 * @param[in] LENGTH Number of input bytes. Zero loads the integer zero.
 * @retval CRYPTO_SUCCESS The integer was loaded successfully.
 * @retval CRYPTO_ERROR_INVALID_ARGUMENT An input pointer is invalid.
 * @retval CRYPTO_ERROR_ALLOCATION_FAILED Internal limb allocation failed.
 * @retval CRYPTO_ERROR_MESSAGE_TOO_LARGE @p LENGTH cannot be represented by
 *         the bignum storage calculation.
 * @note Leading zero bytes are accepted and are not retained as significant
 *       limbs.
 */
CRYPTO_API CryptoError CRYPTO_BIGNUM_FROM_BYTES_BE(CRYPTO_BIGNUM *OUTPUT, const uint8_t *BYTES, size_t LENGTH);

/**
 * @brief Load an unsigned integer from a little-endian byte string.
 * @param[in,out] OUTPUT Initialized bignum receiving the decoded value.
 * @param[in] BYTES Least-significant byte first; may be null when LENGTH is zero.
 * @param[in] LENGTH Number of input bytes. Zero loads the integer zero.
 * @retval CRYPTO_SUCCESS The integer was loaded successfully.
 * @retval CRYPTO_ERROR_INVALID_ARGUMENT An input pointer is invalid.
 * @retval CRYPTO_ERROR_ALLOCATION_FAILED Internal limb allocation failed.
 * @retval CRYPTO_ERROR_MESSAGE_TOO_LARGE @p LENGTH cannot be represented by
 *         the bignum storage calculation.
 * @note Trailing zero bytes are accepted and are not retained as significant
 *       limbs.
 */
CRYPTO_API CryptoError CRYPTO_BIGNUM_FROM_BYTES_LE(CRYPTO_BIGNUM *OUTPUT, const uint8_t *BYTES, size_t LENGTH);

/**
 * @brief Store an unsigned integer as a fixed-width big-endian byte string.
 * @param[in] INPUT Initialized bignum to encode.
 * @param[out] OUTPUT Destination buffer; may be null when OUTPUT_LENGTH is zero.
 * @param[in] OUTPUT_LENGTH Requested fixed width. It must be large enough for
 *                          the significant value.
 * @retval CRYPTO_SUCCESS The integer was stored successfully.
 * @retval CRYPTO_ERROR_INVALID_ARGUMENT An input pointer is invalid.
 * @retval CRYPTO_ERROR_BUFFER_TOO_SMALL @p OUTPUT_LENGTH cannot hold the
 *         significant value.
 * @note OUTPUT is zero-padded on the most-significant (leading) side.
 */
CRYPTO_API CryptoError CRYPTO_BIGNUM_TO_BYTES_BE(const CRYPTO_BIGNUM *INPUT, uint8_t *OUTPUT, size_t OUTPUT_LENGTH);

/**
 * @brief Store an unsigned integer as a fixed-width little-endian byte string.
 * @param[in] INPUT Initialized bignum to encode.
 * @param[out] OUTPUT Destination buffer; may be null when OUTPUT_LENGTH is zero.
 * @param[in] OUTPUT_LENGTH Requested fixed width. It must be large enough for
 *                          the significant value.
 * @retval CRYPTO_SUCCESS The integer was stored successfully.
 * @retval CRYPTO_ERROR_INVALID_ARGUMENT An input pointer is invalid.
 * @retval CRYPTO_ERROR_BUFFER_TOO_SMALL @p OUTPUT_LENGTH cannot hold the
 *         significant value.
 * @note OUTPUT is zero-padded on the most-significant (trailing) side.
 */
CRYPTO_API CryptoError CRYPTO_BIGNUM_TO_BYTES_LE(const CRYPTO_BIGNUM *INPUT, uint8_t *OUTPUT, size_t OUTPUT_LENGTH);

/**
 * @brief Test an integer for probable primality with randomized Miller-Rabin.
 * @param[in] VALUE Initialized non-negative integer to test.
 * @param[in] ROUNDS Number of Miller-Rabin rounds. Zero selects 32 rounds.
 * @return 1 if VALUE is probably prime; 0 if it is composite, invalid, or the
 *         test cannot complete (for example, if randomness fails).
 * @note A return value of 1 is probabilistic. This API deliberately does not
 *       distinguish a composite input from an internal failure.
 */
CRYPTO_API int CRYPTO_PRIME_IS_PROBABLE(const CRYPTO_BIGNUM *VALUE, uint32_t ROUNDS);

/**
 * @brief Generate an odd probable prime with an exact bit length.
 * @param[in,out] OUTPUT Initialized bignum receiving the generated prime.
 * @param[in] BITS Exact requested bit length; must be at least 2.
 * @param[in] ROUNDS Miller-Rabin rounds. Zero selects 32 rounds.
 * @return CRYPTO_SUCCESS on success, CRYPTO_ERROR_RANDOM_FAILED if operating-
 *         system randomness is unavailable, or another negative CryptoError.
 * @note On success, OUTPUT's previous value is released and replaced.
 */
CRYPTO_API CryptoError CRYPTO_PRIME_GENERATE(CRYPTO_BIGNUM *OUTPUT, size_t BITS, uint32_t ROUNDS);

/**
 * @brief Generate a safe prime P and its Sophie Germain prime Q.
 * @param[in,out] P Initialized bignum receiving the safe prime.
 * @param[in,out] Q Distinct initialized bignum receiving the prime Q such that
 *                  P = 2Q + 1.
 * @param[in] P_BITS Exact requested bit length of P; must be at least 3.
 * @param[in] ROUNDS Miller-Rabin rounds for both candidates. Zero selects 32.
 * @return CRYPTO_SUCCESS on success or a negative CryptoError on failure.
 * @note P and Q must refer to different objects. On success, both previous
 *       values are released and replaced, and Q has P_BITS - 1 bits.
 */
CRYPTO_API CryptoError CRYPTO_PRIME_GENERATE_SAFE(CRYPTO_BIGNUM *P, CRYPTO_BIGNUM *Q, size_t P_BITS, uint32_t ROUNDS);
CRYPTO_END_DECLS

#endif

/** @} */
