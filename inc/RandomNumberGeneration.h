#ifndef CRYPTO_RANDOM_NUMBER_GENERATION_H
#define CRYPTO_RANDOM_NUMBER_GENERATION_H

/**
 * @file RandomNumberGeneration.h
 * @brief Operating-system random bytes and runtime-selected AES CTR-DRBG APIs.
 *
 * CRYPTO_RANDOM_BYTES() reads directly from the operating system. The
 * CTR-DRBG interface supports AES-128, AES-192, and AES-256, each with or
 * without the SP 800-90A derivation function (DF). A CTR-DRBG context contains
 * secret mutable state: do not inspect, modify, serialize, or duplicate it.
 *
 * @defgroup crypto_random Random-number generation API
 * @brief Direct operating-system random bytes and AES CTR-DRBG state.
 * @{
 */

#include "Def.h"

/** @brief AES block and CTR-DRBG V-state length in bytes. */
#define CRYPTO_CTR_DRBG_BLOCK_BYTES 16u
/** @brief Maximum AES key storage required by a CTR-DRBG context. */
#define CRYPTO_CTR_DRBG_MAX_KEY_BYTES 32u
/** @brief Maximum Key || V seed length among the supported parameter sets. */
#define CRYPTO_CTR_DRBG_MAX_SEED_BYTES 48u
/** @brief Maximum bytes produced by one CRYPTO_CTR_DRBG_GENERATE() request. */
#define CRYPTO_CTR_DRBG_MAX_REQUEST_BYTES 65536u

/**
 * @brief Mutable AES CTR-DRBG state.
 *
 * Treat all members as private implementation state. Create the state with a
 * CRYPTO_CTR_DRBG_INSTANTIATE* function and erase it with
 * CRYPTO_CTR_DRBG_CLEAR(). A single context must not be used concurrently.
 */
typedef struct {
    AlgID ALG; /**< Selected ALG_CTR_DRBG_AES_* identifier. */
    uint8_t KEY[CRYPTO_CTR_DRBG_MAX_KEY_BYTES]; /**< Secret AES key state. */
    uint8_t V[CRYPTO_CTR_DRBG_BLOCK_BYTES]; /**< Secret counter state. */
    uint64_t RESEED_COUNTER; /**< Requests since instantiation or reseeding. */
    uint8_t KEY_LENGTH; /**< Active bytes in KEY: 16, 24, or 32. */
    uint8_t USE_DF; /**< Nonzero when the derivation-function variant is active. */
    uint8_t INSTANTIATED; /**< Nonzero only for an instantiated context. */
} CRYPTO_CTR_DRBG_CONTEXT;

CRYPTO_BEGIN_DECLS

/**
 * @brief Fill a buffer directly from the operating-system random source.
 * @param[out] OUTPUT Destination buffer; may be null only when OUTPUT_LENGTH
 *                    is zero.
 * @param[in] OUTPUT_LENGTH Number of random bytes requested.
 * @return CRYPTO_SUCCESS on success, CRYPTO_ERROR_INVALID_ARGUMENT for an
 *         invalid buffer, or CRYPTO_ERROR_RANDOM_FAILED if the operating-system
 *         source cannot satisfy the request.
 * @note This function does not use or depend on a CTR-DRBG context.
 */
CRYPTO_API CryptoError CRYPTO_RANDOM_BYTES(uint8_t *OUTPUT, size_t OUTPUT_LENGTH);

/**
 * @brief Return the Key || V seed-state length for a CTR-DRBG algorithm.
 * @param[in] ALG Any ALG_CTR_DRBG_AES_*_DF or ALG_CTR_DRBG_AES_*_NO_DF
 *                identifier.
 * @return 32, 40, or 48 bytes for AES-128, AES-192, or AES-256 respectively;
 *         zero if ALG is unsupported.
 * @note For NO_DF instantiation and reseeding, this is the exact required
 *       entropy length. DF variants use the entropy constraints documented on
 *       CRYPTO_CTR_DRBG_INSTANTIATE() and CRYPTO_CTR_DRBG_RESEED().
 */
CRYPTO_API size_t CRYPTO_CTR_DRBG_SEED_SIZE(AlgID ALG);

/**
 * @brief Instantiate an AES CTR-DRBG from caller-supplied entropy.
 * @param[out] CONTEXT Destination context. On success it is ready to generate;
 *                     failures after initialization clear its state.
 * @param[in] ENTROPY Entropy input supplied by the caller; never null.
 * @param[in] ENTROPY_LENGTH Entropy length in bytes.
 * @param[in] NONCE Optional nonce; may be null only when NONCE_LENGTH is zero.
 * @param[in] NONCE_LENGTH Nonce length in bytes.
 * @param[in] PERSONALIZATION Optional personalization string; may be null only
 *                            when PERSONALIZATION_LENGTH is zero.
 * @param[in] PERSONALIZATION_LENGTH Personalization length in bytes.
 * @param[in] ALG Selected ALG_CTR_DRBG_AES_*_DF or *_NO_DF identifier.
 * @return CRYPTO_SUCCESS on success or a negative CryptoError on failure.
 *
 * For a DF algorithm, ENTROPY_LENGTH must be at least the AES key length and
 * ENTROPY_LENGTH + NONCE_LENGTH must be at least the key length plus half that
 * length rounded up. For a NO_DF algorithm, ENTROPY_LENGTH must equal
 * CRYPTO_CTR_DRBG_SEED_SIZE(ALG), NONCE_LENGTH must be zero, and the
 * personalization string must not exceed the seed size.
 *
 * @warning The caller is responsible for the quality, independence, and
 *          claimed entropy of caller-supplied ENTROPY and NONCE data.
 */
CRYPTO_API CryptoError CRYPTO_CTR_DRBG_INSTANTIATE(
    CRYPTO_CTR_DRBG_CONTEXT *CONTEXT,
    const uint8_t *ENTROPY, size_t ENTROPY_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *PERSONALIZATION, size_t PERSONALIZATION_LENGTH,
    AlgID ALG);

/**
 * @brief Instantiate an AES CTR-DRBG using operating-system entropy.
 * @param[out] CONTEXT Destination context.
 * @param[in] PERSONALIZATION Optional personalization string; may be null only
 *                            when PERSONALIZATION_LENGTH is zero.
 * @param[in] PERSONALIZATION_LENGTH Personalization length in bytes. For a
 *                                   NO_DF algorithm it must not exceed the
 *                                   algorithm's seed size.
 * @param[in] ALG Selected ALG_CTR_DRBG_AES_*_DF or *_NO_DF identifier.
 * @return CRYPTO_SUCCESS on success, CRYPTO_ERROR_RANDOM_FAILED if operating-
 *         system entropy cannot be obtained, or another negative CryptoError.
 */
CRYPTO_API CryptoError CRYPTO_CTR_DRBG_INSTANTIATE_OS(
    CRYPTO_CTR_DRBG_CONTEXT *CONTEXT,
    const uint8_t *PERSONALIZATION, size_t PERSONALIZATION_LENGTH,
    AlgID ALG);

/**
 * @brief Reseed an instantiated CTR-DRBG from caller-supplied entropy.
 * @param[in,out] CONTEXT Instantiated context to update.
 * @param[in] ENTROPY Fresh entropy input; never null.
 * @param[in] ENTROPY_LENGTH Entropy length in bytes. DF variants require at
 *                           least the AES key length; NO_DF variants require
 *                           exactly CRYPTO_CTR_DRBG_SEED_SIZE(CONTEXT->ALG).
 * @param[in] ADDITIONAL Optional additional input; may be null only when
 *                       ADDITIONAL_LENGTH is zero.
 * @param[in] ADDITIONAL_LENGTH Additional-input length. For NO_DF variants it
 *                              must not exceed the seed size.
 * @return CRYPTO_SUCCESS on success or a negative CryptoError on failure.
 * @post On success, the reseed counter is reset to one.
 */
CRYPTO_API CryptoError CRYPTO_CTR_DRBG_RESEED(
    CRYPTO_CTR_DRBG_CONTEXT *CONTEXT,
    const uint8_t *ENTROPY, size_t ENTROPY_LENGTH,
    const uint8_t *ADDITIONAL, size_t ADDITIONAL_LENGTH);

/**
 * @brief Reseed an instantiated CTR-DRBG using operating-system entropy.
 * @param[in,out] CONTEXT Instantiated context to update.
 * @param[in] ADDITIONAL Optional additional input; may be null only when
 *                       ADDITIONAL_LENGTH is zero.
 * @param[in] ADDITIONAL_LENGTH Additional-input length. For NO_DF variants it
 *                              must not exceed the seed size.
 * @return CRYPTO_SUCCESS on success, CRYPTO_ERROR_RANDOM_FAILED if operating-
 *         system entropy cannot be obtained, or another negative CryptoError.
 */
CRYPTO_API CryptoError CRYPTO_CTR_DRBG_RESEED_OS(
    CRYPTO_CTR_DRBG_CONTEXT *CONTEXT,
    const uint8_t *ADDITIONAL, size_t ADDITIONAL_LENGTH);

/**
 * @brief Generate pseudorandom bytes and advance CTR-DRBG state.
 * @param[in,out] CONTEXT Instantiated context.
 * @param[out] OUTPUT Destination; may be null only when OUTPUT_LENGTH is zero.
 * @param[in] OUTPUT_LENGTH Bytes requested, at most
 *                          CRYPTO_CTR_DRBG_MAX_REQUEST_BYTES.
 * @param[in] ADDITIONAL Optional request-specific additional input; may be null
 *                       only when ADDITIONAL_LENGTH is zero.
 * @param[in] ADDITIONAL_LENGTH Additional-input length. For NO_DF variants it
 *                              must not exceed the seed size.
 * @param[in] PREDICTION_RESISTANCE If nonzero, reseed from the operating system
 *                                  before generation; ADDITIONAL is consumed by
 *                                  that reseed operation.
 * @return CRYPTO_SUCCESS on success, CRYPTO_ERROR_RESEED_REQUIRED after the
 *         reseed interval is exceeded, CRYPTO_ERROR_MESSAGE_TOO_LARGE for an
 *         oversized request, or another negative CryptoError on failure.
 * @note If generation fails after output processing begins, OUTPUT is cleared.
 */
CRYPTO_API CryptoError CRYPTO_CTR_DRBG_GENERATE(
    CRYPTO_CTR_DRBG_CONTEXT *CONTEXT,
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *ADDITIONAL, size_t ADDITIONAL_LENGTH,
    int PREDICTION_RESISTANCE);

/**
 * @brief Securely erase a CTR-DRBG context.
 * @param[in,out] CONTEXT Context to clear. A null pointer is ignored.
 * @post The complete structure is zeroed and is no longer instantiated.
 * @note Call this when the context is no longer needed, including after a
 *       failed instantiation attempt.
 */
CRYPTO_API void CRYPTO_CTR_DRBG_CLEAR(CRYPTO_CTR_DRBG_CONTEXT *CONTEXT);
CRYPTO_END_DECLS

#endif

/** @} */
