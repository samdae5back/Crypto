/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBERAC_RANDOM_NUMBER_GENERATION_H
#define LIBERAC_RANDOM_NUMBER_GENERATION_H

/**
 * @file RandomNumberGeneration.h
 * @brief Operating-system random bytes and runtime-selected CTR-DRBG APIs.
 *
 * LIBERAC_RANDOM_BYTES() reads directly from the operating system. The
 * CTR-DRBG interface supports AES-128, AES-192, and AES-256, each with or
 * without the SP 800-90A derivation function (DF). Three-key TDEA is also
 * available strictly for legacy standards and interoperability coverage; it
 * is not recommended for new designs. A CTR-DRBG context contains secret
 * mutable state: do not inspect, modify, serialize, or duplicate it.
 *
 * @defgroup crypto_random Random-number generation API
 * @brief Direct operating-system random bytes and CTR-DRBG state.
 * @{
 */

#include "Def.h"

/** @brief Maximum block and CTR-DRBG V-state storage in bytes. */
#define LIBERAC_CTR_DRBG_BLOCK_BYTES 16u
/** @brief Maximum effective key-state storage required by a context. */
#define LIBERAC_CTR_DRBG_MAX_KEY_BYTES 32u
/** @brief Maximum Key || V seed length among the supported parameter sets. */
#define LIBERAC_CTR_DRBG_MAX_SEED_BYTES 48u
/** @brief Effective three-key TDEA key-state length, excluding parity bits. */
#define LIBERAC_CTR_DRBG_TDEA_KEY_BYTES 21u
/** @brief Three-key TDEA CTR-DRBG counter-state length. */
#define LIBERAC_CTR_DRBG_TDEA_BLOCK_BYTES 8u
/** @brief Three-key TDEA Key || V seed length. */
#define LIBERAC_CTR_DRBG_TDEA_SEED_BYTES 29u
/** @brief Maximum bytes in one legacy TDEA CTR-DRBG request. */
#define LIBERAC_CTR_DRBG_TDEA_MAX_REQUEST_BYTES 1024u
/** @brief Maximum bytes in one AES CTR-DRBG request. */
#define LIBERAC_CTR_DRBG_MAX_REQUEST_BYTES 65536u

/**
 * @brief Mutable CTR-DRBG state.
 *
 * Treat all members as private implementation state. Create the state with a
 * LIBERAC_CTR_DRBG_INSTANTIATE* function and erase it with
 * LIBERAC_CTR_DRBG_CLEAR(). A single context must not be used concurrently.
 */
typedef struct {
    LiberaCAlgID ALG; /**< Selected LIBERAC_ALG_CTR_DRBG_* identifier. */
    uint8_t KEY[LIBERAC_CTR_DRBG_MAX_KEY_BYTES]; /**< Secret effective key state. */
    uint8_t V[LIBERAC_CTR_DRBG_BLOCK_BYTES]; /**< Secret counter-state storage. */
    uint64_t RESEED_COUNTER; /**< Requests since instantiation or reseeding. */
    uint8_t KEY_LENGTH; /**< Active bytes in KEY: 16, 21, 24, or 32. */
    uint8_t USE_DF; /**< Nonzero when the derivation-function variant is active. */
    uint8_t INSTANTIATED; /**< Nonzero only for an instantiated context. */
} LiberaCCtrDrbgContext;

LIBERAC_BEGIN_DECLS

/**
 * @brief Fill a buffer directly from the operating-system random source.
 * @param[out] OUTPUT Destination buffer; may be null only when OUTPUT_LENGTH
 *                    is zero.
 * @param[in] OUTPUT_LENGTH Number of random bytes requested.
 * @return LIBERAC_SUCCESS on success, LIBERAC_ERROR_INVALID_ARGUMENT for an
 *         invalid buffer, or LIBERAC_ERROR_RANDOM_FAILED if the operating-system
 *         source cannot satisfy the request.
 * @note This function does not use or depend on a CTR-DRBG context.
 */
LIBERAC_API LiberaCError LIBERAC_RANDOM_BYTES(uint8_t *OUTPUT, size_t OUTPUT_LENGTH);

/**
 * @brief Return the Key || V seed-state length for a CTR-DRBG algorithm.
 * @param[in] ALG Any supported LIBERAC_ALG_CTR_DRBG_* identifier.
 * @return 29 bytes for legacy three-key TDEA, or 32, 40, or 48 bytes for
 *         AES-128, AES-192, or AES-256 respectively; zero if unsupported.
 * @note For NO_DF instantiation and reseeding, this is the exact required
 *       entropy length. DF variants use the entropy constraints documented on
 *       LIBERAC_CTR_DRBG_INSTANTIATE() and LIBERAC_CTR_DRBG_RESEED().
 */
LIBERAC_API size_t LIBERAC_CTR_DRBG_SEED_SIZE(LiberaCAlgID ALG);

/**
 * @brief Instantiate a CTR-DRBG from caller-supplied entropy.
 * @param[out] CONTEXT Destination context. On success it is ready to generate;
 *                     failures after initialization clear its state.
 * @param[in] ENTROPY Entropy input supplied by the caller; never null.
 * @param[in] ENTROPY_LENGTH Entropy length in bytes.
 * @param[in] NONCE Optional nonce; may be null only when NONCE_LENGTH is zero.
 * @param[in] NONCE_LENGTH Nonce length in bytes.
 * @param[in] PERSONALIZATION Optional personalization string; may be null only
 *                            when PERSONALIZATION_LENGTH is zero.
 * @param[in] PERSONALIZATION_LENGTH Personalization length in bytes.
 * @param[in] ALG Selected LIBERAC_ALG_CTR_DRBG_* identifier.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 *
 * For a DF algorithm, ENTROPY_LENGTH must be at least the selected security
 * strength: 14 bytes for legacy TDEA, or the AES key length. The combined
 * entropy and nonce lengths must be at least 21 bytes for TDEA, or the AES key
 * length plus half that length rounded up. For a NO_DF algorithm,
 * ENTROPY_LENGTH must equal LIBERAC_CTR_DRBG_SEED_SIZE(ALG), NONCE_LENGTH must
 * be zero, and the personalization string must not exceed the seed size.
 *
 * @warning The caller is responsible for the quality, independence, and
 *          claimed entropy of caller-supplied ENTROPY and NONCE data.
 */
LIBERAC_API LiberaCError LIBERAC_CTR_DRBG_INSTANTIATE(
    LiberaCCtrDrbgContext *CONTEXT,
    const uint8_t *ENTROPY, size_t ENTROPY_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *PERSONALIZATION, size_t PERSONALIZATION_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Instantiate a CTR-DRBG using operating-system entropy.
 * @param[out] CONTEXT Destination context.
 * @param[in] PERSONALIZATION Optional personalization string; may be null only
 *                            when PERSONALIZATION_LENGTH is zero.
 * @param[in] PERSONALIZATION_LENGTH Personalization length in bytes. For a
 *                                   NO_DF algorithm it must not exceed the
 *                                   algorithm's seed size.
 * @param[in] ALG Selected LIBERAC_ALG_CTR_DRBG_* identifier.
 * @return LIBERAC_SUCCESS on success, LIBERAC_ERROR_RANDOM_FAILED if operating-
 *         system entropy cannot be obtained, or another negative LiberaCError.
 */
LIBERAC_API LiberaCError LIBERAC_CTR_DRBG_INSTANTIATE_OS(
    LiberaCCtrDrbgContext *CONTEXT,
    const uint8_t *PERSONALIZATION, size_t PERSONALIZATION_LENGTH,
    LiberaCAlgID ALG);

/**
 * @brief Reseed an instantiated CTR-DRBG from caller-supplied entropy.
 * @param[in,out] CONTEXT Instantiated context to update.
 * @param[in] ENTROPY Fresh entropy input; never null.
 * @param[in] ENTROPY_LENGTH Entropy length in bytes. DF variants require at
 *                           least 14 bytes for TDEA or the AES key length;
 *                           NO_DF variants require exactly
 *                           LIBERAC_CTR_DRBG_SEED_SIZE(CONTEXT->ALG).
 * @param[in] ADDITIONAL Optional additional input; may be null only when
 *                       ADDITIONAL_LENGTH is zero.
 * @param[in] ADDITIONAL_LENGTH Additional-input length. For NO_DF variants it
 *                              must not exceed the seed size.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @post On success, the reseed counter is reset to one.
 */
LIBERAC_API LiberaCError LIBERAC_CTR_DRBG_RESEED(
    LiberaCCtrDrbgContext *CONTEXT,
    const uint8_t *ENTROPY, size_t ENTROPY_LENGTH,
    const uint8_t *ADDITIONAL, size_t ADDITIONAL_LENGTH);

/**
 * @brief Reseed an instantiated CTR-DRBG using operating-system entropy.
 * @param[in,out] CONTEXT Instantiated context to update.
 * @param[in] ADDITIONAL Optional additional input; may be null only when
 *                       ADDITIONAL_LENGTH is zero.
 * @param[in] ADDITIONAL_LENGTH Additional-input length. For NO_DF variants it
 *                              must not exceed the seed size.
 * @return LIBERAC_SUCCESS on success, LIBERAC_ERROR_RANDOM_FAILED if operating-
 *         system entropy cannot be obtained, or another negative LiberaCError.
 */
LIBERAC_API LiberaCError LIBERAC_CTR_DRBG_RESEED_OS(
    LiberaCCtrDrbgContext *CONTEXT,
    const uint8_t *ADDITIONAL, size_t ADDITIONAL_LENGTH);

/**
 * @brief Generate pseudorandom bytes and advance CTR-DRBG state.
 * @param[in,out] CONTEXT Instantiated context.
 * @param[out] OUTPUT Destination; may be null only when OUTPUT_LENGTH is zero.
 * @param[in] OUTPUT_LENGTH Bytes requested, at most 1,024 for legacy TDEA or
 *                          LIBERAC_CTR_DRBG_MAX_REQUEST_BYTES for AES.
 * @param[in] ADDITIONAL Optional request-specific additional input; may be null
 *                       only when ADDITIONAL_LENGTH is zero.
 * @param[in] ADDITIONAL_LENGTH Additional-input length. For NO_DF variants it
 *                              must not exceed the seed size.
 * @param[in] PREDICTION_RESISTANCE If nonzero, reseed from the operating system
 *                                  before generation; ADDITIONAL is consumed by
 *                                  that reseed operation.
 * @return LIBERAC_SUCCESS on success, LIBERAC_ERROR_RESEED_REQUIRED after the
 *         reseed interval is exceeded, LIBERAC_ERROR_MESSAGE_TOO_LARGE for an
 *         oversized request, or another negative LiberaCError on failure.
 * @note If generation fails after output processing begins, OUTPUT is cleared.
 * @warning The TDEA identifiers exist for legacy compatibility only. New
 *          systems should select an AES CTR-DRBG identifier.
 */
LIBERAC_API LiberaCError LIBERAC_CTR_DRBG_GENERATE(
    LiberaCCtrDrbgContext *CONTEXT,
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
LIBERAC_API void LIBERAC_CTR_DRBG_CLEAR(LiberaCCtrDrbgContext *CONTEXT);
LIBERAC_END_DECLS

#endif

/** @} */
