/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBERAC_KEY_ENCAPSULATION_H
#define LIBERAC_KEY_ENCAPSULATION_H

/**
 * @file KeyEncapsulation.h
 * @brief Runtime-selected post-quantum key-encapsulation APIs.
 *
 * ML-KEM keys and ciphertexts are fixed-size encoded byte strings. Query the
 * selected parameter set's sizes before allocating buffers. Every successful
 * encapsulation or decapsulation produces exactly
 * LIBERAC_ML_KEM_SHARED_SECRET_BYTES bytes of shared secret material.
 *
 * @defgroup crypto_key_encapsulation Key-encapsulation API
 * @brief Key generation, encapsulation, and decapsulation for supported KEMs.
 * @{
 */

#include "Def.h"

/** @brief ML-KEM-512 encoded public-key length in bytes. */
#define LIBERAC_ML_KEM_512_PUBLIC_KEY_BYTES 800u
/** @brief ML-KEM-512 encoded private-key length in bytes. */
#define LIBERAC_ML_KEM_512_PRIVATE_KEY_BYTES 1632u
/** @brief ML-KEM-512 encoded ciphertext length in bytes. */
#define LIBERAC_ML_KEM_512_CIPHERTEXT_BYTES 768u
/** @brief ML-KEM-768 encoded public-key length in bytes. */
#define LIBERAC_ML_KEM_768_PUBLIC_KEY_BYTES 1184u
/** @brief ML-KEM-768 encoded private-key length in bytes. */
#define LIBERAC_ML_KEM_768_PRIVATE_KEY_BYTES 2400u
/** @brief ML-KEM-768 encoded ciphertext length in bytes. */
#define LIBERAC_ML_KEM_768_CIPHERTEXT_BYTES 1088u
/** @brief ML-KEM-1024 encoded public-key length in bytes. */
#define LIBERAC_ML_KEM_1024_PUBLIC_KEY_BYTES 1568u
/** @brief ML-KEM-1024 encoded private-key length in bytes. */
#define LIBERAC_ML_KEM_1024_PRIVATE_KEY_BYTES 3168u
/** @brief ML-KEM-1024 encoded ciphertext length in bytes. */
#define LIBERAC_ML_KEM_1024_CIPHERTEXT_BYTES 1568u
/** @brief Shared-secret length produced by every supported ML-KEM parameter set. */
#define LIBERAC_ML_KEM_SHARED_SECRET_BYTES 32u

/** @brief NTRU+768 encoded public-key length in bytes. */
#define LIBERAC_NTRU_PLUS_768_PUBLIC_KEY_BYTES 1152u
/** @brief NTRU+768 encoded private-key length in bytes. */
#define LIBERAC_NTRU_PLUS_768_PRIVATE_KEY_BYTES 2336u
/** @brief NTRU+768 encoded ciphertext length in bytes. */
#define LIBERAC_NTRU_PLUS_768_CIPHERTEXT_BYTES 1152u
/** @brief NTRU+864 encoded public-key length in bytes. */
#define LIBERAC_NTRU_PLUS_864_PUBLIC_KEY_BYTES 1296u
/** @brief NTRU+864 encoded private-key length in bytes. */
#define LIBERAC_NTRU_PLUS_864_PRIVATE_KEY_BYTES 2624u
/** @brief NTRU+864 encoded ciphertext length in bytes. */
#define LIBERAC_NTRU_PLUS_864_CIPHERTEXT_BYTES 1296u
/** @brief NTRU+1152 encoded public-key length in bytes. */
#define LIBERAC_NTRU_PLUS_1152_PUBLIC_KEY_BYTES 1728u
/** @brief NTRU+1152 encoded private-key length in bytes. */
#define LIBERAC_NTRU_PLUS_1152_PRIVATE_KEY_BYTES 3488u
/** @brief NTRU+1152 encoded ciphertext length in bytes. */
#define LIBERAC_NTRU_PLUS_1152_CIPHERTEXT_BYTES 1728u
/** @brief Shared-secret length produced by every supported NTRU+ parameter set. */
#define LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES 32u

/** @brief SMAUG-T-128 encoded public-key length in bytes. */
#define LIBERAC_SMAUG_T_128_PUBLIC_KEY_BYTES 672u
/** @brief SMAUG-T-128 encoded private-key length in bytes. */
#define LIBERAC_SMAUG_T_128_PRIVATE_KEY_BYTES 832u
/** @brief SMAUG-T-128 encoded ciphertext length in bytes. */
#define LIBERAC_SMAUG_T_128_CIPHERTEXT_BYTES 672u
/** @brief SMAUG-T-192 encoded public-key length in bytes. */
#define LIBERAC_SMAUG_T_192_PUBLIC_KEY_BYTES 1088u
/** @brief SMAUG-T-192 encoded private-key length in bytes. */
#define LIBERAC_SMAUG_T_192_PRIVATE_KEY_BYTES 1312u
/** @brief SMAUG-T-192 encoded ciphertext length in bytes. */
#define LIBERAC_SMAUG_T_192_CIPHERTEXT_BYTES 992u
/** @brief SMAUG-T-256 encoded public-key length in bytes. */
#define LIBERAC_SMAUG_T_256_PUBLIC_KEY_BYTES 1440u
/** @brief SMAUG-T-256 encoded private-key length in bytes. */
#define LIBERAC_SMAUG_T_256_PRIVATE_KEY_BYTES 1728u
/** @brief SMAUG-T-256 encoded ciphertext length in bytes. */
#define LIBERAC_SMAUG_T_256_CIPHERTEXT_BYTES 1376u
/** @brief Shared-secret length produced by every supported SMAUG-T parameter set. */
#define LIBERAC_SMAUG_T_SHARED_SECRET_BYTES 32u

LIBERAC_BEGIN_DECLS

/**
 * @brief Return the encoded ML-KEM public-key size for an algorithm.
 * @param[in] ALG One of LIBERAC_ALG_ML_KEM_512, LIBERAC_ALG_ML_KEM_768, or LIBERAC_ALG_ML_KEM_1024.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_ML_KEM_PUBLIC_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded ML-KEM private-key size for an algorithm.
 * @param[in] ALG One of LIBERAC_ALG_ML_KEM_512, LIBERAC_ALG_ML_KEM_768, or LIBERAC_ALG_ML_KEM_1024.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_ML_KEM_PRIVATE_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded ML-KEM ciphertext size for an algorithm.
 * @param[in] ALG One of LIBERAC_ALG_ML_KEM_512, LIBERAC_ALG_ML_KEM_768, or LIBERAC_ALG_ML_KEM_1024.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_ML_KEM_CIPHERTEXT_SIZE(LiberaCAlgID ALG);

/**
 * @brief Generate an ML-KEM key pair using operating-system randomness.
 * @param[out] PUBLIC_KEY Buffer receiving the encoded public key.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY; must be at least
 *                              LIBERAC_ML_KEM_PUBLIC_KEY_SIZE(ALG).
 * @param[out] PRIVATE_KEY Buffer receiving the encoded private key.
 * @param[in] PRIVATE_KEY_LENGTH Available bytes in PRIVATE_KEY; must be at
 *                               least LIBERAC_ML_KEM_PRIVATE_KEY_SIZE(ALG).
 * @param[in] ALG ML-KEM parameter-set identifier.
 * @retval LIBERAC_SUCCESS The key pair was generated successfully.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT An output pointer is null or the
 *         required public-key and private-key output regions overlap.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL An output buffer is undersized.
 * @retval LIBERAC_ERROR_RANDOM_FAILED Operating-system entropy collection
 *         failed.
 * @retval LIBERAC_ERROR_ALLOCATION_FAILED A private workspace could not be
 *         allocated.
 * @retval LIBERAC_ERROR_INTERNAL An internal invariant failed.
 * @note Pointer, size, and overlap validation failures leave the supplied
 *       buffers unchanged. After those checks pass, a generation failure
 *       clears the required portions of both output buffers.
 */
LIBERAC_API LiberaCError LIBERAC_ML_KEM_KEYGEN(uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Encapsulate a fresh shared secret to an ML-KEM public key.
 * @param[in] PUBLIC_KEY Encoded ML-KEM public key.
 * @param[in] PUBLIC_KEY_LENGTH Available public-key bytes; must be at least
 *                              LIBERAC_ML_KEM_PUBLIC_KEY_SIZE(ALG).
 * @param[out] SHARED_SECRET Buffer receiving exactly
 *                           LIBERAC_ML_KEM_SHARED_SECRET_BYTES bytes.
 * @param[out] CIPHERTEXT Buffer receiving the encoded ciphertext.
 * @param[in] CIPHERTEXT_LENGTH Available bytes in CIPHERTEXT; must be at least
 *                              LIBERAC_ML_KEM_CIPHERTEXT_SIZE(ALG).
 * @param[in] ALG ML-KEM parameter-set identifier matching PUBLIC_KEY.
 * @retval LIBERAC_SUCCESS Encapsulation completed successfully.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT An input or output pointer is null,
 *         an output overlaps the required public-key input region, or the
 *         shared-secret and ciphertext output regions overlap.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL A supplied encoded-key or ciphertext
 *         buffer is undersized.
 * @retval LIBERAC_ERROR_RANDOM_FAILED Operating-system entropy collection
 *         failed.
 * @retval LIBERAC_ERROR_ALLOCATION_FAILED A private workspace could not be
 *         allocated.
 * @retval LIBERAC_ERROR_INVALID_KEY The encoded public key contains a
 *         non-canonical coefficient.
 * @retval LIBERAC_ERROR_INTERNAL An internal invariant failed.
 * @note Key generation and encapsulation require a working operating-system
 *       random source.
 * @note Pointer, size, and overlap validation failures leave the supplied
 *       buffers unchanged. After those checks pass, an invalid public key or
 *       operational failure clears the shared secret and required ciphertext
 *       region.
 */
LIBERAC_API LiberaCError LIBERAC_ML_KEM_ENCAPS(const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t SHARED_SECRET[LIBERAC_ML_KEM_SHARED_SECRET_BYTES], uint8_t *CIPHERTEXT, size_t CIPHERTEXT_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Decapsulate an ML-KEM ciphertext with the corresponding private key.
 * @param[in] PRIVATE_KEY Encoded ML-KEM private key.
 * @param[in] PRIVATE_KEY_LENGTH Available private-key bytes; must be at least
 *                               LIBERAC_ML_KEM_PRIVATE_KEY_SIZE(ALG).
 * @param[in] CIPHERTEXT Encoded ML-KEM ciphertext.
 * @param[in] CIPHERTEXT_LENGTH Available ciphertext bytes; must be at least
 *                              LIBERAC_ML_KEM_CIPHERTEXT_SIZE(ALG).
 * @param[out] SHARED_SECRET Buffer receiving exactly
 *                           LIBERAC_ML_KEM_SHARED_SECRET_BYTES bytes.
 * @param[in] ALG ML-KEM parameter-set identifier matching the key and ciphertext.
 * @retval LIBERAC_SUCCESS Decapsulation or implicit rejection completed.
 * @retval LIBERAC_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval LIBERAC_ERROR_INVALID_ARGUMENT An input or output pointer is null or
 *         the shared-secret output overlaps a required private-key or
 *         ciphertext input region.
 * @retval LIBERAC_ERROR_BUFFER_TOO_SMALL A supplied private-key or ciphertext
 *         buffer is undersized.
 * @retval LIBERAC_ERROR_ALLOCATION_FAILED A private workspace could not be
 *         allocated.
 * @retval LIBERAC_ERROR_INVALID_KEY The decapsulation key's embedded public
 *         key does not match its stored hash.
 * @retval LIBERAC_ERROR_INTERNAL An internal invariant failed.
 * @note ML-KEM uses implicit rejection: a correctly sized but invalid
 *       ciphertext produces a pseudorandom replacement secret rather than an
 *       authentication error. The shared secret must be consumed by an
 *       authenticated higher-level protocol.
 * @note Pointer, size, and overlap validation failures leave the supplied
 *       buffers unchanged. After those checks pass, an invalid key or
 *       internal failure clears the shared-secret output.
 */
LIBERAC_API LiberaCError LIBERAC_ML_KEM_DECAPS(const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, const uint8_t *CIPHERTEXT, size_t CIPHERTEXT_LENGTH, uint8_t SHARED_SECRET[LIBERAC_ML_KEM_SHARED_SECRET_BYTES], LiberaCAlgID ALG);

/**
 * @brief Return the encoded NTRU+ public-key size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_NTRU_PLUS_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_NTRU_PLUS_PUBLIC_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded NTRU+ private-key size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_NTRU_PLUS_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_NTRU_PLUS_PRIVATE_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded NTRU+ ciphertext size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_NTRU_PLUS_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_NTRU_PLUS_CIPHERTEXT_SIZE(LiberaCAlgID ALG);

/**
 * @brief Generate an NTRU+ key pair using operating-system randomness.
 * @param[out] PUBLIC_KEY Buffer receiving the encoded public key.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY.
 * @param[out] PRIVATE_KEY Buffer receiving the encoded private key.
 * @param[in] PRIVATE_KEY_LENGTH Available bytes in PRIVATE_KEY.
 * @param[in] ALG An LIBERAC_ALG_NTRU_PLUS_* parameter-set identifier.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note Validated output regions are cleared if generation fails.
 */
LIBERAC_API LiberaCError LIBERAC_NTRU_PLUS_KEYGEN(uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Encapsulate a fresh shared secret to an NTRU+ public key.
 * @param[in] PUBLIC_KEY Encoded public key selected by ALG.
 * @param[in] PUBLIC_KEY_LENGTH Available public-key bytes.
 * @param[out] SHARED_SECRET Buffer receiving LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES bytes.
 * @param[out] CIPHERTEXT Buffer receiving the encoded ciphertext.
 * @param[in] CIPHERTEXT_LENGTH Available ciphertext bytes.
 * @param[in] ALG An LIBERAC_ALG_NTRU_PLUS_* parameter-set identifier.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note Non-canonical public-key encodings are rejected.
 */
LIBERAC_API LiberaCError LIBERAC_NTRU_PLUS_ENCAPS(const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t SHARED_SECRET[LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES], uint8_t *CIPHERTEXT, size_t CIPHERTEXT_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Decapsulate an NTRU+ ciphertext with the corresponding private key.
 * @param[in] PRIVATE_KEY Encoded private key selected by ALG.
 * @param[in] PRIVATE_KEY_LENGTH Available private-key bytes.
 * @param[in] CIPHERTEXT Encoded ciphertext selected by ALG.
 * @param[in] CIPHERTEXT_LENGTH Available ciphertext bytes.
 * @param[out] SHARED_SECRET Buffer receiving LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES bytes.
 * @param[in] ALG An LIBERAC_ALG_NTRU_PLUS_* parameter-set identifier.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @retval LIBERAC_ERROR_AUTHENTICATION_FAILED The ciphertext is non-canonical
 *         or fails NTRU+ reencryption validation.
 * @note Authentication failure clears the shared-secret output.
 */
LIBERAC_API LiberaCError LIBERAC_NTRU_PLUS_DECAPS(const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, const uint8_t *CIPHERTEXT, size_t CIPHERTEXT_LENGTH, uint8_t SHARED_SECRET[LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES], LiberaCAlgID ALG);

/**
 * @brief Return the encoded SMAUG-T public-key size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_SMAUG_T_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_SMAUG_T_PUBLIC_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded SMAUG-T private-key size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_SMAUG_T_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_SMAUG_T_PRIVATE_KEY_SIZE(LiberaCAlgID ALG);

/**
 * @brief Return the encoded SMAUG-T ciphertext size for an algorithm.
 * @param[in] ALG An LIBERAC_ALG_SMAUG_T_* parameter-set identifier.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
LIBERAC_API size_t LIBERAC_SMAUG_T_CIPHERTEXT_SIZE(LiberaCAlgID ALG);

/**
 * @brief Generate a SMAUG-T key pair using operating-system randomness.
 * @param[out] PUBLIC_KEY Buffer receiving the encoded public key.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY.
 * @param[out] PRIVATE_KEY Buffer receiving the encoded private key.
 * @param[in] PRIVATE_KEY_LENGTH Available bytes in PRIVATE_KEY.
 * @param[in] ALG An LIBERAC_ALG_SMAUG_T_* parameter-set identifier.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note Validated output regions are cleared if generation fails.
 */
LIBERAC_API LiberaCError LIBERAC_SMAUG_T_KEYGEN(uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Encapsulate a fresh shared secret to a SMAUG-T public key.
 * @param[in] PUBLIC_KEY Encoded public key selected by ALG.
 * @param[in] PUBLIC_KEY_LENGTH Available public-key bytes.
 * @param[out] SHARED_SECRET Buffer receiving LIBERAC_SMAUG_T_SHARED_SECRET_BYTES bytes.
 * @param[out] CIPHERTEXT Buffer receiving the encoded ciphertext.
 * @param[in] CIPHERTEXT_LENGTH Available ciphertext bytes.
 * @param[in] ALG An LIBERAC_ALG_SMAUG_T_* parameter-set identifier.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 */
LIBERAC_API LiberaCError LIBERAC_SMAUG_T_ENCAPS(const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t SHARED_SECRET[LIBERAC_SMAUG_T_SHARED_SECRET_BYTES], uint8_t *CIPHERTEXT, size_t CIPHERTEXT_LENGTH, LiberaCAlgID ALG);

/**
 * @brief Decapsulate a SMAUG-T ciphertext with the corresponding private key.
 * @param[in] PRIVATE_KEY Encoded private key selected by ALG.
 * @param[in] PRIVATE_KEY_LENGTH Available private-key bytes.
 * @param[in] CIPHERTEXT Encoded ciphertext selected by ALG.
 * @param[in] CIPHERTEXT_LENGTH Available ciphertext bytes.
 * @param[out] SHARED_SECRET Buffer receiving LIBERAC_SMAUG_T_SHARED_SECRET_BYTES bytes.
 * @param[in] ALG An LIBERAC_ALG_SMAUG_T_* parameter-set identifier.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note Correctly sized invalid ciphertexts use implicit rejection.
 */
LIBERAC_API LiberaCError LIBERAC_SMAUG_T_DECAPS(const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, const uint8_t *CIPHERTEXT, size_t CIPHERTEXT_LENGTH, uint8_t SHARED_SECRET[LIBERAC_SMAUG_T_SHARED_SECRET_BYTES], LiberaCAlgID ALG);
LIBERAC_END_DECLS

#endif

/** @} */
