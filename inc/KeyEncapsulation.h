#ifndef CRYPTO_KEY_ENCAPSULATION_H
#define CRYPTO_KEY_ENCAPSULATION_H

/**
 * @file KeyEncapsulation.h
 * @brief Runtime-selected ML-KEM key generation and encapsulation APIs.
 *
 * ML-KEM keys and ciphertexts are fixed-size encoded byte strings. Query the
 * selected parameter set's sizes before allocating buffers. Every successful
 * encapsulation or decapsulation produces exactly
 * CRYPTO_ML_KEM_SHARED_SECRET_BYTES bytes of shared secret material.
 *
 * @defgroup crypto_key_encapsulation Key-encapsulation API
 * @brief ML-KEM key generation, encapsulation, and decapsulation.
 * @{
 */

#include "Def.h"

/** @brief ML-KEM-512 encoded public-key length in bytes. */
#define CRYPTO_ML_KEM_512_PUBLIC_KEY_BYTES 800u
/** @brief ML-KEM-512 encoded private-key length in bytes. */
#define CRYPTO_ML_KEM_512_PRIVATE_KEY_BYTES 1632u
/** @brief ML-KEM-512 encoded ciphertext length in bytes. */
#define CRYPTO_ML_KEM_512_CIPHERTEXT_BYTES 768u
/** @brief ML-KEM-768 encoded public-key length in bytes. */
#define CRYPTO_ML_KEM_768_PUBLIC_KEY_BYTES 1184u
/** @brief ML-KEM-768 encoded private-key length in bytes. */
#define CRYPTO_ML_KEM_768_PRIVATE_KEY_BYTES 2400u
/** @brief ML-KEM-768 encoded ciphertext length in bytes. */
#define CRYPTO_ML_KEM_768_CIPHERTEXT_BYTES 1088u
/** @brief ML-KEM-1024 encoded public-key length in bytes. */
#define CRYPTO_ML_KEM_1024_PUBLIC_KEY_BYTES 1568u
/** @brief ML-KEM-1024 encoded private-key length in bytes. */
#define CRYPTO_ML_KEM_1024_PRIVATE_KEY_BYTES 3168u
/** @brief ML-KEM-1024 encoded ciphertext length in bytes. */
#define CRYPTO_ML_KEM_1024_CIPHERTEXT_BYTES 1568u
/** @brief Shared-secret length produced by every supported ML-KEM parameter set. */
#define CRYPTO_ML_KEM_SHARED_SECRET_BYTES 32u

CRYPTO_BEGIN_DECLS

/**
 * @brief Return the encoded ML-KEM public-key size for an algorithm.
 * @param[in] ALG One of ALG_ML_KEM_512, ALG_ML_KEM_768, or ALG_ML_KEM_1024.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
CRYPTO_API size_t CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(AlgID ALG);

/**
 * @brief Return the encoded ML-KEM private-key size for an algorithm.
 * @param[in] ALG One of ALG_ML_KEM_512, ALG_ML_KEM_768, or ALG_ML_KEM_1024.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
CRYPTO_API size_t CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(AlgID ALG);

/**
 * @brief Return the encoded ML-KEM ciphertext size for an algorithm.
 * @param[in] ALG One of ALG_ML_KEM_512, ALG_ML_KEM_768, or ALG_ML_KEM_1024.
 * @return Required size in bytes, or zero if ALG is unsupported.
 */
CRYPTO_API size_t CRYPTO_ML_KEM_CIPHERTEXT_SIZE(AlgID ALG);

/**
 * @brief Generate an ML-KEM key pair using operating-system randomness.
 * @param[out] PUBLIC_KEY Buffer receiving the encoded public key.
 * @param[in] PUBLIC_KEY_LENGTH Available bytes in PUBLIC_KEY; must be at least
 *                              CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(ALG).
 * @param[out] PRIVATE_KEY Buffer receiving the encoded private key.
 * @param[in] PRIVATE_KEY_LENGTH Available bytes in PRIVATE_KEY; must be at
 *                               least CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(ALG).
 * @param[in] ALG ML-KEM parameter-set identifier.
 * @retval CRYPTO_SUCCESS The key pair was generated successfully.
 * @retval CRYPTO_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval CRYPTO_ERROR_INVALID_ARGUMENT An output pointer is null or the
 *         required public-key and private-key output regions overlap.
 * @retval CRYPTO_ERROR_BUFFER_TOO_SMALL An output buffer is undersized.
 * @retval CRYPTO_ERROR_RANDOM_FAILED Operating-system entropy collection
 *         failed.
 * @retval CRYPTO_ERROR_ALLOCATION_FAILED A private workspace could not be
 *         allocated.
 * @retval CRYPTO_ERROR_INTERNAL An internal invariant failed.
 * @note Pointer, size, and overlap validation failures leave the supplied
 *       buffers unchanged. After those checks pass, a generation failure
 *       clears the required portions of both output buffers.
 */
CRYPTO_API CryptoError CRYPTO_ML_KEM_KEYGEN(uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, AlgID ALG);

/**
 * @brief Encapsulate a fresh shared secret to an ML-KEM public key.
 * @param[in] PUBLIC_KEY Encoded ML-KEM public key.
 * @param[in] PUBLIC_KEY_LENGTH Available public-key bytes; must be at least
 *                              CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(ALG).
 * @param[out] SHARED_SECRET Buffer receiving exactly
 *                           CRYPTO_ML_KEM_SHARED_SECRET_BYTES bytes.
 * @param[out] CIPHERTEXT Buffer receiving the encoded ciphertext.
 * @param[in] CIPHERTEXT_LENGTH Available bytes in CIPHERTEXT; must be at least
 *                              CRYPTO_ML_KEM_CIPHERTEXT_SIZE(ALG).
 * @param[in] ALG ML-KEM parameter-set identifier matching PUBLIC_KEY.
 * @retval CRYPTO_SUCCESS Encapsulation completed successfully.
 * @retval CRYPTO_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval CRYPTO_ERROR_INVALID_ARGUMENT An input or output pointer is null,
 *         an output overlaps the required public-key input region, or the
 *         shared-secret and ciphertext output regions overlap.
 * @retval CRYPTO_ERROR_BUFFER_TOO_SMALL A supplied encoded-key or ciphertext
 *         buffer is undersized.
 * @retval CRYPTO_ERROR_RANDOM_FAILED Operating-system entropy collection
 *         failed.
 * @retval CRYPTO_ERROR_ALLOCATION_FAILED A private workspace could not be
 *         allocated.
 * @retval CRYPTO_ERROR_INVALID_KEY The encoded public key contains a
 *         non-canonical coefficient.
 * @retval CRYPTO_ERROR_INTERNAL An internal invariant failed.
 * @note Key generation and encapsulation require a working operating-system
 *       random source.
 * @note Pointer, size, and overlap validation failures leave the supplied
 *       buffers unchanged. After those checks pass, an invalid public key or
 *       operational failure clears the shared secret and required ciphertext
 *       region.
 */
CRYPTO_API CryptoError CRYPTO_ML_KEM_ENCAPS(const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH, uint8_t SHARED_SECRET[CRYPTO_ML_KEM_SHARED_SECRET_BYTES], uint8_t *CIPHERTEXT, size_t CIPHERTEXT_LENGTH, AlgID ALG);

/**
 * @brief Decapsulate an ML-KEM ciphertext with the corresponding private key.
 * @param[in] PRIVATE_KEY Encoded ML-KEM private key.
 * @param[in] PRIVATE_KEY_LENGTH Available private-key bytes; must be at least
 *                               CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(ALG).
 * @param[in] CIPHERTEXT Encoded ML-KEM ciphertext.
 * @param[in] CIPHERTEXT_LENGTH Available ciphertext bytes; must be at least
 *                              CRYPTO_ML_KEM_CIPHERTEXT_SIZE(ALG).
 * @param[out] SHARED_SECRET Buffer receiving exactly
 *                           CRYPTO_ML_KEM_SHARED_SECRET_BYTES bytes.
 * @param[in] ALG ML-KEM parameter-set identifier matching the key and ciphertext.
 * @retval CRYPTO_SUCCESS Decapsulation or implicit rejection completed.
 * @retval CRYPTO_ERROR_INVALID_ALG_ID @p ALG is unsupported.
 * @retval CRYPTO_ERROR_INVALID_ARGUMENT An input or output pointer is null or
 *         the shared-secret output overlaps a required private-key or
 *         ciphertext input region.
 * @retval CRYPTO_ERROR_BUFFER_TOO_SMALL A supplied private-key or ciphertext
 *         buffer is undersized.
 * @retval CRYPTO_ERROR_ALLOCATION_FAILED A private workspace could not be
 *         allocated.
 * @retval CRYPTO_ERROR_INVALID_KEY The decapsulation key's embedded public
 *         key does not match its stored hash.
 * @retval CRYPTO_ERROR_INTERNAL An internal invariant failed.
 * @note ML-KEM uses implicit rejection: a correctly sized but invalid
 *       ciphertext produces a pseudorandom replacement secret rather than an
 *       authentication error. The shared secret must be consumed by an
 *       authenticated higher-level protocol.
 * @note Pointer, size, and overlap validation failures leave the supplied
 *       buffers unchanged. After those checks pass, an invalid key or
 *       internal failure clears the shared-secret output.
 */
CRYPTO_API CryptoError CRYPTO_ML_KEM_DECAPS(const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH, const uint8_t *CIPHERTEXT, size_t CIPHERTEXT_LENGTH, uint8_t SHARED_SECRET[CRYPTO_ML_KEM_SHARED_SECRET_BYTES], AlgID ALG);
CRYPTO_END_DECLS

#endif

/** @} */
