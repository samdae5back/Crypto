/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_ASYMMETRIC_CIPHER_H
#define CRYPTO_ASYMMETRIC_CIPHER_H

/**
 * @file AsymmetricCipher.h
 * @brief Public-key encryption APIs for raw RSA and safe-prime ElGamal.
 *
 * All key and ciphertext objects in this header own dynamically allocated
 * CRYPTO_BIGNUM members. Initialize each object with its matching INIT
 * function before first use, and release it with the matching FREE function.
 * The algorithm identifier is supplied at run time as the final argument.
 *
 * @warning ALG_RSA_RAW and ALG_ELGAMAL_SAFE_PRIME provide the mathematical
 *          primitives only. They do not add padding, message encoding,
 *          integrity, or chosen-ciphertext protection. Applications should
 *          not use them as general-purpose encryption schemes without a
 *          suitable, independently reviewed higher-level construction.
 *
 * @defgroup crypto_asymmetric_cipher Asymmetric-cipher API
 * @brief Raw RSA and safe-prime ElGamal operations and managed key objects.
 * @{
 */

#include "Util.h"

/** @brief Raw RSA public key. */
typedef struct {
    CRYPTO_BIGNUM N; /**< RSA modulus. */
    CRYPTO_BIGNUM E; /**< Public exponent; generated keys use 65537. */
} CRYPTO_RSA_PUBLIC_KEY;

/** @brief Raw RSA private key. */
typedef struct {
    CRYPTO_BIGNUM N; /**< RSA modulus. */
    CRYPTO_BIGNUM D; /**< Private exponent. */
    CRYPTO_BIGNUM P; /**< First secret prime factor of N. */
    CRYPTO_BIGNUM Q; /**< Second secret prime factor of N. */
} CRYPTO_RSA_PRIVATE_KEY;

/** @brief Safe-prime ElGamal public key. */
typedef struct {
    CRYPTO_BIGNUM P; /**< Safe-prime modulus, where P = 2Q + 1. */
    CRYPTO_BIGNUM Q; /**< Prime order of the selected subgroup. */
    CRYPTO_BIGNUM G; /**< Subgroup generator. */
    CRYPTO_BIGNUM H; /**< Public value G^X mod P. */
} CRYPTO_ELGAMAL_PUBLIC_KEY;

/** @brief Safe-prime ElGamal private key. */
typedef struct {
    CRYPTO_BIGNUM X; /**< Secret exponent in the subgroup of order Q. */
} CRYPTO_ELGAMAL_PRIVATE_KEY;

/** @brief ElGamal ciphertext pair. */
typedef struct {
    CRYPTO_BIGNUM C1; /**< Ephemeral group element G^Y mod P. */
    CRYPTO_BIGNUM C2; /**< Message multiplied by H^Y modulo P. */
} CRYPTO_ELGAMAL_CIPHERTEXT;

CRYPTO_BEGIN_DECLS

/**
 * @brief Initialize an RSA public-key object.
 * @param[out] KEY Object to initialize. A null pointer is ignored.
 * @note Do not call this on an object that currently owns storage; call
 *       CRYPTO_RSA_PUBLIC_KEY_FREE() first.
 */
CRYPTO_API void CRYPTO_RSA_PUBLIC_KEY_INIT(CRYPTO_RSA_PUBLIC_KEY *KEY);

/**
 * @brief Clear and release an RSA public-key object.
 * @param[in,out] KEY Initialized object to release. A null pointer is ignored.
 * @post KEY is reset and may be initialized or freed again.
 */
CRYPTO_API void CRYPTO_RSA_PUBLIC_KEY_FREE(CRYPTO_RSA_PUBLIC_KEY *KEY);

/**
 * @brief Initialize an RSA private-key object.
 * @param[out] KEY Object to initialize. A null pointer is ignored.
 * @note Do not call this on an object that currently owns storage; call
 *       CRYPTO_RSA_PRIVATE_KEY_FREE() first.
 */
CRYPTO_API void CRYPTO_RSA_PRIVATE_KEY_INIT(CRYPTO_RSA_PRIVATE_KEY *KEY);

/**
 * @brief Clear and release an RSA private-key object.
 * @param[in,out] KEY Initialized object to release. A null pointer is ignored.
 * @post KEY is reset and may be initialized or freed again.
 */
CRYPTO_API void CRYPTO_RSA_PRIVATE_KEY_FREE(CRYPTO_RSA_PRIVATE_KEY *KEY);

/**
 * @brief Generate a raw RSA key pair.
 * @param[in,out] PUBLIC_KEY Initialized destination for the public key.
 * @param[in,out] PRIVATE_KEY Initialized destination for the private key.
 * @param[in] MODULUS_BITS Requested modulus size in bits; must be at least 32.
 * @param[in] PRIME_ROUNDS Miller-Rabin rounds used for prime generation. Zero
 *                         selects the default of 32 rounds.
 * @param[in] ALG Must be ALG_RSA_RAW.
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_INVALID_ALG_ID for an
 *         unsupported identifier, CRYPTO_ERROR_INVALID_ARGUMENT for invalid
 *         inputs, or another CryptoError describing generation failure.
 * @note On success, any values previously owned by the initialized key
 *       objects are released and replaced.
 */
CRYPTO_API CryptoError CRYPTO_RSA_KEYGEN(CRYPTO_RSA_PUBLIC_KEY *PUBLIC_KEY, CRYPTO_RSA_PRIVATE_KEY *PRIVATE_KEY, size_t MODULUS_BITS, uint32_t PRIME_ROUNDS, AlgID ALG);

/**
 * @brief Apply the raw RSA public operation to an integer message.
 * @param[in,out] CIPHERTEXT Initialized bignum receiving MESSAGE^E mod N.
 * @param[in] MESSAGE Non-negative integer message; it must be less than N.
 * @param[in] PUBLIC_KEY Initialized RSA public key.
 * @param[in] ALG Must be ALG_RSA_RAW.
 * @return CRYPTO_SUCCESS on success, CRYPTO_ERROR_MESSAGE_TOO_LARGE when the
 *         message is not less than N, or another CryptoError on failure.
 * @warning This function does not perform an RSA padding or encoding scheme.
 */
CRYPTO_API CryptoError CRYPTO_RSA_ENCRYPT(CRYPTO_BIGNUM *CIPHERTEXT, const CRYPTO_BIGNUM *MESSAGE, const CRYPTO_RSA_PUBLIC_KEY *PUBLIC_KEY, AlgID ALG);

/**
 * @brief Apply the raw RSA private operation to a ciphertext integer.
 * @param[in,out] MESSAGE Initialized bignum receiving CIPHERTEXT^D mod N.
 * @param[in] CIPHERTEXT Non-negative ciphertext integer; it must be less than N.
 * @param[in] PRIVATE_KEY Initialized RSA private key.
 * @param[in] ALG Must be ALG_RSA_RAW.
 * @return CRYPTO_SUCCESS on success or a negative CryptoError on failure.
 * @warning This function does not validate or remove an RSA padding scheme.
 */
CRYPTO_API CryptoError CRYPTO_RSA_DECRYPT(CRYPTO_BIGNUM *MESSAGE, const CRYPTO_BIGNUM *CIPHERTEXT, const CRYPTO_RSA_PRIVATE_KEY *PRIVATE_KEY, AlgID ALG);

/**
 * @brief Initialize an ElGamal public-key object.
 * @param[out] KEY Object to initialize. A null pointer is ignored.
 * @note Do not reinitialize an object that currently owns storage.
 */
CRYPTO_API void CRYPTO_ELGAMAL_PUBLIC_KEY_INIT(CRYPTO_ELGAMAL_PUBLIC_KEY *KEY);

/**
 * @brief Clear and release an ElGamal public-key object.
 * @param[in,out] KEY Initialized object to release. A null pointer is ignored.
 */
CRYPTO_API void CRYPTO_ELGAMAL_PUBLIC_KEY_FREE(CRYPTO_ELGAMAL_PUBLIC_KEY *KEY);

/**
 * @brief Initialize an ElGamal private-key object.
 * @param[out] KEY Object to initialize. A null pointer is ignored.
 * @note Do not reinitialize an object that currently owns storage.
 */
CRYPTO_API void CRYPTO_ELGAMAL_PRIVATE_KEY_INIT(CRYPTO_ELGAMAL_PRIVATE_KEY *KEY);

/**
 * @brief Clear and release an ElGamal private-key object.
 * @param[in,out] KEY Initialized object to release. A null pointer is ignored.
 */
CRYPTO_API void CRYPTO_ELGAMAL_PRIVATE_KEY_FREE(CRYPTO_ELGAMAL_PRIVATE_KEY *KEY);

/**
 * @brief Initialize an ElGamal ciphertext object.
 * @param[out] CIPHERTEXT Object to initialize. A null pointer is ignored.
 * @note Do not reinitialize an object that currently owns storage.
 */
CRYPTO_API void CRYPTO_ELGAMAL_CIPHERTEXT_INIT(CRYPTO_ELGAMAL_CIPHERTEXT *CIPHERTEXT);

/**
 * @brief Clear and release an ElGamal ciphertext object.
 * @param[in,out] CIPHERTEXT Initialized object to release. A null pointer is
 *                           ignored.
 */
CRYPTO_API void CRYPTO_ELGAMAL_CIPHERTEXT_FREE(CRYPTO_ELGAMAL_CIPHERTEXT *CIPHERTEXT);

/**
 * @brief Generate a safe-prime ElGamal key pair.
 * @param[in,out] PUBLIC_KEY Initialized destination for the public key.
 * @param[in,out] PRIVATE_KEY Initialized destination for the private key.
 * @param[in] MODULUS_BITS Requested bit length of the safe-prime modulus P;
 *                         must be at least 32.
 * @param[in] PRIME_ROUNDS Miller-Rabin rounds. Zero selects 32 rounds.
 * @param[in] ALG Must be ALG_ELGAMAL_SAFE_PRIME.
 * @return CRYPTO_SUCCESS on success or a negative CryptoError on failure.
 * @note The generated public key describes a prime-order subgroup of the
 *       multiplicative group modulo P.
 */
CRYPTO_API CryptoError CRYPTO_ELGAMAL_KEYGEN(CRYPTO_ELGAMAL_PUBLIC_KEY *PUBLIC_KEY, CRYPTO_ELGAMAL_PRIVATE_KEY *PRIVATE_KEY, size_t MODULUS_BITS, uint32_t PRIME_ROUNDS, AlgID ALG);

/**
 * @brief Encrypt a non-negative integer with safe-prime ElGamal.
 * @param[in,out] CIPHERTEXT Initialized destination for the ciphertext pair.
 * @param[in] MESSAGE Integer message in the range 0 <= MESSAGE < P.
 * @param[in] PUBLIC_KEY Initialized ElGamal public key.
 * @param[in] ALG Must be ALG_ELGAMAL_SAFE_PRIME.
 * @return CRYPTO_SUCCESS on success, CRYPTO_ERROR_MESSAGE_TOO_LARGE when the
 *         message is not less than P, or another CryptoError on failure.
 * @note Fresh randomness is obtained from CRYPTO_RANDOM_BYTES internally.
 */
CRYPTO_API CryptoError CRYPTO_ELGAMAL_ENCRYPT(CRYPTO_ELGAMAL_CIPHERTEXT *CIPHERTEXT, const CRYPTO_BIGNUM *MESSAGE, const CRYPTO_ELGAMAL_PUBLIC_KEY *PUBLIC_KEY, AlgID ALG);

/**
 * @brief Decrypt a safe-prime ElGamal ciphertext.
 * @param[in,out] MESSAGE Initialized bignum receiving the recovered integer.
 * @param[in] CIPHERTEXT Initialized ciphertext whose components must be less
 *                       than the public modulus P.
 * @param[in] PUBLIC_KEY Public key corresponding to PRIVATE_KEY.
 * @param[in] PRIVATE_KEY ElGamal private key.
 * @param[in] ALG Must be ALG_ELGAMAL_SAFE_PRIME.
 * @return CRYPTO_SUCCESS on success or a negative CryptoError on failure.
 */
CRYPTO_API CryptoError CRYPTO_ELGAMAL_DECRYPT(CRYPTO_BIGNUM *MESSAGE, const CRYPTO_ELGAMAL_CIPHERTEXT *CIPHERTEXT, const CRYPTO_ELGAMAL_PUBLIC_KEY *PUBLIC_KEY, const CRYPTO_ELGAMAL_PRIVATE_KEY *PRIVATE_KEY, AlgID ALG);
CRYPTO_END_DECLS

#endif

/** @} */
