/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBERAC_ASYMMETRIC_CIPHER_H
#define LIBERAC_ASYMMETRIC_CIPHER_H

/**
 * @file AsymmetricCipher.h
 * @brief Public-key encryption APIs for raw RSA and safe-prime ElGamal.
 *
 * All key and ciphertext objects in this header own dynamically allocated
 * LiberaCBignum members. Initialize each object with its matching INIT
 * function before first use, and release it with the matching FREE function.
 * The algorithm identifier is supplied at run time as the final argument.
 *
 * @warning LIBERAC_ALG_RSA_RAW and LIBERAC_ALG_ELGAMAL_SAFE_PRIME provide the mathematical
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
    LiberaCBignum N; /**< RSA modulus. */
    LiberaCBignum E; /**< Public exponent; generated keys use 65537. */
} LiberaCRsaPublicKey;

/** @brief Raw RSA private key. */
typedef struct {
    LiberaCBignum N; /**< RSA modulus. */
    LiberaCBignum D; /**< Private exponent. */
    LiberaCBignum P; /**< First secret prime factor of N. */
    LiberaCBignum Q; /**< Second secret prime factor of N. */
} LiberaCRsaPrivateKey;

/** @brief Safe-prime ElGamal public key. */
typedef struct {
    LiberaCBignum P; /**< Safe-prime modulus, where P = 2Q + 1. */
    LiberaCBignum Q; /**< Prime order of the selected subgroup. */
    LiberaCBignum G; /**< Subgroup generator. */
    LiberaCBignum H; /**< Public value G^X mod P. */
} LiberaCElgamalPublicKey;

/** @brief Safe-prime ElGamal private key. */
typedef struct {
    LiberaCBignum X; /**< Secret exponent in the subgroup of order Q. */
} LiberaCElgamalPrivateKey;

/** @brief ElGamal ciphertext pair. */
typedef struct {
    LiberaCBignum C1; /**< Ephemeral group element G^Y mod P. */
    LiberaCBignum C2; /**< Message multiplied by H^Y modulo P. */
} LiberaCElgamalCiphertext;

LIBERAC_BEGIN_DECLS

/**
 * @brief Initialize an RSA public-key object.
 * @param[out] KEY Object to initialize. A null pointer is ignored.
 * @note Do not call this on an object that currently owns storage; call
 *       LIBERAC_RSA_PUBLIC_KEY_FREE() first.
 */
LIBERAC_API void LIBERAC_RSA_PUBLIC_KEY_INIT(LiberaCRsaPublicKey *KEY);

/**
 * @brief Clear and release an RSA public-key object.
 * @param[in,out] KEY Initialized object to release. A null pointer is ignored.
 * @post KEY is reset and may be initialized or freed again.
 */
LIBERAC_API void LIBERAC_RSA_PUBLIC_KEY_FREE(LiberaCRsaPublicKey *KEY);

/**
 * @brief Initialize an RSA private-key object.
 * @param[out] KEY Object to initialize. A null pointer is ignored.
 * @note Do not call this on an object that currently owns storage; call
 *       LIBERAC_RSA_PRIVATE_KEY_FREE() first.
 */
LIBERAC_API void LIBERAC_RSA_PRIVATE_KEY_INIT(LiberaCRsaPrivateKey *KEY);

/**
 * @brief Clear and release an RSA private-key object.
 * @param[in,out] KEY Initialized object to release. A null pointer is ignored.
 * @post KEY is reset and may be initialized or freed again.
 */
LIBERAC_API void LIBERAC_RSA_PRIVATE_KEY_FREE(LiberaCRsaPrivateKey *KEY);

/**
 * @brief Generate a raw RSA key pair.
 * @param[in,out] PUBLIC_KEY Initialized destination for the public key.
 * @param[in,out] PRIVATE_KEY Initialized destination for the private key.
 * @param[in] MODULUS_BITS Requested modulus size in bits; must be at least 32.
 * @param[in] PRIME_ROUNDS Miller-Rabin rounds used for prime generation. Zero
 *                         selects the default of 32 rounds.
 * @param[in] ALG Must be LIBERAC_ALG_RSA_RAW.
 * @return LIBERAC_SUCCESS on success; LIBERAC_ERROR_INVALID_ALG_ID for an
 *         unsupported identifier, LIBERAC_ERROR_INVALID_ARGUMENT for invalid
 *         inputs, or another LiberaCError describing generation failure.
 * @note On success, any values previously owned by the initialized key
 *       objects are released and replaced.
 */
LIBERAC_API LiberaCError LIBERAC_RSA_KEYGEN(LiberaCRsaPublicKey *PUBLIC_KEY, LiberaCRsaPrivateKey *PRIVATE_KEY, size_t MODULUS_BITS, uint32_t PRIME_ROUNDS, LiberaCAlgID ALG);

/**
 * @brief Apply the raw RSA public operation to an integer message.
 * @param[in,out] CIPHERTEXT Initialized bignum receiving MESSAGE^E mod N.
 * @param[in] MESSAGE Non-negative integer message; it must be less than N.
 * @param[in] PUBLIC_KEY Initialized RSA public key.
 * @param[in] ALG Must be LIBERAC_ALG_RSA_RAW.
 * @return LIBERAC_SUCCESS on success, LIBERAC_ERROR_MESSAGE_TOO_LARGE when the
 *         message is not less than N, or another LiberaCError on failure.
 * @warning This function does not perform an RSA padding or encoding scheme.
 */
LIBERAC_API LiberaCError LIBERAC_RSA_ENCRYPT(LiberaCBignum *CIPHERTEXT, const LiberaCBignum *MESSAGE, const LiberaCRsaPublicKey *PUBLIC_KEY, LiberaCAlgID ALG);

/**
 * @brief Apply the raw RSA private operation to a ciphertext integer.
 * @param[in,out] MESSAGE Initialized bignum receiving CIPHERTEXT^D mod N.
 * @param[in] CIPHERTEXT Non-negative ciphertext integer; it must be less than N.
 * @param[in] PRIVATE_KEY Initialized RSA private key.
 * @param[in] ALG Must be LIBERAC_ALG_RSA_RAW.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @warning This function does not validate or remove an RSA padding scheme.
 */
LIBERAC_API LiberaCError LIBERAC_RSA_DECRYPT(LiberaCBignum *MESSAGE, const LiberaCBignum *CIPHERTEXT, const LiberaCRsaPrivateKey *PRIVATE_KEY, LiberaCAlgID ALG);

/**
 * @brief Initialize an ElGamal public-key object.
 * @param[out] KEY Object to initialize. A null pointer is ignored.
 * @note Do not reinitialize an object that currently owns storage.
 */
LIBERAC_API void LIBERAC_ELGAMAL_PUBLIC_KEY_INIT(LiberaCElgamalPublicKey *KEY);

/**
 * @brief Clear and release an ElGamal public-key object.
 * @param[in,out] KEY Initialized object to release. A null pointer is ignored.
 */
LIBERAC_API void LIBERAC_ELGAMAL_PUBLIC_KEY_FREE(LiberaCElgamalPublicKey *KEY);

/**
 * @brief Initialize an ElGamal private-key object.
 * @param[out] KEY Object to initialize. A null pointer is ignored.
 * @note Do not reinitialize an object that currently owns storage.
 */
LIBERAC_API void LIBERAC_ELGAMAL_PRIVATE_KEY_INIT(LiberaCElgamalPrivateKey *KEY);

/**
 * @brief Clear and release an ElGamal private-key object.
 * @param[in,out] KEY Initialized object to release. A null pointer is ignored.
 */
LIBERAC_API void LIBERAC_ELGAMAL_PRIVATE_KEY_FREE(LiberaCElgamalPrivateKey *KEY);

/**
 * @brief Initialize an ElGamal ciphertext object.
 * @param[out] CIPHERTEXT Object to initialize. A null pointer is ignored.
 * @note Do not reinitialize an object that currently owns storage.
 */
LIBERAC_API void LIBERAC_ELGAMAL_CIPHERTEXT_INIT(LiberaCElgamalCiphertext *CIPHERTEXT);

/**
 * @brief Clear and release an ElGamal ciphertext object.
 * @param[in,out] CIPHERTEXT Initialized object to release. A null pointer is
 *                           ignored.
 */
LIBERAC_API void LIBERAC_ELGAMAL_CIPHERTEXT_FREE(LiberaCElgamalCiphertext *CIPHERTEXT);

/**
 * @brief Generate a safe-prime ElGamal key pair.
 * @param[in,out] PUBLIC_KEY Initialized destination for the public key.
 * @param[in,out] PRIVATE_KEY Initialized destination for the private key.
 * @param[in] MODULUS_BITS Requested bit length of the safe-prime modulus P;
 *                         must be at least 32.
 * @param[in] PRIME_ROUNDS Miller-Rabin rounds. Zero selects 32 rounds.
 * @param[in] ALG Must be LIBERAC_ALG_ELGAMAL_SAFE_PRIME.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note The generated public key describes a prime-order subgroup of the
 *       multiplicative group modulo P.
 */
LIBERAC_API LiberaCError LIBERAC_ELGAMAL_KEYGEN(LiberaCElgamalPublicKey *PUBLIC_KEY, LiberaCElgamalPrivateKey *PRIVATE_KEY, size_t MODULUS_BITS, uint32_t PRIME_ROUNDS, LiberaCAlgID ALG);

/**
 * @brief Encrypt a non-negative integer with safe-prime ElGamal.
 * @param[in,out] CIPHERTEXT Initialized destination for the ciphertext pair.
 * @param[in] MESSAGE Integer message in the range 0 <= MESSAGE < P.
 * @param[in] PUBLIC_KEY Initialized ElGamal public key.
 * @param[in] ALG Must be LIBERAC_ALG_ELGAMAL_SAFE_PRIME.
 * @return LIBERAC_SUCCESS on success, LIBERAC_ERROR_MESSAGE_TOO_LARGE when the
 *         message is not less than P, or another LiberaCError on failure.
 * @note Fresh randomness is obtained from LIBERAC_RANDOM_BYTES internally.
 */
LIBERAC_API LiberaCError LIBERAC_ELGAMAL_ENCRYPT(LiberaCElgamalCiphertext *CIPHERTEXT, const LiberaCBignum *MESSAGE, const LiberaCElgamalPublicKey *PUBLIC_KEY, LiberaCAlgID ALG);

/**
 * @brief Decrypt a safe-prime ElGamal ciphertext.
 * @param[in,out] MESSAGE Initialized bignum receiving the recovered integer.
 * @param[in] CIPHERTEXT Initialized ciphertext whose components must be less
 *                       than the public modulus P.
 * @param[in] PUBLIC_KEY Public key corresponding to PRIVATE_KEY.
 * @param[in] PRIVATE_KEY ElGamal private key.
 * @param[in] ALG Must be LIBERAC_ALG_ELGAMAL_SAFE_PRIME.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 */
LIBERAC_API LiberaCError LIBERAC_ELGAMAL_DECRYPT(LiberaCBignum *MESSAGE, const LiberaCElgamalCiphertext *CIPHERTEXT, const LiberaCElgamalPublicKey *PUBLIC_KEY, const LiberaCElgamalPrivateKey *PRIVATE_KEY, LiberaCAlgID ALG);
LIBERAC_END_DECLS

#endif

/** @} */
