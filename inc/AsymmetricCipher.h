/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBERAC_ASYMMETRIC_CIPHER_H
#define LIBERAC_ASYMMETRIC_CIPHER_H

/**
 * @file AsymmetricCipher.h
 * @brief RSA encryption/signature schemes and safe-prime ElGamal APIs.
 *
 * All key and ciphertext objects in this header own dynamically allocated
 * LiberaCBignum members. Initialize each object with its matching INIT
 * function before first use, and release it with the matching FREE function.
 * The algorithm identifier is supplied at run time as the final argument.
 *
 * @warning LIBERAC_ALG_RSA_RAW and LIBERAC_ALG_ELGAMAL_SAFE_PRIME provide
 *          mathematical primitives only. They do not add padding, message
 *          encoding, integrity, or chosen-ciphertext protection. Use
 *          LIBERAC_ALG_RSA_OAEP for RSA encryption and LIBERAC_ALG_RSA_PSS
 *          for RSA signatures.
 *
 * @defgroup crypto_asymmetric_cipher Asymmetric-cipher API
 * @brief RSA OAEP/PSS, raw RSA, and safe-prime ElGamal operations.
 * @{
 */

#include "Util.h"

/** @brief RSA public key. */
typedef struct {
    LiberaCBignum N; /**< RSA modulus. */
    LiberaCBignum E; /**< Public exponent; generated keys use 65537. */
} LiberaCRsaPublicKey;

/** @brief RSA private key. */
typedef struct {
    LiberaCBignum N; /**< RSA modulus. */
    LiberaCBignum D; /**< Private exponent. */
    LiberaCBignum P; /**< First secret prime factor of N. */
    LiberaCBignum Q; /**< Second secret prime factor of N. */
} LiberaCRsaPrivateKey;

/**
 * @brief Select a PSS salt whose length equals the selected hash digest.
 *
 * Pass this value as SALT_LENGTH to the PSS sign or verify API. Verification
 * still requires that exact resolved length; it does not auto-detect salt.
 */
#define LIBERAC_RSA_PSS_SALT_LENGTH_DIGEST ((size_t)-1)

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
 * @brief Generate an RSA key pair.
 * @param[in,out] PUBLIC_KEY Initialized destination for the public key.
 * @param[in,out] PRIVATE_KEY Initialized destination for the private key.
 * @param[in] MODULUS_BITS Requested modulus size in bits; must be at least 32.
 * @param[in] PRIME_ROUNDS Miller-Rabin rounds used for prime generation. Zero
 *                         selects the default of 32 rounds.
 * @param[in] ALG Any LIBERAC_ALG_RSA_RAW, _OAEP, or _PSS identifier. The
 *                generated key material is scheme-independent.
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
 * @brief Return the RSA modulus width in octets for a public key.
 * @param[in] PUBLIC_KEY Initialized RSA public key.
 * @return ceil(bit_length(N) / 8), or zero for an invalid key.
 */
LIBERAC_API size_t LIBERAC_RSA_PUBLIC_MODULUS_SIZE(const LiberaCRsaPublicKey *PUBLIC_KEY);

/**
 * @brief Return the RSA modulus width in octets for a private key.
 * @param[in] PRIVATE_KEY Initialized RSA private key.
 * @return ceil(bit_length(N) / 8), or zero for an invalid key.
 */
LIBERAC_API size_t LIBERAC_RSA_PRIVATE_MODULUS_SIZE(const LiberaCRsaPrivateKey *PRIVATE_KEY);

/**
 * @brief Return the largest OAEP plaintext for a modulus/hash combination.
 * @param[in] MODULUS_BYTES RSA modulus width k in octets.
 * @param[in] HASH_ALG SHA-1 or fixed-output SHA-2 selector used by OAEP/MGF1.
 * @param[in] ALG Must be LIBERAC_ALG_RSA_OAEP.
 * @return k - 2*hLen - 2, or zero when unsupported or structurally too small.
 * @note A return value of zero can also describe a valid empty-only encoding.
 */
LIBERAC_API size_t LIBERAC_RSA_OAEP_MAX_MESSAGE_SIZE(size_t MODULUS_BYTES, LiberaCAlgID HASH_ALG, LiberaCAlgID ALG);

/**
 * @brief Encrypt bytes with RSAES-OAEP and MGF1.
 * @param[out] CIPHERTEXT Destination; the first modulus-size bytes are written.
 * @param[in] CIPHERTEXT_LENGTH Destination capacity.
 * @param[in] MESSAGE Plaintext; may be null only when MESSAGE_LENGTH is zero.
 * @param[in] MESSAGE_LENGTH Plaintext bytes, at most the OAEP size query.
 * @param[in] LABEL Optional associated label; null only when LABEL_LENGTH is zero.
 * @param[in] LABEL_LENGTH Label bytes hashed into the OAEP encoding.
 * @param[in] PUBLIC_KEY Recipient RSA public key.
 * @param[in] HASH_ALG SHA-1 or fixed-output SHA-2 selector used for Hash and MGF1.
 * @param[in] ALG Must be LIBERAC_ALG_RSA_OAEP.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 * @note Fresh seed material is obtained from the operating-system random source.
 */
LIBERAC_API LiberaCError LIBERAC_RSA_OAEP_ENCRYPT(
    uint8_t *CIPHERTEXT, size_t CIPHERTEXT_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *LABEL, size_t LABEL_LENGTH,
    const LiberaCRsaPublicKey *PUBLIC_KEY,
    LiberaCAlgID HASH_ALG, LiberaCAlgID ALG);

/**
 * @brief Decrypt and authenticate an RSAES-OAEP ciphertext.
 * @param[out] MESSAGE Destination with capacity for the maximum OAEP plaintext.
 * @param[in] MESSAGE_CAPACITY Destination capacity.
 * @param[out] MESSAGE_LENGTH Recovered length; set to zero on every failure.
 * @param[in] CIPHERTEXT Exact modulus-width ciphertext.
 * @param[in] CIPHERTEXT_LENGTH Ciphertext length; must equal the modulus width.
 * @param[in] LABEL Label that must match the encryption label.
 * @param[in] LABEL_LENGTH Label length.
 * @param[in] PRIVATE_KEY Recipient RSA private key.
 * @param[in] HASH_ALG SHA-1 or fixed-output SHA-2 selector used for Hash and MGF1.
 * @param[in] ALG Must be LIBERAC_ALG_RSA_OAEP.
 * @return LIBERAC_SUCCESS on success. Every ciphertext/range/OAEP-format failure
 *         returns LIBERAC_ERROR_AUTHENTICATION_FAILED.
 * @note The maximum plaintext region is cleared before decoding and remains
 *       cleared on failure. OAEP format checks use one full delimiter scan.
 */
LIBERAC_API LiberaCError LIBERAC_RSA_OAEP_DECRYPT(
    uint8_t *MESSAGE, size_t MESSAGE_CAPACITY, size_t *MESSAGE_LENGTH,
    const uint8_t *CIPHERTEXT, size_t CIPHERTEXT_LENGTH,
    const uint8_t *LABEL, size_t LABEL_LENGTH,
    const LiberaCRsaPrivateKey *PRIVATE_KEY,
    LiberaCAlgID HASH_ALG, LiberaCAlgID ALG);

/**
 * @brief Sign a message with RSASSA-PSS and MGF1.
 * @param[in] PRIVATE_KEY RSA private key.
 * @param[in] MESSAGE Message bytes; null only when MESSAGE_LENGTH is zero.
 * @param[in] MESSAGE_LENGTH Message length.
 * @param[out] SIGNATURE Modulus-width signature destination.
 * @param[in] SIGNATURE_LENGTH Destination capacity.
 * @param[in] SALT_LENGTH Exact salt bytes, or LIBERAC_RSA_PSS_SALT_LENGTH_DIGEST.
 * @param[in] HASH_ALG SHA-1 or fixed-output SHA-2 selector used for Hash and MGF1.
 * @param[in] ALG Must be LIBERAC_ALG_RSA_PSS.
 * @return LIBERAC_SUCCESS on success or a negative LiberaCError on failure.
 */
LIBERAC_API LiberaCError LIBERAC_RSA_PSS_SIGN(
    const LiberaCRsaPrivateKey *PRIVATE_KEY,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH,
    size_t SALT_LENGTH, LiberaCAlgID HASH_ALG, LiberaCAlgID ALG);

/**
 * @brief Verify an RSASSA-PSS signature with an exact salt-length policy.
 * @param[in] PUBLIC_KEY RSA public key.
 * @param[in] MESSAGE Message bytes; null only when MESSAGE_LENGTH is zero.
 * @param[in] MESSAGE_LENGTH Message length.
 * @param[in] SIGNATURE Exact modulus-width signature.
 * @param[in] SIGNATURE_LENGTH Signature length.
 * @param[in] SALT_LENGTH Required salt bytes, or digest-length sentinel.
 * @param[in] HASH_ALG SHA-1 or fixed-output SHA-2 selector used for Hash and MGF1.
 * @param[in] ALG Must be LIBERAC_ALG_RSA_PSS.
 * @return LIBERAC_SUCCESS or LIBERAC_ERROR_SIGNATURE_INVALID for a mismatch.
 */
LIBERAC_API LiberaCError LIBERAC_RSA_PSS_VERIFY(
    const LiberaCRsaPublicKey *PUBLIC_KEY,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH,
    size_t SALT_LENGTH, LiberaCAlgID HASH_ALG, LiberaCAlgID ALG);

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
