/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "AsymmetricCipher.h"

#include "AsymmetricCipher/ElGamal/elgamal_internal.h"
#include "AsymmetricCipher/RSA/rsa_internal.h"

void LIBERAC_RSA_PUBLIC_KEY_INIT(LiberaCRsaPublicKey *key) {
    crypto_rsa_public_key_init_internal(key);
}

void LIBERAC_RSA_PUBLIC_KEY_FREE(LiberaCRsaPublicKey *key) {
    crypto_rsa_public_key_free_internal(key);
}

void LIBERAC_RSA_PRIVATE_KEY_INIT(LiberaCRsaPrivateKey *key) {
    crypto_rsa_private_key_init_internal(key);
}

void LIBERAC_RSA_PRIVATE_KEY_FREE(LiberaCRsaPrivateKey *key) {
    crypto_rsa_private_key_free_internal(key);
}

LiberaCError LIBERAC_RSA_KEYGEN(LiberaCRsaPublicKey *public_key,
                               LiberaCRsaPrivateKey *private_key,
                               size_t modulus_bits, uint32_t prime_rounds,
                               LiberaCAlgID alg) {
    return crypto_rsa_keygen_internal(alg, public_key, private_key,
                                      modulus_bits, prime_rounds);
}

LiberaCError LIBERAC_RSA_ENCRYPT(LiberaCBignum *ciphertext,
                                const LiberaCBignum *message,
                                const LiberaCRsaPublicKey *public_key,
                                LiberaCAlgID alg) {
    return crypto_rsa_encrypt_internal(alg, ciphertext, message, public_key);
}

LiberaCError LIBERAC_RSA_DECRYPT(LiberaCBignum *message,
                                const LiberaCBignum *ciphertext,
                                const LiberaCRsaPrivateKey *private_key,
                                LiberaCAlgID alg) {
    return crypto_rsa_decrypt_internal(alg, message, ciphertext, private_key);
}

void LIBERAC_ELGAMAL_PUBLIC_KEY_INIT(LiberaCElgamalPublicKey *key) {
    crypto_elgamal_public_key_init_internal(key);
}

void LIBERAC_ELGAMAL_PUBLIC_KEY_FREE(LiberaCElgamalPublicKey *key) {
    crypto_elgamal_public_key_free_internal(key);
}

void LIBERAC_ELGAMAL_PRIVATE_KEY_INIT(LiberaCElgamalPrivateKey *key) {
    crypto_elgamal_private_key_init_internal(key);
}

void LIBERAC_ELGAMAL_PRIVATE_KEY_FREE(LiberaCElgamalPrivateKey *key) {
    crypto_elgamal_private_key_free_internal(key);
}

void LIBERAC_ELGAMAL_CIPHERTEXT_INIT(LiberaCElgamalCiphertext *ciphertext) {
    crypto_elgamal_ciphertext_init_internal(ciphertext);
}

void LIBERAC_ELGAMAL_CIPHERTEXT_FREE(LiberaCElgamalCiphertext *ciphertext) {
    crypto_elgamal_ciphertext_free_internal(ciphertext);
}

LiberaCError LIBERAC_ELGAMAL_KEYGEN(LiberaCElgamalPublicKey *public_key,
                                   LiberaCElgamalPrivateKey *private_key,
                                   size_t modulus_bits, uint32_t prime_rounds,
                                   LiberaCAlgID alg) {
    return crypto_elgamal_keygen_internal(alg, public_key, private_key,
                                          modulus_bits, prime_rounds);
}

LiberaCError LIBERAC_ELGAMAL_ENCRYPT(LiberaCElgamalCiphertext *ciphertext,
                                    const LiberaCBignum *message,
                                    const LiberaCElgamalPublicKey *public_key,
                                    LiberaCAlgID alg) {
    return crypto_elgamal_encrypt_internal(alg, ciphertext, message, public_key);
}

LiberaCError LIBERAC_ELGAMAL_DECRYPT(LiberaCBignum *message,
                                    const LiberaCElgamalCiphertext *ciphertext,
                                    const LiberaCElgamalPublicKey *public_key,
                                    const LiberaCElgamalPrivateKey *private_key,
                                    LiberaCAlgID alg) {
    return crypto_elgamal_decrypt_internal(alg, message, ciphertext,
                                           public_key, private_key);
}
