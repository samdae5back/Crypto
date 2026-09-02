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

size_t LIBERAC_RSA_PUBLIC_MODULUS_SIZE(
    const LiberaCRsaPublicKey *public_key) {
    return crypto_rsa_public_modulus_size_internal(public_key);
}

size_t LIBERAC_RSA_PRIVATE_MODULUS_SIZE(
    const LiberaCRsaPrivateKey *private_key) {
    return crypto_rsa_private_modulus_size_internal(private_key);
}

size_t LIBERAC_RSA_OAEP_MAX_MESSAGE_SIZE(
    size_t modulus_bytes, LiberaCAlgID hash_alg, LiberaCAlgID alg) {
    return crypto_rsa_oaep_max_message_size_internal(
        modulus_bytes, hash_alg, alg);
}

LiberaCError LIBERAC_RSA_OAEP_ENCRYPT(
    uint8_t *ciphertext, size_t ciphertext_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *label, size_t label_length,
    const LiberaCRsaPublicKey *public_key,
    LiberaCAlgID hash_alg, LiberaCAlgID alg) {
    return crypto_rsa_oaep_encrypt_internal(
        alg, hash_alg, ciphertext, ciphertext_length,
        message, message_length, label, label_length, public_key);
}

LiberaCError LIBERAC_RSA_OAEP_DECRYPT(
    uint8_t *message, size_t message_capacity, size_t *message_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    const uint8_t *label, size_t label_length,
    const LiberaCRsaPrivateKey *private_key,
    LiberaCAlgID hash_alg, LiberaCAlgID alg) {
    return crypto_rsa_oaep_decrypt_internal(
        alg, hash_alg, message, message_capacity, message_length,
        ciphertext, ciphertext_length, label, label_length, private_key);
}

LiberaCError LIBERAC_RSA_PSS_SIGN(
    const LiberaCRsaPrivateKey *private_key,
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t signature_length,
    size_t salt_length, LiberaCAlgID hash_alg, LiberaCAlgID alg) {
    return crypto_rsa_pss_sign_internal(
        alg, hash_alg, private_key, message, message_length,
        signature, signature_length, salt_length);
}

LiberaCError LIBERAC_RSA_PSS_VERIFY(
    const LiberaCRsaPublicKey *public_key,
    const uint8_t *message, size_t message_length,
    const uint8_t *signature, size_t signature_length,
    size_t salt_length, LiberaCAlgID hash_alg, LiberaCAlgID alg) {
    return crypto_rsa_pss_verify_internal(
        alg, hash_alg, public_key, message, message_length,
        signature, signature_length, salt_length);
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
