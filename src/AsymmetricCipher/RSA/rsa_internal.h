/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_RSA_INTERNAL_H
#define CRYPTO_RSA_INTERNAL_H

#include "AsymmetricCipher.h"

uint32_t rsa_inverse_u32(uint32_t a, uint32_t m);
void crypto_rsa_public_key_init_internal(LiberaCRsaPublicKey *key);
void crypto_rsa_public_key_free_internal(LiberaCRsaPublicKey *key);
void crypto_rsa_private_key_init_internal(LiberaCRsaPrivateKey *key);
void crypto_rsa_private_key_free_internal(LiberaCRsaPrivateKey *key);
LiberaCError crypto_rsa_keygen_internal(LiberaCAlgID alg, LiberaCRsaPublicKey *public_key,
                                        LiberaCRsaPrivateKey *private_key,
                                        size_t modulus_bits, uint32_t prime_rounds);
LiberaCError crypto_rsa_encrypt_internal(LiberaCAlgID alg, LiberaCBignum *ciphertext,
                                        const LiberaCBignum *message,
                                        const LiberaCRsaPublicKey *public_key);
LiberaCError crypto_rsa_decrypt_internal(LiberaCAlgID alg, LiberaCBignum *message,
                                        const LiberaCBignum *ciphertext,
                                        const LiberaCRsaPrivateKey *private_key);

size_t crypto_rsa_public_modulus_size_internal(
    const LiberaCRsaPublicKey *public_key);
size_t crypto_rsa_private_modulus_size_internal(
    const LiberaCRsaPrivateKey *private_key);
size_t crypto_rsa_oaep_max_message_size_internal(
    size_t modulus_bytes, LiberaCAlgID hash_alg, LiberaCAlgID alg);
LiberaCError crypto_rsa_oaep_encrypt_internal(
    LiberaCAlgID alg, LiberaCAlgID hash_alg,
    uint8_t *ciphertext, size_t ciphertext_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *label, size_t label_length,
    const LiberaCRsaPublicKey *public_key);
LiberaCError crypto_rsa_oaep_decrypt_internal(
    LiberaCAlgID alg, LiberaCAlgID hash_alg,
    uint8_t *message, size_t message_capacity, size_t *message_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    const uint8_t *label, size_t label_length,
    const LiberaCRsaPrivateKey *private_key);
LiberaCError crypto_rsa_pss_sign_internal(
    LiberaCAlgID alg, LiberaCAlgID hash_alg,
    const LiberaCRsaPrivateKey *private_key,
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t signature_length, size_t salt_length);
LiberaCError crypto_rsa_pss_verify_internal(
    LiberaCAlgID alg, LiberaCAlgID hash_alg,
    const LiberaCRsaPublicKey *public_key,
    const uint8_t *message, size_t message_length,
    const uint8_t *signature, size_t signature_length, size_t salt_length);

#endif
