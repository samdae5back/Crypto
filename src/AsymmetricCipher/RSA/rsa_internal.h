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

#endif
