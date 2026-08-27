/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_RSA_INTERNAL_H
#define CRYPTO_RSA_INTERNAL_H

#include "AsymmetricCipher.h"

uint32_t rsa_inverse_u32(uint32_t a, uint32_t m);
void crypto_rsa_public_key_init_internal(CRYPTO_RSA_PUBLIC_KEY *key);
void crypto_rsa_public_key_free_internal(CRYPTO_RSA_PUBLIC_KEY *key);
void crypto_rsa_private_key_init_internal(CRYPTO_RSA_PRIVATE_KEY *key);
void crypto_rsa_private_key_free_internal(CRYPTO_RSA_PRIVATE_KEY *key);
CryptoError crypto_rsa_keygen_internal(AlgID alg, CRYPTO_RSA_PUBLIC_KEY *public_key,
                                        CRYPTO_RSA_PRIVATE_KEY *private_key,
                                        size_t modulus_bits, uint32_t prime_rounds);
CryptoError crypto_rsa_encrypt_internal(AlgID alg, CRYPTO_BIGNUM *ciphertext,
                                        const CRYPTO_BIGNUM *message,
                                        const CRYPTO_RSA_PUBLIC_KEY *public_key);
CryptoError crypto_rsa_decrypt_internal(AlgID alg, CRYPTO_BIGNUM *message,
                                        const CRYPTO_BIGNUM *ciphertext,
                                        const CRYPTO_RSA_PRIVATE_KEY *private_key);

#endif
