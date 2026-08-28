/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_ELGAMAL_INTERNAL_H
#define CRYPTO_ELGAMAL_INTERNAL_H

#include "AsymmetricCipher.h"

LiberaCError elgamal_random_nonzero(LiberaCBignum *out,
                                    const LiberaCBignum *upper);
void crypto_elgamal_public_key_init_internal(LiberaCElgamalPublicKey *key);
void crypto_elgamal_public_key_free_internal(LiberaCElgamalPublicKey *key);
void crypto_elgamal_private_key_init_internal(LiberaCElgamalPrivateKey *key);
void crypto_elgamal_private_key_free_internal(LiberaCElgamalPrivateKey *key);
void crypto_elgamal_ciphertext_init_internal(LiberaCElgamalCiphertext *ciphertext);
void crypto_elgamal_ciphertext_free_internal(LiberaCElgamalCiphertext *ciphertext);
LiberaCError crypto_elgamal_keygen_internal(LiberaCAlgID alg,
                                            LiberaCElgamalPublicKey *public_key,
                                            LiberaCElgamalPrivateKey *private_key,
                                            size_t modulus_bits, uint32_t prime_rounds);
LiberaCError crypto_elgamal_encrypt_internal(LiberaCAlgID alg,
                                             LiberaCElgamalCiphertext *ciphertext,
                                             const LiberaCBignum *message,
                                             const LiberaCElgamalPublicKey *public_key);
LiberaCError crypto_elgamal_decrypt_internal(LiberaCAlgID alg, LiberaCBignum *message,
                                             const LiberaCElgamalCiphertext *ciphertext,
                                             const LiberaCElgamalPublicKey *public_key,
                                             const LiberaCElgamalPrivateKey *private_key);

#endif
