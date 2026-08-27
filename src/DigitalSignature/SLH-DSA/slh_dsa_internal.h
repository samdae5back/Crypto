/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_SLH_DSA_INTERNAL_H
#define CRYPTO_SLH_DSA_INTERNAL_H

#include "DigitalSignature.h"

size_t crypto_slh_dsa_public_key_size_internal(AlgID alg);
size_t crypto_slh_dsa_private_key_size_internal(AlgID alg);
size_t crypto_slh_dsa_signature_size_internal(AlgID alg);
CryptoError crypto_slh_dsa_keygen_internal(
    AlgID alg, uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length);
CryptoError crypto_slh_dsa_keygen_seeded_internal(
    AlgID alg, const uint8_t *seed, size_t seed_length,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length);
CryptoError crypto_slh_dsa_sign_internal(
    AlgID alg, const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length);
CryptoError crypto_slh_dsa_sign_seeded_internal(
    AlgID alg, const uint8_t *randomness, size_t randomness_length,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length);
CryptoError crypto_slh_dsa_verify_internal(
    AlgID alg, const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length);

#endif
