/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_KEY_AGREEMENT_INTERNAL_H
#define CRYPTO_KEY_AGREEMENT_INTERNAL_H

#include "Def.h"

size_t crypto_key_agreement_private_key_size_internal(LiberaCAlgID alg);
size_t crypto_key_agreement_public_key_size_internal(LiberaCAlgID alg);
size_t crypto_key_agreement_shared_secret_size_internal(LiberaCAlgID alg);

LiberaCError crypto_key_agreement_keygen_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length);

LiberaCError crypto_key_agreement_public_from_private_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    const uint8_t *private_key, size_t private_key_length);

LiberaCError crypto_key_agreement_shared_secret_internal(
    LiberaCAlgID alg,
    uint8_t *shared_secret, size_t shared_secret_length,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *peer_public_key, size_t peer_public_key_length);

LiberaCError crypto_ecdh_keygen_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length);
LiberaCError crypto_ecdh_public_from_private_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    const uint8_t *private_key, size_t private_key_length);
LiberaCError crypto_ecdh_shared_secret_internal(
    LiberaCAlgID alg,
    uint8_t *shared_secret, size_t shared_secret_length,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *peer_public_key, size_t peer_public_key_length);

LiberaCError crypto_x25519_keygen_internal(
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length);
LiberaCError crypto_x25519_public_from_private_internal(
    uint8_t *public_key, size_t public_key_length,
    const uint8_t *private_key, size_t private_key_length);
LiberaCError crypto_x25519_shared_secret_internal(
    uint8_t *shared_secret, size_t shared_secret_length,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *peer_public_key, size_t peer_public_key_length);

#endif
