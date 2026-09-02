/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_ED25519_INTERNAL_H
#define CRYPTO_ED25519_INTERNAL_H

#include "Def.h"

size_t crypto_ed25519_private_key_size_internal(LiberaCAlgID alg);
size_t crypto_ed25519_public_key_size_internal(LiberaCAlgID alg);
size_t crypto_ed25519_signature_size_internal(LiberaCAlgID alg);

LiberaCError crypto_ed25519_keygen_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length);
LiberaCError crypto_ed25519_public_from_private_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    const uint8_t *private_key, size_t private_key_length);
LiberaCError crypto_ed25519_sign_internal(
    LiberaCAlgID alg,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t signature_length);
LiberaCError crypto_ed25519_verify_internal(
    LiberaCAlgID alg,
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *signature, size_t signature_length);

#endif
