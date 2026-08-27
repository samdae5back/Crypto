/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_SMAUG_T_INTERNAL_H
#define CRYPTO_SMAUG_T_INTERNAL_H

#include "KeyEncapsulation.h"

size_t crypto_smaug_t_public_key_size_internal(AlgID algorithm);
size_t crypto_smaug_t_private_key_size_internal(AlgID algorithm);
size_t crypto_smaug_t_ciphertext_size_internal(AlgID algorithm);

CryptoError crypto_smaug_t_keygen_internal(
    AlgID algorithm,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length);

CryptoError crypto_smaug_t_encaps_internal(
    AlgID algorithm,
    const uint8_t *public_key, size_t public_key_length,
    uint8_t shared_secret[CRYPTO_SMAUG_T_SHARED_SECRET_BYTES],
    uint8_t *ciphertext, size_t ciphertext_length);

CryptoError crypto_smaug_t_decaps_internal(
    AlgID algorithm,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t shared_secret[CRYPTO_SMAUG_T_SHARED_SECRET_BYTES]);

#endif
