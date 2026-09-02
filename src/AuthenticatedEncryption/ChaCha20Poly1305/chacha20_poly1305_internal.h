/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_CHACHA20_POLY1305_INTERNAL_H
#define CRYPTO_CHACHA20_POLY1305_INTERNAL_H

#include "AuthenticatedEncryption.h"

LiberaCError crypto_chacha20_poly1305_validate_lengths(
    size_t message_length, size_t aad_length);
LiberaCError crypto_chacha20_poly1305_encrypt_internal(
    uint8_t *output,
    uint8_t tag[LIBERAC_CHACHA20_POLY1305_TAG_BYTES],
    const uint8_t *input, size_t input_length,
    const uint8_t key[LIBERAC_CHACHA20_POLY1305_KEY_BYTES],
    const uint8_t nonce[LIBERAC_CHACHA20_POLY1305_NONCE_BYTES],
    const uint8_t *aad, size_t aad_length);
LiberaCError crypto_chacha20_poly1305_decrypt_internal(
    uint8_t *output,
    const uint8_t tag[LIBERAC_CHACHA20_POLY1305_TAG_BYTES],
    const uint8_t *input, size_t input_length,
    const uint8_t key[LIBERAC_CHACHA20_POLY1305_KEY_BYTES],
    const uint8_t nonce[LIBERAC_CHACHA20_POLY1305_NONCE_BYTES],
    const uint8_t *aad, size_t aad_length);

#endif
