/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_CHACHA20_INTERNAL_H
#define CRYPTO_CHACHA20_INTERNAL_H

#include "StreamCipher.h"

LiberaCError crypto_chacha20_validate_length(
    size_t input_length, uint32_t initial_counter);
void crypto_chacha20_block_internal(
    uint8_t output[LIBERAC_CHACHA20_BLOCK_BYTES],
    const uint8_t key[LIBERAC_CHACHA20_KEY_BYTES],
    const uint8_t nonce[LIBERAC_CHACHA20_NONCE_BYTES],
    uint32_t counter);
LiberaCError crypto_chacha20_xor_internal(
    uint8_t *output, const uint8_t *input, size_t input_length,
    const uint8_t key[LIBERAC_CHACHA20_KEY_BYTES],
    const uint8_t nonce[LIBERAC_CHACHA20_NONCE_BYTES],
    uint32_t initial_counter);

#endif
