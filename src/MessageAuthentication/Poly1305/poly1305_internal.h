/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_POLY1305_INTERNAL_H
#define CRYPTO_POLY1305_INTERNAL_H

#include "MessageAuthentication.h"

typedef struct {
    uint32_t R[5];
    uint32_t H[5];
    uint32_t PAD[4];
    uint8_t BUFFER[16];
    size_t LEFTOVER;
} CryptoPoly1305Context;

void crypto_poly1305_init_internal(
    CryptoPoly1305Context *context,
    const uint8_t key[LIBERAC_POLY1305_KEY_BYTES]);
void crypto_poly1305_update_internal(
    CryptoPoly1305Context *context,
    const uint8_t *message, size_t message_length);
void crypto_poly1305_final_internal(
    CryptoPoly1305Context *context,
    uint8_t tag[LIBERAC_POLY1305_TAG_BYTES]);
void crypto_poly1305_internal(
    uint8_t tag[LIBERAC_POLY1305_TAG_BYTES],
    const uint8_t *message, size_t message_length,
    const uint8_t key[LIBERAC_POLY1305_KEY_BYTES]);

#endif
