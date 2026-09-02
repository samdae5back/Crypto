/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef CRYPTO_TRIPLE_DES_INTERNAL_H
#define CRYPTO_TRIPLE_DES_INTERNAL_H

#include "BlockCipher.h"

typedef enum { CRYPTO_TDES_MODE_ECB = 1, CRYPTO_TDES_MODE_CBC = 2 } CryptoTdesMode;

typedef struct {
    uint64_t ROUND_KEYS[3][16];
} CryptoTdesEde3Context;

LiberaCError crypto_tdes_ede3_context_init(
    CryptoTdesEde3Context *CONTEXT,
    const uint8_t *KEY, size_t KEY_LENGTH);
LiberaCError crypto_tdes_ede3_encrypt_block(
    CryptoTdesEde3Context *CONTEXT,
    const uint8_t INPUT[LIBERAC_TDES_BLOCK_BYTES],
    uint8_t OUTPUT[LIBERAC_TDES_BLOCK_BYTES]);
void crypto_tdes_ede3_context_clear(CryptoTdesEde3Context *CONTEXT);

LiberaCError crypto_tdes_ede3_crypt(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    CryptoTdesMode MODE, int ENCRYPT);

#endif
