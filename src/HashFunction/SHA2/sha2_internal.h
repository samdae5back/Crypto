/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_SHA2_INTERNAL_H
#define CRYPTO_SHA2_INTERNAL_H

#include "Def.h"

#define CRYPTO_SHA2_MAX_BLOCK_BYTES 128u

typedef union crypto_sha2_state {
    uint32_t WORDS32[8];
    uint64_t WORDS64[8];
} crypto_sha2_state;

typedef struct crypto_sha2_context {
    crypto_sha2_state STATE;
    uint8_t BLOCK[CRYPTO_SHA2_MAX_BLOCK_BYTES];
    uint64_t LENGTH_LOW;
    uint64_t LENGTH_HIGH;
    size_t BUFFER_LENGTH;
    uint8_t USE_SHA512;
} crypto_sha2_context;

CryptoError crypto_sha2_init(
    crypto_sha2_context *CONTEXT,
    AlgID ALG);
CryptoError crypto_sha2_update(
    crypto_sha2_context *CONTEXT,
    const uint8_t *INPUT, size_t INPUT_LENGTH);
void crypto_sha2_finalize(crypto_sha2_context *CONTEXT);
void crypto_sha2_squeeze(
    const crypto_sha2_context *CONTEXT,
    uint8_t *OUTPUT,
    AlgID ALG);
void crypto_sha2_clear(crypto_sha2_context *CONTEXT);

#endif
