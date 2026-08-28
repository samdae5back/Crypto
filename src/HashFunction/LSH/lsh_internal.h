/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_LSH_INTERNAL_H
#define CRYPTO_LSH_INTERNAL_H

#include "Def.h"

#define CRYPTO_LSH_MAX_STATE_BYTES 128u
#define CRYPTO_LSH_MAX_BLOCK_BYTES 256u

typedef struct crypto_lsh_context {
    uint8_t STATE[CRYPTO_LSH_MAX_STATE_BYTES];
    uint8_t BLOCK[CRYPTO_LSH_MAX_BLOCK_BYTES];
    size_t BLOCK_LENGTH;
    size_t BUFFER_LENGTH;
    uint8_t USE_LSH512;
} crypto_lsh_context;

LiberaCError crypto_lsh_init(
    crypto_lsh_context *CONTEXT,
    LiberaCAlgID ALG);
LiberaCError crypto_lsh_update(
    crypto_lsh_context *CONTEXT,
    const uint8_t *INPUT, size_t INPUT_LENGTH);
void crypto_lsh_finalize(crypto_lsh_context *CONTEXT);
void crypto_lsh_squeeze(
    const crypto_lsh_context *CONTEXT,
    uint8_t *OUTPUT,
    LiberaCAlgID ALG);
void crypto_lsh_clear(crypto_lsh_context *CONTEXT);

#endif
