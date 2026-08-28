/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef CRYPTO_SHA1_INTERNAL_H
#define CRYPTO_SHA1_INTERNAL_H

#include "Def.h"

typedef struct crypto_sha1_context {
    uint32_t STATE[5];
    uint8_t BLOCK[64];
    uint64_t LENGTH;
    size_t BUFFER_LENGTH;
} crypto_sha1_context;

void crypto_sha1_init(crypto_sha1_context *CONTEXT);
LiberaCError crypto_sha1_update(crypto_sha1_context *CONTEXT,
                                const uint8_t *INPUT, size_t INPUT_LENGTH);
void crypto_sha1_finalize(crypto_sha1_context *CONTEXT);
void crypto_sha1_squeeze(const crypto_sha1_context *CONTEXT, uint8_t *OUTPUT);

#endif
