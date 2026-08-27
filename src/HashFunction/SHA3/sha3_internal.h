/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_SHA3_INTERNAL_H
#define CRYPTO_SHA3_INTERNAL_H

#include "Def.h"

typedef struct crypto_sha3_context {
    uint64_t state[25];
    size_t rate;
    size_t position;
    uint8_t domain;
    uint8_t finalized;
} crypto_sha3_context;

CryptoError crypto_sha3_hash(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    AlgID ALG);

void crypto_sha3_256(
    uint8_t OUTPUT[32], const uint8_t *INPUT, size_t INPUT_LENGTH);
void crypto_sha3_512(
    uint8_t OUTPUT[64], const uint8_t *INPUT, size_t INPUT_LENGTH);
void crypto_shake128(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH);
void crypto_shake256(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH);

void crypto_shake128_init(crypto_sha3_context *CONTEXT);
void crypto_shake256_init(crypto_sha3_context *CONTEXT);
void crypto_sha3_update(
    crypto_sha3_context *CONTEXT,
    const uint8_t *INPUT, size_t INPUT_LENGTH);
void crypto_sha3_finalize(crypto_sha3_context *CONTEXT);
void crypto_sha3_squeeze(
    crypto_sha3_context *CONTEXT,
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH);
void crypto_sha3_clear(crypto_sha3_context *CONTEXT);

#endif
