/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_HAETAE_SYMMETRIC_H
#define CRYPTO_HAETAE_SYMMETRIC_H

#include <string.h>

#include "HashFunction/SHA3/sha3_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/Endian/endian_internal.h"

#include "haetae.h"

#define CRYPTO_HAETAE_SHAKE128_RATE 168u
#define CRYPTO_HAETAE_SHAKE256_RATE 136u

static inline void crypto_haetae_shake128_stream_init(
    crypto_sha3_context *context,
    const uint8_t seed[CRYPTO_HAETAE_SEED_BYTES],
    uint16_t nonce) {
    uint8_t input[CRYPTO_HAETAE_SEED_BYTES + 2u];

    memcpy(input, seed, CRYPTO_HAETAE_SEED_BYTES);
    crypto_store16_le(input + CRYPTO_HAETAE_SEED_BYTES, nonce);
    crypto_shake128_init(context);
    crypto_sha3_update(context, input, sizeof(input));
    crypto_sha3_finalize(context);
    crypto_zeroize(input, sizeof(input));
}

static inline void crypto_haetae_shake256_stream_init(
    crypto_sha3_context *context,
    const uint8_t seed[CRYPTO_HAETAE_CRH_BYTES],
    uint16_t nonce) {
    uint8_t input[CRYPTO_HAETAE_CRH_BYTES + 2u];

    memcpy(input, seed, CRYPTO_HAETAE_CRH_BYTES);
    crypto_store16_le(input + CRYPTO_HAETAE_CRH_BYTES, nonce);
    crypto_shake256_init(context);
    crypto_sha3_update(context, input, sizeof(input));
    crypto_sha3_finalize(context);
    crypto_zeroize(input, sizeof(input));
}

static inline void crypto_haetae_shake128_squeeze_blocks(
    crypto_sha3_context *context,
    uint8_t *output,
    size_t block_count) {
    crypto_sha3_squeeze(
        context, output, block_count * CRYPTO_HAETAE_SHAKE128_RATE);
}

static inline void crypto_haetae_shake256_squeeze_blocks(
    crypto_sha3_context *context,
    uint8_t *output,
    size_t block_count) {
    crypto_sha3_squeeze(
        context, output, block_count * CRYPTO_HAETAE_SHAKE256_RATE);
}

#endif
