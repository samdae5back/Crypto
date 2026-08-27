/* SPDX-License-Identifier: MIT */

#ifndef CRYPTO_AIMER_HASH_H
#define CRYPTO_AIMER_HASH_H

#include "../aimer_params.h"
#include "HashFunction/SHA3/sha3_internal.h"

typedef crypto_sha3_context crypto_aimer_hash_context;

static inline void crypto_aimer_hash_init(
    crypto_aimer_hash_context *ctx, const crypto_aimer_params *params) {
    if (params->security_bits == 128u) {
        crypto_shake128_init(ctx);
    } else {
        crypto_shake256_init(ctx);
    }
}

static inline void crypto_aimer_hash_init_prefix(
    crypto_aimer_hash_context *ctx, const crypto_aimer_params *params,
    uint8_t prefix) {
    crypto_aimer_hash_init(ctx, params);
    crypto_sha3_update(ctx, &prefix, sizeof(prefix));
}

static inline void crypto_aimer_hash_absorb(
    crypto_aimer_hash_context *ctx, const uint8_t *data, size_t data_length) {
    crypto_sha3_update(ctx, data, data_length);
}

static inline void crypto_aimer_hash_finalize(
    crypto_aimer_hash_context *ctx, const crypto_aimer_params *params) {
    (void)params;
    crypto_sha3_finalize(ctx);
}

static inline void crypto_aimer_hash_squeeze(
    crypto_aimer_hash_context *ctx, uint8_t *output, size_t output_length,
    const crypto_aimer_params *params) {
    (void)params;
    crypto_sha3_squeeze(ctx, output, output_length);
}

static inline void crypto_aimer_hash_clear(crypto_aimer_hash_context *ctx) {
    crypto_sha3_clear(ctx);
}

#endif
