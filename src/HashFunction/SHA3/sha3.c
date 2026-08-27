/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "sha3_internal.h"

#include "Util/Bit/bit_internal.h"
#include "Util/Core/secure_zero.h"

static void keccak_f1600(uint64_t state[25]) {
    static const uint64_t round_constants[24] = {
        UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
        UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
        UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
        UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
        UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
        UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
        UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
        UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
        UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
        UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
    };
    static const unsigned int rotation_offsets[25] = {
        0u, 1u, 62u, 28u, 27u,
        36u, 44u, 6u, 55u, 20u,
        3u, 10u, 43u, 25u, 39u,
        41u, 45u, 15u, 21u, 8u,
        18u, 2u, 61u, 56u, 14u
    };
    uint64_t columns[5];
    uint64_t deltas[5];
    uint64_t permuted[25];
    size_t round, x, y;

    for (round = 0; round < 24u; ++round) {
        for (x = 0; x < 5u; ++x) {
            columns[x] = state[x] ^ state[x + 5u] ^ state[x + 10u] ^
                         state[x + 15u] ^ state[x + 20u];
        }
        for (x = 0; x < 5u; ++x) {
            deltas[x] = columns[(x + 4u) % 5u] ^
                        crypto_rotl64(columns[(x + 1u) % 5u], 1u);
        }
        for (y = 0; y < 5u; ++y) {
            for (x = 0; x < 5u; ++x) {
                state[x + (5u * y)] ^= deltas[x];
            }
        }
        for (y = 0; y < 5u; ++y) {
            for (x = 0; x < 5u; ++x) {
                const size_t new_x = y;
                const size_t new_y = ((2u * x) + (3u * y)) % 5u;
                permuted[new_x + (5u * new_y)] =
                    crypto_rotl64(state[x + (5u * y)],
                                  rotation_offsets[x + (5u * y)]);
            }
        }
        for (y = 0; y < 5u; ++y) {
            for (x = 0; x < 5u; ++x) {
                state[x + (5u * y)] =
                    permuted[x + (5u * y)] ^
                    ((~permuted[((x + 1u) % 5u) + (5u * y)]) &
                     permuted[((x + 2u) % 5u) + (5u * y)]);
            }
        }
        state[0] ^= round_constants[round];
    }

    crypto_zeroize(permuted, sizeof(permuted));
    crypto_zeroize(deltas, sizeof(deltas));
    crypto_zeroize(columns, sizeof(columns));
}

static void sha3_context_init(
    crypto_sha3_context *context, size_t rate, uint8_t domain) {
    crypto_zeroize(context, sizeof(*context));
    context->rate = rate;
    context->domain = domain;
}

static void xor_byte(
    crypto_sha3_context *context, size_t position, uint8_t value) {
    const size_t lane = position / 8u;
    const unsigned int shift = (unsigned int)(8u * (position % 8u));
    context->state[lane] ^= (uint64_t)value << shift;
}

static uint8_t get_byte(
    const crypto_sha3_context *context, size_t position) {
    const size_t lane = position / 8u;
    const unsigned int shift = (unsigned int)(8u * (position % 8u));
    return (uint8_t)(context->state[lane] >> shift);
}

CryptoError crypto_sha3_init(
    crypto_sha3_context *CONTEXT,
    AlgID ALG) {
    if (CONTEXT == NULL) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    switch (ALG) {
        case ALG_HASH_SHA3_224:
            sha3_context_init(CONTEXT, 144u, 0x06u);
            break;
        case ALG_HASH_SHA3_256:
            sha3_context_init(CONTEXT, 136u, 0x06u);
            break;
        case ALG_HASH_SHA3_384:
            sha3_context_init(CONTEXT, 104u, 0x06u);
            break;
        case ALG_HASH_SHA3_512:
            sha3_context_init(CONTEXT, 72u, 0x06u);
            break;
        case ALG_HASH_SHAKE128:
            sha3_context_init(CONTEXT, 168u, 0x1fu);
            break;
        case ALG_HASH_SHAKE256:
            sha3_context_init(CONTEXT, 136u, 0x1fu);
            break;
        default:
            crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
            return CRYPTO_ERROR_INVALID_ALG_ID;
    }
    return CRYPTO_SUCCESS;
}

void crypto_shake128_init(crypto_sha3_context *CONTEXT) {
    if (CONTEXT != NULL) {
        sha3_context_init(CONTEXT, 168u, 0x1fu);
    }
}

void crypto_shake256_init(crypto_sha3_context *CONTEXT) {
    if (CONTEXT != NULL) {
        sha3_context_init(CONTEXT, 136u, 0x1fu);
    }
}

void crypto_sha3_update(
    crypto_sha3_context *CONTEXT,
    const uint8_t *INPUT, size_t INPUT_LENGTH) {
    size_t index;

    if (CONTEXT == NULL || (INPUT == NULL && INPUT_LENGTH != 0u) ||
        CONTEXT->finalized != 0u) {
        return;
    }
    for (index = 0; index < INPUT_LENGTH; ++index) {
        xor_byte(CONTEXT, CONTEXT->position, INPUT[index]);
        ++CONTEXT->position;
        if (CONTEXT->position == CONTEXT->rate) {
            keccak_f1600(CONTEXT->state);
            CONTEXT->position = 0u;
        }
    }
}

void crypto_sha3_finalize(crypto_sha3_context *CONTEXT) {
    if (CONTEXT == NULL || CONTEXT->finalized != 0u) {
        return;
    }
    xor_byte(CONTEXT, CONTEXT->position, CONTEXT->domain);
    xor_byte(CONTEXT, CONTEXT->rate - 1u, 0x80u);
    keccak_f1600(CONTEXT->state);
    CONTEXT->position = 0u;
    CONTEXT->finalized = 1u;
}

void crypto_sha3_squeeze(
    crypto_sha3_context *CONTEXT,
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    size_t index;

    if (CONTEXT == NULL || (OUTPUT == NULL && OUTPUT_LENGTH != 0u)) {
        return;
    }
    if (CONTEXT->finalized == 0u) {
        crypto_sha3_finalize(CONTEXT);
    }
    for (index = 0; index < OUTPUT_LENGTH; ++index) {
        if (CONTEXT->position == CONTEXT->rate) {
            keccak_f1600(CONTEXT->state);
            CONTEXT->position = 0u;
        }
        OUTPUT[index] = get_byte(CONTEXT, CONTEXT->position);
        ++CONTEXT->position;
    }
}

void crypto_sha3_clear(crypto_sha3_context *CONTEXT) {
    if (CONTEXT != NULL) {
        crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
    }
}

static void sha3_fixed(
    uint8_t *output, size_t output_length,
    const uint8_t *input, size_t input_length,
    size_t rate) {
    crypto_sha3_context context;

    sha3_context_init(&context, rate, 0x06u);
    crypto_sha3_update(&context, input, input_length);
    crypto_sha3_squeeze(&context, output, output_length);
    crypto_sha3_clear(&context);
}

void crypto_sha3_256(
    uint8_t OUTPUT[32], const uint8_t *INPUT, size_t INPUT_LENGTH) {
    sha3_fixed(OUTPUT, 32u, INPUT, INPUT_LENGTH, 136u);
}

void crypto_sha3_512(
    uint8_t OUTPUT[64], const uint8_t *INPUT, size_t INPUT_LENGTH) {
    sha3_fixed(OUTPUT, 64u, INPUT, INPUT_LENGTH, 72u);
}

void crypto_shake128(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH) {
    crypto_sha3_context context;

    crypto_shake128_init(&context);
    crypto_sha3_update(&context, INPUT, INPUT_LENGTH);
    crypto_sha3_squeeze(&context, OUTPUT, OUTPUT_LENGTH);
    crypto_sha3_clear(&context);
}

void crypto_shake256(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH) {
    crypto_sha3_context context;

    crypto_shake256_init(&context);
    crypto_sha3_update(&context, INPUT, INPUT_LENGTH);
    crypto_sha3_squeeze(&context, OUTPUT, OUTPUT_LENGTH);
    crypto_sha3_clear(&context);
}
