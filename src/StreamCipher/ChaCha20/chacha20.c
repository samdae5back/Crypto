/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "StreamCipher/ChaCha20/chacha20_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/Endian/endian_internal.h"

#include <string.h>

static uint32_t rotate_left32(uint32_t value, unsigned int shift) {
    return (value << shift) | (value >> (32u - shift));
}

#define CHACHA_QUARTER_ROUND(a, b, c, d) do { \
    (a) += (b);                              \
    (d) ^= (a);                              \
    (d) = rotate_left32((d), 16u);           \
    (c) += (d);                              \
    (b) ^= (c);                              \
    (b) = rotate_left32((b), 12u);           \
    (a) += (b);                              \
    (d) ^= (a);                              \
    (d) = rotate_left32((d), 8u);            \
    (c) += (d);                              \
    (b) ^= (c);                              \
    (b) = rotate_left32((b), 7u);            \
} while (0)

static void chacha20_initial_state(
    uint32_t state[16],
    const uint8_t key[LIBERAC_CHACHA20_KEY_BYTES],
    const uint8_t nonce[LIBERAC_CHACHA20_NONCE_BYTES]) {
    size_t i;

    state[0] = UINT32_C(0x61707865);
    state[1] = UINT32_C(0x3320646e);
    state[2] = UINT32_C(0x79622d32);
    state[3] = UINT32_C(0x6b206574);
    for (i = 0u; i < 8u; ++i)
        state[4u + i] = crypto_load32_le(key + 4u * i);
    state[12] = 0u;
    state[13] = crypto_load32_le(nonce);
    state[14] = crypto_load32_le(nonce + 4u);
    state[15] = crypto_load32_le(nonce + 8u);
}

static void chacha20_block_from_state(
    uint8_t output[LIBERAC_CHACHA20_BLOCK_BYTES],
    const uint32_t initial[16], uint32_t counter) {
    uint32_t x[16];
    size_t i;
    unsigned int double_round;

    memcpy(x, initial, sizeof(x));
    x[12] = counter;

    for (double_round = 0u; double_round < 10u; ++double_round) {
        CHACHA_QUARTER_ROUND(x[0], x[4], x[8], x[12]);
        CHACHA_QUARTER_ROUND(x[1], x[5], x[9], x[13]);
        CHACHA_QUARTER_ROUND(x[2], x[6], x[10], x[14]);
        CHACHA_QUARTER_ROUND(x[3], x[7], x[11], x[15]);
        CHACHA_QUARTER_ROUND(x[0], x[5], x[10], x[15]);
        CHACHA_QUARTER_ROUND(x[1], x[6], x[11], x[12]);
        CHACHA_QUARTER_ROUND(x[2], x[7], x[8], x[13]);
        CHACHA_QUARTER_ROUND(x[3], x[4], x[9], x[14]);
    }

    for (i = 0u; i < 16u; ++i) {
        uint32_t original = (i == 12u) ? counter : initial[i];
        crypto_store32_le(output + 4u * i, x[i] + original);
    }
    crypto_zeroize(x, sizeof(x));
}

LiberaCError crypto_chacha20_validate_length(
    size_t input_length, uint32_t initial_counter) {
    size_t blocks = input_length / LIBERAC_CHACHA20_BLOCK_BYTES;
    uint64_t available_blocks = (uint64_t)UINT32_MAX - initial_counter + 1u;

    if ((input_length % LIBERAC_CHACHA20_BLOCK_BYTES) != 0u) ++blocks;
    if (blocks > available_blocks) return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    return LIBERAC_SUCCESS;
}

void crypto_chacha20_block_internal(
    uint8_t output[LIBERAC_CHACHA20_BLOCK_BYTES],
    const uint8_t key[LIBERAC_CHACHA20_KEY_BYTES],
    const uint8_t nonce[LIBERAC_CHACHA20_NONCE_BYTES],
    uint32_t counter) {
    uint32_t initial[16];

    chacha20_initial_state(initial, key, nonce);
    chacha20_block_from_state(output, initial, counter);
    crypto_zeroize(initial, sizeof(initial));
}

LiberaCError crypto_chacha20_xor_internal(
    uint8_t *output, const uint8_t *input, size_t input_length,
    const uint8_t key[LIBERAC_CHACHA20_KEY_BYTES],
    const uint8_t nonce[LIBERAC_CHACHA20_NONCE_BYTES],
    uint32_t initial_counter) {
    uint32_t initial[16];
    uint8_t stream[LIBERAC_CHACHA20_BLOCK_BYTES];
    uint32_t counter = initial_counter;
    size_t offset = 0u;
    LiberaCError err;

    err = crypto_chacha20_validate_length(input_length, initial_counter);
    if (err != LIBERAC_SUCCESS) return err;

    chacha20_initial_state(initial, key, nonce);
    while (offset < input_length) {
        size_t chunk = input_length - offset;
        size_t i;

        if (chunk > sizeof(stream)) chunk = sizeof(stream);
        chacha20_block_from_state(stream, initial, counter);
        for (i = 0u; i < chunk; ++i)
            output[offset + i] = (uint8_t)(input[offset + i] ^ stream[i]);
        offset += chunk;
        if (offset < input_length) ++counter;
    }

    crypto_zeroize(stream, sizeof(stream));
    crypto_zeroize(initial, sizeof(initial));
    return LIBERAC_SUCCESS;
}

#undef CHACHA_QUARTER_ROUND
