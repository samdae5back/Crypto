/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stddef.h>
#include <stdint.h>

#include "auxiliary.h"
#include "hash.h"
#include "parameter.h"

static unsigned int mlkem_bit_at(const unsigned char *input,
                                 size_t bit_index) {
    return ((unsigned int)input[bit_index / 8u] >> (bit_index % 8u)) & 1u;
}

static int mlkem_power_of_two(int exponent) {
    return 1 << exponent;
}

int ByteEncode(const int *input, size_t bit_width, unsigned char *output) {
    uint32_t bit_buffer = 0u;
    unsigned int buffered_bits = 0u;
    uint32_t mask;
    size_t coefficient;

    if (!input || !output || bit_width < 1u || bit_width > 12u) return -1;

    mask = (UINT32_C(1) << bit_width) - UINT32_C(1);
    for (coefficient = 0u; coefficient < MLKEM_N; ++coefficient) {
        uint32_t value = (uint32_t)input[coefficient] & mask;

        /*
         * At most seven bits remain before the next coefficient is appended,
         * so a 32-bit reservoir is ample for every supported width (<= 12).
         * The loop shape depends only on the public encoding width.
         */
        bit_buffer |= value << buffered_bits;
        buffered_bits += (unsigned int)bit_width;
        while (buffered_bits >= 8u) {
            *output++ = (unsigned char)bit_buffer;
            bit_buffer >>= 8u;
            buffered_bits -= 8u;
        }
    }
    return 0;
}

int ByteDecode(const unsigned char *input, size_t bit_width, int *output) {
    uint32_t bit_buffer = 0u;
    unsigned int buffered_bits = 0u;
    uint32_t mask;
    unsigned int modulus;
    size_t coefficient;

    if (!input || !output || bit_width < 1u || bit_width > 12u) return -1;

    mask = (UINT32_C(1) << bit_width) - UINT32_C(1);
    modulus = bit_width == 12u ? (unsigned int)MLKEM_Q
                               : (unsigned int)mlkem_power_of_two((int)bit_width);

    for (coefficient = 0u; coefficient < MLKEM_N; ++coefficient) {
        uint32_t value;

        while (buffered_bits < bit_width) {
            bit_buffer |= (uint32_t)(*input++) << buffered_bits;
            buffered_bits += 8u;
        }
        value = bit_buffer & mask;
        bit_buffer >>= (unsigned int)bit_width;
        buffered_bits -= (unsigned int)bit_width;
        output[coefficient] = (int)(value % modulus);
    }
    return 0;
}

int SampleNTT(const unsigned char *input, int *output, size_t input_length) {
    enum { MLKEM_SHAKE128_RATE_BYTES = 168 };
    crypto_sha3_ctx context;
    unsigned char bytes[MLKEM_SHAKE128_RATE_BYTES];
    size_t index = 0u;
    int result = -1;

    if (!input || !output) return -1;

    XOF_init(&context);
    XOF_absorb(&context, input, input_length);
    while (index < MLKEM_N) {
        size_t offset;

        /*
         * Consume one full SHAKE128 rate block at a time.  The former code
         * squeezed three bytes per call; parsing the same byte stream in
         * 3-byte groups preserves the FIPS 203 rejection-sampling order while
         * avoiding roughly one XOF helper call per candidate pair.
         */
        if (XOF_squeeze(&context, bytes, sizeof(bytes)) != 0) goto cleanup;
        for (offset = 0u; offset < sizeof(bytes) && index < MLKEM_N;
             offset += 3u) {
            int first = (int)bytes[offset] +
                        MLKEM_N * ((int)bytes[offset + 1u] % 16);
            int second = ((int)bytes[offset + 1u] / 16) +
                         16 * (int)bytes[offset + 2u];

            if (first < MLKEM_Q) output[index++] = first;
            if (second < MLKEM_Q && index < MLKEM_N)
                output[index++] = second;
        }
    }
    result = 0;

cleanup:
    XOF_clear(&context);
    return result;
}

int SamplePolyCBD(const unsigned char *input, int *output,
                  size_t input_length) {
    size_t eta;
    size_t coefficient;
    size_t bit;

    if (!input || !output || (input_length != 128u && input_length != 192u))
        return -1;
    eta = input_length / 64u;

    for (coefficient = 0u; coefficient < MLKEM_N; ++coefficient) {
        int x = 0;
        int y = 0;
        size_t x_offset = (2u * coefficient) * eta;
        size_t y_offset = (2u * coefficient + 1u) * eta;
        for (bit = 0u; bit < eta; ++bit) {
            x += (int)mlkem_bit_at(input, x_offset + bit);
            y += (int)mlkem_bit_at(input, y_offset + bit);
        }
        output[coefficient] = (x - y + MLKEM_Q) % MLKEM_Q;
    }
    return 0;
}

int Comp(const int *input, int bit_width, int *output, size_t length) {
    int power;
    size_t i;

    if (!input || !output || bit_width < 1 || bit_width > 12) return -1;
    power = mlkem_power_of_two(bit_width);
    for (i = 0u; i < length; ++i) {
        output[i] = (power * input[i] + MLKEM_Q / 2) / MLKEM_Q;
        output[i] %= power;
    }
    return 0;
}

int Decomp(const int *input, int bit_width, int *output, size_t length) {
    int power;
    int half_power;
    size_t i;

    if (!input || !output || bit_width < 1 || bit_width > 12) return -1;
    power = mlkem_power_of_two(bit_width);
    half_power = mlkem_power_of_two(bit_width - 1);
    for (i = 0u; i < length; ++i)
        output[i] = (MLKEM_Q * input[i] + half_power) / power;
    return 0;
}
