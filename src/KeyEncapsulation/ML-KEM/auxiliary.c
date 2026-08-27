/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stddef.h>
#include <string.h>

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
    size_t coefficient;
    size_t bit;

    if (!input || !output || bit_width < 1u || bit_width > 12u) return -1;

    memset(output, 0, bit_width * 32u);
    for (coefficient = 0u; coefficient < MLKEM_N; ++coefficient) {
        unsigned int value = (unsigned int)input[coefficient];
        for (bit = 0u; bit < bit_width; ++bit) {
            size_t output_bit = coefficient * bit_width + bit;
            output[output_bit / 8u] |=
                (unsigned char)(((value >> bit) & 1u)
                                << (output_bit % 8u));
        }
    }
    return 0;
}

int ByteDecode(const unsigned char *input, size_t bit_width, int *output) {
    int modulus;
    size_t coefficient;
    size_t bit;

    if (!input || !output || bit_width < 1u || bit_width > 12u) return -1;
    modulus = bit_width == 12u ? MLKEM_Q : mlkem_power_of_two((int)bit_width);

    memset(output, 0, sizeof(*output) * MLKEM_N);
    for (coefficient = 0u; coefficient < MLKEM_N; ++coefficient) {
        unsigned int value = 0u;
        for (bit = 0u; bit < bit_width; ++bit) {
            size_t input_bit = coefficient * bit_width + bit;
            value |= mlkem_bit_at(input, input_bit) << bit;
        }
        output[coefficient] = (int)(value % (unsigned int)modulus);
    }
    return 0;
}

int SampleNTT(const unsigned char *input, int *output, size_t input_length) {
    crypto_sha3_ctx context;
    unsigned char bytes[3];
    size_t index = 0u;
    int result = -1;

    if (!input || !output) return -1;

    XOF_init(&context);
    XOF_absorb(&context, input, input_length);
    while (index < MLKEM_N) {
        int first;
        int second;

        if (XOF_squeeze(&context, bytes, sizeof(bytes)) != 0) goto cleanup;
        first = (int)bytes[0] + MLKEM_N * ((int)bytes[1] % 16);
        second = ((int)bytes[1] / 16) + 16 * (int)bytes[2];
        if (first < MLKEM_Q) output[index++] = first;
        if (second < MLKEM_Q && index < MLKEM_N) output[index++] = second;
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
