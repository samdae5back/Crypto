/*
 * Copyright (c) 2026 Team SMAUG-T
 * SPDX-License-Identifier: MIT
 *
 * This runtime-parameterized integration is based on the SMAUG-T 1.2.0
 * reference implementation. The upstream license is reproduced in LICENSE.
 */

#include "smaug_t_internal.h"

#include <stdint.h>
#include <string.h>

#include "HashFunction/SHA3/sha3_internal.h"
#include "RandomNumberGeneration/KAT/pqc_kat_rng_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/Endian/endian_internal.h"
#include "Util/PQC/pqc_internal.h"
#include "parameter.h"

#define CRYPTO_SMAUG_T_DG_RANDOM_BITS 10u
#define CRYPTO_SMAUG_T_DG_SEED_WORDS \
    ((CRYPTO_SMAUG_T_DG_RANDOM_BITS * CRYPTO_SMAUG_T_N) / 64u)

typedef crypto_pqc_poly16 crypto_smaug_t_poly;
typedef crypto_pqc_polyvec16 crypto_smaug_t_polyvec;

typedef struct crypto_smaug_t_public_key {
    uint8_t seed[CRYPTO_SMAUG_T_SEED_BYTES];
    crypto_smaug_t_polyvec matrix[CRYPTO_SMAUG_T_MAX_RANK];
    crypto_smaug_t_polyvec vector;
} crypto_smaug_t_public_key;

typedef struct crypto_smaug_t_ciphertext {
    crypto_smaug_t_polyvec first;
    crypto_smaug_t_poly second;
} crypto_smaug_t_ciphertext;

static const crypto_smaug_t_parameters *smaug_t_parameters_for(
    LiberaCAlgID algorithm) {
    size_t index;

    for (index = 0u;
         index < sizeof(CRYPTO_SMAUG_T_PARAMETER_SETS) /
                     sizeof(CRYPTO_SMAUG_T_PARAMETER_SETS[0]);
         ++index) {
        if (CRYPTO_SMAUG_T_PARAMETER_SETS[index].algorithm == algorithm) {
            return &CRYPTO_SMAUG_T_PARAMETER_SETS[index];
        }
    }
    return NULL;
}

static void smaug_t_hash_g(
    uint8_t *output, size_t output_length,
    const uint8_t *first, size_t first_length,
    const uint8_t *second, size_t second_length) {
    crypto_sha3_context context;

    crypto_shake256_init(&context);
    crypto_sha3_update(&context, first, first_length);
    crypto_sha3_update(&context, second, second_length);
    crypto_sha3_finalize(&context);
    crypto_sha3_squeeze(&context, output, output_length);
    crypto_sha3_clear(&context);
}

static void smaug_t_pack_poly(
    uint8_t *output, const crypto_smaug_t_poly *polynomial,
    unsigned int bits, unsigned int scale) {
    const uint32_t mask = (UINT32_C(1) << bits) - UINT32_C(1);
    uint32_t accumulator = 0u;
    unsigned int accumulator_bits = 0u;
    size_t output_index = 0u;
    size_t index;

    memset(output, 0, (CRYPTO_SMAUG_T_N * bits) / 8u);
    for (index = 0u; index < CRYPTO_SMAUG_T_N; ++index) {
        uint32_t value = ((uint16_t)polynomial->coeffs[index] >> scale) & mask;
        accumulator |= value << accumulator_bits;
        accumulator_bits += bits;
        while (accumulator_bits >= 8u) {
            output[output_index++] = (uint8_t)accumulator;
            accumulator >>= 8u;
            accumulator_bits -= 8u;
        }
    }
}

static void smaug_t_unpack_poly(
    crypto_smaug_t_poly *polynomial, const uint8_t *input,
    unsigned int bits, unsigned int scale) {
    const uint32_t mask = (UINT32_C(1) << bits) - UINT32_C(1);
    uint32_t accumulator = 0u;
    unsigned int accumulator_bits = 0u;
    size_t input_index = 0u;
    size_t index;

    memset(polynomial, 0, sizeof(*polynomial));
    for (index = 0u; index < CRYPTO_SMAUG_T_N; ++index) {
        uint32_t value;
        while (accumulator_bits < bits) {
            accumulator |= (uint32_t)input[input_index++] << accumulator_bits;
            accumulator_bits += 8u;
        }
        value = accumulator & mask;
        accumulator >>= bits;
        accumulator_bits -= bits;
        polynomial->coeffs[index] =
            (int16_t)(uint16_t)(value << scale);
    }
}

static void smaug_t_pack_secret_poly(
    uint8_t output[CRYPTO_SMAUG_T_SECRET_POLY_BYTES],
    const crypto_smaug_t_poly *polynomial) {
    size_t index;

    for (index = 0u; index < CRYPTO_SMAUG_T_N / 4u; ++index) {
        const size_t coefficient = index * 4u;
        output[index] =
            (uint8_t)(((1 - polynomial->coeffs[coefficient]) & 3) |
                      (((1 - polynomial->coeffs[coefficient + 1u]) & 3) << 2) |
                      (((1 - polynomial->coeffs[coefficient + 2u]) & 3) << 4) |
                      (((1 - polynomial->coeffs[coefficient + 3u]) & 3) << 6));
    }
}

static void smaug_t_unpack_secret_poly(
    crypto_smaug_t_poly *polynomial,
    const uint8_t input[CRYPTO_SMAUG_T_SECRET_POLY_BYTES]) {
    size_t index;

    for (index = 0u; index < CRYPTO_SMAUG_T_N / 4u; ++index) {
        const size_t coefficient = index * 4u;
        const uint8_t value = input[index];
        polynomial->coeffs[coefficient] = (int16_t)(1 - (value & 3u));
        polynomial->coeffs[coefficient + 1u] =
            (int16_t)(1 - ((value >> 2) & 3u));
        polynomial->coeffs[coefficient + 2u] =
            (int16_t)(1 - ((value >> 4) & 3u));
        polynomial->coeffs[coefficient + 3u] =
            (int16_t)(1 - ((value >> 6) & 3u));
    }
}

static void smaug_t_pack_secret_key(
    uint8_t *output, const crypto_smaug_t_polyvec *secret_key,
    const crypto_smaug_t_parameters *parameters) {
    size_t index;

    for (index = 0u; index < parameters->rank; ++index) {
        smaug_t_pack_secret_poly(
            output + index * CRYPTO_SMAUG_T_SECRET_POLY_BYTES,
            &secret_key->vec[index]);
    }
}

static void smaug_t_unpack_secret_key(
    crypto_smaug_t_polyvec *secret_key, const uint8_t *input,
    const crypto_smaug_t_parameters *parameters) {
    size_t index;

    memset(secret_key, 0, sizeof(*secret_key));
    for (index = 0u; index < parameters->rank; ++index) {
        smaug_t_unpack_secret_poly(
            &secret_key->vec[index],
            input + index * CRYPTO_SMAUG_T_SECRET_POLY_BYTES);
    }
}

static int smaug_t_encoded_secret_key_is_valid(
    const uint8_t *private_key,
    const crypto_smaug_t_parameters *parameters) {
    uint32_t invalid = 0u;
    size_t index;

    for (index = 0u; index < parameters->pke_private_key_bytes; ++index) {
        uint8_t value = private_key[index];
        invalid |= (uint32_t)((value & 3u) == 3u);
        invalid |= (uint32_t)(((value >> 2) & 3u) == 3u);
        invalid |= (uint32_t)(((value >> 4) & 3u) == 3u);
        invalid |= (uint32_t)(((value >> 6) & 3u) == 3u);
    }
    return invalid == 0u;
}

static int smaug_t_rejection_sample(
    int16_t output[CRYPTO_SMAUG_T_N],
    const uint16_t random_words[CRYPTO_SMAUG_T_HWT_SEED_BYTES / 2u]) {
    size_t index;
    size_t random_index = CRYPTO_SMAUG_T_N;

    for (index = 0u; index < CRYPTO_SMAUG_T_N; ++index) {
        const uint16_t modulus = (uint16_t)(CRYPTO_SMAUG_T_N - index);
        const uint16_t threshold = (uint16_t)(65536u % modulus);
        uint32_t product = (uint32_t)random_words[index] * modulus;
        uint16_t low = (uint16_t)product;

        while (low < threshold) {
            if (random_index >= CRYPTO_SMAUG_T_HWT_SEED_BYTES / 2u) {
                return -1;
            }
            product = (uint32_t)random_words[random_index++] * modulus;
            low = (uint16_t)product;
        }
        output[index] = (int16_t)(product >> 16);
    }
    return 0;
}

static int smaug_t_hwt(
    int16_t output[CRYPTO_SMAUG_T_N], const uint8_t seed[34],
    const crypto_smaug_t_parameters *parameters) {
    int16_t sample_indices[CRYPTO_SMAUG_T_N] = {0};
    uint16_t random_words[CRYPTO_SMAUG_T_HWT_SEED_BYTES / 2u] = {0};
    uint8_t signs[CRYPTO_SMAUG_T_N / 4u] = {0};
    uint8_t buffer[CRYPTO_SMAUG_T_HWT_SEED_BYTES] = {0};
    crypto_sha3_context context;
    int16_t cutoff =
        (int16_t)(CRYPTO_SMAUG_T_N - parameters->hamming_weight);
    int result = -1;
    size_t index;

    crypto_shake256_init(&context);
    crypto_sha3_update(&context, seed, CRYPTO_SMAUG_T_SEED_BYTES + 2u);
    crypto_sha3_finalize(&context);
    crypto_sha3_squeeze(&context, buffer, sizeof(buffer));
    for (index = 0u; index < sizeof(random_words) / sizeof(random_words[0]);
         ++index) {
        random_words[index] = crypto_load16_le(buffer + 2u * index);
    }
    if (smaug_t_rejection_sample(sample_indices, random_words) != 0) {
        goto cleanup;
    }
    crypto_sha3_squeeze(&context, signs, sizeof(signs));

    for (index = 0u; index < CRYPTO_SMAUG_T_N; ++index) {
        const int16_t below = (int16_t)-(sample_indices[index] < cutoff);
        const int16_t nonzero = (int16_t)(1 + below);
        const uint8_t sign_bit = (uint8_t)(
            (signs[(((index >> 4) >> 3) << 4) + (index & 15u)] >>
             ((index >> 4) & 7u)) &
            1u);
        const int16_t sign = (int16_t)(2 * (int16_t)sign_bit - 1);

        cutoff = (int16_t)(cutoff + below);
        output[index] = (int16_t)(nonzero * sign);
    }
    result = 0;

cleanup:
    crypto_sha3_clear(&context);
    crypto_zeroize(buffer, sizeof(buffer));
    crypto_zeroize(signs, sizeof(signs));
    crypto_zeroize(random_words, sizeof(random_words));
    crypto_zeroize(sample_indices, sizeof(sample_indices));
    return result;
}

static void smaug_t_sample_cbd(
    crypto_smaug_t_poly *polynomial, const uint8_t *buffer,
    const crypto_smaug_t_parameters *parameters) {
    size_t i;
    size_t j;

    if (parameters->algorithm == LIBERAC_ALG_SMAUG_T_128) {
        for (i = 0u; i < CRYPTO_SMAUG_T_N / 8u; ++i) {
            const uint32_t value = crypto_load24_le(buffer + 3u * i);
            uint32_t magnitude = value & UINT32_C(0x00249249);
            const uint32_t signs =
                (value >> 2) & UINT32_C(0x00249249);
            magnitude &= (value >> 1) & UINT32_C(0x00249249);
            for (j = 0u; j < 8u; ++j) {
                const int16_t nonzero =
                    (int16_t)((magnitude >> (3u * j)) & 1u);
                const int16_t sign =
                    (int16_t)((signs >> (3u * j)) & 1u);
                polynomial->coeffs[8u * i + j] =
                    (int16_t)(nonzero * (1 - 2 * sign));
            }
        }
    } else if (parameters->algorithm == LIBERAC_ALG_SMAUG_T_192) {
        for (i = 0u; i < CRYPTO_SMAUG_T_N / 16u; ++i) {
            const uint32_t value = crypto_load32_le(buffer + 4u * i);
            for (j = 0u; j < 16u; ++j) {
                const int16_t first =
                    (int16_t)((value >> (2u * j)) & 1u);
                const int16_t second =
                    (int16_t)((value >> (2u * j + 1u)) & 1u);
                polynomial->coeffs[16u * i + j] =
                    (int16_t)(first - second);
            }
        }
    } else {
        for (i = 0u; i < CRYPTO_SMAUG_T_N / 8u; ++i) {
            const uint32_t value = crypto_load32_le(buffer + 4u * i);
            uint32_t magnitude = value & UINT32_C(0x11111111);
            const uint32_t signs =
                (value >> 3) & UINT32_C(0x11111111);
            magnitude |= (value >> 1) & UINT32_C(0x11111111);
            magnitude &= (value >> 2) & UINT32_C(0x11111111);
            for (j = 0u; j < 8u; ++j) {
                const int16_t nonzero =
                    (int16_t)((magnitude >> (4u * j)) & 1u);
                const int16_t sign =
                    (int16_t)((signs >> (4u * j)) & 1u);
                polynomial->coeffs[8u * i + j] =
                    (int16_t)(nonzero * (1 - 2 * sign));
            }
        }
    }
}

static void smaug_t_load_discrete_gaussian_words(
    uint64_t output[CRYPTO_SMAUG_T_DG_SEED_WORDS],
    const uint8_t input[CRYPTO_SMAUG_T_DG_SEED_WORDS * 8u]) {
    uint8_t lane[8];
    size_t group;
    size_t word;
    size_t byte;

    for (group = 0u; group < CRYPTO_SMAUG_T_DG_SEED_WORDS / 10u; ++group) {
        const size_t position = group * 80u;
        for (word = 0u; word < 10u; ++word) {
            for (byte = 0u; byte < sizeof(lane); ++byte) {
                lane[byte] = input[position + byte * 10u + word];
            }
            output[group * 10u + word] = crypto_load64_le(lane);
        }
    }
    crypto_zeroize(lane, sizeof(lane));
}

static void smaug_t_discrete_gaussian_poly(
    crypto_smaug_t_poly *polynomial, const uint8_t seed[33],
    const crypto_smaug_t_parameters *parameters) {
    uint64_t random_words[CRYPTO_SMAUG_T_DG_SEED_WORDS] = {0};
    uint8_t buffer[CRYPTO_SMAUG_T_DG_SEED_WORDS * 8u] = {0};
    size_t block;

    crypto_shake256(buffer, sizeof(buffer), seed,
                    CRYPTO_SMAUG_T_SEED_BYTES + 1u);
    smaug_t_load_discrete_gaussian_words(random_words, buffer);

    for (block = 0u; block < CRYPTO_SMAUG_T_N / 64u; ++block) {
        const uint64_t *x = random_words + block * 10u;
        const uint64_t low =
            (x[0] & x[1] & x[2] & x[3] & x[4] & x[5] & x[7] & ~x[8]) |
            (x[0] & x[3] & x[4] & x[5] & x[6] & x[8]) |
            (x[1] & x[3] & x[4] & x[5] & x[6] & x[8]) |
            (x[2] & x[3] & x[4] & x[5] & x[6] & x[8]) |
            (~x[2] & ~x[3] & ~x[6] & x[8]) |
            (~x[1] & ~x[3] & ~x[6] & x[8]) |
            (x[6] & x[7] & ~x[8]) |
            (~x[5] & ~x[6] & x[8]) |
            (~x[4] & ~x[6] & x[8]) |
            (~x[7] & x[8]);
        const uint64_t high =
            (x[1] & x[2] & x[4] & x[5] & x[7] & x[8]) |
            (x[3] & x[4] & x[5] & x[7] & x[8]) |
            (x[6] & x[7] & x[8]);
        size_t coefficient;

        for (coefficient = 0u; coefficient < 64u; ++coefficient) {
            const uint16_t magnitude =
                (uint16_t)(((low >> coefficient) & 1u) |
                           (((high >> coefficient) & 1u) << 1));
            const uint16_t sign = (uint16_t)((x[9] >> coefficient) & 1u);
            const int16_t signed_magnitude =
                sign != 0u ? (int16_t)-(int16_t)magnitude
                           : (int16_t)magnitude;
            polynomial->coeffs[block * 64u + coefficient] =
                (int16_t)(uint16_t)(
                    (uint16_t)signed_magnitude << (16u - parameters->log_q));
        }
    }

    crypto_zeroize(buffer, sizeof(buffer));
    crypto_zeroize(random_words, sizeof(random_words));
}

static void smaug_t_discrete_gaussian_vector(
    crypto_smaug_t_polyvec *vector,
    const uint8_t seed[CRYPTO_SMAUG_T_SEED_BYTES],
    const crypto_smaug_t_parameters *parameters) {
    uint8_t extended_seed[CRYPTO_SMAUG_T_SEED_BYTES + 1u] = {0};
    size_t index;

    memcpy(extended_seed, seed, CRYPTO_SMAUG_T_SEED_BYTES);
    for (index = 0u; index < parameters->rank; ++index) {
        extended_seed[CRYPTO_SMAUG_T_SEED_BYTES] =
            (uint8_t)(parameters->rank * index);
        smaug_t_discrete_gaussian_poly(
            &vector->vec[index], extended_seed, parameters);
    }
    crypto_zeroize(extended_seed, sizeof(extended_seed));
}

#define CRYPTO_SMAUG_T_KARATSUBA_N 64u
#define CRYPTO_SMAUG_T_TOOM_BLOCK (CRYPTO_SMAUG_T_N / 4u)
#define CRYPTO_SMAUG_T_TOOM_PRODUCT_BLOCK \
    (2u * CRYPTO_SMAUG_T_TOOM_BLOCK - 1u)
#define CRYPTO_SMAUG_T_OVERFLOWING_MUL(left, right) \
    ((uint16_t)((uint32_t)(left) * (uint32_t)(right)))

static void smaug_t_karatsuba_simple(
    const uint16_t *left, const uint16_t *right, uint16_t *result) {
    uint16_t middle_low[CRYPTO_SMAUG_T_KARATSUBA_N / 2u - 1u];
    uint16_t middle_all[CRYPTO_SMAUG_T_KARATSUBA_N / 2u - 1u];
    uint16_t middle_high[CRYPTO_SMAUG_T_KARATSUBA_N / 2u - 1u];
    uint16_t middle_result[CRYPTO_SMAUG_T_KARATSUBA_N - 1u];
    size_t i;
    size_t j;

    memset(middle_low, 0, sizeof(middle_low));
    memset(middle_all, 0, sizeof(middle_all));
    memset(middle_high, 0, sizeof(middle_high));
    memset(middle_result, 0, sizeof(middle_result));
    memset(result, 0,
           (2u * CRYPTO_SMAUG_T_KARATSUBA_N - 1u) * sizeof(uint16_t));

    for (i = 0u; i < CRYPTO_SMAUG_T_KARATSUBA_N / 4u; ++i) {
        const uint16_t left0 = left[i];
        const uint16_t left1 = left[i + CRYPTO_SMAUG_T_KARATSUBA_N / 4u];
        const uint16_t left2 =
            left[i + 2u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u];
        const uint16_t left3 =
            left[i + 3u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u];

        for (j = 0u; j < CRYPTO_SMAUG_T_KARATSUBA_N / 4u; ++j) {
            uint16_t right0 = right[j];
            uint16_t right1 =
                right[j + CRYPTO_SMAUG_T_KARATSUBA_N / 4u];
            const uint16_t right2 =
                right[j + 2u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u];
            const uint16_t right3 =
                right[j + 3u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u];
            uint16_t sum_left;
            uint16_t sum_right;

            result[i + j] = (uint16_t)(
                result[i + j] +
                CRYPTO_SMAUG_T_OVERFLOWING_MUL(left0, right0));
            result[i + j + 2u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u] =
                (uint16_t)(
                    result[i + j +
                           2u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u] +
                    CRYPTO_SMAUG_T_OVERFLOWING_MUL(left1, right1));

            sum_right = (uint16_t)(right0 + right1);
            sum_left = (uint16_t)(left0 + left1);
            middle_low[i + j] = (uint16_t)(
                middle_low[i + j] +
                CRYPTO_SMAUG_T_OVERFLOWING_MUL(sum_right, sum_left));

            result[i + j + 4u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u] =
                (uint16_t)(
                    result[i + j +
                           4u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u] +
                    CRYPTO_SMAUG_T_OVERFLOWING_MUL(right2, left2));
            result[i + j + 6u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u] =
                (uint16_t)(
                    result[i + j +
                           6u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u] +
                    CRYPTO_SMAUG_T_OVERFLOWING_MUL(right3, left3));

            sum_left = (uint16_t)(left2 + left3);
            sum_right = (uint16_t)(right2 + right3);
            middle_high[i + j] = (uint16_t)(
                middle_high[i + j] +
                CRYPTO_SMAUG_T_OVERFLOWING_MUL(sum_left, sum_right));

            right0 = (uint16_t)(right0 + right2);
            sum_left = (uint16_t)(left0 + left2);
            middle_result[i + j] = (uint16_t)(
                middle_result[i + j] +
                CRYPTO_SMAUG_T_OVERFLOWING_MUL(right0, sum_left));

            right1 = (uint16_t)(right1 + right3);
            sum_right = (uint16_t)(left1 + left3);
            middle_result[i + j +
                          2u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u] =
                (uint16_t)(
                    middle_result[i + j +
                                  2u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u] +
                    CRYPTO_SMAUG_T_OVERFLOWING_MUL(right1, sum_right));

            right0 = (uint16_t)(right0 + right1);
            sum_left = (uint16_t)(sum_left + sum_right);
            middle_all[i + j] = (uint16_t)(
                middle_all[i + j] +
                CRYPTO_SMAUG_T_OVERFLOWING_MUL(right0, sum_left));
        }
    }

    for (i = 0u; i < CRYPTO_SMAUG_T_KARATSUBA_N / 2u - 1u; ++i) {
        middle_all[i] = (uint16_t)(
            middle_all[i] - middle_result[i] -
            middle_result[i + 2u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u]);
        middle_low[i] = (uint16_t)(
            middle_low[i] - result[i] -
            result[i + 2u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u]);
        middle_high[i] = (uint16_t)(
            middle_high[i] -
            result[i + 4u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u] -
            result[i + 6u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u]);
    }

    for (i = 0u; i < CRYPTO_SMAUG_T_KARATSUBA_N / 2u - 1u; ++i) {
        middle_result[i + CRYPTO_SMAUG_T_KARATSUBA_N / 4u] =
            (uint16_t)(
                middle_result[i + CRYPTO_SMAUG_T_KARATSUBA_N / 4u] +
                middle_all[i]);
        result[i + CRYPTO_SMAUG_T_KARATSUBA_N / 4u] =
            (uint16_t)(
                result[i + CRYPTO_SMAUG_T_KARATSUBA_N / 4u] +
                middle_low[i]);
        result[i + 5u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u] =
            (uint16_t)(
                result[i + 5u * CRYPTO_SMAUG_T_KARATSUBA_N / 4u] +
                middle_high[i]);
    }

    for (i = 0u; i < CRYPTO_SMAUG_T_KARATSUBA_N - 1u; ++i) {
        middle_result[i] = (uint16_t)(
            middle_result[i] - result[i] -
            result[i + CRYPTO_SMAUG_T_KARATSUBA_N]);
    }
    for (i = 0u; i < CRYPTO_SMAUG_T_KARATSUBA_N - 1u; ++i) {
        result[i + CRYPTO_SMAUG_T_KARATSUBA_N / 2u] =
            (uint16_t)(
                result[i + CRYPTO_SMAUG_T_KARATSUBA_N / 2u] +
                middle_result[i]);
    }

    crypto_zeroize(middle_result, sizeof(middle_result));
    crypto_zeroize(middle_high, sizeof(middle_high));
    crypto_zeroize(middle_all, sizeof(middle_all));
    crypto_zeroize(middle_low, sizeof(middle_low));
}

static void smaug_t_toom_cook_4way(
    const uint16_t *left, const uint16_t *right, uint16_t *result) {
    const uint16_t inverse_3 = UINT16_C(43691);
    const uint16_t inverse_9 = UINT16_C(36409);
    const uint16_t inverse_15 = UINT16_C(61167);
    uint16_t left_1[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t left_2[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t left_3[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t left_4[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t left_5[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t left_6[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t left_7[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t right_1[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t right_2[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t right_3[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t right_4[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t right_5[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t right_6[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t right_7[CRYPTO_SMAUG_T_TOOM_BLOCK];
    uint16_t product_1[CRYPTO_SMAUG_T_TOOM_PRODUCT_BLOCK] = {0};
    uint16_t product_2[CRYPTO_SMAUG_T_TOOM_PRODUCT_BLOCK] = {0};
    uint16_t product_3[CRYPTO_SMAUG_T_TOOM_PRODUCT_BLOCK] = {0};
    uint16_t product_4[CRYPTO_SMAUG_T_TOOM_PRODUCT_BLOCK] = {0};
    uint16_t product_5[CRYPTO_SMAUG_T_TOOM_PRODUCT_BLOCK] = {0};
    uint16_t product_6[CRYPTO_SMAUG_T_TOOM_PRODUCT_BLOCK] = {0};
    uint16_t product_7[CRYPTO_SMAUG_T_TOOM_PRODUCT_BLOCK] = {0};
    const uint16_t *left_0 = left;
    const uint16_t *left_block_1 = left + CRYPTO_SMAUG_T_TOOM_BLOCK;
    const uint16_t *left_block_2 = left + 2u * CRYPTO_SMAUG_T_TOOM_BLOCK;
    const uint16_t *left_block_3 = left + 3u * CRYPTO_SMAUG_T_TOOM_BLOCK;
    const uint16_t *right_0 = right;
    const uint16_t *right_block_1 = right + CRYPTO_SMAUG_T_TOOM_BLOCK;
    const uint16_t *right_block_2 = right + 2u * CRYPTO_SMAUG_T_TOOM_BLOCK;
    const uint16_t *right_block_3 = right + 3u * CRYPTO_SMAUG_T_TOOM_BLOCK;
    size_t index;

    for (index = 0u; index < CRYPTO_SMAUG_T_TOOM_BLOCK; ++index) {
        uint16_t value0 = left_0[index];
        uint16_t value1 = left_block_1[index];
        uint16_t value2 = left_block_2[index];
        uint16_t value3 = left_block_3[index];
        uint16_t even = (uint16_t)(value0 + value2);
        uint16_t odd = (uint16_t)(value1 + value3);

        left_3[index] = (uint16_t)(even + odd);
        left_4[index] = (uint16_t)(even - odd);
        even = (uint16_t)(((value0 << 2) + value2) << 1);
        odd = (uint16_t)((value1 << 2) + value3);
        left_5[index] = (uint16_t)(even + odd);
        left_6[index] = (uint16_t)(even - odd);
        left_2[index] = (uint16_t)(
            (value3 << 3) + (value2 << 2) + (value1 << 1) + value0);
        left_7[index] = value0;
        left_1[index] = value3;

        value0 = right_0[index];
        value1 = right_block_1[index];
        value2 = right_block_2[index];
        value3 = right_block_3[index];
        even = (uint16_t)(value0 + value2);
        odd = (uint16_t)(value1 + value3);
        right_3[index] = (uint16_t)(even + odd);
        right_4[index] = (uint16_t)(even - odd);
        even = (uint16_t)(((value0 << 2) + value2) << 1);
        odd = (uint16_t)((value1 << 2) + value3);
        right_5[index] = (uint16_t)(even + odd);
        right_6[index] = (uint16_t)(even - odd);
        right_2[index] = (uint16_t)(
            (value3 << 3) + (value2 << 2) + (value1 << 1) + value0);
        right_7[index] = value0;
        right_1[index] = value3;
    }

    smaug_t_karatsuba_simple(left_1, right_1, product_1);
    smaug_t_karatsuba_simple(left_2, right_2, product_2);
    smaug_t_karatsuba_simple(left_3, right_3, product_3);
    smaug_t_karatsuba_simple(left_4, right_4, product_4);
    smaug_t_karatsuba_simple(left_5, right_5, product_5);
    smaug_t_karatsuba_simple(left_6, right_6, product_6);
    smaug_t_karatsuba_simple(left_7, right_7, product_7);

    for (index = 0u; index < CRYPTO_SMAUG_T_TOOM_PRODUCT_BLOCK; ++index) {
        uint16_t r0 = product_1[index];
        uint16_t r1 = product_2[index];
        uint16_t r2 = product_3[index];
        uint16_t r3 = product_4[index];
        uint16_t r4 = product_5[index];
        uint16_t r5 = product_6[index];
        const uint16_t r6 = product_7[index];

        r1 = (uint16_t)(r1 + r4);
        r5 = (uint16_t)(r5 - r4);
        /* This Toom-Cook interpolation difference is exactly divisible by 2. */
        r3 = (uint16_t)(((int)r3 - (int)r2) / 2);
        r4 = (uint16_t)(r4 - r0);
        r4 = (uint16_t)(r4 - (r6 << 6));
        r4 = (uint16_t)((r4 << 1) + r5);
        r2 = (uint16_t)(r2 + r3);
        r1 = (uint16_t)(r1 - (r2 << 6) - r2);
        r2 = (uint16_t)(r2 - r6);
        r2 = (uint16_t)(r2 - r0);
        r1 = (uint16_t)(r1 + 45u * r2);
        r4 = (uint16_t)(
            ((uint32_t)((int)r4 - ((int)r2 << 3)) * inverse_3) >> 3);
        r5 = (uint16_t)(r5 + r1);
        r1 = (uint16_t)(
            ((uint32_t)((int)r1 + ((int)r3 << 4)) * inverse_9) >> 1);
        r3 = (uint16_t)-(uint16_t)(r3 + r1);
        r5 = (uint16_t)(((30u * r1 - r5) * (uint32_t)inverse_15) >> 2);
        r2 = (uint16_t)(r2 - r4);
        r1 = (uint16_t)(r1 - r5);

        result[index] = (uint16_t)(result[index] + r6);
        result[index + 64u] = (uint16_t)(result[index + 64u] + r5);
        result[index + 128u] = (uint16_t)(result[index + 128u] + r4);
        result[index + 192u] = (uint16_t)(result[index + 192u] + r3);
        result[index + 256u] = (uint16_t)(result[index + 256u] + r2);
        result[index + 320u] = (uint16_t)(result[index + 320u] + r1);
        result[index + 384u] = (uint16_t)(result[index + 384u] + r0);
    }

    crypto_zeroize(product_7, sizeof(product_7));
    crypto_zeroize(product_6, sizeof(product_6));
    crypto_zeroize(product_5, sizeof(product_5));
    crypto_zeroize(product_4, sizeof(product_4));
    crypto_zeroize(product_3, sizeof(product_3));
    crypto_zeroize(product_2, sizeof(product_2));
    crypto_zeroize(product_1, sizeof(product_1));
    crypto_zeroize(right_7, sizeof(right_7));
    crypto_zeroize(right_6, sizeof(right_6));
    crypto_zeroize(right_5, sizeof(right_5));
    crypto_zeroize(right_4, sizeof(right_4));
    crypto_zeroize(right_3, sizeof(right_3));
    crypto_zeroize(right_2, sizeof(right_2));
    crypto_zeroize(right_1, sizeof(right_1));
    crypto_zeroize(left_7, sizeof(left_7));
    crypto_zeroize(left_6, sizeof(left_6));
    crypto_zeroize(left_5, sizeof(left_5));
    crypto_zeroize(left_4, sizeof(left_4));
    crypto_zeroize(left_3, sizeof(left_3));
    crypto_zeroize(left_2, sizeof(left_2));
    crypto_zeroize(left_1, sizeof(left_1));
}

static void smaug_t_poly_multiply_accumulate(
    const int16_t left[CRYPTO_SMAUG_T_N],
    const int16_t right[CRYPTO_SMAUG_T_N],
    int16_t result[CRYPTO_SMAUG_T_N]) {
    uint16_t product[2u * CRYPTO_SMAUG_T_N] = {0};
    size_t index;

    smaug_t_toom_cook_4way(
        (const uint16_t *)(const void *)left,
        (const uint16_t *)(const void *)right, product);
    for (index = CRYPTO_SMAUG_T_N;
         index < 2u * CRYPTO_SMAUG_T_N; ++index) {
        const size_t reduced_index = index - CRYPTO_SMAUG_T_N;
        result[reduced_index] = (int16_t)(uint16_t)(
            (uint16_t)result[reduced_index] + product[reduced_index] -
            product[index]);
    }
    crypto_zeroize(product, sizeof(product));
}

static void smaug_t_vector_multiply_add(
    crypto_smaug_t_poly *result,
    const crypto_smaug_t_polyvec *left,
    const crypto_smaug_t_polyvec *right,
    unsigned int scale,
    const crypto_smaug_t_parameters *parameters) {
    crypto_smaug_t_poly shifted;
    crypto_smaug_t_poly product;
    crypto_smaug_t_poly scaled_product;
    size_t vector_index;
    size_t coefficient;

    memset(&product, 0, sizeof(product));
    for (vector_index = 0u; vector_index < parameters->rank; ++vector_index) {
        for (coefficient = 0u; coefficient < CRYPTO_SMAUG_T_N;
             ++coefficient) {
            shifted.coeffs[coefficient] = (int16_t)(
                (uint16_t)left->vec[vector_index].coeffs[coefficient] >>
                scale);
        }
        smaug_t_poly_multiply_accumulate(
            shifted.coeffs, right->vec[vector_index].coeffs,
            product.coeffs);
    }
    for (coefficient = 0u; coefficient < CRYPTO_SMAUG_T_N;
         ++coefficient) {
        scaled_product.coeffs[coefficient] = (int16_t)(uint16_t)(
            (uint16_t)product.coeffs[coefficient] << scale);
    }
    crypto_pqc_poly16_add(result, result, &scaled_product);

    crypto_zeroize(&scaled_product, sizeof(scaled_product));
    crypto_zeroize(&product, sizeof(product));
    crypto_zeroize(&shifted, sizeof(shifted));
}

static void smaug_t_matrix_vector_multiply_add(
    crypto_smaug_t_polyvec *result,
    const crypto_smaug_t_polyvec matrix[CRYPTO_SMAUG_T_MAX_RANK],
    const crypto_smaug_t_polyvec *vector,
    const crypto_smaug_t_parameters *parameters) {
    const unsigned int scale = 16u - parameters->log_q;
    crypto_smaug_t_poly shifted;
    crypto_smaug_t_poly product;
    size_t row;
    size_t column;
    size_t coefficient;

    memset(result, 0, sizeof(*result));
    for (column = 0u; column < parameters->rank; ++column) {
        memset(&product, 0, sizeof(product));
        for (row = 0u; row < parameters->rank; ++row) {
            for (coefficient = 0u; coefficient < CRYPTO_SMAUG_T_N;
                 ++coefficient) {
                shifted.coeffs[coefficient] = (int16_t)(
                    (uint16_t)matrix[row].vec[column].coeffs[coefficient] >>
                    scale);
            }
            smaug_t_poly_multiply_accumulate(
                shifted.coeffs, vector->vec[row].coeffs, product.coeffs);
        }
        for (coefficient = 0u; coefficient < CRYPTO_SMAUG_T_N;
             ++coefficient) {
            result->vec[column].coeffs[coefficient] =
                (int16_t)(uint16_t)(
                    (uint16_t)product.coeffs[coefficient] << scale);
        }
    }

    crypto_zeroize(&product, sizeof(product));
    crypto_zeroize(&shifted, sizeof(shifted));
}

static void smaug_t_matrix_vector_multiply_subtract(
    crypto_smaug_t_polyvec *result,
    const crypto_smaug_t_polyvec matrix[CRYPTO_SMAUG_T_MAX_RANK],
    const crypto_smaug_t_polyvec *vector,
    const crypto_smaug_t_parameters *parameters) {
    const unsigned int scale = 16u - parameters->log_q;
    crypto_smaug_t_poly shifted;
    crypto_smaug_t_poly product;
    crypto_smaug_t_poly scaled_product;
    size_t row;
    size_t column;
    size_t coefficient;

    for (row = 0u; row < parameters->rank; ++row) {
        memset(&product, 0, sizeof(product));
        for (column = 0u; column < parameters->rank; ++column) {
            for (coefficient = 0u; coefficient < CRYPTO_SMAUG_T_N;
                 ++coefficient) {
                shifted.coeffs[coefficient] = (int16_t)(
                    (uint16_t)matrix[row].vec[column].coeffs[coefficient] >>
                    scale);
            }
            smaug_t_poly_multiply_accumulate(
                shifted.coeffs, vector->vec[column].coeffs,
                product.coeffs);
        }
        for (coefficient = 0u; coefficient < CRYPTO_SMAUG_T_N;
             ++coefficient) {
            scaled_product.coeffs[coefficient] = (int16_t)(uint16_t)(
                (uint16_t)product.coeffs[coefficient] << scale);
        }
        crypto_pqc_poly16_sub(
            &result->vec[row], &result->vec[row], &scaled_product);
    }

    crypto_zeroize(&scaled_product, sizeof(scaled_product));
    crypto_zeroize(&product, sizeof(product));
    crypto_zeroize(&shifted, sizeof(shifted));
}

static void smaug_t_expand_matrix(
    crypto_smaug_t_polyvec matrix[CRYPTO_SMAUG_T_MAX_RANK],
    const uint8_t seed[CRYPTO_SMAUG_T_SEED_BYTES],
    const crypto_smaug_t_parameters *parameters) {
    uint8_t buffer[CRYPTO_SMAUG_T_MAX_PUBLIC_POLY_BYTES] = {0};
    uint8_t extended_seed[CRYPTO_SMAUG_T_SEED_BYTES + 2u] = {0};
    size_t row;
    size_t column;

    memset(matrix, 0,
           sizeof(crypto_smaug_t_polyvec) * CRYPTO_SMAUG_T_MAX_RANK);
    memcpy(extended_seed, seed, CRYPTO_SMAUG_T_SEED_BYTES);
    for (row = 0u; row < parameters->rank; ++row) {
        for (column = 0u; column < parameters->rank; ++column) {
            extended_seed[CRYPTO_SMAUG_T_SEED_BYTES] = (uint8_t)row;
            extended_seed[CRYPTO_SMAUG_T_SEED_BYTES + 1u] = (uint8_t)column;
            crypto_shake128(
                buffer, parameters->public_poly_bytes,
                extended_seed, sizeof(extended_seed));
            smaug_t_unpack_poly(
                &matrix[row].vec[column], buffer,
                parameters->log_q, 16u - parameters->log_q);
        }
    }

    crypto_zeroize(extended_seed, sizeof(extended_seed));
    crypto_zeroize(buffer, sizeof(buffer));
}

static LiberaCError smaug_t_expand_secret(
    crypto_smaug_t_polyvec *secret_key,
    const uint8_t seed[CRYPTO_SMAUG_T_SEED_BYTES],
    const crypto_smaug_t_parameters *parameters) {
    uint8_t extended_seed[CRYPTO_SMAUG_T_SEED_BYTES + 2u] = {0};
    size_t vector_index;

    memset(secret_key, 0, sizeof(*secret_key));
    memcpy(extended_seed, seed, CRYPTO_SMAUG_T_SEED_BYTES);
    for (vector_index = 0u; vector_index < parameters->rank; ++vector_index) {
        unsigned int attempt;

        extended_seed[CRYPTO_SMAUG_T_SEED_BYTES] =
            (uint8_t)(vector_index * parameters->rank);
        for (attempt = 0u; attempt <= UINT8_MAX; ++attempt) {
            extended_seed[CRYPTO_SMAUG_T_SEED_BYTES + 1u] =
                (uint8_t)attempt;
            if (smaug_t_hwt(
                    secret_key->vec[vector_index].coeffs,
                    extended_seed, parameters) == 0) {
                break;
            }
        }
        if (attempt > UINT8_MAX) {
            crypto_zeroize(extended_seed, sizeof(extended_seed));
            crypto_zeroize(secret_key, sizeof(*secret_key));
            return LIBERAC_ERROR_INTERNAL;
        }
    }
    crypto_zeroize(extended_seed, sizeof(extended_seed));
    return LIBERAC_SUCCESS;
}

static void smaug_t_expand_ephemeral(
    crypto_smaug_t_polyvec *ephemeral,
    const uint8_t seed[CRYPTO_SMAUG_T_SEED_BYTES],
    const crypto_smaug_t_parameters *parameters) {
    uint8_t buffer[CRYPTO_SMAUG_T_MAX_CBD_SEED_BYTES] = {0};
    uint8_t extended_seed[CRYPTO_SMAUG_T_SEED_BYTES + 1u] = {0};
    size_t vector_index;

    memset(ephemeral, 0, sizeof(*ephemeral));
    memcpy(extended_seed, seed, CRYPTO_SMAUG_T_SEED_BYTES);
    for (vector_index = 0u; vector_index < parameters->rank; ++vector_index) {
        extended_seed[CRYPTO_SMAUG_T_SEED_BYTES] = (uint8_t)vector_index;
        crypto_shake256(
            buffer, parameters->cbd_seed_bytes,
            extended_seed, sizeof(extended_seed));
        smaug_t_sample_cbd(
            &ephemeral->vec[vector_index], buffer, parameters);
    }

    crypto_zeroize(extended_seed, sizeof(extended_seed));
    crypto_zeroize(buffer, sizeof(buffer));
}

static void smaug_t_generate_public_key(
    crypto_smaug_t_public_key *public_key,
    const crypto_smaug_t_polyvec *secret_key,
    const uint8_t error_seed[CRYPTO_SMAUG_T_SEED_BYTES],
    const crypto_smaug_t_parameters *parameters) {
    smaug_t_expand_matrix(public_key->matrix, public_key->seed, parameters);
    memset(&public_key->vector, 0, sizeof(public_key->vector));
    smaug_t_discrete_gaussian_vector(
        &public_key->vector, error_seed, parameters);
    smaug_t_matrix_vector_multiply_subtract(
        &public_key->vector, public_key->matrix, secret_key, parameters);
}

static void smaug_t_pack_public_key(
    uint8_t *output, const crypto_smaug_t_public_key *public_key,
    const crypto_smaug_t_parameters *parameters) {
    size_t vector_index;

    memcpy(output, public_key->seed, CRYPTO_SMAUG_T_SEED_BYTES);
    for (vector_index = 0u; vector_index < parameters->rank; ++vector_index) {
        smaug_t_pack_poly(
            output + CRYPTO_SMAUG_T_SEED_BYTES +
                vector_index * parameters->public_poly_bytes,
            &public_key->vector.vec[vector_index],
            parameters->log_q, 16u - parameters->log_q);
    }
}

static void smaug_t_unpack_public_key(
    crypto_smaug_t_public_key *public_key, const uint8_t *input,
    const crypto_smaug_t_parameters *parameters) {
    size_t vector_index;

    memset(public_key, 0, sizeof(*public_key));
    memcpy(public_key->seed, input, CRYPTO_SMAUG_T_SEED_BYTES);
    smaug_t_expand_matrix(public_key->matrix, public_key->seed, parameters);
    for (vector_index = 0u; vector_index < parameters->rank; ++vector_index) {
        smaug_t_unpack_poly(
            &public_key->vector.vec[vector_index],
            input + CRYPTO_SMAUG_T_SEED_BYTES +
                vector_index * parameters->public_poly_bytes,
            parameters->log_q, 16u - parameters->log_q);
    }
}

static void smaug_t_pack_ciphertext(
    uint8_t *output, const crypto_smaug_t_ciphertext *ciphertext,
    const crypto_smaug_t_parameters *parameters) {
    size_t vector_index;

    for (vector_index = 0u; vector_index < parameters->rank; ++vector_index) {
        smaug_t_pack_poly(
            output + vector_index * parameters->ciphertext_poly_bytes,
            &ciphertext->first.vec[vector_index], parameters->log_p, 0u);
    }
    smaug_t_pack_poly(
        output + parameters->ciphertext_vector_bytes,
        &ciphertext->second, parameters->log_p_prime, 0u);
}

static void smaug_t_unpack_ciphertext(
    crypto_smaug_t_ciphertext *ciphertext, const uint8_t *input,
    const crypto_smaug_t_parameters *parameters) {
    size_t vector_index;

    memset(ciphertext, 0, sizeof(*ciphertext));
    for (vector_index = 0u; vector_index < parameters->rank; ++vector_index) {
        smaug_t_unpack_poly(
            &ciphertext->first.vec[vector_index],
            input + vector_index * parameters->ciphertext_poly_bytes,
            parameters->log_p, 0u);
    }
    smaug_t_unpack_poly(
        &ciphertext->second,
        input + parameters->ciphertext_vector_bytes,
        parameters->log_p_prime, 0u);
}

static void smaug_t_compute_ciphertext_first(
    crypto_smaug_t_polyvec *first,
    const crypto_smaug_t_polyvec matrix[CRYPTO_SMAUG_T_MAX_RANK],
    const crypto_smaug_t_polyvec *ephemeral,
    const crypto_smaug_t_parameters *parameters) {
    size_t vector_index;
    size_t coefficient;

    smaug_t_matrix_vector_multiply_add(
        first, matrix, ephemeral, parameters);
    for (vector_index = 0u; vector_index < parameters->rank; ++vector_index) {
        for (coefficient = 0u; coefficient < CRYPTO_SMAUG_T_N;
             ++coefficient) {
            uint16_t value =
                (uint16_t)first->vec[vector_index].coeffs[coefficient];
            value = (uint16_t)(
                (value + parameters->round_add) & parameters->round_mask);
            first->vec[vector_index].coeffs[coefficient] =
                (int16_t)(value >> (16u - parameters->log_p));
        }
    }
}

static void smaug_t_compute_ciphertext_second(
    crypto_smaug_t_poly *second,
    const uint8_t message[CRYPTO_SMAUG_T_MESSAGE_BYTES],
    const crypto_smaug_t_polyvec *public_vector,
    const crypto_smaug_t_polyvec *ephemeral,
    const crypto_smaug_t_parameters *parameters) {
    size_t byte;
    size_t bit;
    size_t coefficient;

    memset(second, 0, sizeof(*second));
    for (byte = 0u; byte < CRYPTO_SMAUG_T_MESSAGE_BYTES; ++byte) {
        for (bit = 0u; bit < 8u; ++bit) {
            second->coeffs[8u * byte + bit] = (int16_t)(uint16_t)(
                (uint16_t)((message[byte] >> bit) & 1u) << 15);
        }
    }

    smaug_t_vector_multiply_add(
        second, public_vector, ephemeral,
        16u - parameters->log_q, parameters);
    for (coefficient = 0u; coefficient < CRYPTO_SMAUG_T_N;
         ++coefficient) {
        uint16_t value = (uint16_t)second->coeffs[coefficient];
        value = (uint16_t)(
            (value + parameters->round_add_prime) &
            parameters->round_mask_prime);
        second->coeffs[coefficient] =
            (int16_t)(value >> (16u - parameters->log_p_prime));
    }
}

static LiberaCError smaug_t_pke_keypair(
    uint8_t *public_key, uint8_t *private_key,
    const uint8_t seed[CRYPTO_SMAUG_T_SEED_BYTES],
    const crypto_smaug_t_parameters *parameters) {
    uint8_t expanded_seed[2u * CRYPTO_SMAUG_T_SEED_BYTES] = {0};
    crypto_smaug_t_public_key decoded_public_key;
    crypto_smaug_t_polyvec decoded_private_key;
    LiberaCError result;

    memset(&decoded_public_key, 0, sizeof(decoded_public_key));
    memset(&decoded_private_key, 0, sizeof(decoded_private_key));
    crypto_sha3_512(expanded_seed, seed, CRYPTO_SMAUG_T_SEED_BYTES);

    result = smaug_t_expand_secret(
        &decoded_private_key, expanded_seed, parameters);
    if (result != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    memcpy(decoded_public_key.seed,
           expanded_seed + CRYPTO_SMAUG_T_SEED_BYTES,
           CRYPTO_SMAUG_T_SEED_BYTES);
    smaug_t_generate_public_key(
        &decoded_public_key, &decoded_private_key,
        expanded_seed, parameters);

    memset(public_key, 0, parameters->public_key_bytes);
    memset(private_key, 0, parameters->pke_private_key_bytes);
    smaug_t_pack_public_key(public_key, &decoded_public_key, parameters);
    smaug_t_pack_secret_key(private_key, &decoded_private_key, parameters);

cleanup:
    crypto_zeroize(&decoded_private_key, sizeof(decoded_private_key));
    crypto_zeroize(&decoded_public_key, sizeof(decoded_public_key));
    crypto_zeroize(expanded_seed, sizeof(expanded_seed));
    return result;
}

static void smaug_t_pke_encrypt(
    uint8_t *ciphertext, const uint8_t *public_key,
    const uint8_t message[CRYPTO_SMAUG_T_MESSAGE_BYTES],
    const uint8_t seed[CRYPTO_SMAUG_T_SEED_BYTES],
    const crypto_smaug_t_parameters *parameters) {
    crypto_smaug_t_public_key decoded_public_key;
    crypto_smaug_t_ciphertext decoded_ciphertext;
    crypto_smaug_t_polyvec ephemeral;

    memset(&decoded_public_key, 0, sizeof(decoded_public_key));
    memset(&decoded_ciphertext, 0, sizeof(decoded_ciphertext));
    memset(&ephemeral, 0, sizeof(ephemeral));

    smaug_t_unpack_public_key(
        &decoded_public_key, public_key, parameters);
    smaug_t_expand_ephemeral(&ephemeral, seed, parameters);
    smaug_t_compute_ciphertext_first(
        &decoded_ciphertext.first, decoded_public_key.matrix,
        &ephemeral, parameters);
    smaug_t_compute_ciphertext_second(
        &decoded_ciphertext.second, message,
        &decoded_public_key.vector, &ephemeral, parameters);
    smaug_t_pack_ciphertext(ciphertext, &decoded_ciphertext, parameters);

    crypto_zeroize(&ephemeral, sizeof(ephemeral));
    crypto_zeroize(&decoded_ciphertext, sizeof(decoded_ciphertext));
    crypto_zeroize(&decoded_public_key, sizeof(decoded_public_key));
}

static void smaug_t_pke_decrypt(
    uint8_t message[CRYPTO_SMAUG_T_MESSAGE_BYTES],
    const uint8_t *private_key, const uint8_t *ciphertext,
    const crypto_smaug_t_parameters *parameters) {
    crypto_smaug_t_polyvec decoded_private_key;
    crypto_smaug_t_ciphertext decoded_ciphertext;
    crypto_smaug_t_poly delta;
    size_t vector_index;
    size_t coefficient;
    size_t byte;
    size_t bit;

    memset(&decoded_private_key, 0, sizeof(decoded_private_key));
    memset(&decoded_ciphertext, 0, sizeof(decoded_ciphertext));
    memset(&delta, 0, sizeof(delta));
    smaug_t_unpack_secret_key(
        &decoded_private_key, private_key, parameters);
    smaug_t_unpack_ciphertext(
        &decoded_ciphertext, ciphertext, parameters);

    for (coefficient = 0u; coefficient < CRYPTO_SMAUG_T_N;
         ++coefficient) {
        delta.coeffs[coefficient] = (int16_t)(uint16_t)(
            (uint16_t)decoded_ciphertext.second.coeffs[coefficient] <<
            (16u - parameters->log_p_prime));
    }
    for (vector_index = 0u; vector_index < parameters->rank; ++vector_index) {
        for (coefficient = 0u; coefficient < CRYPTO_SMAUG_T_N;
             ++coefficient) {
            decoded_ciphertext.first.vec[vector_index].coeffs[coefficient] =
                (int16_t)(uint16_t)(
                    (uint16_t)decoded_ciphertext.first.vec[vector_index]
                        .coeffs[coefficient]
                    << (16u - parameters->log_p));
        }
    }

    smaug_t_vector_multiply_add(
        &delta, &decoded_ciphertext.first, &decoded_private_key,
        16u - parameters->log_p, parameters);

    memset(message, 0, CRYPTO_SMAUG_T_MESSAGE_BYTES);
    for (byte = 0u; byte < CRYPTO_SMAUG_T_MESSAGE_BYTES; ++byte) {
        for (bit = 0u; bit < 8u; ++bit) {
            const uint16_t value = (uint16_t)(
                (uint16_t)delta.coeffs[8u * byte + bit] +
                UINT16_C(0x4000));
            message[byte] |= (uint8_t)(((value >> 15) & 1u) << bit);
        }
    }

    crypto_zeroize(&delta, sizeof(delta));
    crypto_zeroize(&decoded_ciphertext, sizeof(decoded_ciphertext));
    crypto_zeroize(&decoded_private_key, sizeof(decoded_private_key));
}

static LiberaCError smaug_t_keypair_deterministic(
    uint8_t *public_key, uint8_t *private_key,
    const uint8_t rejection_secret[CRYPTO_SMAUG_T_SEED_BYTES],
    const uint8_t seed[CRYPTO_SMAUG_T_SEED_BYTES],
    const crypto_smaug_t_parameters *parameters) {
    LiberaCError result = smaug_t_pke_keypair(
        public_key, private_key, seed, parameters);

    if (result != LIBERAC_SUCCESS) {
        return result;
    }
    memcpy(private_key + parameters->pke_private_key_bytes,
           rejection_secret, CRYPTO_SMAUG_T_SEED_BYTES);
    memcpy(private_key + parameters->pke_private_key_bytes +
               CRYPTO_SMAUG_T_SEED_BYTES,
           public_key, parameters->public_key_bytes);
    return LIBERAC_SUCCESS;
}

static void smaug_t_encapsulate_deterministic(
    uint8_t *ciphertext,
    uint8_t shared_secret[LIBERAC_SMAUG_T_SHARED_SECRET_BYTES],
    const uint8_t *public_key,
    const uint8_t message[CRYPTO_SMAUG_T_MESSAGE_BYTES],
    const crypto_smaug_t_parameters *parameters) {
    uint8_t seed_and_secret[
        CRYPTO_SMAUG_T_SEED_BYTES +
        LIBERAC_SMAUG_T_SHARED_SECRET_BYTES] = {0};
    uint8_t public_key_hash[32] = {0};

    crypto_sha3_256(
        public_key_hash, public_key, parameters->public_key_bytes);
    smaug_t_hash_g(
        seed_and_secret, sizeof(seed_and_secret),
        message, CRYPTO_SMAUG_T_MESSAGE_BYTES,
        public_key_hash, sizeof(public_key_hash));
    smaug_t_pke_encrypt(
        ciphertext, public_key, message, seed_and_secret, parameters);
    memset(shared_secret, 0, LIBERAC_SMAUG_T_SHARED_SECRET_BYTES);
    crypto_pqc_cmov(
        shared_secret,
        seed_and_secret + CRYPTO_SMAUG_T_SEED_BYTES,
        LIBERAC_SMAUG_T_SHARED_SECRET_BYTES, 1u);

    crypto_zeroize(public_key_hash, sizeof(public_key_hash));
    crypto_zeroize(seed_and_secret, sizeof(seed_and_secret));
}

static void smaug_t_decapsulate_deterministic(
    uint8_t shared_secret[LIBERAC_SMAUG_T_SHARED_SECRET_BYTES],
    const uint8_t *ciphertext, const uint8_t *private_key,
    const crypto_smaug_t_parameters *parameters) {
    uint8_t message[CRYPTO_SMAUG_T_MESSAGE_BYTES] = {0};
    uint8_t selected[
        CRYPTO_SMAUG_T_SEED_BYTES +
        LIBERAC_SMAUG_T_SHARED_SECRET_BYTES] = {0};
    uint8_t rejected[
        CRYPTO_SMAUG_T_SEED_BYTES +
        LIBERAC_SMAUG_T_SHARED_SECRET_BYTES] = {0};
    uint8_t hash_result[32] = {0};
    uint8_t comparison[CRYPTO_SMAUG_T_MAX_CIPHERTEXT_BYTES] = {0};
    const uint8_t *public_key =
        private_key + parameters->pke_private_key_bytes +
        CRYPTO_SMAUG_T_SEED_BYTES;
    int failed;

    smaug_t_pke_decrypt(
        message, private_key, ciphertext, parameters);
    crypto_sha3_256(
        hash_result, public_key, parameters->public_key_bytes);
    smaug_t_hash_g(
        selected, sizeof(selected),
        message, sizeof(message), hash_result, sizeof(hash_result));
    smaug_t_pke_encrypt(
        comparison, public_key, message, selected, parameters);
    failed = crypto_pqc_verify(
        ciphertext, comparison, parameters->ciphertext_bytes);

    crypto_sha3_256(
        hash_result, ciphertext, parameters->ciphertext_bytes);
    smaug_t_hash_g(
        rejected, sizeof(rejected),
        private_key + parameters->pke_private_key_bytes,
        CRYPTO_SMAUG_T_SEED_BYTES,
        hash_result, sizeof(hash_result));

    memset(shared_secret, 0, LIBERAC_SMAUG_T_SHARED_SECRET_BYTES);
    crypto_pqc_cmov(
        selected + CRYPTO_SMAUG_T_SEED_BYTES,
        rejected + CRYPTO_SMAUG_T_SEED_BYTES,
        LIBERAC_SMAUG_T_SHARED_SECRET_BYTES, (uint8_t)failed);
    crypto_pqc_cmov(
        shared_secret, selected + CRYPTO_SMAUG_T_SEED_BYTES,
        LIBERAC_SMAUG_T_SHARED_SECRET_BYTES, 1u);

    crypto_zeroize(comparison, sizeof(comparison));
    crypto_zeroize(hash_result, sizeof(hash_result));
    crypto_zeroize(rejected, sizeof(rejected));
    crypto_zeroize(selected, sizeof(selected));
    crypto_zeroize(message, sizeof(message));
}

size_t crypto_smaug_t_public_key_size_internal(LiberaCAlgID algorithm) {
    const crypto_smaug_t_parameters *parameters =
        smaug_t_parameters_for(algorithm);
    return parameters != NULL ? parameters->public_key_bytes : 0u;
}

size_t crypto_smaug_t_private_key_size_internal(LiberaCAlgID algorithm) {
    const crypto_smaug_t_parameters *parameters =
        smaug_t_parameters_for(algorithm);
    return parameters != NULL ? parameters->private_key_bytes : 0u;
}

size_t crypto_smaug_t_ciphertext_size_internal(LiberaCAlgID algorithm) {
    const crypto_smaug_t_parameters *parameters =
        smaug_t_parameters_for(algorithm);
    return parameters != NULL ? parameters->ciphertext_bytes : 0u;
}

LiberaCError crypto_smaug_t_keygen_internal(
    LiberaCAlgID algorithm,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length) {
    const crypto_smaug_t_parameters *parameters =
        smaug_t_parameters_for(algorithm);
    uint8_t rejection_secret[CRYPTO_SMAUG_T_SEED_BYTES] = {0};
    uint8_t seed[CRYPTO_SMAUG_T_SEED_BYTES] = {0};
    LiberaCError result;

    if (parameters == NULL) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (public_key == NULL || private_key == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (public_key_length < parameters->public_key_bytes ||
        private_key_length < parameters->private_key_bytes) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(
            public_key, parameters->public_key_bytes,
            private_key, parameters->private_key_bytes)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    result = crypto_pqc_random_bytes_internal(
        rejection_secret, sizeof(rejection_secret));
    if (result == LIBERAC_SUCCESS) {
        result = crypto_pqc_random_bytes_internal(seed, sizeof(seed));
    }
    if (result == LIBERAC_SUCCESS) {
        result = smaug_t_keypair_deterministic(
            public_key, private_key, rejection_secret, seed, parameters);
    }
    if (result != LIBERAC_SUCCESS) {
        crypto_zeroize(public_key, parameters->public_key_bytes);
        crypto_zeroize(private_key, parameters->private_key_bytes);
    }

    crypto_zeroize(seed, sizeof(seed));
    crypto_zeroize(rejection_secret, sizeof(rejection_secret));
    return result;
}

LiberaCError crypto_smaug_t_encaps_internal(
    LiberaCAlgID algorithm,
    const uint8_t *public_key, size_t public_key_length,
    uint8_t shared_secret[LIBERAC_SMAUG_T_SHARED_SECRET_BYTES],
    uint8_t *ciphertext, size_t ciphertext_length) {
    const crypto_smaug_t_parameters *parameters =
        smaug_t_parameters_for(algorithm);
    uint8_t message[CRYPTO_SMAUG_T_MESSAGE_BYTES] = {0};
    LiberaCError result;

    if (parameters == NULL) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (public_key == NULL || shared_secret == NULL || ciphertext == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (public_key_length < parameters->public_key_bytes ||
        ciphertext_length < parameters->ciphertext_bytes) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(
            public_key, parameters->public_key_bytes,
            shared_secret, LIBERAC_SMAUG_T_SHARED_SECRET_BYTES) ||
        crypto_ranges_overlap(
            public_key, parameters->public_key_bytes,
            ciphertext, parameters->ciphertext_bytes) ||
        crypto_ranges_overlap(
            shared_secret, LIBERAC_SMAUG_T_SHARED_SECRET_BYTES,
            ciphertext, parameters->ciphertext_bytes)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    result = crypto_pqc_random_bytes_internal(message, sizeof(message));
    if (result == LIBERAC_SUCCESS) {
        smaug_t_encapsulate_deterministic(
            ciphertext, shared_secret, public_key, message, parameters);
    } else {
        crypto_zeroize(shared_secret, LIBERAC_SMAUG_T_SHARED_SECRET_BYTES);
        crypto_zeroize(ciphertext, parameters->ciphertext_bytes);
    }
    crypto_zeroize(message, sizeof(message));
    return result;
}

LiberaCError crypto_smaug_t_decaps_internal(
    LiberaCAlgID algorithm,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t shared_secret[LIBERAC_SMAUG_T_SHARED_SECRET_BYTES]) {
    const crypto_smaug_t_parameters *parameters =
        smaug_t_parameters_for(algorithm);

    if (parameters == NULL) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (private_key == NULL || ciphertext == NULL || shared_secret == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (private_key_length < parameters->private_key_bytes ||
        ciphertext_length < parameters->ciphertext_bytes) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(
            private_key, parameters->private_key_bytes,
            shared_secret, LIBERAC_SMAUG_T_SHARED_SECRET_BYTES) ||
        crypto_ranges_overlap(
            ciphertext, parameters->ciphertext_bytes,
            shared_secret, LIBERAC_SMAUG_T_SHARED_SECRET_BYTES)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (!smaug_t_encoded_secret_key_is_valid(private_key, parameters)) {
        crypto_zeroize(shared_secret, LIBERAC_SMAUG_T_SHARED_SECRET_BYTES);
        return LIBERAC_ERROR_INVALID_KEY;
    }

    smaug_t_decapsulate_deterministic(
        shared_secret, ciphertext, private_key, parameters);
    return LIBERAC_SUCCESS;
}
