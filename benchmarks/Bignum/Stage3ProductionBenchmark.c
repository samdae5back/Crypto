/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "Util/Bignum/bignum_internal.h"

#define BENCHMARK_SAMPLES 5u

typedef struct {
    size_t bits;
    LiberaCBignum a;
    LiberaCBignum b;
} Stage3ProductionCase;

static double benchmark_cpu_microseconds(void) {
    return (double)clock() * 1000000.0 / (double)CLOCKS_PER_SEC;
}

static int compare_double(const void *left, const void *right) {
    const double a = *(const double *)left;
    const double b = *(const double *)right;
    return (a > b) - (a < b);
}

static uint32_t benchmark_prng(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void benchmark_fill(uint8_t *out, size_t length, uint32_t *state) {
    size_t i;
    uint32_t word = 0u;

    for (i = 0u; i < length; ++i) {
        if ((i & 3u) == 0u)
            word = benchmark_prng(state);
        out[i] = (uint8_t)(word >> (8u * (i & 3u)));
    }
}

static uint32_t benchmark_checksum(const LiberaCBignum *value) {
    uint32_t checksum = UINT32_C(2166136261);
    size_t i;

    for (i = 0u; i < value->LENGTH; ++i) {
        checksum ^= value->LIMBS[i];
        checksum *= UINT32_C(16777619);
    }
    return checksum;
}

static int bignum_equal(const LiberaCBignum *a, const LiberaCBignum *b) {
    return crypto_bignum_compare(a, b) == 0;
}

static int stage3_case_init(Stage3ProductionCase *test_case,
                            size_t bits, uint32_t seed) {
    size_t bytes = bits / 8u;
    size_t limbs = bits / 32u;
    uint8_t *a_bytes = NULL;
    uint8_t *b_bytes = NULL;
    uint32_t state = seed;
    int ok = 0;

    if (!test_case || bits == 0u || (bits & 31u) != 0u)
        return 0;

    memset(test_case, 0, sizeof(*test_case));
    test_case->bits = bits;
    crypto_bignum_init(&test_case->a);
    crypto_bignum_init(&test_case->b);

    a_bytes = (uint8_t *)malloc(bytes);
    b_bytes = (uint8_t *)malloc(bytes);
    if (!a_bytes || !b_bytes)
        goto done;

    benchmark_fill(a_bytes, bytes, &state);
    benchmark_fill(b_bytes, bytes, &state);
    a_bytes[0] |= UINT8_C(0x80);
    b_bytes[0] |= UINT8_C(0x80);

    if (crypto_bignum_from_bytes_be(&test_case->a, a_bytes, bytes) !=
            LIBERAC_SUCCESS ||
        crypto_bignum_from_bytes_be(&test_case->b, b_bytes, bytes) !=
            LIBERAC_SUCCESS ||
        test_case->a.LENGTH != limbs || test_case->b.LENGTH != limbs)
        goto done;

    ok = 1;

done:
    free(a_bytes);
    free(b_bytes);
    return ok;
}

static void stage3_case_clear(Stage3ProductionCase *test_case) {
    if (!test_case)
        return;
    crypto_bignum_free(&test_case->a);
    crypto_bignum_free(&test_case->b);
}

static int validate_one_case(const Stage3ProductionCase *test_case) {
    LiberaCBignum reference, production, alias_left, alias_right;
    int ok = 0;

    crypto_bignum_init(&reference);
    crypto_bignum_init(&production);
    crypto_bignum_init(&alias_left);
    crypto_bignum_init(&alias_right);

    if (crypto_bignum_mul_stage2(&reference,
                                 &test_case->a,
                                 &test_case->b) != LIBERAC_SUCCESS ||
        crypto_bignum_mul(&production,
                          &test_case->a,
                          &test_case->b) != LIBERAC_SUCCESS ||
        !bignum_equal(&reference, &production))
        goto done;

    if (crypto_bignum_copy(&alias_left, &test_case->a) != LIBERAC_SUCCESS ||
        crypto_bignum_mul(&alias_left, &alias_left,
                          &test_case->b) != LIBERAC_SUCCESS ||
        !bignum_equal(&reference, &alias_left))
        goto done;

    if (crypto_bignum_copy(&alias_right, &test_case->b) != LIBERAC_SUCCESS ||
        crypto_bignum_mul(&alias_right, &test_case->a,
                          &alias_right) != LIBERAC_SUCCESS ||
        !bignum_equal(&reference, &alias_right))
        goto done;

    ok = 1;

done:
    crypto_bignum_free(&reference);
    crypto_bignum_free(&production);
    crypto_bignum_free(&alias_left);
    crypto_bignum_free(&alias_right);
    return ok;
}

static int randomized_validation(void) {
    uint32_t state = UINT32_C(0x13198a2e);
    size_t limbs;

    /* Cover every equal-width size around and beyond the 96-limb boundary. */
    for (limbs = 1u; limbs <= 160u; ++limbs) {
        Stage3ProductionCase test_case;
        size_t bits = limbs * 32u;
        if (!stage3_case_init(&test_case, bits, benchmark_prng(&state)) ||
            !validate_one_case(&test_case)) {
            stage3_case_clear(&test_case);
            return 0;
        }
        stage3_case_clear(&test_case);
    }
    return 1;
}

typedef LiberaCError (*MulFunction)(LiberaCBignum *,
                                    const LiberaCBignum *,
                                    const LiberaCBignum *);

static int benchmark_path(const Stage3ProductionCase *test_case,
                          const char *path,
                          MulFunction function,
                          size_t iterations) {
    LiberaCBignum out;
    double samples[BENCHMARK_SAMPLES];
    uint32_t checksum = 0u;
    size_t sample, iteration;

    crypto_bignum_init(&out);
    if (function(&out, &test_case->a, &test_case->b) != LIBERAC_SUCCESS)
        goto fail;

    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (function(&out, &test_case->a,
                         &test_case->b) != LIBERAC_SUCCESS)
                goto fail;
            checksum ^= benchmark_checksum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }

    qsort(samples, BENCHMARK_SAMPLES, sizeof(samples[0]), compare_double);
    printf("stage3-production,mul,%zu,%s,%zu,%.3f,%u\n",
           test_case->bits, path, iterations,
           samples[BENCHMARK_SAMPLES / 2u], checksum);
    crypto_bignum_free(&out);
    return 1;

fail:
    crypto_bignum_free(&out);
    return 0;
}

int main(void) {
    static const size_t bit_sizes[] = {
        512u, 1024u, 1536u, 2048u, 3072u, 4096u, 6144u, 8192u
    };
    static const size_t iteration_counts[] = {
        20000u, 10000u, 6000u, 4000u, 2000u, 1200u, 600u, 350u
    };
    size_t index;

    if (!randomized_validation()) {
        fputs("stage3 production differential validation failed\n", stderr);
        return 1;
    }

    puts("stage,operation,bits,path,iterations,median_us_per_op,checksum");
    for (index = 0u; index < sizeof(bit_sizes) / sizeof(bit_sizes[0]); ++index) {
        Stage3ProductionCase test_case;
        size_t bits = bit_sizes[index];
        size_t iterations = iteration_counts[index];

        if (!stage3_case_init(&test_case, bits,
                              UINT32_C(0xa4093822) ^ (uint32_t)bits) ||
            !validate_one_case(&test_case) ||
            !benchmark_path(&test_case, "stage2-schoolbook-reference",
                            crypto_bignum_mul_stage2, iterations) ||
            !benchmark_path(&test_case, "stage3-production-dispatch",
                            crypto_bignum_mul, iterations)) {
            stage3_case_clear(&test_case);
            fputs("stage3 production benchmark failed\n", stderr);
            return 1;
        }
        stage3_case_clear(&test_case);
    }
    return 0;
}
