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
    uint32_t *workspace;
    size_t workspace_words;
} Stage3Case;

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

static size_t words_length(const uint32_t *words, size_t length) {
    while (length != 0u && words[length - 1u] == 0u)
        --length;
    return length;
}

static int schoolbook_words(uint32_t *out,
                            const uint32_t *a, size_t a_length,
                            const uint32_t *b, size_t b_length) {
    size_t i, j, out_length;
    if (!out || (!a && a_length) || (!b && b_length))
        return -1;
    if (a_length > SIZE_MAX - b_length)
        return -1;
    out_length = a_length + b_length;
    if (out_length != 0u)
        memset(out, 0, out_length * sizeof(uint32_t));
    for (i = 0u; i < a_length; ++i) {
        uint64_t carry = 0u;
        for (j = 0u; j < b_length; ++j) {
            size_t index = i + j;
            uint64_t current = (uint64_t)a[i] * b[j] + out[index] + carry;
            out[index] = (uint32_t)current;
            carry = current >> 32;
        }
        if (b_length != 0u)
            out[i + b_length] = (uint32_t)carry;
    }
    return 0;
}

static int add_halves(uint32_t *out, size_t out_length,
                      const uint32_t *low, size_t low_length,
                      const uint32_t *high, size_t high_length) {
    size_t length = low_length > high_length ? low_length : high_length;
    size_t i;
    uint64_t carry = 0u;
    if (!out || out_length < length + 1u)
        return -1;
    memset(out, 0, out_length * sizeof(uint32_t));
    for (i = 0u; i < length; ++i) {
        uint64_t left = i < low_length ? low[i] : 0u;
        uint64_t right = i < high_length ? high[i] : 0u;
        uint64_t sum = left + right + carry;
        out[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    out[length] = (uint32_t)carry;
    return 0;
}

static int subtract_words(uint32_t *value, size_t value_length,
                          const uint32_t *subtrahend,
                          size_t subtrahend_length) {
    size_t i;
    uint64_t borrow = 0u;
    if (!value || (!subtrahend && subtrahend_length) ||
        subtrahend_length > value_length)
        return -1;
    for (i = 0u; i < value_length; ++i) {
        uint64_t right = (i < subtrahend_length ? subtrahend[i] : 0u) +
                         borrow;
        uint64_t left = value[i];
        value[i] = (uint32_t)(left - right);
        borrow = left < right;
    }
    return borrow == 0u ? 0 : -1;
}

static int add_shifted(uint32_t *out, size_t out_length,
                       const uint32_t *value, size_t value_length,
                       size_t offset) {
    size_t i;
    uint64_t carry = 0u;
    if (!out || (!value && value_length) || offset > out_length ||
        value_length > out_length - offset)
        return -1;
    for (i = 0u; i < value_length; ++i) {
        uint64_t sum = (uint64_t)out[offset + i] + value[i] + carry;
        out[offset + i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    i = offset + value_length;
    while (carry != 0u && i < out_length) {
        uint64_t sum = (uint64_t)out[i] + carry;
        out[i] = (uint32_t)sum;
        carry = sum >> 32;
        ++i;
    }
    return carry == 0u ? 0 : -1;
}

/* One portable Karatsuba split with Stage-2 schoolbook leaves. The experiment
 * intentionally avoids recursion first: it measures whether the 25% reduction
 * in quadratic limb products is already enough to pay for sum/subtract and
 * assembly overhead at LiberaCrypt-relevant operand sizes. */
static int karatsuba_one_level(LiberaCBignum *out,
                               const LiberaCBignum *a,
                               const LiberaCBignum *b,
                               uint32_t *workspace,
                               size_t workspace_words) {
    size_t n, low_length, high_length, sum_length;
    size_t z0_capacity, z2_capacity, z1_capacity, required;
    size_t z0_length, z2_length, z1_length, out_length;
    uint32_t *z0, *z2, *sum_a, *sum_b, *z1;

    if (!out || !a || !b || !workspace || out == a || out == b ||
        a->LENGTH != b->LENGTH || a->LENGTH < 4u)
        return -1;
    n = a->LENGTH;
    low_length = n / 2u;
    high_length = n - low_length;
    sum_length = high_length + 1u;
    z0_capacity = 2u * low_length;
    z2_capacity = 2u * high_length;
    z1_capacity = 2u * sum_length;
    if (n > (SIZE_MAX - 8u) / 4u)
        return -1;
    required = z0_capacity + z2_capacity + 2u * sum_length + z1_capacity;
    if (workspace_words < required)
        return -1;

    z0 = workspace;
    z2 = z0 + z0_capacity;
    sum_a = z2 + z2_capacity;
    sum_b = sum_a + sum_length;
    z1 = sum_b + sum_length;
    memset(workspace, 0, required * sizeof(uint32_t));

    if (schoolbook_words(z0, a->LIMBS, low_length,
                         b->LIMBS, low_length) != 0 ||
        schoolbook_words(z2, a->LIMBS + low_length, high_length,
                         b->LIMBS + low_length, high_length) != 0 ||
        add_halves(sum_a, sum_length,
                   a->LIMBS, low_length,
                   a->LIMBS + low_length, high_length) != 0 ||
        add_halves(sum_b, sum_length,
                   b->LIMBS, low_length,
                   b->LIMBS + low_length, high_length) != 0 ||
        schoolbook_words(z1, sum_a, sum_length,
                         sum_b, sum_length) != 0)
        return -1;

    z0_length = words_length(z0, z0_capacity);
    z2_length = words_length(z2, z2_capacity);
    if (subtract_words(z1, z1_capacity, z0, z0_length) != 0 ||
        subtract_words(z1, z1_capacity, z2, z2_length) != 0)
        return -1;
    z1_length = words_length(z1, z1_capacity);

    if (n > SIZE_MAX / 2u)
        return -1;
    out_length = 2u * n;
    if (bignum_reserve(out, out_length) != 0)
        return -1;
    memset(out->LIMBS, 0, out_length * sizeof(uint32_t));
    if (add_shifted(out->LIMBS, out_length, z0, z0_length, 0u) != 0 ||
        add_shifted(out->LIMBS, out_length, z1, z1_length, low_length) != 0 ||
        add_shifted(out->LIMBS, out_length, z2, z2_length,
                    2u * low_length) != 0)
        return -1;
    out->LENGTH = out_length;
    bignum_normalize(out);
    return 0;
}

static int stage3_case_init(Stage3Case *test_case, size_t bits,
                            uint32_t seed) {
    size_t bytes = bits / 8u;
    size_t limbs = bytes / 4u;
    uint8_t *a_bytes = NULL, *b_bytes = NULL;
    uint32_t state = seed;
    int ok = 0;

    if (!test_case || bits == 0u || (bits & 31u) != 0u || limbs < 4u)
        return 0;
    memset(test_case, 0, sizeof(*test_case));
    test_case->bits = bits;
    crypto_bignum_init(&test_case->a);
    crypto_bignum_init(&test_case->b);
    if (limbs > (SIZE_MAX - 8u) / 4u)
        return 0;
    test_case->workspace_words = 4u * limbs + 8u;
    test_case->workspace = (uint32_t *)calloc(test_case->workspace_words,
                                              sizeof(uint32_t));
    a_bytes = (uint8_t *)malloc(bytes);
    b_bytes = (uint8_t *)malloc(bytes);
    if (!test_case->workspace || !a_bytes || !b_bytes)
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

static void stage3_case_clear(Stage3Case *test_case) {
    if (!test_case) return;
    crypto_bignum_free(&test_case->a);
    crypto_bignum_free(&test_case->b);
    free(test_case->workspace);
    test_case->workspace = NULL;
    test_case->workspace_words = 0u;
}

static int validate_case(const Stage3Case *test_case) {
    LiberaCBignum schoolbook, karatsuba;
    int ok;
    crypto_bignum_init(&schoolbook);
    crypto_bignum_init(&karatsuba);
    ok = crypto_bignum_mul(&schoolbook, &test_case->a, &test_case->b) ==
             LIBERAC_SUCCESS &&
         karatsuba_one_level(&karatsuba, &test_case->a, &test_case->b,
                             test_case->workspace,
                             test_case->workspace_words) == 0 &&
         crypto_bignum_compare(&schoolbook, &karatsuba) == 0;
    crypto_bignum_free(&schoolbook);
    crypto_bignum_free(&karatsuba);
    return ok;
}

static int randomized_validation(void) {
    uint32_t state = UINT32_C(0x243f6a88);
    size_t index;
    for (index = 0u; index < 120u; ++index) {
        size_t limbs = 4u + index % 157u;
        size_t bits = 32u * limbs;
        Stage3Case test_case;
        if (!stage3_case_init(&test_case, bits, benchmark_prng(&state)) ||
            !validate_case(&test_case)) {
            stage3_case_clear(&test_case);
            return 0;
        }
        stage3_case_clear(&test_case);
    }
    return 1;
}

static void print_result(size_t bits, const char *path, size_t iterations,
                         double samples[BENCHMARK_SAMPLES],
                         uint32_t checksum) {
    qsort(samples, BENCHMARK_SAMPLES, sizeof(samples[0]), compare_double);
    printf("stage3,mul,%zu,%s,%zu,%.3f,%u\n", bits, path, iterations,
           samples[BENCHMARK_SAMPLES / 2u], checksum);
}

static int benchmark_case(const Stage3Case *test_case, size_t iterations) {
    LiberaCBignum out;
    double samples[BENCHMARK_SAMPLES];
    uint32_t checksum = 0u;
    size_t sample, iteration;

    crypto_bignum_init(&out);
    if (crypto_bignum_mul(&out, &test_case->a, &test_case->b) !=
        LIBERAC_SUCCESS)
        goto fail;
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (crypto_bignum_mul(&out, &test_case->a, &test_case->b) !=
                LIBERAC_SUCCESS)
                goto fail;
            checksum ^= benchmark_checksum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    print_result(test_case->bits, "stage2-schoolbook", iterations,
                 samples, checksum);

    crypto_bignum_free(&out);
    crypto_bignum_init(&out);
    checksum = 0u;
    if (karatsuba_one_level(&out, &test_case->a, &test_case->b,
                            test_case->workspace,
                            test_case->workspace_words) != 0)
        goto fail;
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (karatsuba_one_level(&out, &test_case->a, &test_case->b,
                                    test_case->workspace,
                                    test_case->workspace_words) != 0)
                goto fail;
            checksum ^= benchmark_checksum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    print_result(test_case->bits, "one-level-karatsuba", iterations,
                 samples, checksum);
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
    size_t index;

    if (!randomized_validation()) {
        fputs("stage3 Karatsuba differential validation failed\n", stderr);
        return 1;
    }

    puts("stage,operation,bits,path,iterations,median_us_per_op,checksum");
    for (index = 0u; index < sizeof(bit_sizes) / sizeof(bit_sizes[0]); ++index) {
        Stage3Case test_case;
        size_t bits = bit_sizes[index];
        size_t iterations = bits <= 512u ? 1400u :
                            (bits <= 1024u ? 700u :
                             (bits <= 1536u ? 400u :
                              (bits <= 2048u ? 250u :
                               (bits <= 3072u ? 130u :
                                (bits <= 4096u ? 80u :
                                 (bits <= 6144u ? 35u : 20u))))));
        if (!stage3_case_init(&test_case, bits,
                              UINT32_C(0xb7e15162) ^ (uint32_t)bits) ||
            !validate_case(&test_case) ||
            !benchmark_case(&test_case, iterations)) {
            stage3_case_clear(&test_case);
            fputs("stage3 Karatsuba benchmark failed\n", stderr);
            return 1;
        }
        stage3_case_clear(&test_case);
    }
    return 0;
}
