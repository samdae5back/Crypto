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
} Stage2Case;

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

/* Exact Stage-1 allocating add path. */
static int stage1_add(LiberaCBignum *out, const LiberaCBignum *a,
                      const LiberaCBignum *b) {
    LiberaCBignum tmp;
    size_t n, i;
    uint64_t carry = 0u;
    if (!out || !a || !b) return -1;
    crypto_bignum_init(&tmp);
    n = a->LENGTH > b->LENGTH ? a->LENGTH : b->LENGTH;
    if (n == SIZE_MAX || bignum_reserve(&tmp, n + 1u) != 0)
        goto fail;
    for (i = 0u; i < n; ++i) {
        uint64_t av = i < a->LENGTH ? a->LIMBS[i] : 0u;
        uint64_t bv = i < b->LENGTH ? b->LIMBS[i] : 0u;
        uint64_t sum = av + bv + carry;
        tmp.LIMBS[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    if (carry != 0u)
        tmp.LIMBS[n++] = (uint32_t)carry;
    tmp.LENGTH = n;
    crypto_bignum_free(out);
    *out = tmp;
    return 0;
fail:
    crypto_bignum_free(&tmp);
    return -1;
}

/* Exact Stage-1 allocating subtract path. */
static int stage1_sub(LiberaCBignum *out, const LiberaCBignum *a,
                      const LiberaCBignum *b) {
    LiberaCBignum tmp;
    size_t i;
    uint64_t borrow = 0u;
    if (!out || !a || !b || crypto_bignum_compare(a, b) < 0)
        return -1;
    crypto_bignum_init(&tmp);
    if (bignum_reserve(&tmp, a->LENGTH) != 0)
        goto fail;
    for (i = 0u; i < a->LENGTH; ++i) {
        uint64_t av = a->LIMBS[i];
        uint64_t bv = (i < b->LENGTH ? b->LIMBS[i] : 0u) + borrow;
        tmp.LIMBS[i] = (uint32_t)(av - bv);
        borrow = av < bv;
    }
    tmp.LENGTH = a->LENGTH;
    bignum_normalize(&tmp);
    crypto_bignum_free(out);
    *out = tmp;
    return 0;
fail:
    crypto_bignum_free(&tmp);
    return -1;
}

/* Exact Stage-1 generic schoolbook multiply: a fresh temporary, one extra
 * result limb, and a carry-propagation loop after every input row. */
static int stage1_mul(LiberaCBignum *out, const LiberaCBignum *a,
                      const LiberaCBignum *b) {
    LiberaCBignum tmp;
    size_t i, j, n;
    if (!out || !a || !b) return -1;
    crypto_bignum_init(&tmp);
    if (a->LENGTH == 0u || b->LENGTH == 0u) {
        crypto_bignum_free(out);
        *out = tmp;
        return 0;
    }
    if (a->LENGTH > SIZE_MAX - b->LENGTH - 1u)
        goto fail;
    n = a->LENGTH + b->LENGTH + 1u;
    if (bignum_reserve(&tmp, n) != 0)
        goto fail;
    memset(tmp.LIMBS, 0, n * sizeof(uint32_t));
    for (i = 0u; i < a->LENGTH; ++i) {
        uint64_t carry = 0u;
        for (j = 0u; j < b->LENGTH; ++j) {
            size_t k = i + j;
            uint64_t current = (uint64_t)a->LIMBS[i] * b->LIMBS[j] +
                               tmp.LIMBS[k] + carry;
            tmp.LIMBS[k] = (uint32_t)current;
            carry = current >> 32;
        }
        j = i + b->LENGTH;
        while (carry != 0u) {
            uint64_t current = (uint64_t)tmp.LIMBS[j] + carry;
            tmp.LIMBS[j] = (uint32_t)current;
            carry = current >> 32;
            ++j;
        }
    }
    tmp.LENGTH = n;
    bignum_normalize(&tmp);
    crypto_bignum_free(out);
    *out = tmp;
    return 0;
fail:
    crypto_bignum_free(&tmp);
    return -1;
}

static int stage1_square_add_product(uint32_t *limbs, size_t limb_count,
                                     size_t offset, uint64_t product) {
    uint64_t sum, carry;
    if (!limbs || offset >= limb_count) return -1;
    sum = (uint64_t)limbs[offset] + (uint32_t)product;
    limbs[offset] = (uint32_t)sum;
    carry = (product >> 32) + (sum >> 32);
    ++offset;
    while (carry != 0u && offset < limb_count) {
        sum = (uint64_t)limbs[offset] + (uint32_t)carry;
        limbs[offset] = (uint32_t)sum;
        carry = (carry >> 32) + (sum >> 32);
        ++offset;
    }
    return carry == 0u ? 0 : -1;
}

/* Exact Stage-1 square path: one fresh temporary and two generic accumulation
 * calls for every symmetric cross product. */
static int stage1_square(LiberaCBignum *out, const LiberaCBignum *a) {
    LiberaCBignum tmp;
    size_t n, i, j, limbs;
    if (!out || !a) return -1;
    crypto_bignum_init(&tmp);
    n = a->LENGTH;
    if (n == 0u) {
        crypto_bignum_free(out);
        *out = tmp;
        return 0;
    }
    if (n > (SIZE_MAX - 1u) / 2u)
        goto fail;
    limbs = 2u * n + 1u;
    if (bignum_reserve(&tmp, limbs) != 0)
        goto fail;
    memset(tmp.LIMBS, 0, limbs * sizeof(uint32_t));
    for (i = 0u; i < n; ++i) {
        uint64_t diagonal = (uint64_t)a->LIMBS[i] * a->LIMBS[i];
        if (stage1_square_add_product(tmp.LIMBS, limbs, 2u * i,
                                      diagonal) != 0)
            goto fail;
        for (j = i + 1u; j < n; ++j) {
            uint64_t cross = (uint64_t)a->LIMBS[i] * a->LIMBS[j];
            if (stage1_square_add_product(tmp.LIMBS, limbs, i + j,
                                          cross) != 0 ||
                stage1_square_add_product(tmp.LIMBS, limbs, i + j,
                                          cross) != 0)
                goto fail;
        }
    }
    tmp.LENGTH = limbs;
    bignum_normalize(&tmp);
    crypto_bignum_free(out);
    *out = tmp;
    return 0;
fail:
    crypto_bignum_free(&tmp);
    return -1;
}

static int stage2_case_init(Stage2Case *test_case, size_t bits,
                            uint32_t seed) {
    size_t bytes = bits / 8u;
    uint8_t *a_bytes = NULL, *b_bytes = NULL;
    uint32_t state = seed;
    LiberaCBignum swap;
    int ok = 0;

    if (!test_case || bits == 0u || (bits & 7u) != 0u)
        return 0;
    memset(test_case, 0, sizeof(*test_case));
    test_case->bits = bits;
    crypto_bignum_init(&test_case->a);
    crypto_bignum_init(&test_case->b);
    crypto_bignum_init(&swap);

    a_bytes = (uint8_t *)malloc(bytes);
    b_bytes = (uint8_t *)malloc(bytes);
    if (!a_bytes || !b_bytes)
        goto done;
    benchmark_fill(a_bytes, bytes, &state);
    benchmark_fill(b_bytes, bytes, &state);
    a_bytes[0] |= UINT8_C(0x80);
    b_bytes[0] |= UINT8_C(0x40);

    if (crypto_bignum_from_bytes_be(&test_case->a, a_bytes, bytes) !=
            LIBERAC_SUCCESS ||
        crypto_bignum_from_bytes_be(&test_case->b, b_bytes, bytes) !=
            LIBERAC_SUCCESS)
        goto done;
    if (crypto_bignum_compare(&test_case->a, &test_case->b) < 0) {
        swap = test_case->a;
        test_case->a = test_case->b;
        test_case->b = swap;
        crypto_bignum_init(&swap);
    }
    ok = 1;

done:
    free(a_bytes);
    free(b_bytes);
    crypto_bignum_free(&swap);
    return ok;
}

static void stage2_case_clear(Stage2Case *test_case) {
    if (!test_case) return;
    crypto_bignum_free(&test_case->a);
    crypto_bignum_free(&test_case->b);
}

static int validate_one_case(const Stage2Case *test_case) {
    LiberaCBignum reference, optimized, alias;
    int ok = 0;
    crypto_bignum_init(&reference);
    crypto_bignum_init(&optimized);
    crypto_bignum_init(&alias);

    if (stage1_add(&reference, &test_case->a, &test_case->b) != 0 ||
        crypto_bignum_add(&optimized, &test_case->a, &test_case->b) !=
            LIBERAC_SUCCESS ||
        !bignum_equal(&reference, &optimized))
        goto done;
    if (crypto_bignum_copy(&alias, &test_case->a) != LIBERAC_SUCCESS ||
        crypto_bignum_add(&alias, &alias, &test_case->b) != LIBERAC_SUCCESS ||
        !bignum_equal(&reference, &alias))
        goto done;

    if (stage1_sub(&reference, &test_case->a, &test_case->b) != 0 ||
        crypto_bignum_sub(&optimized, &test_case->a, &test_case->b) !=
            LIBERAC_SUCCESS ||
        !bignum_equal(&reference, &optimized))
        goto done;
    if (crypto_bignum_copy(&alias, &test_case->a) != LIBERAC_SUCCESS ||
        crypto_bignum_sub(&alias, &alias, &test_case->b) != LIBERAC_SUCCESS ||
        !bignum_equal(&reference, &alias))
        goto done;

    if (stage1_mul(&reference, &test_case->a, &test_case->b) != 0 ||
        crypto_bignum_mul(&optimized, &test_case->a, &test_case->b) !=
            LIBERAC_SUCCESS ||
        !bignum_equal(&reference, &optimized))
        goto done;
    if (crypto_bignum_copy(&alias, &test_case->a) != LIBERAC_SUCCESS ||
        crypto_bignum_mul(&alias, &alias, &test_case->b) != LIBERAC_SUCCESS ||
        !bignum_equal(&reference, &alias))
        goto done;

    if (stage1_square(&reference, &test_case->a) != 0 ||
        crypto_bignum_square(&optimized, &test_case->a) != LIBERAC_SUCCESS ||
        !bignum_equal(&reference, &optimized))
        goto done;
    if (crypto_bignum_copy(&alias, &test_case->a) != LIBERAC_SUCCESS ||
        crypto_bignum_square(&alias, &alias) != LIBERAC_SUCCESS ||
        !bignum_equal(&reference, &alias))
        goto done;

    ok = 1;
done:
    crypto_bignum_free(&reference);
    crypto_bignum_free(&optimized);
    crypto_bignum_free(&alias);
    return ok;
}

static int randomized_validation(void) {
    uint32_t state = UINT32_C(0x8f3c2a17);
    size_t index;
    for (index = 0u; index < 120u; ++index) {
        Stage2Case test_case;
        size_t bits = 32u * (1u + index % 80u);
        if (!stage2_case_init(&test_case, bits, benchmark_prng(&state)) ||
            !validate_one_case(&test_case)) {
            stage2_case_clear(&test_case);
            return 0;
        }
        stage2_case_clear(&test_case);
    }
    return 1;
}

static void print_result(const char *operation, size_t bits, const char *path,
                         size_t iterations,
                         double samples[BENCHMARK_SAMPLES],
                         uint32_t checksum) {
    qsort(samples, BENCHMARK_SAMPLES, sizeof(samples[0]), compare_double);
    printf("stage2,%s,%zu,%s,%zu,%.3f,%u\n", operation, bits, path,
           iterations, samples[BENCHMARK_SAMPLES / 2u], checksum);
}

typedef int (*BinaryOperation)(LiberaCBignum *, const LiberaCBignum *,
                               const LiberaCBignum *);

static int current_add_adapter(LiberaCBignum *out, const LiberaCBignum *a,
                               const LiberaCBignum *b) {
    return crypto_bignum_add(out, a, b) == LIBERAC_SUCCESS ? 0 : -1;
}

static int current_sub_adapter(LiberaCBignum *out, const LiberaCBignum *a,
                               const LiberaCBignum *b) {
    return crypto_bignum_sub(out, a, b) == LIBERAC_SUCCESS ? 0 : -1;
}

static int current_mul_adapter(LiberaCBignum *out, const LiberaCBignum *a,
                               const LiberaCBignum *b) {
    return crypto_bignum_mul(out, a, b) == LIBERAC_SUCCESS ? 0 : -1;
}

static int benchmark_binary_pair(const Stage2Case *test_case,
                                 const char *operation,
                                 BinaryOperation reference,
                                 BinaryOperation optimized,
                                 size_t iterations) {
    double samples[BENCHMARK_SAMPLES];
    LiberaCBignum out;
    uint32_t checksum = 0u;
    size_t sample, iteration;

    crypto_bignum_init(&out);
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (reference(&out, &test_case->a, &test_case->b) != 0)
                goto fail;
            checksum ^= benchmark_checksum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    print_result(operation, test_case->bits, "stage1-allocating", iterations,
                 samples, checksum);

    crypto_bignum_free(&out);
    crypto_bignum_init(&out);
    checksum = 0u;
    if (optimized(&out, &test_case->a, &test_case->b) != 0)
        goto fail;
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (optimized(&out, &test_case->a, &test_case->b) != 0)
                goto fail;
            checksum ^= benchmark_checksum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    print_result(operation, test_case->bits, "stage2-reuse", iterations,
                 samples, checksum);
    crypto_bignum_free(&out);
    return 1;

fail:
    crypto_bignum_free(&out);
    return 0;
}

static int benchmark_square_pair(const Stage2Case *test_case,
                                 size_t iterations) {
    double samples[BENCHMARK_SAMPLES];
    LiberaCBignum out;
    uint32_t checksum = 0u;
    size_t sample, iteration;

    crypto_bignum_init(&out);
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (stage1_square(&out, &test_case->a) != 0)
                goto fail;
            checksum ^= benchmark_checksum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    print_result("square", test_case->bits, "stage1-double-add", iterations,
                 samples, checksum);

    crypto_bignum_free(&out);
    crypto_bignum_init(&out);
    checksum = 0u;
    if (crypto_bignum_square(&out, &test_case->a) != LIBERAC_SUCCESS)
        goto fail;
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (crypto_bignum_square(&out, &test_case->a) != LIBERAC_SUCCESS)
                goto fail;
            checksum ^= benchmark_checksum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    print_result("square", test_case->bits, "stage2-double-product", iterations,
                 samples, checksum);
    crypto_bignum_free(&out);
    return 1;

fail:
    crypto_bignum_free(&out);
    return 0;
}

int main(void) {
    static const size_t bit_sizes[] = {1024u, 2048u, 3072u, 4096u};
    size_t index;

    if (!randomized_validation()) {
        fputs("stage2 bignum differential validation failed\n", stderr);
        return 1;
    }

    puts("stage,operation,bits,path,iterations,median_us_per_op,checksum");
    for (index = 0u; index < sizeof(bit_sizes) / sizeof(bit_sizes[0]); ++index) {
        Stage2Case test_case;
        size_t bits = bit_sizes[index];
        size_t linear_iterations = bits <= 1024u ? 3000u :
                                   (bits <= 2048u ? 1500u :
                                    (bits <= 3072u ? 900u : 600u));
        size_t quadratic_iterations = bits <= 1024u ? 600u :
                                      (bits <= 2048u ? 250u :
                                       (bits <= 3072u ? 120u : 70u));

        if (!stage2_case_init(&test_case, bits,
                              UINT32_C(0x517cc1b7) ^ (uint32_t)bits) ||
            !validate_one_case(&test_case) ||
            !benchmark_binary_pair(&test_case, "add", stage1_add,
                                   current_add_adapter, linear_iterations) ||
            !benchmark_binary_pair(&test_case, "sub", stage1_sub,
                                   current_sub_adapter, linear_iterations) ||
            !benchmark_binary_pair(&test_case, "mul", stage1_mul,
                                   current_mul_adapter,
                                   quadratic_iterations) ||
            !benchmark_square_pair(&test_case, quadratic_iterations)) {
            stage2_case_clear(&test_case);
            fputs("stage2 bignum benchmark failed\n", stderr);
            return 1;
        }
        stage2_case_clear(&test_case);
    }
    return 0;
}
