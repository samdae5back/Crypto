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
#include "Util/Bignum/bignum_montgomery.h"

#define BENCHMARK_SAMPLES 5u

typedef struct {
    size_t bits;
    LiberaCBignum numerator;
    LiberaCBignum modulus;
    LiberaCBignum a;
    LiberaCBignum b;
} BignumBenchmarkCase;

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

static uint32_t benchmark_checksum_words(const uint32_t *words, size_t count) {
    uint32_t checksum = UINT32_C(2166136261);
    size_t i;
    for (i = 0u; i < count; ++i) {
        checksum ^= words[i];
        checksum *= UINT32_C(16777619);
    }
    return checksum;
}

static uint32_t benchmark_checksum_bignum(const LiberaCBignum *value) {
    return benchmark_checksum_words(value->LIMBS, value->LENGTH);
}

static int benchmark_bignum_equal(const LiberaCBignum *a,
                                  const LiberaCBignum *b) {
    return crypto_bignum_compare(a, b) == 0;
}

/* Exact pre-stage-1 reduction shape retained only in the benchmark. */
static int benchmark_mod_bitwise(LiberaCBignum *out,
                                 const LiberaCBignum *a,
                                 const LiberaCBignum *modulus) {
    LiberaCBignum r, tmp;
    size_t bits, i;

    if (!out || !a || !modulus || modulus->LENGTH == 0u)
        return -1;
    if (crypto_bignum_compare(a, modulus) < 0)
        return crypto_bignum_copy(out, a);

    crypto_bignum_init(&r);
    crypto_bignum_init(&tmp);
    bits = crypto_bignum_bit_length(a);
    for (i = bits; i > 0u; --i) {
        if (bignum_shift_left_one(&r) != 0)
            goto fail;
        if (bignum_get_bit(a, i - 1u) && bignum_add_u32(&r, 1u) != 0)
            goto fail;
        if (crypto_bignum_compare(&r, modulus) >= 0) {
            if (crypto_bignum_sub(&tmp, &r, modulus) != LIBERAC_SUCCESS)
                goto fail;
            crypto_bignum_free(&r);
            r = tmp;
            crypto_bignum_init(&tmp);
        }
    }
    crypto_bignum_free(out);
    *out = r;
    crypto_bignum_init(&r);
    crypto_bignum_free(&tmp);
    return 0;

fail:
    crypto_bignum_free(&r);
    crypto_bignum_free(&tmp);
    return -1;
}

static int benchmark_mod_mul_bitwise(LiberaCBignum *out,
                                     const LiberaCBignum *a,
                                     const LiberaCBignum *b,
                                     const LiberaCBignum *modulus) {
    LiberaCBignum product;
    int rc;
    crypto_bignum_init(&product);
    if (crypto_bignum_mul(&product, a, b) != LIBERAC_SUCCESS)
        return -1;
    rc = benchmark_mod_bitwise(out, &product, modulus);
    crypto_bignum_free(&product);
    return rc;
}

/* Exact pre-stage-1 R^2 setup: 64*n bignum doublings with conditional
 * subtraction. */
static int benchmark_r2_doubling(uint32_t *r2, size_t n,
                                 const LiberaCBignum *modulus) {
    LiberaCBignum x, reduced;
    size_t rounds, i;

    if (!r2 || !modulus || n == 0u || modulus->LENGTH != n ||
        n > SIZE_MAX / 64u)
        return -1;
    crypto_bignum_init(&x);
    crypto_bignum_init(&reduced);
    if (crypto_bignum_set_u64(&x, 1u) != LIBERAC_SUCCESS)
        goto fail;
    rounds = 64u * n;
    for (i = 0u; i < rounds; ++i) {
        if (bignum_shift_left_one(&x) != 0)
            goto fail;
        if (crypto_bignum_compare(&x, modulus) >= 0) {
            if (crypto_bignum_sub(&reduced, &x, modulus) != LIBERAC_SUCCESS)
                goto fail;
            crypto_bignum_free(&x);
            x = reduced;
            crypto_bignum_init(&reduced);
        }
    }
    if (x.LENGTH > n)
        goto fail;
    memset(r2, 0, n * sizeof(uint32_t));
    if (x.LENGTH != 0u)
        memcpy(r2, x.LIMBS, x.LENGTH * sizeof(uint32_t));
    crypto_bignum_free(&x);
    crypto_bignum_free(&reduced);
    return 0;

fail:
    crypto_bignum_free(&x);
    crypto_bignum_free(&reduced);
    return -1;
}

/* Exact pre-stage-1 CIOS core, including the n+1-limb shift after every outer
 * iteration.  It leaves the same unreduced candidate shape as the new core. */
static int benchmark_mont_cios_shift(uint32_t *work,
                                     const uint32_t *a,
                                     const uint32_t *b,
                                     const uint32_t *modulus,
                                     size_t n, uint32_t n0inv) {
    size_t i, j;
    if (!work || !a || !b || !modulus || n == 0u)
        return -1;
    memset(work, 0, (n + 2u) * sizeof(uint32_t));

    for (i = 0u; i < n; ++i) {
        uint64_t carry = 0u;
        for (j = 0u; j < n; ++j) {
            uint64_t z = (uint64_t)a[j] * b[i] + work[j] + carry;
            work[j] = (uint32_t)z;
            carry = z >> 32;
        }
        {
            uint64_t z = (uint64_t)work[n] + carry;
            work[n] = (uint32_t)z;
            work[n + 1u] += (uint32_t)(z >> 32);
        }

        {
            uint32_t m = work[0] * n0inv;
            carry = 0u;
            for (j = 0u; j < n; ++j) {
                uint64_t z = (uint64_t)m * modulus[j] + work[j] + carry;
                work[j] = (uint32_t)z;
                carry = z >> 32;
            }
            {
                uint64_t z = (uint64_t)work[n] + carry;
                work[n] = (uint32_t)z;
                work[n + 1u] += (uint32_t)(z >> 32);
            }
        }

        for (j = 0u; j <= n; ++j)
            work[j] = work[j + 1u];
        work[n + 1u] = 0u;
    }
    return 0;
}

static int benchmark_case_init(BignumBenchmarkCase *test_case, size_t bits,
                               uint32_t seed) {
    uint8_t *modulus_bytes = NULL, *numerator_bytes = NULL;
    uint8_t *a_bytes = NULL, *b_bytes = NULL;
    size_t bytes = bits / 8u;
    uint32_t state = seed;
    int ok = 0;

    if (!test_case || bits == 0u || (bits & 7u) != 0u)
        return 0;
    memset(test_case, 0, sizeof(*test_case));
    test_case->bits = bits;
    crypto_bignum_init(&test_case->numerator);
    crypto_bignum_init(&test_case->modulus);
    crypto_bignum_init(&test_case->a);
    crypto_bignum_init(&test_case->b);

    modulus_bytes = (uint8_t *)malloc(bytes);
    numerator_bytes = (uint8_t *)malloc(2u * bytes);
    a_bytes = (uint8_t *)malloc(bytes);
    b_bytes = (uint8_t *)malloc(bytes);
    if (!modulus_bytes || !numerator_bytes || !a_bytes || !b_bytes)
        goto done;

    benchmark_fill(modulus_bytes, bytes, &state);
    benchmark_fill(numerator_bytes, 2u * bytes, &state);
    benchmark_fill(a_bytes, bytes, &state);
    benchmark_fill(b_bytes, bytes, &state);
    modulus_bytes[0] |= UINT8_C(0x80);
    modulus_bytes[bytes - 1u] |= UINT8_C(0x01);
    numerator_bytes[0] |= UINT8_C(0x80);

    if (crypto_bignum_from_bytes_be(&test_case->modulus, modulus_bytes, bytes) !=
            LIBERAC_SUCCESS ||
        crypto_bignum_from_bytes_be(&test_case->numerator, numerator_bytes,
                                    2u * bytes) != LIBERAC_SUCCESS ||
        crypto_bignum_from_bytes_be(&test_case->a, a_bytes, bytes) !=
            LIBERAC_SUCCESS ||
        crypto_bignum_from_bytes_be(&test_case->b, b_bytes, bytes) !=
            LIBERAC_SUCCESS ||
        crypto_bignum_mod(&test_case->a, &test_case->a,
                          &test_case->modulus) != LIBERAC_SUCCESS ||
        crypto_bignum_mod(&test_case->b, &test_case->b,
                          &test_case->modulus) != LIBERAC_SUCCESS)
        goto done;
    ok = 1;

done:
    free(modulus_bytes);
    free(numerator_bytes);
    free(a_bytes);
    free(b_bytes);
    return ok;
}

static void benchmark_case_clear(BignumBenchmarkCase *test_case) {
    if (!test_case) return;
    crypto_bignum_free(&test_case->numerator);
    crypto_bignum_free(&test_case->modulus);
    crypto_bignum_free(&test_case->a);
    crypto_bignum_free(&test_case->b);
}

static int benchmark_validate_mod(const BignumBenchmarkCase *test_case) {
    LiberaCBignum reference, optimized;
    int ok;
    crypto_bignum_init(&reference);
    crypto_bignum_init(&optimized);
    ok = benchmark_mod_bitwise(&reference, &test_case->numerator,
                               &test_case->modulus) == 0 &&
         crypto_bignum_mod(&optimized, &test_case->numerator,
                           &test_case->modulus) == LIBERAC_SUCCESS &&
         benchmark_bignum_equal(&reference, &optimized) &&
         benchmark_mod_mul_bitwise(&reference, &test_case->a, &test_case->b,
                                   &test_case->modulus) == 0 &&
         crypto_bignum_mod_mul(&optimized, &test_case->a, &test_case->b,
                               &test_case->modulus) == LIBERAC_SUCCESS &&
         benchmark_bignum_equal(&reference, &optimized);
    crypto_bignum_free(&reference);
    crypto_bignum_free(&optimized);
    return ok;
}

static int benchmark_validate_montgomery(const BignumBenchmarkCase *test_case) {
    size_t n = test_case->modulus.LENGTH;
    size_t words;
    uint32_t *buffer;
    uint32_t *a, *b, *old_work, *new_work, *old_r2, *new_r2;
    uint32_t n0inv;
    int ok;

    if (n == 0u || n > SIZE_MAX / 6u)
        return 0;
    words = 6u * n + 4u;
    buffer = (uint32_t *)calloc(words, sizeof(uint32_t));
    if (!buffer)
        return 0;
    a = buffer;
    b = a + n;
    old_work = b + n;
    new_work = old_work + n + 2u;
    old_r2 = new_work + n + 2u;
    new_r2 = old_r2 + n;

    memcpy(a, test_case->a.LIMBS,
           test_case->a.LENGTH * sizeof(uint32_t));
    memcpy(b, test_case->b.LIMBS,
           test_case->b.LENGTH * sizeof(uint32_t));
    n0inv = bignum_mont_n0inv(test_case->modulus.LIMBS[0]);

    ok = benchmark_mont_cios_shift(old_work, a, b,
                                   test_case->modulus.LIMBS, n, n0inv) == 0 &&
         bignum_mont_cios_candidate(new_work, a, n, b, n,
                                    test_case->modulus.LIMBS, n, n0inv) == 0 &&
         memcmp(old_work, new_work, (n + 1u) * sizeof(uint32_t)) == 0 &&
         benchmark_r2_doubling(old_r2, n, &test_case->modulus) == 0 &&
         bignum_mont_compute_r2_words(new_r2, n, &test_case->modulus) == 0 &&
         memcmp(old_r2, new_r2, n * sizeof(uint32_t)) == 0;
    free(buffer);
    return ok;
}

static int benchmark_randomized_reduction_validation(void) {
    uint32_t state = UINT32_C(0x6d5a56e9);
    size_t case_index;
    for (case_index = 0u; case_index < 80u; ++case_index) {
        size_t bits = 64u + 32u * (case_index % 31u);
        BignumBenchmarkCase test_case;
        if (!benchmark_case_init(&test_case, bits,
                                 benchmark_prng(&state)) ||
            !benchmark_validate_mod(&test_case)) {
            benchmark_case_clear(&test_case);
            return 0;
        }
        benchmark_case_clear(&test_case);
    }
    return 1;
}

static void benchmark_print(const char *operation, size_t bits,
                            const char *path, size_t iterations,
                            double samples[BENCHMARK_SAMPLES],
                            uint32_t checksum) {
    qsort(samples, BENCHMARK_SAMPLES, sizeof(samples[0]), compare_double);
    printf("stage1,%s,%zu,%s,%zu,%.3f,%u\n", operation, bits, path,
           iterations, samples[BENCHMARK_SAMPLES / 2u], checksum);
}

static int benchmark_reduction_paths(const BignumBenchmarkCase *test_case,
                                     size_t iterations) {
    double samples[BENCHMARK_SAMPLES];
    LiberaCBignum out;
    uint32_t checksum = 0u;
    size_t sample, iteration;

    crypto_bignum_init(&out);
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (benchmark_mod_bitwise(&out, &test_case->numerator,
                                      &test_case->modulus) != 0)
                goto fail;
            checksum ^= benchmark_checksum_bignum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    benchmark_print("mod-2x", test_case->bits, "bitwise-reference",
                    iterations, samples, checksum);

    checksum = 0u;
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (crypto_bignum_mod(&out, &test_case->numerator,
                                  &test_case->modulus) != LIBERAC_SUCCESS)
                goto fail;
            checksum ^= benchmark_checksum_bignum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    benchmark_print("mod-2x", test_case->bits, "normalized-word",
                    iterations, samples, checksum);
    crypto_bignum_free(&out);
    return 1;

fail:
    crypto_bignum_free(&out);
    return 0;
}

static int benchmark_mod_mul_paths(const BignumBenchmarkCase *test_case,
                                   size_t iterations) {
    double samples[BENCHMARK_SAMPLES];
    LiberaCBignum out;
    uint32_t checksum = 0u;
    size_t sample, iteration;

    crypto_bignum_init(&out);
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (benchmark_mod_mul_bitwise(&out, &test_case->a, &test_case->b,
                                          &test_case->modulus) != 0)
                goto fail;
            checksum ^= benchmark_checksum_bignum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    benchmark_print("mod-mul", test_case->bits, "multiply-bitwise-mod",
                    iterations, samples, checksum);

    checksum = 0u;
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (crypto_bignum_mod_mul(&out, &test_case->a, &test_case->b,
                                      &test_case->modulus) != LIBERAC_SUCCESS)
                goto fail;
            checksum ^= benchmark_checksum_bignum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    benchmark_print("mod-mul", test_case->bits, "multiply-word-mod",
                    iterations, samples, checksum);
    crypto_bignum_free(&out);
    return 1;

fail:
    crypto_bignum_free(&out);
    return 0;
}

static int benchmark_r2_paths(const BignumBenchmarkCase *test_case,
                              size_t iterations) {
    double samples[BENCHMARK_SAMPLES];
    size_t n = test_case->modulus.LENGTH;
    uint32_t *r2 = (uint32_t *)calloc(n, sizeof(uint32_t));
    uint32_t checksum = 0u;
    size_t sample, iteration;
    if (!r2)
        return 0;

    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (benchmark_r2_doubling(r2, n, &test_case->modulus) != 0)
                goto fail;
            checksum ^= benchmark_checksum_words(r2, n) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    benchmark_print("mont-r2-setup", test_case->bits, "doubling-reference",
                    iterations, samples, checksum);

    checksum = 0u;
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (bignum_mont_compute_r2_words(r2, n,
                                             &test_case->modulus) != 0)
                goto fail;
            checksum ^= benchmark_checksum_words(r2, n) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    benchmark_print("mont-r2-setup", test_case->bits, "direct-word-reduction",
                    iterations, samples, checksum);
    free(r2);
    return 1;

fail:
    free(r2);
    return 0;
}

static int benchmark_cios_paths(const BignumBenchmarkCase *test_case,
                                size_t iterations) {
    double samples[BENCHMARK_SAMPLES];
    size_t n = test_case->modulus.LENGTH;
    size_t words = 4u * n + 4u;
    uint32_t *buffer = (uint32_t *)calloc(words, sizeof(uint32_t));
    uint32_t *a, *b, *work;
    uint32_t n0inv, checksum = 0u;
    size_t sample, iteration;
    if (!buffer)
        return 0;
    a = buffer;
    b = a + n;
    work = b + n;
    memcpy(a, test_case->a.LIMBS,
           test_case->a.LENGTH * sizeof(uint32_t));
    memcpy(b, test_case->b.LIMBS,
           test_case->b.LENGTH * sizeof(uint32_t));
    n0inv = bignum_mont_n0inv(test_case->modulus.LIMBS[0]);

    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (benchmark_mont_cios_shift(work, a, b,
                                          test_case->modulus.LIMBS,
                                          n, n0inv) != 0)
                goto fail;
            checksum ^= benchmark_checksum_words(work, n + 1u) +
                        (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    benchmark_print("mont-cios-core", test_case->bits, "shift-reference",
                    iterations, samples, checksum);

    checksum = 0u;
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (bignum_mont_cios_candidate(work, a, n, b, n,
                                            test_case->modulus.LIMBS, n,
                                            n0inv) != 0)
                goto fail;
            checksum ^= benchmark_checksum_words(work, n + 1u) +
                        (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    benchmark_print("mont-cios-core", test_case->bits, "integrated-shift",
                    iterations, samples, checksum);
    free(buffer);
    return 1;

fail:
    free(buffer);
    return 0;
}

int main(void) {
    static const size_t bit_sizes[] = {2048u, 3072u, 4096u};
    size_t index;

    if (!benchmark_randomized_reduction_validation()) {
        fputs("stage1 randomized reduction differential validation failed\n",
              stderr);
        return 1;
    }

    puts("stage,operation,bits,path,iterations,median_us_per_op,checksum");
    for (index = 0u; index < sizeof(bit_sizes) / sizeof(bit_sizes[0]); ++index) {
        BignumBenchmarkCase test_case;
        size_t bits = bit_sizes[index];
        size_t slow_iterations = bits <= 2048u ? 2u : 1u;
        size_t cios_iterations = bits <= 2048u ? 400u :
                                 (bits <= 3072u ? 200u : 100u);

        if (!benchmark_case_init(&test_case, bits,
                                 UINT32_C(0x9e3779b9) ^ (uint32_t)bits) ||
            !benchmark_validate_mod(&test_case) ||
            !benchmark_validate_montgomery(&test_case) ||
            !benchmark_reduction_paths(&test_case, slow_iterations) ||
            !benchmark_mod_mul_paths(&test_case, slow_iterations) ||
            !benchmark_r2_paths(&test_case, slow_iterations) ||
            !benchmark_cios_paths(&test_case, cios_iterations)) {
            benchmark_case_clear(&test_case);
            fputs("stage1 bignum benchmark validation failed\n", stderr);
            return 1;
        }
        benchmark_case_clear(&test_case);
    }
    return 0;
}
