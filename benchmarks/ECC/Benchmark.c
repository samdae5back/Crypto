/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "Util/ECC/ecc_internal.h"
#include "Reference.h"

#define BENCHMARK_SAMPLES 5u

typedef LiberaCError (*ScalarMultiplyFunction)(
    const CryptoEcCurve *, CryptoEcAffinePoint *, const CryptoEcAffinePoint *,
    const uint8_t *, size_t);

static double benchmark_cpu_microseconds(void) {
    return (double)clock() * 1000000.0 / (double)CLOCKS_PER_SEC;
}

static void scalar_from_small_subtraction(const CryptoEcCurve *curve,
                                          uint8_t *scalar,
                                          uint32_t subtract_value) {
    size_t limb_index;
    uint64_t borrow = subtract_value;

    memset(scalar, 0, curve->scalar_bytes);
    for (limb_index = 0u; limb_index < curve->limbs; ++limb_index) {
        const uint64_t order_limb = curve->order[limb_index];
        const uint64_t subtrahend = borrow & UINT32_MAX;
        const uint64_t difference = order_limb - subtrahend;
        uint32_t output_limb = (uint32_t)difference;
        size_t byte_index;

        borrow = order_limb < subtrahend;
        if (limb_index + 1u == curve->limbs &&
            (curve->scalar_bits & 31u) != 0u) {
            output_limb &= (UINT32_C(1) << (curve->scalar_bits & 31u)) - 1u;
        }
        for (byte_index = 0u; byte_index < 4u; ++byte_index) {
            const size_t absolute = limb_index * 4u + byte_index;
            if (absolute < curve->scalar_bytes) {
                scalar[curve->scalar_bytes - 1u - absolute] =
                    (uint8_t)(output_limb >> (byte_index * 8u));
            }
        }
    }
}

static uint32_t point_checksum(const CryptoEcCurve *curve,
                               const CryptoEcAffinePoint *point) {
    uint8_t encoded[1u + 2u * 66u];
    size_t encoded_length = sizeof(encoded);
    size_t index;
    uint32_t checksum = UINT32_C(2166136261);

    if (crypto_ec_point_encode(curve, point, 0, encoded, &encoded_length) !=
        LIBERAC_SUCCESS) {
        return 0u;
    }
    for (index = 0u; index < encoded_length; ++index) {
        checksum ^= encoded[index];
        checksum *= UINT32_C(16777619);
    }
    return checksum;
}

static int compare_double(const void *left, const void *right) {
    const double a = *(const double *)left;
    const double b = *(const double *)right;
    return (a > b) - (a < b);
}

static int benchmark_path(const CryptoEcCurve *curve, const char *curve_name,
                          const char *path_name,
                          ScalarMultiplyFunction multiply,
                          size_t iterations) {
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint output;
    uint8_t scalar[66];
    double samples[BENCHMARK_SAMPLES];
    uint32_t checksum = 0u;
    size_t sample;

    crypto_ec_affine_generator(curve, &generator);
    scalar_from_small_subtraction(curve, scalar, UINT32_C(0x12345));

    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        const double start = benchmark_cpu_microseconds();
        size_t iteration;
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (multiply(curve, &output, &generator, scalar,
                         curve->scalar_bytes) != LIBERAC_SUCCESS) {
                return 0;
            }
            checksum ^= point_checksum(curve, &output) + (uint32_t)iteration;
        }
        samples[sample] =
            (benchmark_cpu_microseconds() - start) / (double)iterations;
    }

    qsort(samples, BENCHMARK_SAMPLES, sizeof(samples[0]), compare_double);
    printf("%s,%s,%zu,%.3f,%u\n", curve_name, path_name, iterations,
           samples[BENCHMARK_SAMPLES / 2u], checksum);
    return 1;
}

int main(void) {
    struct CurveBenchmark {
        CryptoEcCurveId id;
        const char *name;
    } curves[] = {
        {CRYPTO_EC_CURVE_P256, "P-256"},
        {CRYPTO_EC_CURVE_P384, "P-384"},
        {CRYPTO_EC_CURVE_P521, "P-521"}
    };
    size_t curve_index;

    puts("curve,path,iterations,median_us_per_op,checksum");
    for (curve_index = 0u;
         curve_index < sizeof(curves) / sizeof(curves[0]); ++curve_index) {
        const CryptoEcCurve *curve = crypto_ec_curve_get(curves[curve_index].id);
        if (!curve ||
            !benchmark_path(curve, curves[curve_index].name, "reference-affine",
                            crypto_ec_scalar_multiply_reference, 1u) ||
            !benchmark_path(curve, curves[curve_index].name,
                            "window4-jacobian-vartime",
                            crypto_ec_scalar_multiply_vartime, 20u) ||
            !benchmark_path(curve, curves[curve_index].name,
                            "ladder-jacobian-fixed", crypto_ec_scalar_multiply_ct,
                            10u)) {
            return 1;
        }
    }
    return 0;
}
