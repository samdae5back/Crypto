/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Util/ECC/ecc_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef LiberaCError (*CryptoEcMultiplyFunction)(
    const CryptoEcCurve *, CryptoEcAffinePoint *,
    const CryptoEcAffinePoint *, const uint8_t *, size_t);

static volatile uint32_t crypto_ec_benchmark_sink = 0u;

static void crypto_ec_benchmark_order_minus_one(
    const CryptoEcCurve *curve, uint8_t *scalar) {
    size_t i;

    for (i = 0u; i < curve->scalar_bytes; ++i) {
        scalar[curve->scalar_bytes - 1u - i] =
            (uint8_t)(curve->order[i / 4u] >> ((i % 4u) * 8u));
    }
    for (i = curve->scalar_bytes; i > 0u; --i) {
        scalar[i - 1u] = (uint8_t)(scalar[i - 1u] - 1u);
        if (scalar[i - 1u] != UINT8_MAX) {
            break;
        }
    }
}

static double crypto_ec_benchmark_elapsed_seconds(clock_t start,
                                                  clock_t end) {
    return (double)(end - start) / (double)CLOCKS_PER_SEC;
}

static double crypto_ec_benchmark_measure(
    const CryptoEcCurve *curve, CryptoEcMultiplyFunction multiply,
    const CryptoEcAffinePoint *generator, const uint8_t *scalar,
    size_t *iterations_out) {
    CryptoEcAffinePoint result;
    size_t iterations = 1u;
    size_t i;
    clock_t start;
    clock_t end;
    double elapsed;

    do {
        start = clock();
        for (i = 0u; i < iterations; ++i) {
            if (multiply(curve, &result, generator, scalar,
                         curve->scalar_bytes) != LIBERAC_SUCCESS) {
                return -1.0;
            }
            crypto_ec_benchmark_sink ^=
                result.x.limb[i % curve->limbs] ^
                result.y.limb[(i + 1u) % curve->limbs] ^
                result.infinity;
        }
        end = clock();
        elapsed = crypto_ec_benchmark_elapsed_seconds(start, end);
        if (elapsed >= 0.12 ||
            iterations >= ((size_t)1u << 20) ||
            iterations > ((size_t)-1) / 2u) {
            break;
        }
        iterations *= 2u;
    } while (1);

    *iterations_out = iterations;
    return elapsed * 1000000000.0 / (double)iterations;
}

static int crypto_ec_benchmark_curve(CryptoEcCurveId id,
                                     const char *name) {
    const CryptoEcCurve *curve = crypto_ec_curve_get(id);
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint reference_result;
    CryptoEcAffinePoint vartime_result;
    CryptoEcAffinePoint fixed_result;
    uint8_t scalar[66u];
    size_t reference_iterations;
    size_t vartime_iterations;
    size_t fixed_iterations;
    double reference_ns;
    double vartime_ns;
    double fixed_ns;

    crypto_ec_affine_generator(curve, &generator);
    crypto_ec_benchmark_order_minus_one(curve, scalar);

    if (crypto_ec_scalar_multiply_reference(
            curve, &reference_result, &generator, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_vartime(
            curve, &vartime_result, &generator, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_ct(
            curve, &fixed_result, &generator, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS ||
        reference_result.infinity != vartime_result.infinity ||
        reference_result.infinity != fixed_result.infinity ||
        crypto_ec_field_equal_mask(
            curve, &reference_result.x,
            &vartime_result.x) != UINT32_MAX ||
        crypto_ec_field_equal_mask(
            curve, &reference_result.y,
            &vartime_result.y) != UINT32_MAX ||
        crypto_ec_field_equal_mask(
            curve, &reference_result.x,
            &fixed_result.x) != UINT32_MAX ||
        crypto_ec_field_equal_mask(
            curve, &reference_result.y,
            &fixed_result.y) != UINT32_MAX) {
        fprintf(stderr, "benchmark precondition failed for %s\n", name);
        return 0;
    }

    reference_ns = crypto_ec_benchmark_measure(
        curve, crypto_ec_scalar_multiply_reference,
        &generator, scalar, &reference_iterations);
    vartime_ns = crypto_ec_benchmark_measure(
        curve, crypto_ec_scalar_multiply_vartime,
        &generator, scalar, &vartime_iterations);
    fixed_ns = crypto_ec_benchmark_measure(
        curve, crypto_ec_scalar_multiply_ct,
        &generator, scalar, &fixed_iterations);

    if (reference_ns <= 0.0 || vartime_ns <= 0.0 || fixed_ns <= 0.0) {
        fprintf(stderr, "benchmark timing failed for %s\n", name);
        return 0;
    }

    printf("ECC_BENCH curve=%s path=reference iterations=%zu "
           "ns_per_op=%.2f\n",
           name, reference_iterations, reference_ns);
    printf("ECC_BENCH curve=%s path=vartime-window4 iterations=%zu "
           "ns_per_op=%.2f\n",
           name, vartime_iterations, vartime_ns);
    printf("ECC_BENCH curve=%s path=ct-ladder iterations=%zu "
           "ns_per_op=%.2f\n",
           name, fixed_iterations, fixed_ns);
    printf("ECC_RATIO curve=%s reference_over_vartime=%.3f "
           "reference_over_ct=%.3f ct_over_vartime=%.3f\n",
           name, reference_ns / vartime_ns,
           reference_ns / fixed_ns,
           fixed_ns / vartime_ns);
    return 1;
}

int main(void) {
    if (!crypto_ec_benchmark_curve(CRYPTO_EC_CURVE_P256, "P-256") ||
        !crypto_ec_benchmark_curve(CRYPTO_EC_CURVE_P384, "P-384") ||
        !crypto_ec_benchmark_curve(CRYPTO_EC_CURVE_P521, "P-521")) {
        return 1;
    }

    printf("ECC_BENCH sink=%u\n",
           (unsigned int)crypto_ec_benchmark_sink);
    return 0;
}
