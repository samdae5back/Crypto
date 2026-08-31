/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "ecc_internal.h"

#include <string.h>

static void crypto_ec_reference_three_times(
    const CryptoEcCurve *curve, CryptoEcFieldElement *out,
    const CryptoEcFieldElement *in) {
    CryptoEcFieldElement twice;

    crypto_ec_field_add(curve, &twice, in, in);
    crypto_ec_field_add(curve, out, &twice, in);
}

static void crypto_ec_affine_double_reference(
    const CryptoEcCurve *curve, CryptoEcAffinePoint *out,
    const CryptoEcAffinePoint *point) {
    CryptoEcAffinePoint result;
    CryptoEcFieldElement one;
    CryptoEcFieldElement numerator;
    CryptoEcFieldElement denominator;
    CryptoEcFieldElement inverse;
    CryptoEcFieldElement slope;
    CryptoEcFieldElement temporary;

    if (point->infinity != 0u ||
        crypto_ec_field_zero_mask(curve, &point->y) == UINT32_MAX) {
        crypto_ec_affine_set_infinity(out);
        return;
    }

    /*
     * Textbook affine formula for a = -3:
     *   lambda = 3*(x^2 - 1)/(2*y)
     *   x3 = lambda^2 - 2*x
     *   y3 = lambda*(x - x3) - y
     *
     * This deliberately performs a field inversion per doubling.  It is kept
     * as a simple, independently shaped reference path rather than a fast or
     * secret-scalar implementation.
     */
    crypto_ec_field_square(curve, &numerator, &point->x);
    crypto_ec_field_one(curve, &one);
    crypto_ec_field_sub(curve, &numerator, &numerator, &one);
    crypto_ec_reference_three_times(curve, &numerator, &numerator);
    crypto_ec_field_add(curve, &denominator, &point->y, &point->y);
    crypto_ec_field_invert_fixed(curve, &inverse, &denominator);
    crypto_ec_field_multiply(curve, &slope, &numerator, &inverse);

    crypto_ec_field_square(curve, &result.x, &slope);
    crypto_ec_field_add(curve, &temporary, &point->x, &point->x);
    crypto_ec_field_sub(curve, &result.x, &result.x, &temporary);
    crypto_ec_field_sub(curve, &temporary, &point->x, &result.x);
    crypto_ec_field_multiply(curve, &result.y, &slope, &temporary);
    crypto_ec_field_sub(curve, &result.y, &result.y, &point->y);
    result.infinity = 0u;

    memcpy(out, &result, sizeof(result));
}

static void crypto_ec_affine_add_reference(
    const CryptoEcCurve *curve, CryptoEcAffinePoint *out,
    const CryptoEcAffinePoint *a, const CryptoEcAffinePoint *b) {
    CryptoEcAffinePoint result;
    CryptoEcFieldElement numerator;
    CryptoEcFieldElement denominator;
    CryptoEcFieldElement inverse;
    CryptoEcFieldElement slope;
    CryptoEcFieldElement temporary;

    if (a->infinity != 0u) {
        memcpy(out, b, sizeof(*out));
        return;
    }
    if (b->infinity != 0u) {
        memcpy(out, a, sizeof(*out));
        return;
    }

    if (crypto_ec_field_equal_mask(curve, &a->x, &b->x) ==
        UINT32_MAX) {
        if (crypto_ec_field_equal_mask(curve, &a->y, &b->y) ==
            UINT32_MAX) {
            crypto_ec_affine_double_reference(curve, out, a);
        } else {
            crypto_ec_affine_set_infinity(out);
        }
        return;
    }

    /*
     * Textbook affine addition:
     *   lambda = (y2-y1)/(x2-x1)
     *   x3 = lambda^2-x1-x2
     *   y3 = lambda*(x1-x3)-y1
     */
    crypto_ec_field_sub(curve, &numerator, &b->y, &a->y);
    crypto_ec_field_sub(curve, &denominator, &b->x, &a->x);
    crypto_ec_field_invert_fixed(curve, &inverse, &denominator);
    crypto_ec_field_multiply(curve, &slope, &numerator, &inverse);
    crypto_ec_field_square(curve, &result.x, &slope);
    crypto_ec_field_sub(curve, &result.x, &result.x, &a->x);
    crypto_ec_field_sub(curve, &result.x, &result.x, &b->x);
    crypto_ec_field_sub(curve, &temporary, &a->x, &result.x);
    crypto_ec_field_multiply(curve, &result.y, &slope, &temporary);
    crypto_ec_field_sub(curve, &result.y, &result.y, &a->y);
    result.infinity = 0u;

    memcpy(out, &result, sizeof(result));
}

LiberaCError crypto_ec_scalar_multiply_reference(
    const CryptoEcCurve *curve, CryptoEcAffinePoint *out,
    const CryptoEcAffinePoint *point, const uint8_t *scalar,
    size_t scalar_length) {
    CryptoEcAffinePoint result;
    size_t byte_index;
    unsigned int bit_index;

    if (curve == NULL || out == NULL || point == NULL ||
        scalar == NULL || scalar_length != curve->scalar_bytes) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_ec_affine_set_infinity(&result);
    for (byte_index = 0u; byte_index < scalar_length; ++byte_index) {
        for (bit_index = 0u; bit_index < 8u; ++bit_index) {
            uint32_t bit =
                ((uint32_t)scalar[byte_index] >> (7u - bit_index)) & 1u;

            crypto_ec_affine_double_reference(curve, &result, &result);
            if (bit != 0u) {
                crypto_ec_affine_add_reference(curve, &result, &result,
                                               point);
            }
        }
    }

    memcpy(out, &result, sizeof(result));
    return LIBERAC_SUCCESS;
}
