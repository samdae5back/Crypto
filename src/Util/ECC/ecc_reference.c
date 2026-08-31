/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "ecc_internal.h"

static int scalar_bit(const uint8_t *scalar, size_t scalar_length,
                      size_t bit_index) {
    const size_t byte_from_end = bit_index / 8u;
    if (byte_from_end >= scalar_length) {
        return 0;
    }
    return (scalar[scalar_length - 1u - byte_from_end] >> (bit_index & 7u)) & 1u;
}

static size_t scalar_bit_length(const uint8_t *scalar, size_t scalar_length) {
    size_t first = 0u;
    unsigned bit;

    while (first < scalar_length && scalar[first] == 0u) {
        ++first;
    }
    if (first == scalar_length) {
        return 0u;
    }
    bit = 8u;
    while (bit > 0u && ((scalar[first] >> (bit - 1u)) & 1u) == 0u) {
        --bit;
    }
    return (scalar_length - first - 1u) * 8u + bit;
}

static void affine_double_reference(const CryptoEcCurve *curve,
                                    CryptoEcAffinePoint *out,
                                    const CryptoEcAffinePoint *point) {
    CryptoEcFieldElement numerator;
    CryptoEcFieldElement denominator;
    CryptoEcFieldElement inverse;
    CryptoEcFieldElement slope;
    CryptoEcFieldElement x_squared;
    CryptoEcFieldElement three_x_squared;
    CryptoEcFieldElement three;
    CryptoEcFieldElement two_x;
    CryptoEcFieldElement temporary;
    CryptoEcAffinePoint result;

    if (point->infinity != 0u ||
        crypto_ec_field_zero_mask(curve, &point->y) != 0u) {
        crypto_ec_affine_set_infinity(out);
        return;
    }

    crypto_ec_field_square(curve, &x_squared, &point->x);
    crypto_ec_field_add(curve, &three_x_squared, &x_squared, &x_squared);
    crypto_ec_field_add(curve, &three_x_squared, &three_x_squared, &x_squared);
    crypto_ec_field_one(curve, &three);
    crypto_ec_field_add(curve, &three, &three, &three);
    crypto_ec_field_add(curve, &three, &three,
                        &(CryptoEcFieldElement){{
                            curve->montgomery_one[0], curve->montgomery_one[1],
                            curve->montgomery_one[2], curve->montgomery_one[3],
                            curve->montgomery_one[4], curve->montgomery_one[5],
                            curve->montgomery_one[6], curve->montgomery_one[7],
                            curve->montgomery_one[8], curve->montgomery_one[9],
                            curve->montgomery_one[10], curve->montgomery_one[11],
                            curve->montgomery_one[12], curve->montgomery_one[13],
                            curve->montgomery_one[14], curve->montgomery_one[15],
                            curve->montgomery_one[16]
                        }});
    crypto_ec_field_sub(curve, &numerator, &three_x_squared, &three);
    crypto_ec_field_add(curve, &denominator, &point->y, &point->y);
    crypto_ec_field_invert_fixed(curve, &inverse, &denominator);
    crypto_ec_field_multiply(curve, &slope, &numerator, &inverse);

    crypto_ec_field_square(curve, &result.x, &slope);
    crypto_ec_field_add(curve, &two_x, &point->x, &point->x);
    crypto_ec_field_sub(curve, &result.x, &result.x, &two_x);
    crypto_ec_field_sub(curve, &temporary, &point->x, &result.x);
    crypto_ec_field_multiply(curve, &result.y, &slope, &temporary);
    crypto_ec_field_sub(curve, &result.y, &result.y, &point->y);
    result.infinity = 0u;
    *out = result;
}

static void affine_add_reference(const CryptoEcCurve *curve,
                                 CryptoEcAffinePoint *out,
                                 const CryptoEcAffinePoint *a,
                                 const CryptoEcAffinePoint *b) {
    CryptoEcFieldElement numerator;
    CryptoEcFieldElement denominator;
    CryptoEcFieldElement inverse;
    CryptoEcFieldElement slope;
    CryptoEcFieldElement temporary;
    CryptoEcAffinePoint result;

    if (a->infinity != 0u) {
        *out = *b;
        return;
    }
    if (b->infinity != 0u) {
        *out = *a;
        return;
    }
    if (crypto_ec_field_equal_mask(curve, &a->x, &b->x) != 0u) {
        if (crypto_ec_field_equal_mask(curve, &a->y, &b->y) != 0u) {
            affine_double_reference(curve, out, a);
        } else {
            crypto_ec_affine_set_infinity(out);
        }
        return;
    }

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
    *out = result;
}

LiberaCError crypto_ec_scalar_multiply_reference(
    const CryptoEcCurve *curve, CryptoEcAffinePoint *out,
    const CryptoEcAffinePoint *point, const uint8_t *scalar,
    size_t scalar_length) {
    CryptoEcAffinePoint result;
    size_t bit_length;
    size_t bit;

    if (!curve || !out || !point || (!scalar && scalar_length != 0u) ||
        scalar_length > curve->scalar_bytes ||
        !crypto_ec_affine_is_on_curve(curve, point)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    crypto_ec_affine_set_infinity(&result);
    bit_length = scalar_bit_length(scalar, scalar_length);
    bit = bit_length;
    while (bit > 0u) {
        CryptoEcAffinePoint doubled;
        affine_double_reference(curve, &doubled, &result);
        result = doubled;
        --bit;
        if (scalar_bit(scalar, scalar_length, bit) != 0) {
            CryptoEcAffinePoint added;
            affine_add_reference(curve, &added, &result, point);
            result = added;
        }
    }
    *out = result;
    return LIBERAC_SUCCESS;
}
