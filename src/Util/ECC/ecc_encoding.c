/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "ecc_internal.h"

static void crypto_ec_curve_rhs(const CryptoEcCurve *curve,
                                CryptoEcFieldElement *out,
                                const CryptoEcFieldElement *x) {
    CryptoEcFieldElement x_squared;
    CryptoEcFieldElement three_x;
    CryptoEcFieldElement twice_x;
    CryptoEcFieldElement b;
    size_t i;

    crypto_ec_field_square(curve, &x_squared, x);
    crypto_ec_field_multiply(curve, out, &x_squared, x);
    crypto_ec_field_add(curve, &twice_x, x, x);
    crypto_ec_field_add(curve, &three_x, &twice_x, x);
    crypto_ec_field_sub(curve, out, out, &three_x);

    for (i = 0u; i < curve->limbs; ++i) {
        b.limb[i] = curve->b[i];
    }
    for (i = curve->limbs; i < CRYPTO_EC_MAX_LIMBS; ++i) {
        b.limb[i] = 0u;
    }
    crypto_ec_field_add(curve, out, out, &b);
}

size_t crypto_ec_point_encoding_size(const CryptoEcCurve *curve,
                                     const CryptoEcAffinePoint *point,
                                     int compressed) {
    if (curve == NULL || point == NULL) {
        return 0u;
    }
    if (point->infinity != 0u) {
        return 1u;
    }
    return 1u + curve->field_bytes * (compressed != 0 ? 1u : 2u);
}

LiberaCError crypto_ec_point_encode(const CryptoEcCurve *curve,
                                    const CryptoEcAffinePoint *point,
                                    int compressed,
                                    uint8_t *output,
                                    size_t *output_length) {
    size_t required;

    if (curve == NULL || point == NULL || output_length == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (!crypto_ec_affine_is_on_curve(curve, point)) {
        return LIBERAC_ERROR_INVALID_KEY;
    }

    required = crypto_ec_point_encoding_size(curve, point, compressed);
    if (output == NULL || *output_length < required) {
        *output_length = required;
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }

    if (point->infinity != 0u) {
        output[0] = 0u;
    } else if (compressed != 0) {
        output[0] =
            (uint8_t)(0x02u | crypto_ec_field_lsb(curve, &point->y));
        crypto_ec_field_to_bytes(curve, output + 1u, &point->x);
    } else {
        output[0] = 0x04u;
        crypto_ec_field_to_bytes(curve, output + 1u, &point->x);
        crypto_ec_field_to_bytes(curve,
                                 output + 1u + curve->field_bytes,
                                 &point->y);
    }

    *output_length = required;
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_ec_point_decode(const CryptoEcCurve *curve,
                                    CryptoEcAffinePoint *point,
                                    const uint8_t *input,
                                    size_t input_length,
                                    int allow_infinity) {
    LiberaCError error;

    if (curve == NULL || point == NULL ||
        input == NULL || input_length == 0u) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_ec_affine_set_infinity(point);

    if (input[0] == 0u) {
        if (input_length == 1u && allow_infinity != 0) {
            return LIBERAC_SUCCESS;
        }
        return LIBERAC_ERROR_INVALID_KEY;
    }

    if ((input[0] == 0x02u || input[0] == 0x03u) &&
        input_length == 1u + curve->field_bytes) {
        CryptoEcFieldElement rhs;
        CryptoEcFieldElement root;
        CryptoEcFieldElement negated;
        uint32_t required_parity = (uint32_t)(input[0] & 1u);
        uint32_t root_parity;

        error = crypto_ec_field_from_bytes(curve, &point->x,
                                           input + 1u,
                                           curve->field_bytes);
        if (error != LIBERAC_SUCCESS) {
            crypto_ec_affine_set_infinity(point);
            return LIBERAC_ERROR_INVALID_KEY;
        }

        crypto_ec_curve_rhs(curve, &rhs, &point->x);
        if (!crypto_ec_field_square_root_fixed(curve, &root, &rhs)) {
            crypto_ec_affine_set_infinity(point);
            return LIBERAC_ERROR_INVALID_KEY;
        }

        root_parity = crypto_ec_field_lsb(curve, &root);
        crypto_ec_field_negate(curve, &negated, &root);
        if (root_parity != required_parity) {
            crypto_ec_field_copy(&root, &negated);
        }
        if (crypto_ec_field_lsb(curve, &root) != required_parity) {
            crypto_ec_affine_set_infinity(point);
            return LIBERAC_ERROR_INVALID_KEY;
        }

        crypto_ec_field_copy(&point->y, &root);
        point->infinity = 0u;
        return LIBERAC_SUCCESS;
    }

    if (input[0] == 0x04u &&
        input_length == 1u + 2u * curve->field_bytes) {
        error = crypto_ec_field_from_bytes(curve, &point->x,
                                           input + 1u,
                                           curve->field_bytes);
        if (error != LIBERAC_SUCCESS) {
            crypto_ec_affine_set_infinity(point);
            return LIBERAC_ERROR_INVALID_KEY;
        }
        error = crypto_ec_field_from_bytes(
            curve, &point->y, input + 1u + curve->field_bytes,
            curve->field_bytes);
        if (error != LIBERAC_SUCCESS) {
            crypto_ec_affine_set_infinity(point);
            return LIBERAC_ERROR_INVALID_KEY;
        }

        point->infinity = 0u;
        if (!crypto_ec_affine_is_on_curve(curve, point)) {
            crypto_ec_affine_set_infinity(point);
            return LIBERAC_ERROR_INVALID_KEY;
        }
        return LIBERAC_SUCCESS;
    }

    return LIBERAC_ERROR_INVALID_KEY;
}
