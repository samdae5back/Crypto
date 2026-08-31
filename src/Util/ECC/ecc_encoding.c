/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "ecc_internal.h"

size_t crypto_ec_point_encoding_size(const CryptoEcCurve *curve,
                                     const CryptoEcAffinePoint *point,
                                     int compressed) {
    if (!curve || !point) {
        return 0u;
    }
    if (point->infinity != 0u) {
        return 1u;
    }
    return 1u + curve->field_bytes * (compressed ? 1u : 2u);
}

LiberaCError crypto_ec_point_encode(const CryptoEcCurve *curve,
                                    const CryptoEcAffinePoint *point,
                                    int compressed,
                                    uint8_t *output,
                                    size_t *output_length) {
    size_t required;

    if (!curve || !point || !output_length ||
        !crypto_ec_affine_is_on_curve(curve, point)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    required = crypto_ec_point_encoding_size(curve, point, compressed);
    if (!output || *output_length < required) {
        *output_length = required;
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (point->infinity != 0u) {
        output[0] = 0u;
    } else if (compressed) {
        output[0] = (uint8_t)(2u | crypto_ec_field_lsb(curve, &point->y));
        crypto_ec_field_to_bytes(curve, output + 1u, &point->x);
    } else {
        output[0] = 4u;
        crypto_ec_field_to_bytes(curve, output + 1u, &point->x);
        crypto_ec_field_to_bytes(curve, output + 1u + curve->field_bytes,
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
    CryptoEcAffinePoint candidate;

    if (!curve || !point || !input || input_length == 0u) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (input[0] == 0u) {
        if (!allow_infinity || input_length != 1u) {
            return LIBERAC_ERROR_INVALID_ARGUMENT;
        }
        crypto_ec_affine_set_infinity(point);
        return LIBERAC_SUCCESS;
    }

    crypto_ec_affine_set_infinity(&candidate);
    if (input[0] == 4u) {
        if (input_length != 1u + 2u * curve->field_bytes ||
            crypto_ec_field_from_bytes(curve, &candidate.x, input + 1u,
                                       curve->field_bytes) != LIBERAC_SUCCESS ||
            crypto_ec_field_from_bytes(curve, &candidate.y,
                                       input + 1u + curve->field_bytes,
                                       curve->field_bytes) != LIBERAC_SUCCESS) {
            return LIBERAC_ERROR_INVALID_ARGUMENT;
        }
        candidate.infinity = 0u;
    } else if (input[0] == 2u || input[0] == 3u) {
        CryptoEcFieldElement x_squared;
        CryptoEcFieldElement x_cubed;
        CryptoEcFieldElement three_x;
        CryptoEcFieldElement right;
        CryptoEcFieldElement b;
        CryptoEcFieldElement negated_y;
        size_t index;
        uint32_t parity_mask;

        if (input_length != 1u + curve->field_bytes ||
            crypto_ec_field_from_bytes(curve, &candidate.x, input + 1u,
                                       curve->field_bytes) != LIBERAC_SUCCESS) {
            return LIBERAC_ERROR_INVALID_ARGUMENT;
        }
        crypto_ec_field_zero(&b);
        for (index = 0u; index < curve->limbs; ++index) {
            b.limb[index] = curve->b[index];
        }
        crypto_ec_field_square(curve, &x_squared, &candidate.x);
        crypto_ec_field_multiply(curve, &x_cubed, &x_squared, &candidate.x);
        crypto_ec_field_add(curve, &three_x, &candidate.x, &candidate.x);
        crypto_ec_field_add(curve, &three_x, &three_x, &candidate.x);
        crypto_ec_field_sub(curve, &right, &x_cubed, &three_x);
        crypto_ec_field_add(curve, &right, &right, &b);
        if (!crypto_ec_field_square_root_fixed(curve, &candidate.y, &right)) {
            return LIBERAC_ERROR_INVALID_ARGUMENT;
        }
        crypto_ec_field_negate(curve, &negated_y, &candidate.y);
        parity_mask = UINT32_C(0) -
                      (crypto_ec_field_lsb(curve, &candidate.y) ^
                       (uint32_t)(input[0] & 1u));
        crypto_ec_field_select(curve, &candidate.y, &candidate.y, &negated_y,
                               parity_mask);
        candidate.infinity = 0u;
    } else {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    if (!crypto_ec_affine_is_on_curve(curve, &candidate)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    *point = candidate;
    return LIBERAC_SUCCESS;
}
