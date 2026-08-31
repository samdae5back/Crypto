/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "ecc_internal.h"

static size_t scalar_public_bit_length(const uint8_t *scalar,
                                       size_t scalar_length) {
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

static unsigned scalar_public_bit(const uint8_t *scalar,
                                  size_t scalar_length,
                                  size_t bit_index) {
    const size_t byte_from_end = bit_index / 8u;
    if (byte_from_end >= scalar_length) {
        return 0u;
    }
    return (scalar[scalar_length - 1u - byte_from_end] >> (bit_index & 7u)) &
           1u;
}

static unsigned scalar_window_value(const uint8_t *scalar,
                                    size_t scalar_length,
                                    size_t low_bit,
                                    unsigned width) {
    unsigned value = 0u;
    unsigned index;
    for (index = 0u; index < width; ++index) {
        value |= scalar_public_bit(scalar, scalar_length, low_bit + index)
                 << index;
    }
    return value;
}

LiberaCError crypto_ec_scalar_multiply_vartime(
    const CryptoEcCurve *curve, CryptoEcAffinePoint *out,
    const CryptoEcAffinePoint *point, const uint8_t *scalar,
    size_t scalar_length) {
    CryptoEcJacobianPoint table[CRYPTO_EC_WINDOW_SIZE];
    CryptoEcJacobianPoint addend;
    CryptoEcJacobianPoint result;
    size_t bit_length;
    size_t window_count;
    size_t window_index;
    unsigned index;

    if (!curve || !out || !point || (!scalar && scalar_length != 0u) ||
        scalar_length > curve->scalar_bytes ||
        !crypto_ec_affine_is_on_curve(curve, point)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    bit_length = scalar_public_bit_length(scalar, scalar_length);
    if (bit_length == 0u || point->infinity != 0u) {
        crypto_ec_affine_set_infinity(out);
        return LIBERAC_SUCCESS;
    }

    crypto_ec_jacobian_set_infinity(curve, &table[0]);
    crypto_ec_affine_to_jacobian(curve, &table[1], point);
    for (index = 2u; index < CRYPTO_EC_WINDOW_SIZE; ++index) {
        crypto_ec_jacobian_add_complete(curve, &table[index],
                                        &table[index - 1u], &table[1]);
    }

    crypto_ec_jacobian_set_infinity(curve, &result);
    window_count =
        (bit_length + CRYPTO_EC_WINDOW_BITS - 1u) / CRYPTO_EC_WINDOW_BITS;
    window_index = window_count;
    while (window_index > 0u) {
        const size_t current_window = --window_index;
        const unsigned value = scalar_window_value(
            scalar, scalar_length, current_window * CRYPTO_EC_WINDOW_BITS,
            CRYPTO_EC_WINDOW_BITS);
        for (index = 0u; index < CRYPTO_EC_WINDOW_BITS; ++index) {
            crypto_ec_jacobian_double(curve, &result, &result);
        }
        if (value != 0u) {
            addend = table[value];
            crypto_ec_jacobian_add_complete(curve, &result, &result, &addend);
        }
    }
    crypto_ec_jacobian_to_affine(curve, out, &result);
    return LIBERAC_SUCCESS;
}
