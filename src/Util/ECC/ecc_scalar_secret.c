/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Util/Core/secure_zero.h"
#include "ecc_internal.h"

static uint32_t scalar_nonzero_mask(uint32_t value) {
    value |= UINT32_C(0) - value;
    return UINT32_C(0) - (value >> 31);
}

static uint32_t scalar_encoded_byte(const CryptoEcCurve *curve,
                                    const uint32_t *value,
                                    size_t byte_index) {
    const size_t little_endian_index = curve->scalar_bytes - 1u - byte_index;
    return (value[little_endian_index / 4u] >>
            ((little_endian_index & 3u) * 8u)) & 0xffu;
}

static uint32_t scalar_secret_bit(const uint8_t *scalar,
                                  const CryptoEcCurve *curve,
                                  size_t bit_index) {
    const size_t byte_from_end = bit_index / 8u;
    return (scalar[curve->scalar_bytes - 1u - byte_from_end] >>
            (bit_index & 7u)) & 1u;
}

int crypto_ec_scalar_is_valid_ct(const CryptoEcCurve *curve,
                                 const uint8_t *scalar,
                                 size_t scalar_length) {
    uint32_t nonzero = 0u;
    uint32_t borrow = 0u;
    size_t index;

    if (!curve || !scalar || scalar_length != curve->scalar_bytes) {
        return 0;
    }
    for (index = 0u; index < scalar_length; ++index) {
        nonzero |= scalar[index];
    }
    index = scalar_length;
    while (index > 0u) {
        uint32_t scalar_byte;
        uint32_t order_byte;
        uint32_t difference;
        --index;
        scalar_byte = scalar[index];
        order_byte = scalar_encoded_byte(curve, curve->order, index);
        difference = scalar_byte - order_byte - borrow;
        borrow = (difference >> 31) & 1u;
    }
    return (int)((scalar_nonzero_mask(nonzero) &
                  (UINT32_C(0) - borrow)) >> 31);
}

LiberaCError crypto_ec_scalar_multiply_ct(
    const CryptoEcCurve *curve, CryptoEcAffinePoint *out,
    const CryptoEcAffinePoint *point, const uint8_t *scalar,
    size_t scalar_length) {
    CryptoEcJacobianPoint r0;
    CryptoEcJacobianPoint r1;
    CryptoEcJacobianPoint sum;
    CryptoEcJacobianPoint doubled;
    size_t bit;

    if (!curve || !out || !point || !scalar ||
        scalar_length != curve->scalar_bytes ||
        !crypto_ec_affine_is_on_curve(curve, point) ||
        !crypto_ec_scalar_is_valid_ct(curve, scalar, scalar_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_ec_jacobian_set_infinity(curve, &r0);
    crypto_ec_affine_to_jacobian(curve, &r1, point);
    bit = curve->scalar_bits;
    while (bit > 0u) {
        const uint32_t scalar_bit = scalar_secret_bit(scalar, curve, --bit);
        const uint32_t swap_mask = UINT32_C(0) - scalar_bit;
        crypto_ec_jacobian_cswap(curve, &r0, &r1, swap_mask);
        crypto_ec_jacobian_add_complete(curve, &sum, &r0, &r1);
        crypto_ec_jacobian_double(curve, &doubled, &r0);
        r1 = sum;
        r0 = doubled;
        crypto_ec_jacobian_cswap(curve, &r0, &r1, swap_mask);
    }
    crypto_ec_jacobian_to_affine(curve, out, &r0);
    crypto_zeroize(&r0, sizeof(r0));
    crypto_zeroize(&r1, sizeof(r1));
    crypto_zeroize(&sum, sizeof(sum));
    crypto_zeroize(&doubled, sizeof(doubled));
    return LIBERAC_SUCCESS;
}
