/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "Util/Core/secure_zero.h"
#include "ecc_internal.h"

#define CRYPTO_EC_SCALAR_PRODUCT_LIMBS (2u * CRYPTO_EC_MAX_LIMBS + 2u)

static uint32_t scalar_arith_nonzero_mask(uint32_t value) {
    value |= UINT32_C(0) - value;
    return UINT32_C(0) - (value >> 31);
}

static uint32_t scalar_subtract_order(const CryptoEcCurve *curve,
                                      uint32_t *out,
                                      const uint32_t *value) {
    uint64_t borrow = 0u;
    size_t index;

    for (index = 0u; index < curve->limbs; ++index) {
        const uint64_t left = value[index];
        const uint64_t right = curve->order[index];
        const uint64_t difference = left - right - borrow;
        out[index] = (uint32_t)difference;
        borrow = left < right + borrow;
    }
    return (uint32_t)borrow;
}

static void scalar_montgomery_multiply_raw(const CryptoEcCurve *curve,
                                           uint32_t *out,
                                           const uint32_t *a,
                                           const uint32_t *b) {
    uint32_t product[CRYPTO_EC_SCALAR_PRODUCT_LIMBS] = {0u};
    uint32_t reduced[CRYPTO_EC_MAX_LIMBS] = {0u};
    uint32_t subtracted[CRYPTO_EC_MAX_LIMBS] = {0u};
    size_t outer;

    for (outer = 0u; outer < curve->limbs; ++outer) {
        uint64_t carry = 0u;
        size_t inner;
        for (inner = 0u; inner < curve->limbs; ++inner) {
            const size_t position = outer + inner;
            const uint64_t value =
                (uint64_t)a[outer] * b[inner] + product[position] + carry;
            product[position] = (uint32_t)value;
            carry = value >> 32;
        }
        for (inner = outer + curve->limbs;
             inner < CRYPTO_EC_SCALAR_PRODUCT_LIMBS; ++inner) {
            const uint64_t value = (uint64_t)product[inner] + carry;
            product[inner] = (uint32_t)value;
            carry = value >> 32;
        }
    }

    for (outer = 0u; outer < curve->limbs; ++outer) {
        const uint32_t multiplier =
            product[outer] * curve->scalar_montgomery_factor;
        uint64_t carry = 0u;
        size_t inner;
        for (inner = 0u; inner < curve->limbs; ++inner) {
            const size_t position = outer + inner;
            const uint64_t value =
                (uint64_t)multiplier * curve->order[inner] +
                product[position] + carry;
            product[position] = (uint32_t)value;
            carry = value >> 32;
        }
        for (inner = outer + curve->limbs;
             inner < CRYPTO_EC_SCALAR_PRODUCT_LIMBS; ++inner) {
            const uint64_t value = (uint64_t)product[inner] + carry;
            product[inner] = (uint32_t)value;
            carry = value >> 32;
        }
    }

    for (outer = 0u; outer < curve->limbs; ++outer) {
        reduced[outer] = product[curve->limbs + outer];
    }
    {
        const uint32_t borrow =
            scalar_subtract_order(curve, subtracted, reduced);
        const uint32_t extra_mask = scalar_arith_nonzero_mask(
            product[2u * curve->limbs]);
        const uint32_t subtract_mask =
            extra_mask | (UINT32_C(0) - (borrow ^ 1u));
        for (outer = 0u; outer < curve->limbs; ++outer) {
            out[outer] = (subtracted[outer] & subtract_mask) |
                         (reduced[outer] & ~subtract_mask);
        }
    }

    crypto_zeroize(product, sizeof(product));
    crypto_zeroize(reduced, sizeof(reduced));
    crypto_zeroize(subtracted, sizeof(subtracted));
}

static void scalar_parse_bytes(const CryptoEcCurve *curve,
                               uint32_t *raw,
                               const uint8_t *input) {
    size_t byte_index;

    for (byte_index = 0u; byte_index < curve->scalar_bytes; ++byte_index) {
        const size_t source = curve->scalar_bytes - 1u - byte_index;
        raw[byte_index / 4u] |=
            (uint32_t)input[source] << ((byte_index & 3u) * 8u);
    }
}

static void scalar_select(const CryptoEcCurve *curve,
                          CryptoEcScalar *out,
                          const CryptoEcScalar *a,
                          const CryptoEcScalar *b,
                          uint32_t select_b_mask) {
    CryptoEcScalar selected;
    size_t index;

    crypto_ec_scalar_zero(&selected);
    for (index = 0u; index < curve->limbs; ++index) {
        selected.limb[index] = (a->limb[index] & ~select_b_mask) |
                               (b->limb[index] & select_b_mask);
    }
    *out = selected;
    crypto_zeroize(&selected, sizeof(selected));
}

static void scalar_power_fixed(const CryptoEcCurve *curve,
                               CryptoEcScalar *out,
                               const CryptoEcScalar *base,
                               const uint32_t *exponent) {
    CryptoEcScalar result;
    CryptoEcScalar multiplied;
    size_t bit = curve->scalar_bits;

    crypto_ec_scalar_zero(&result);
    memcpy(result.limb, curve->scalar_montgomery_one,
           curve->limbs * sizeof(uint32_t));
    crypto_ec_scalar_zero(&multiplied);
    while (bit > 0u) {
        const size_t current = --bit;
        const uint32_t exponent_bit =
            (exponent[current / 32u] >> (current & 31u)) & 1u;
        const uint32_t select_mask = UINT32_C(0) - exponent_bit;
        crypto_ec_scalar_multiply(curve, &result, &result, &result);
        crypto_ec_scalar_multiply(curve, &multiplied, &result, base);
        scalar_select(curve, &result, &result, &multiplied, select_mask);
    }
    *out = result;
    crypto_zeroize(&result, sizeof(result));
    crypto_zeroize(&multiplied, sizeof(multiplied));
}

void crypto_ec_scalar_zero(CryptoEcScalar *out) {
    memset(out, 0, sizeof(*out));
}

LiberaCError crypto_ec_scalar_from_bytes(const CryptoEcCurve *curve,
                                         CryptoEcScalar *out,
                                         const uint8_t *input,
                                         size_t input_length) {
    uint32_t raw[CRYPTO_EC_MAX_LIMBS] = {0u};
    uint32_t difference[CRYPTO_EC_MAX_LIMBS] = {0u};
    CryptoEcScalar standard;
    uint32_t borrow;

    if (curve == NULL || out == NULL || input == NULL ||
        input_length != curve->scalar_bytes) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_ec_scalar_zero(out);
    crypto_ec_scalar_zero(&standard);
    scalar_parse_bytes(curve, raw, input);
    borrow = scalar_subtract_order(curve, difference, raw);
    if (borrow == 0u) {
        crypto_zeroize(raw, sizeof(raw));
        crypto_zeroize(difference, sizeof(difference));
        crypto_zeroize(&standard, sizeof(standard));
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    memcpy(standard.limb, raw, curve->limbs * sizeof(uint32_t));
    scalar_montgomery_multiply_raw(
        curve, out->limb, standard.limb, curve->scalar_montgomery_r2);

    crypto_zeroize(raw, sizeof(raw));
    crypto_zeroize(difference, sizeof(difference));
    crypto_zeroize(&standard, sizeof(standard));
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_ec_scalar_from_bytes_reduced(
    const CryptoEcCurve *curve, CryptoEcScalar *out,
    const uint8_t *input, size_t input_length) {
    uint32_t raw[CRYPTO_EC_MAX_LIMBS] = {0u};
    uint32_t reduced[CRYPTO_EC_MAX_LIMBS] = {0u};
    CryptoEcScalar standard;
    uint32_t borrow;
    uint32_t subtract_mask;
    size_t index;
    size_t excess_bits;

    if (curve == NULL || out == NULL || input == NULL ||
        input_length != curve->scalar_bytes) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    excess_bits = input_length * 8u - curve->scalar_bits;
    if (excess_bits != 0u &&
        (input[0] >> (8u - excess_bits)) != 0u) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_ec_scalar_zero(&standard);
    scalar_parse_bytes(curve, raw, input);
    borrow = scalar_subtract_order(curve, reduced, raw);
    subtract_mask = UINT32_C(0) - (borrow ^ 1u);
    for (index = 0u; index < curve->limbs; ++index) {
        standard.limb[index] = (reduced[index] & subtract_mask) |
                               (raw[index] & ~subtract_mask);
    }
    scalar_montgomery_multiply_raw(
        curve, out->limb, standard.limb, curve->scalar_montgomery_r2);

    crypto_zeroize(raw, sizeof(raw));
    crypto_zeroize(reduced, sizeof(reduced));
    crypto_zeroize(&standard, sizeof(standard));
    return LIBERAC_SUCCESS;
}

void crypto_ec_scalar_to_bytes(const CryptoEcCurve *curve,
                               uint8_t *output,
                               const CryptoEcScalar *in) {
    uint32_t one[CRYPTO_EC_MAX_LIMBS] = {0u};
    uint32_t standard[CRYPTO_EC_MAX_LIMBS] = {0u};
    size_t byte_index;

    one[0] = 1u;
    scalar_montgomery_multiply_raw(curve, standard, in->limb, one);
    for (byte_index = 0u; byte_index < curve->scalar_bytes; ++byte_index) {
        const size_t source = curve->scalar_bytes - 1u - byte_index;
        output[byte_index] =
            (uint8_t)(standard[source / 4u] >> ((source & 3u) * 8u));
    }
    crypto_zeroize(one, sizeof(one));
    crypto_zeroize(standard, sizeof(standard));
}

void crypto_ec_scalar_add(const CryptoEcCurve *curve,
                          CryptoEcScalar *out,
                          const CryptoEcScalar *a,
                          const CryptoEcScalar *b) {
    CryptoEcScalar sum;
    CryptoEcScalar reduced;
    uint64_t carry = 0u;
    uint32_t borrow;
    uint32_t subtract_mask;
    size_t index;

    crypto_ec_scalar_zero(&sum);
    crypto_ec_scalar_zero(&reduced);
    for (index = 0u; index < curve->limbs; ++index) {
        const uint64_t value =
            (uint64_t)a->limb[index] + b->limb[index] + carry;
        sum.limb[index] = (uint32_t)value;
        carry = value >> 32;
    }
    borrow = scalar_subtract_order(curve, reduced.limb, sum.limb);
    subtract_mask = (UINT32_C(0) - (uint32_t)carry) |
                    (UINT32_C(0) - (borrow ^ 1u));
    crypto_ec_scalar_zero(out);
    for (index = 0u; index < curve->limbs; ++index) {
        out->limb[index] = (reduced.limb[index] & subtract_mask) |
                           (sum.limb[index] & ~subtract_mask);
    }
    crypto_zeroize(&sum, sizeof(sum));
    crypto_zeroize(&reduced, sizeof(reduced));
}

void crypto_ec_scalar_multiply(const CryptoEcCurve *curve,
                               CryptoEcScalar *out,
                               const CryptoEcScalar *a,
                               const CryptoEcScalar *b) {
    CryptoEcScalar result;

    crypto_ec_scalar_zero(&result);
    scalar_montgomery_multiply_raw(curve, result.limb, a->limb, b->limb);
    *out = result;
    crypto_zeroize(&result, sizeof(result));
}

void crypto_ec_scalar_invert_fixed(const CryptoEcCurve *curve,
                                   CryptoEcScalar *out,
                                   const CryptoEcScalar *a) {
    scalar_power_fixed(curve, out, a, curve->scalar_inverse_exponent);
}

uint32_t crypto_ec_scalar_equal_mask(const CryptoEcCurve *curve,
                                     const CryptoEcScalar *a,
                                     const CryptoEcScalar *b) {
    uint32_t difference = 0u;
    size_t index;

    for (index = 0u; index < curve->limbs; ++index) {
        difference |= a->limb[index] ^ b->limb[index];
    }
    return ~scalar_arith_nonzero_mask(difference);
}

uint32_t crypto_ec_scalar_zero_mask(const CryptoEcCurve *curve,
                                    const CryptoEcScalar *a) {
    CryptoEcScalar zero;
    uint32_t result;

    crypto_ec_scalar_zero(&zero);
    result = crypto_ec_scalar_equal_mask(curve, a, &zero);
    crypto_zeroize(&zero, sizeof(zero));
    return result;
}
