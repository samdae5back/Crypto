/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "ecc_internal.h"

#define CRYPTO_EC_PRODUCT_LIMBS (2u * CRYPTO_EC_MAX_LIMBS + 2u)

static uint32_t field_nonzero_mask(uint32_t value) {
    value |= UINT32_C(0) - value;
    return UINT32_C(0) - (value >> 31);
}

static uint32_t field_sub_modulus(const CryptoEcCurve *curve,
                                  uint32_t *out,
                                  const uint32_t *value) {
    uint64_t borrow = 0u;
    size_t index;

    for (index = 0u; index < curve->limbs; ++index) {
        const uint64_t left = value[index];
        const uint64_t right = curve->p[index];
        const uint64_t difference = left - right - borrow;
        out[index] = (uint32_t)difference;
        borrow = left < right + borrow;
    }
    return (uint32_t)borrow;
}

static void field_add_modulus(const CryptoEcCurve *curve,
                              uint32_t *out,
                              const uint32_t *value) {
    uint64_t carry = 0u;
    size_t index;

    for (index = 0u; index < curve->limbs; ++index) {
        const uint64_t sum =
            (uint64_t)value[index] + curve->p[index] + carry;
        out[index] = (uint32_t)sum;
        carry = sum >> 32;
    }
}

static void field_montgomery_multiply_raw(const CryptoEcCurve *curve,
                                          uint32_t *out,
                                          const uint32_t *a,
                                          const uint32_t *b) {
    uint32_t product[CRYPTO_EC_PRODUCT_LIMBS] = {0u};
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
             inner < CRYPTO_EC_PRODUCT_LIMBS; ++inner) {
            const uint64_t value = (uint64_t)product[inner] + carry;
            product[inner] = (uint32_t)value;
            carry = value >> 32;
        }
    }

    for (outer = 0u; outer < curve->limbs; ++outer) {
        const uint32_t multiplier =
            product[outer] * curve->montgomery_factor;
        uint64_t carry = 0u;
        size_t inner;
        for (inner = 0u; inner < curve->limbs; ++inner) {
            const size_t position = outer + inner;
            const uint64_t value =
                (uint64_t)multiplier * curve->p[inner] +
                product[position] + carry;
            product[position] = (uint32_t)value;
            carry = value >> 32;
        }
        for (inner = outer + curve->limbs;
             inner < CRYPTO_EC_PRODUCT_LIMBS; ++inner) {
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
            field_sub_modulus(curve, subtracted, reduced);
        const uint32_t extra_mask = field_nonzero_mask(product[2u * curve->limbs]);
        const uint32_t subtract_mask = extra_mask | (UINT32_C(0) - (borrow ^ 1u));
        for (outer = 0u; outer < curve->limbs; ++outer) {
            out[outer] = (subtracted[outer] & subtract_mask) |
                         (reduced[outer] & ~subtract_mask);
        }
    }
}

static int field_raw_compare(const CryptoEcCurve *curve,
                             const uint32_t *a,
                             const uint32_t *b) {
    size_t index = curve->limbs;
    while (index > 0u) {
        --index;
        if (a[index] < b[index]) {
            return -1;
        }
        if (a[index] > b[index]) {
            return 1;
        }
    }
    return 0;
}

static void field_power_fixed(const CryptoEcCurve *curve,
                              CryptoEcFieldElement *out,
                              const CryptoEcFieldElement *base,
                              const uint32_t *exponent,
                              size_t exponent_bits) {
    CryptoEcFieldElement result;
    CryptoEcFieldElement multiplied;
    size_t bit = exponent_bits;

    crypto_ec_field_one(curve, &result);
    while (bit > 0u) {
        const size_t current = --bit;
        crypto_ec_field_square(curve, &result, &result);
        crypto_ec_field_multiply(curve, &multiplied, &result, base);
        if (((exponent[current / 32u] >> (current & 31u)) & 1u) != 0u) {
            result = multiplied;
        }
    }
    *out = result;
}

void crypto_ec_field_zero(CryptoEcFieldElement *out) {
    memset(out, 0, sizeof(*out));
}

void crypto_ec_field_one(const CryptoEcCurve *curve,
                         CryptoEcFieldElement *out) {
    size_t index;
    crypto_ec_field_zero(out);
    for (index = 0u; index < curve->limbs; ++index) {
        out->limb[index] = curve->montgomery_one[index];
    }
}

void crypto_ec_field_copy(CryptoEcFieldElement *out,
                          const CryptoEcFieldElement *in) {
    *out = *in;
}

void crypto_ec_field_add(const CryptoEcCurve *curve,
                         CryptoEcFieldElement *out,
                         const CryptoEcFieldElement *a,
                         const CryptoEcFieldElement *b) {
    CryptoEcFieldElement sum;
    CryptoEcFieldElement reduced;
    uint64_t carry = 0u;
    size_t index;
    uint32_t borrow;
    uint32_t subtract_mask;

    crypto_ec_field_zero(&sum);
    for (index = 0u; index < curve->limbs; ++index) {
        const uint64_t value =
            (uint64_t)a->limb[index] + b->limb[index] + carry;
        sum.limb[index] = (uint32_t)value;
        carry = value >> 32;
    }
    borrow = field_sub_modulus(curve, reduced.limb, sum.limb);
    subtract_mask = (UINT32_C(0) - (uint32_t)carry) |
                    (UINT32_C(0) - (borrow ^ 1u));
    crypto_ec_field_zero(out);
    for (index = 0u; index < curve->limbs; ++index) {
        out->limb[index] = (reduced.limb[index] & subtract_mask) |
                           (sum.limb[index] & ~subtract_mask);
    }
}

void crypto_ec_field_sub(const CryptoEcCurve *curve,
                         CryptoEcFieldElement *out,
                         const CryptoEcFieldElement *a,
                         const CryptoEcFieldElement *b) {
    CryptoEcFieldElement difference;
    CryptoEcFieldElement corrected;
    uint64_t borrow = 0u;
    size_t index;
    uint32_t correction_mask;

    crypto_ec_field_zero(&difference);
    for (index = 0u; index < curve->limbs; ++index) {
        const uint64_t left = a->limb[index];
        const uint64_t right = b->limb[index];
        const uint64_t value = left - right - borrow;
        difference.limb[index] = (uint32_t)value;
        borrow = left < right + borrow;
    }
    field_add_modulus(curve, corrected.limb, difference.limb);
    correction_mask = UINT32_C(0) - (uint32_t)borrow;
    crypto_ec_field_zero(out);
    for (index = 0u; index < curve->limbs; ++index) {
        out->limb[index] = (corrected.limb[index] & correction_mask) |
                           (difference.limb[index] & ~correction_mask);
    }
}

void crypto_ec_field_negate(const CryptoEcCurve *curve,
                            CryptoEcFieldElement *out,
                            const CryptoEcFieldElement *a) {
    CryptoEcFieldElement zero;
    crypto_ec_field_zero(&zero);
    crypto_ec_field_sub(curve, out, &zero, a);
}

void crypto_ec_field_multiply(const CryptoEcCurve *curve,
                              CryptoEcFieldElement *out,
                              const CryptoEcFieldElement *a,
                              const CryptoEcFieldElement *b) {
    CryptoEcFieldElement result;
    crypto_ec_field_zero(&result);
    field_montgomery_multiply_raw(curve, result.limb, a->limb, b->limb);
    *out = result;
}

void crypto_ec_field_square(const CryptoEcCurve *curve,
                            CryptoEcFieldElement *out,
                            const CryptoEcFieldElement *a) {
    crypto_ec_field_multiply(curve, out, a, a);
}

void crypto_ec_field_invert_fixed(const CryptoEcCurve *curve,
                                  CryptoEcFieldElement *out,
                                  const CryptoEcFieldElement *a) {
    field_power_fixed(curve, out, a, curve->inverse_exponent,
                      curve->field_bits);
}

int crypto_ec_field_square_root_fixed(const CryptoEcCurve *curve,
                                      CryptoEcFieldElement *out,
                                      const CryptoEcFieldElement *a) {
    CryptoEcFieldElement squared;
    CryptoEcFieldElement candidate;
    uint32_t valid_mask;

    field_power_fixed(curve, &candidate, a, curve->square_root_exponent,
                      curve->field_bits);
    crypto_ec_field_square(curve, &squared, &candidate);
    valid_mask = crypto_ec_field_equal_mask(curve, &squared, a);
    crypto_ec_field_select(curve, out, &candidate, &(CryptoEcFieldElement){{0u}},
                           ~valid_mask);
    return valid_mask != 0u;
}

uint32_t crypto_ec_field_equal_mask(const CryptoEcCurve *curve,
                                    const CryptoEcFieldElement *a,
                                    const CryptoEcFieldElement *b) {
    uint32_t difference = 0u;
    size_t index;
    for (index = 0u; index < curve->limbs; ++index) {
        difference |= a->limb[index] ^ b->limb[index];
    }
    return ~field_nonzero_mask(difference);
}

uint32_t crypto_ec_field_zero_mask(const CryptoEcCurve *curve,
                                   const CryptoEcFieldElement *a) {
    CryptoEcFieldElement zero;
    crypto_ec_field_zero(&zero);
    return crypto_ec_field_equal_mask(curve, a, &zero);
}

void crypto_ec_field_select(const CryptoEcCurve *curve,
                            CryptoEcFieldElement *out,
                            const CryptoEcFieldElement *a,
                            const CryptoEcFieldElement *b,
                            uint32_t select_b_mask) {
    size_t index;
    crypto_ec_field_zero(out);
    for (index = 0u; index < curve->limbs; ++index) {
        out->limb[index] = (a->limb[index] & ~select_b_mask) |
                           (b->limb[index] & select_b_mask);
    }
}

LiberaCError crypto_ec_field_from_bytes(const CryptoEcCurve *curve,
                                        CryptoEcFieldElement *out,
                                        const uint8_t *input,
                                        size_t input_length) {
    uint32_t raw[CRYPTO_EC_MAX_LIMBS] = {0u};
    CryptoEcFieldElement standard;
    size_t byte_index;

    if (!curve || !out || !input || input_length != curve->field_bytes) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    for (byte_index = 0u; byte_index < input_length; ++byte_index) {
        const size_t source = input_length - 1u - byte_index;
        raw[byte_index / 4u] |=
            (uint32_t)input[source] << ((byte_index & 3u) * 8u);
    }
    if (field_raw_compare(curve, raw, curve->p) >= 0) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    crypto_ec_field_zero(&standard);
    for (byte_index = 0u; byte_index < curve->limbs; ++byte_index) {
        standard.limb[byte_index] = raw[byte_index];
    }
    field_montgomery_multiply_raw(curve, out->limb, standard.limb,
                                  curve->montgomery_r2);
    return LIBERAC_SUCCESS;
}

void crypto_ec_field_to_bytes(const CryptoEcCurve *curve,
                              uint8_t *output,
                              const CryptoEcFieldElement *in) {
    uint32_t one[CRYPTO_EC_MAX_LIMBS] = {0u};
    uint32_t standard[CRYPTO_EC_MAX_LIMBS] = {0u};
    size_t byte_index;

    one[0] = 1u;
    field_montgomery_multiply_raw(curve, standard, in->limb, one);
    for (byte_index = 0u; byte_index < curve->field_bytes; ++byte_index) {
        const size_t source = curve->field_bytes - 1u - byte_index;
        output[byte_index] =
            (uint8_t)(standard[source / 4u] >> ((source & 3u) * 8u));
    }
}

uint32_t crypto_ec_field_lsb(const CryptoEcCurve *curve,
                             const CryptoEcFieldElement *in) {
    uint32_t one[CRYPTO_EC_MAX_LIMBS] = {0u};
    uint32_t standard[CRYPTO_EC_MAX_LIMBS] = {0u};
    one[0] = 1u;
    field_montgomery_multiply_raw(curve, standard, in->limb, one);
    return standard[0] & 1u;
}
