/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "ecc_internal.h"
#include "Util/Core/secure_zero.h"

#include <string.h>

#define CRYPTO_EC_WIDE_LIMBS (2u * CRYPTO_EC_MAX_LIMBS + 2u)

static uint32_t crypto_ec_ct_zero_mask_u32(uint32_t value) {
    value |= (uint32_t)(0u - value);
    return (uint32_t)(0u - ((value >> 31) ^ 1u));
}

static uint32_t crypto_ec_limbs_sub(uint32_t *out,
                                    const uint32_t *a,
                                    const uint32_t *b,
                                    size_t limbs) {
    uint32_t borrow = 0u;
    size_t i;

    for (i = 0u; i < limbs; ++i) {
        uint64_t subtrahend = (uint64_t)b[i] + (uint64_t)borrow;
        uint64_t minuend = (uint64_t)a[i];
        out[i] = (uint32_t)(minuend - subtrahend);
        borrow = (uint32_t)(minuend < subtrahend);
    }
    return borrow;
}

static uint32_t crypto_ec_limbs_less_than(const uint32_t *a,
                                          const uint32_t *b,
                                          size_t limbs) {
    uint32_t ignored[CRYPTO_EC_MAX_LIMBS];
    uint32_t borrow = crypto_ec_limbs_sub(ignored, a, b, limbs);
    return borrow;
}

static void crypto_ec_montgomery_multiply(const CryptoEcCurve *curve,
                                          uint32_t *out,
                                          const uint32_t *a,
                                          const uint32_t *b) {
    uint32_t product[CRYPTO_EC_WIDE_LIMBS];
    uint32_t reduced[CRYPTO_EC_MAX_LIMBS];
    uint32_t candidate[CRYPTO_EC_MAX_LIMBS];
    size_t n = curve->limbs;
    size_t i;
    size_t j;
    size_t k;
    uint32_t borrow;
    uint32_t high = 0u;
    uint32_t use_candidate;
    uint32_t mask;

    memset(product, 0, sizeof(product));

    /*
     * Fixed-bound schoolbook multiplication.  Carry propagation continues to
     * the end of the public-width buffer instead of terminating when carry is
     * zero, so the loop schedule does not depend on field values.
     */
    for (i = 0u; i < n; ++i) {
        uint64_t carry = 0u;

        for (j = 0u; j < n; ++j) {
            uint64_t accumulator =
                (uint64_t)a[i] * (uint64_t)b[j] +
                (uint64_t)product[i + j] + carry;
            product[i + j] = (uint32_t)accumulator;
            carry = accumulator >> 32;
        }

        for (k = i + n; k < (2u * n + 2u); ++k) {
            uint64_t accumulator = (uint64_t)product[k] + carry;
            product[k] = (uint32_t)accumulator;
            carry = accumulator >> 32;
        }
    }

    /*
     * Word-at-a-time Montgomery REDC with R = 2^(32*n).  Every reduction and
     * carry loop is fixed by the selected curve width.  The factor is
     * -p^(-1) mod 2^32.
     */
    for (i = 0u; i < n; ++i) {
        uint32_t multiplier =
            (uint32_t)((uint64_t)product[i] *
                       (uint64_t)curve->montgomery_factor);
        uint64_t carry = 0u;

        for (j = 0u; j < n; ++j) {
            uint64_t accumulator =
                (uint64_t)product[i + j] +
                (uint64_t)multiplier * (uint64_t)curve->p[j] + carry;
            product[i + j] = (uint32_t)accumulator;
            carry = accumulator >> 32;
        }

        for (k = i + n; k < (2u * n + 2u); ++k) {
            uint64_t accumulator = (uint64_t)product[k] + carry;
            product[k] = (uint32_t)accumulator;
            carry = accumulator >> 32;
        }
    }

    for (i = 0u; i < n; ++i) {
        reduced[i] = product[n + i];
    }
    for (i = n; i < CRYPTO_EC_MAX_LIMBS; ++i) {
        reduced[i] = 0u;
        candidate[i] = 0u;
    }

    borrow = crypto_ec_limbs_sub(candidate, reduced, curve->p, n);
    for (i = 2u * n; i < 2u * n + 2u; ++i) {
        high |= product[i];
    }

    /*
     * REDC produces a value below 2p.  Subtract p when the n-limb result is
     * already at least p, or when an extra high limb represents R + low.
     */
    use_candidate =
        (crypto_ec_ct_zero_mask_u32(high) ^ UINT32_MAX) |
        (uint32_t)(0u - (borrow ^ 1u));
    mask = use_candidate;
    for (i = 0u; i < n; ++i) {
        out[i] = (reduced[i] & ~mask) | (candidate[i] & mask);
    }
    for (i = n; i < CRYPTO_EC_MAX_LIMBS; ++i) {
        out[i] = 0u;
    }
}

static void crypto_ec_field_power_fixed(
    const CryptoEcCurve *curve, CryptoEcFieldElement *out,
    const CryptoEcFieldElement *base, const uint32_t *exponent,
    size_t exponent_bits) {
    CryptoEcFieldElement table[CRYPTO_EC_WINDOW_SIZE];
    CryptoEcFieldElement result;
    size_t windows = (exponent_bits + CRYPTO_EC_WINDOW_BITS - 1u) /
                     CRYPTO_EC_WINDOW_BITS;
    size_t table_index;
    size_t window_index;

    crypto_ec_field_one(curve, &table[0]);
    crypto_ec_field_copy(&table[1], base);
    for (table_index = 2u; table_index < CRYPTO_EC_WINDOW_SIZE;
         ++table_index) {
        crypto_ec_field_multiply(curve, &table[table_index],
                                 &table[table_index - 1u], base);
    }
    crypto_ec_field_one(curve, &result);

    /*
     * The exponent is a public curve constant.  A fixed four-bit window keeps
     * the schedule and table address independent of the secret field input
     * while reducing inversion/square-root multiplications substantially.
     */
    for (window_index = windows; window_index > 0u; --window_index) {
        size_t first_bit =
            (window_index - 1u) * CRYPTO_EC_WINDOW_BITS;
        uint32_t digit =
            (exponent[first_bit / 32u] >>
             (first_bit % 32u)) & 0x0fu;
        unsigned int squaring;

        /*
         * Windows never cross a 32-bit limb boundary because both widths are
         * powers of two and the first bit is a multiple of four.
         */
        for (squaring = 0u; squaring < CRYPTO_EC_WINDOW_BITS;
             ++squaring) {
            crypto_ec_field_square(curve, &result, &result);
        }
        if (digit != 0u) {
            crypto_ec_field_multiply(curve, &result, &result,
                                     &table[digit]);
        }
    }

    crypto_ec_field_copy(out, &result);
    crypto_zeroize(table, sizeof(table));
    crypto_zeroize(&result, sizeof(result));
}

void crypto_ec_field_zero(CryptoEcFieldElement *out) {
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
}

void crypto_ec_field_one(const CryptoEcCurve *curve,
                         CryptoEcFieldElement *out) {
    size_t i;

    if (curve == NULL || out == NULL) {
        return;
    }
    for (i = 0u; i < curve->limbs; ++i) {
        out->limb[i] = curve->montgomery_one[i];
    }
    for (i = curve->limbs; i < CRYPTO_EC_MAX_LIMBS; ++i) {
        out->limb[i] = 0u;
    }
}

void crypto_ec_field_copy(CryptoEcFieldElement *out,
                          const CryptoEcFieldElement *in) {
    if (out != NULL && in != NULL) {
        memcpy(out, in, sizeof(*out));
    }
}

void crypto_ec_field_add(const CryptoEcCurve *curve,
                         CryptoEcFieldElement *out,
                         const CryptoEcFieldElement *a,
                         const CryptoEcFieldElement *b) {
    CryptoEcFieldElement sum;
    CryptoEcFieldElement candidate;
    uint64_t carry = 0u;
    uint32_t borrow;
    uint32_t use_candidate;
    uint32_t mask;
    size_t i;

    for (i = 0u; i < curve->limbs; ++i) {
        uint64_t accumulator =
            (uint64_t)a->limb[i] + (uint64_t)b->limb[i] + carry;
        sum.limb[i] = (uint32_t)accumulator;
        carry = accumulator >> 32;
    }
    for (i = curve->limbs; i < CRYPTO_EC_MAX_LIMBS; ++i) {
        sum.limb[i] = 0u;
        candidate.limb[i] = 0u;
    }

    borrow = crypto_ec_limbs_sub(candidate.limb, sum.limb, curve->p,
                                 curve->limbs);
    use_candidate = (uint32_t)(0u - (uint32_t)carry) |
                    (uint32_t)(0u - (borrow ^ 1u));
    mask = use_candidate;
    for (i = 0u; i < curve->limbs; ++i) {
        out->limb[i] =
            (sum.limb[i] & ~mask) | (candidate.limb[i] & mask);
    }
    for (i = curve->limbs; i < CRYPTO_EC_MAX_LIMBS; ++i) {
        out->limb[i] = 0u;
    }
}

void crypto_ec_field_sub(const CryptoEcCurve *curve,
                         CryptoEcFieldElement *out,
                         const CryptoEcFieldElement *a,
                         const CryptoEcFieldElement *b) {
    CryptoEcFieldElement difference;
    CryptoEcFieldElement corrected;
    uint32_t borrow;
    uint32_t mask;
    uint64_t carry = 0u;
    size_t i;

    borrow = crypto_ec_limbs_sub(difference.limb, a->limb, b->limb,
                                 curve->limbs);
    mask = (uint32_t)(0u - borrow);

    for (i = 0u; i < curve->limbs; ++i) {
        uint64_t accumulator =
            (uint64_t)difference.limb[i] +
            ((uint64_t)curve->p[i] & (uint64_t)mask) + carry;
        corrected.limb[i] = (uint32_t)accumulator;
        carry = accumulator >> 32;
    }
    for (i = curve->limbs; i < CRYPTO_EC_MAX_LIMBS; ++i) {
        corrected.limb[i] = 0u;
    }

    crypto_ec_field_copy(out, &corrected);
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

    crypto_ec_montgomery_multiply(curve, result.limb, a->limb, b->limb);
    crypto_ec_field_copy(out, &result);
}

void crypto_ec_field_square(const CryptoEcCurve *curve,
                            CryptoEcFieldElement *out,
                            const CryptoEcFieldElement *a) {
    crypto_ec_field_multiply(curve, out, a, a);
}

void crypto_ec_field_invert_fixed(const CryptoEcCurve *curve,
                                  CryptoEcFieldElement *out,
                                  const CryptoEcFieldElement *a) {
    crypto_ec_field_power_fixed(curve, out, a, curve->inverse_exponent,
                                curve->field_bits);
}

int crypto_ec_field_square_root_fixed(const CryptoEcCurve *curve,
                                      CryptoEcFieldElement *out,
                                      const CryptoEcFieldElement *a) {
    CryptoEcFieldElement root;
    CryptoEcFieldElement check;
    CryptoEcFieldElement zero;
    uint32_t valid_mask;

    crypto_ec_field_power_fixed(curve, &root, a,
                                curve->square_root_exponent,
                                curve->field_bits);
    crypto_ec_field_square(curve, &check, &root);
    valid_mask = crypto_ec_field_equal_mask(curve, &check, a);
    crypto_ec_field_zero(&zero);
    crypto_ec_field_select(curve, out, &zero, &root, valid_mask);
    return (int)(valid_mask & 1u);
}

uint32_t crypto_ec_field_equal_mask(const CryptoEcCurve *curve,
                                    const CryptoEcFieldElement *a,
                                    const CryptoEcFieldElement *b) {
    uint32_t difference = 0u;
    size_t i;

    for (i = 0u; i < curve->limbs; ++i) {
        difference |= a->limb[i] ^ b->limb[i];
    }
    return crypto_ec_ct_zero_mask_u32(difference);
}

uint32_t crypto_ec_field_zero_mask(const CryptoEcCurve *curve,
                                   const CryptoEcFieldElement *a) {
    uint32_t aggregate = 0u;
    size_t i;

    for (i = 0u; i < curve->limbs; ++i) {
        aggregate |= a->limb[i];
    }
    return crypto_ec_ct_zero_mask_u32(aggregate);
}

void crypto_ec_field_select(const CryptoEcCurve *curve,
                            CryptoEcFieldElement *out,
                            const CryptoEcFieldElement *a,
                            const CryptoEcFieldElement *b,
                            uint32_t select_b_mask) {
    size_t i;

    for (i = 0u; i < curve->limbs; ++i) {
        out->limb[i] =
            (a->limb[i] & ~select_b_mask) |
            (b->limb[i] & select_b_mask);
    }
    for (i = curve->limbs; i < CRYPTO_EC_MAX_LIMBS; ++i) {
        out->limb[i] = 0u;
    }
}

LiberaCError crypto_ec_field_from_bytes(const CryptoEcCurve *curve,
                                        CryptoEcFieldElement *out,
                                        const uint8_t *input,
                                        size_t input_length) {
    CryptoEcFieldElement normal;
    CryptoEcFieldElement r2;
    size_t i;

    if (curve == NULL || out == NULL ||
        (input == NULL && input_length != 0u) ||
        input_length != curve->field_bytes) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_ec_field_zero(&normal);
    for (i = 0u; i < input_length; ++i) {
        size_t source = input_length - 1u - i;
        size_t limb_index = i / 4u;
        size_t shift = (i % 4u) * 8u;
        normal.limb[limb_index] |=
            (uint32_t)input[source] << shift;
    }

    if (crypto_ec_limbs_less_than(normal.limb, curve->p,
                                  curve->limbs) == 0u) {
        crypto_ec_field_zero(out);
        return LIBERAC_ERROR_INVALID_KEY;
    }

    for (i = 0u; i < curve->limbs; ++i) {
        r2.limb[i] = curve->montgomery_r2[i];
    }
    for (i = curve->limbs; i < CRYPTO_EC_MAX_LIMBS; ++i) {
        r2.limb[i] = 0u;
    }
    crypto_ec_field_multiply(curve, out, &normal, &r2);
    return LIBERAC_SUCCESS;
}

void crypto_ec_field_to_bytes(const CryptoEcCurve *curve,
                              uint8_t *output,
                              const CryptoEcFieldElement *in) {
    CryptoEcFieldElement normal_one;
    CryptoEcFieldElement normal;
    size_t i;

    crypto_ec_field_zero(&normal_one);
    normal_one.limb[0] = 1u;
    crypto_ec_field_multiply(curve, &normal, in, &normal_one);

    for (i = 0u; i < curve->field_bytes; ++i) {
        size_t destination = curve->field_bytes - 1u - i;
        output[destination] =
            (uint8_t)(normal.limb[i / 4u] >> ((i % 4u) * 8u));
    }
}

uint32_t crypto_ec_field_lsb(const CryptoEcCurve *curve,
                             const CryptoEcFieldElement *in) {
    CryptoEcFieldElement normal_one;
    CryptoEcFieldElement normal;

    crypto_ec_field_zero(&normal_one);
    normal_one.limb[0] = 1u;
    crypto_ec_field_multiply(curve, &normal, in, &normal_one);
    return normal.limb[0] & 1u;
}
