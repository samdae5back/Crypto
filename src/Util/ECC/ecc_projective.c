/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "ecc_internal.h"
#include "Util/Core/secure_zero.h"

#include <string.h>

static void crypto_ec_field_twice(const CryptoEcCurve *curve,
                                  CryptoEcFieldElement *out,
                                  const CryptoEcFieldElement *in) {
    crypto_ec_field_add(curve, out, in, in);
}

static void crypto_ec_field_three_times(const CryptoEcCurve *curve,
                                        CryptoEcFieldElement *out,
                                        const CryptoEcFieldElement *in) {
    CryptoEcFieldElement twice;

    crypto_ec_field_twice(curve, &twice, in);
    crypto_ec_field_add(curve, out, &twice, in);
}

static void crypto_ec_field_four_times(const CryptoEcCurve *curve,
                                       CryptoEcFieldElement *out,
                                       const CryptoEcFieldElement *in) {
    CryptoEcFieldElement twice;

    crypto_ec_field_twice(curve, &twice, in);
    crypto_ec_field_twice(curve, out, &twice);
}

static void crypto_ec_field_eight_times(const CryptoEcCurve *curve,
                                        CryptoEcFieldElement *out,
                                        const CryptoEcFieldElement *in) {
    CryptoEcFieldElement twice;
    CryptoEcFieldElement four_times;

    crypto_ec_field_twice(curve, &twice, in);
    crypto_ec_field_twice(curve, &four_times, &twice);
    crypto_ec_field_twice(curve, out, &four_times);
}

static void crypto_ec_jacobian_canonicalize(
    const CryptoEcCurve *curve, CryptoEcJacobianPoint *point) {
    CryptoEcFieldElement zero;
    CryptoEcFieldElement one;
    uint32_t infinity_mask =
        crypto_ec_field_zero_mask(curve, &point->z);

    crypto_ec_field_zero(&zero);
    crypto_ec_field_one(curve, &one);
    crypto_ec_field_select(curve, &point->x, &point->x, &zero,
                           infinity_mask);
    crypto_ec_field_select(curve, &point->y, &point->y, &one,
                           infinity_mask);
    crypto_ec_field_select(curve, &point->z, &point->z, &zero,
                           infinity_mask);
}

void crypto_ec_affine_set_infinity(CryptoEcAffinePoint *point) {
    if (point == NULL) {
        return;
    }
    crypto_ec_field_zero(&point->x);
    crypto_ec_field_zero(&point->y);
    point->infinity = 1u;
}

void crypto_ec_jacobian_set_infinity(const CryptoEcCurve *curve,
                                     CryptoEcJacobianPoint *point) {
    if (curve == NULL || point == NULL) {
        return;
    }
    crypto_ec_field_zero(&point->x);
    crypto_ec_field_one(curve, &point->y);
    crypto_ec_field_zero(&point->z);
}

void crypto_ec_affine_generator(const CryptoEcCurve *curve,
                                CryptoEcAffinePoint *point) {
    size_t i;

    if (curve == NULL || point == NULL) {
        return;
    }
    for (i = 0u; i < curve->limbs; ++i) {
        point->x.limb[i] = curve->generator_x[i];
        point->y.limb[i] = curve->generator_y[i];
    }
    for (i = curve->limbs; i < CRYPTO_EC_MAX_LIMBS; ++i) {
        point->x.limb[i] = 0u;
        point->y.limb[i] = 0u;
    }
    point->infinity = 0u;
}

int crypto_ec_affine_is_infinity(const CryptoEcAffinePoint *point) {
    return point != NULL && point->infinity != 0u;
}

int crypto_ec_jacobian_is_infinity(const CryptoEcCurve *curve,
                                   const CryptoEcJacobianPoint *point) {
    if (curve == NULL || point == NULL) {
        return 0;
    }
    return (int)(crypto_ec_field_zero_mask(curve, &point->z) & 1u);
}

int crypto_ec_affine_is_on_curve(const CryptoEcCurve *curve,
                                 const CryptoEcAffinePoint *point) {
    CryptoEcFieldElement left;
    CryptoEcFieldElement x_squared;
    CryptoEcFieldElement right;
    CryptoEcFieldElement three_x;
    CryptoEcFieldElement b;
    size_t i;

    if (curve == NULL || point == NULL) {
        return 0;
    }
    if (point->infinity != 0u) {
        return 1;
    }

    crypto_ec_field_square(curve, &left, &point->y);
    crypto_ec_field_square(curve, &x_squared, &point->x);
    crypto_ec_field_multiply(curve, &right, &x_squared, &point->x);
    crypto_ec_field_three_times(curve, &three_x, &point->x);
    crypto_ec_field_sub(curve, &right, &right, &three_x);

    for (i = 0u; i < curve->limbs; ++i) {
        b.limb[i] = curve->b[i];
    }
    for (i = curve->limbs; i < CRYPTO_EC_MAX_LIMBS; ++i) {
        b.limb[i] = 0u;
    }
    crypto_ec_field_add(curve, &right, &right, &b);

    return (int)(crypto_ec_field_equal_mask(curve, &left, &right) & 1u);
}

void crypto_ec_affine_to_jacobian(const CryptoEcCurve *curve,
                                  CryptoEcJacobianPoint *out,
                                  const CryptoEcAffinePoint *in) {
    if (curve == NULL || out == NULL || in == NULL) {
        return;
    }
    if (in->infinity != 0u) {
        crypto_ec_jacobian_set_infinity(curve, out);
        return;
    }

    crypto_ec_field_copy(&out->x, &in->x);
    crypto_ec_field_copy(&out->y, &in->y);
    crypto_ec_field_one(curve, &out->z);
}

void crypto_ec_jacobian_to_affine(const CryptoEcCurve *curve,
                                  CryptoEcAffinePoint *out,
                                  const CryptoEcJacobianPoint *in) {
    CryptoEcFieldElement z_inverse;
    CryptoEcFieldElement z_inverse_squared;
    CryptoEcFieldElement z_inverse_cubed;
    CryptoEcFieldElement x;
    CryptoEcFieldElement y;
    CryptoEcFieldElement zero;
    uint32_t infinity_mask;

    if (curve == NULL || out == NULL || in == NULL) {
        return;
    }

    infinity_mask = crypto_ec_field_zero_mask(curve, &in->z);
    crypto_ec_field_invert_fixed(curve, &z_inverse, &in->z);
    crypto_ec_field_square(curve, &z_inverse_squared, &z_inverse);
    crypto_ec_field_multiply(curve, &z_inverse_cubed,
                             &z_inverse_squared, &z_inverse);
    crypto_ec_field_multiply(curve, &x, &in->x, &z_inverse_squared);
    crypto_ec_field_multiply(curve, &y, &in->y, &z_inverse_cubed);

    crypto_ec_field_zero(&zero);
    crypto_ec_field_select(curve, &out->x, &x, &zero, infinity_mask);
    crypto_ec_field_select(curve, &out->y, &y, &zero, infinity_mask);
    out->infinity = infinity_mask & 1u;
}

void crypto_ec_jacobian_double(const CryptoEcCurve *curve,
                               CryptoEcJacobianPoint *out,
                               const CryptoEcJacobianPoint *point) {
    CryptoEcFieldElement delta;
    CryptoEcFieldElement gamma;
    CryptoEcFieldElement beta;
    CryptoEcFieldElement alpha;
    CryptoEcFieldElement gamma_squared;
    CryptoEcFieldElement temporary1;
    CryptoEcFieldElement temporary2;
    CryptoEcFieldElement beta_four;
    CryptoEcFieldElement beta_eight;
    CryptoEcFieldElement gamma_eight;
    CryptoEcJacobianPoint result;

    /*
     * Jacobian doubling specialized for a = -3:
     *   delta = Z^2
     *   gamma = Y^2
     *   beta  = X*gamma
     *   alpha = 3*(X-delta)*(X+delta)
     */
    crypto_ec_field_square(curve, &delta, &point->z);
    crypto_ec_field_square(curve, &gamma, &point->y);
    crypto_ec_field_multiply(curve, &beta, &point->x, &gamma);
    crypto_ec_field_sub(curve, &temporary1, &point->x, &delta);
    crypto_ec_field_add(curve, &temporary2, &point->x, &delta);
    crypto_ec_field_multiply(curve, &alpha, &temporary1, &temporary2);
    crypto_ec_field_three_times(curve, &alpha, &alpha);

    crypto_ec_field_square(curve, &result.x, &alpha);
    crypto_ec_field_eight_times(curve, &beta_eight, &beta);
    crypto_ec_field_sub(curve, &result.x, &result.x, &beta_eight);

    crypto_ec_field_add(curve, &temporary1, &point->y, &point->z);
    crypto_ec_field_square(curve, &result.z, &temporary1);
    crypto_ec_field_sub(curve, &result.z, &result.z, &gamma);
    crypto_ec_field_sub(curve, &result.z, &result.z, &delta);

    crypto_ec_field_four_times(curve, &beta_four, &beta);
    crypto_ec_field_sub(curve, &temporary1, &beta_four, &result.x);
    crypto_ec_field_multiply(curve, &result.y, &alpha, &temporary1);
    crypto_ec_field_square(curve, &gamma_squared, &gamma);
    crypto_ec_field_eight_times(curve, &gamma_eight, &gamma_squared);
    crypto_ec_field_sub(curve, &result.y, &result.y, &gamma_eight);

    crypto_ec_jacobian_canonicalize(curve, &result);
    memcpy(out, &result, sizeof(result));
}

static void crypto_ec_jacobian_add_generic(
    const CryptoEcCurve *curve, CryptoEcJacobianPoint *generic,
    CryptoEcFieldElement *h, CryptoEcFieldElement *r_difference,
    const CryptoEcJacobianPoint *a, const CryptoEcJacobianPoint *b) {
    CryptoEcFieldElement z1_squared;
    CryptoEcFieldElement z2_squared;
    CryptoEcFieldElement u1;
    CryptoEcFieldElement u2;
    CryptoEcFieldElement s1;
    CryptoEcFieldElement s2;
    CryptoEcFieldElement r_twice;
    CryptoEcFieldElement i_value;
    CryptoEcFieldElement j_value;
    CryptoEcFieldElement v_value;
    CryptoEcFieldElement temporary1;
    CryptoEcFieldElement temporary2;

    crypto_ec_field_square(curve, &z1_squared, &a->z);
    crypto_ec_field_square(curve, &z2_squared, &b->z);
    crypto_ec_field_multiply(curve, &u1, &a->x, &z2_squared);
    crypto_ec_field_multiply(curve, &u2, &b->x, &z1_squared);

    crypto_ec_field_multiply(curve, &temporary1, &b->z, &z2_squared);
    crypto_ec_field_multiply(curve, &s1, &a->y, &temporary1);
    crypto_ec_field_multiply(curve, &temporary1, &a->z, &z1_squared);
    crypto_ec_field_multiply(curve, &s2, &b->y, &temporary1);

    crypto_ec_field_sub(curve, h, &u2, &u1);
    crypto_ec_field_sub(curve, r_difference, &s2, &s1);
    crypto_ec_field_twice(curve, &r_twice, r_difference);

    crypto_ec_field_twice(curve, &temporary1, h);
    crypto_ec_field_square(curve, &i_value, &temporary1);
    crypto_ec_field_multiply(curve, &j_value, h, &i_value);
    crypto_ec_field_multiply(curve, &v_value, &u1, &i_value);

    crypto_ec_field_square(curve, &generic->x, &r_twice);
    crypto_ec_field_sub(curve, &generic->x, &generic->x, &j_value);
    crypto_ec_field_twice(curve, &temporary1, &v_value);
    crypto_ec_field_sub(curve, &generic->x, &generic->x, &temporary1);

    crypto_ec_field_sub(curve, &temporary1, &v_value, &generic->x);
    crypto_ec_field_multiply(curve, &generic->y, &r_twice, &temporary1);
    crypto_ec_field_multiply(curve, &temporary2, &s1, &j_value);
    crypto_ec_field_twice(curve, &temporary2, &temporary2);
    crypto_ec_field_sub(curve, &generic->y, &generic->y, &temporary2);

    crypto_ec_field_add(curve, &temporary1, &a->z, &b->z);
    crypto_ec_field_square(curve, &generic->z, &temporary1);
    crypto_ec_field_sub(curve, &generic->z, &generic->z, &z1_squared);
    crypto_ec_field_sub(curve, &generic->z, &generic->z, &z2_squared);
    crypto_ec_field_multiply(curve, &generic->z, &generic->z, h);
}

void crypto_ec_jacobian_add_vartime(const CryptoEcCurve *curve,
                                    CryptoEcJacobianPoint *out,
                                    const CryptoEcJacobianPoint *a,
                                    const CryptoEcJacobianPoint *b) {
    CryptoEcJacobianPoint generic;
    CryptoEcFieldElement h;
    CryptoEcFieldElement r_difference;

    /*
     * This path is used only when the point/scalar relationship is public.
     * Public exceptional cases are handled with branches so ordinary additions
     * do not pay for an unused doubling candidate.
     */
    if (crypto_ec_jacobian_is_infinity(curve, a)) {
        memcpy(out, b, sizeof(*out));
        crypto_ec_jacobian_canonicalize(curve, out);
        return;
    }
    if (crypto_ec_jacobian_is_infinity(curve, b)) {
        memcpy(out, a, sizeof(*out));
        crypto_ec_jacobian_canonicalize(curve, out);
        return;
    }

    crypto_ec_jacobian_add_generic(curve, &generic, &h, &r_difference,
                                   a, b);
    if (crypto_ec_field_zero_mask(curve, &h) == UINT32_MAX) {
        if (crypto_ec_field_zero_mask(curve, &r_difference) ==
            UINT32_MAX) {
            crypto_ec_jacobian_double(curve, out, a);
        } else {
            crypto_ec_jacobian_set_infinity(curve, out);
        }
        return;
    }

    crypto_ec_jacobian_canonicalize(curve, &generic);
    memcpy(out, &generic, sizeof(generic));
}

void crypto_ec_jacobian_add_complete(const CryptoEcCurve *curve,
                                     CryptoEcJacobianPoint *out,
                                     const CryptoEcJacobianPoint *a,
                                     const CryptoEcJacobianPoint *b) {
    CryptoEcFieldElement h;
    CryptoEcFieldElement r_difference;
    CryptoEcJacobianPoint generic;
    CryptoEcJacobianPoint doubled;
    CryptoEcJacobianPoint infinity;
    CryptoEcJacobianPoint result;
    uint32_t a_infinity;
    uint32_t b_infinity;
    uint32_t h_zero;
    uint32_t r_zero;
    uint32_t same_point;
    uint32_t opposite_points;

    /*
     * The ordinary Jacobian formula is supplemented with precomputed doubling
     * and infinity candidates, then resolved by masks.  This gives complete
     * function behavior without scalar-dependent branches or table indices.
     */
    crypto_ec_jacobian_add_generic(curve, &generic, &h, &r_difference,
                                   a, b);
    crypto_ec_jacobian_double(curve, &doubled, a);
    crypto_ec_jacobian_set_infinity(curve, &infinity);

    a_infinity = crypto_ec_field_zero_mask(curve, &a->z);
    b_infinity = crypto_ec_field_zero_mask(curve, &b->z);
    h_zero = crypto_ec_field_zero_mask(curve, &h);
    r_zero = crypto_ec_field_zero_mask(curve, &r_difference);
    same_point = h_zero & r_zero;
    opposite_points = h_zero & ~r_zero;

    memcpy(&result, &generic, sizeof(result));
    crypto_ec_jacobian_select(curve, &result, &result, &infinity,
                              opposite_points);
    crypto_ec_jacobian_select(curve, &result, &result, &doubled,
                              same_point);
    crypto_ec_jacobian_select(curve, &result, &result, a, b_infinity);
    crypto_ec_jacobian_select(curve, &result, &result, b, a_infinity);
    crypto_ec_jacobian_canonicalize(curve, &result);
    memcpy(out, &result, sizeof(result));
}

void crypto_ec_jacobian_select(const CryptoEcCurve *curve,
                               CryptoEcJacobianPoint *out,
                               const CryptoEcJacobianPoint *a,
                               const CryptoEcJacobianPoint *b,
                               uint32_t select_b_mask) {
    crypto_ec_field_select(curve, &out->x, &a->x, &b->x,
                           select_b_mask);
    crypto_ec_field_select(curve, &out->y, &a->y, &b->y,
                           select_b_mask);
    crypto_ec_field_select(curve, &out->z, &a->z, &b->z,
                           select_b_mask);
}

void crypto_ec_jacobian_cswap(const CryptoEcCurve *curve,
                              CryptoEcJacobianPoint *a,
                              CryptoEcJacobianPoint *b,
                              uint32_t swap_mask) {
    size_t i;

    for (i = 0u; i < curve->limbs; ++i) {
        uint32_t temporary;

        temporary = (a->x.limb[i] ^ b->x.limb[i]) & swap_mask;
        a->x.limb[i] ^= temporary;
        b->x.limb[i] ^= temporary;

        temporary = (a->y.limb[i] ^ b->y.limb[i]) & swap_mask;
        a->y.limb[i] ^= temporary;
        b->y.limb[i] ^= temporary;

        temporary = (a->z.limb[i] ^ b->z.limb[i]) & swap_mask;
        a->z.limb[i] ^= temporary;
        b->z.limb[i] ^= temporary;
    }
}

LiberaCError crypto_ec_scalar_multiply_vartime(
    const CryptoEcCurve *curve, CryptoEcAffinePoint *out,
    const CryptoEcAffinePoint *point, const uint8_t *scalar,
    size_t scalar_length) {
    CryptoEcJacobianPoint table[CRYPTO_EC_WINDOW_SIZE];
    CryptoEcJacobianPoint base;
    CryptoEcJacobianPoint result;
    size_t byte_index;
    size_t table_index;
    unsigned int half;
    int started = 0;

    if (curve == NULL || out == NULL || point == NULL ||
        scalar == NULL || scalar_length != curve->scalar_bytes) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_ec_affine_to_jacobian(curve, &base, point);
    crypto_ec_jacobian_set_infinity(curve, &table[0]);
    memcpy(&table[1], &base, sizeof(base));
    for (table_index = 2u; table_index < CRYPTO_EC_WINDOW_SIZE;
         ++table_index) {
        crypto_ec_jacobian_add_vartime(curve, &table[table_index],
                                        &table[table_index - 1u], &base);
    }
    crypto_ec_jacobian_set_infinity(curve, &result);

    for (byte_index = 0u; byte_index < scalar_length; ++byte_index) {
        for (half = 0u; half < 2u; ++half) {
            uint32_t digit =
                half == 0u ? (uint32_t)(scalar[byte_index] >> 4)
                           : (uint32_t)(scalar[byte_index] & 0x0fu);
            unsigned int doubling;

            if (!started) {
                if (digit == 0u) {
                    continue;
                }
                memcpy(&result, &table[digit], sizeof(result));
                started = 1;
                continue;
            }

            for (doubling = 0u; doubling < CRYPTO_EC_WINDOW_BITS;
                 ++doubling) {
                crypto_ec_jacobian_double(curve, &result, &result);
            }
            if (digit != 0u) {
                crypto_ec_jacobian_add_vartime(curve, &result, &result,
                                               &table[digit]);
            }
        }
    }

    crypto_ec_jacobian_to_affine(curve, out, &result);
    crypto_zeroize(table, sizeof(table));
    crypto_zeroize(&base, sizeof(base));
    crypto_zeroize(&result, sizeof(result));
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_ec_scalar_multiply_ct(
    const CryptoEcCurve *curve, CryptoEcAffinePoint *out,
    const CryptoEcAffinePoint *point, const uint8_t *scalar,
    size_t scalar_length) {
    CryptoEcJacobianPoint r0;
    CryptoEcJacobianPoint r1;
    CryptoEcJacobianPoint sum;
    CryptoEcJacobianPoint doubled;
    size_t byte_index;
    unsigned int bit_index;

    if (curve == NULL || out == NULL || point == NULL ||
        scalar == NULL || scalar_length != curve->scalar_bytes) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_ec_jacobian_set_infinity(curve, &r0);
    crypto_ec_affine_to_jacobian(curve, &r1, point);

    /*
     * Montgomery-ladder state invariant: r1 = r0 + P.  Each fixed-width bit
     * performs exactly one complete addition, one doubling, and two masked
     * swaps.  Scalar bits never select a table entry or a control-flow path.
     */
    for (byte_index = 0u; byte_index < scalar_length; ++byte_index) {
        for (bit_index = 0u; bit_index < 8u; ++bit_index) {
            uint32_t bit =
                ((uint32_t)scalar[byte_index] >> (7u - bit_index)) & 1u;
            uint32_t mask = (uint32_t)(0u - bit);

            crypto_ec_jacobian_cswap(curve, &r0, &r1, mask);
            crypto_ec_jacobian_add_complete(curve, &sum, &r0, &r1);
            crypto_ec_jacobian_double(curve, &doubled, &r0);
            memcpy(&r1, &sum, sizeof(r1));
            memcpy(&r0, &doubled, sizeof(r0));
            crypto_ec_jacobian_cswap(curve, &r0, &r1, mask);
        }
    }

    crypto_ec_jacobian_to_affine(curve, out, &r0);
    crypto_zeroize(&r0, sizeof(r0));
    crypto_zeroize(&r1, sizeof(r1));
    crypto_zeroize(&sum, sizeof(sum));
    crypto_zeroize(&doubled, sizeof(doubled));
    return LIBERAC_SUCCESS;
}

int crypto_ec_scalar_is_valid_ct(const CryptoEcCurve *curve,
                                 const uint8_t *scalar,
                                 size_t scalar_length) {
    uint32_t value[CRYPTO_EC_MAX_LIMBS];
    uint32_t difference[CRYPTO_EC_MAX_LIMBS];
    uint32_t aggregate = 0u;
    uint32_t borrow = 0u;
    uint32_t nonzero;
    size_t i;

    if (curve == NULL || scalar == NULL ||
        scalar_length != curve->scalar_bytes) {
        return 0;
    }

    memset(value, 0, sizeof(value));
    memset(difference, 0, sizeof(difference));
    for (i = 0u; i < scalar_length; ++i) {
        size_t source = scalar_length - 1u - i;
        value[i / 4u] |=
            (uint32_t)scalar[source] << ((i % 4u) * 8u);
    }

    for (i = 0u; i < curve->limbs; ++i) {
        uint64_t subtrahend =
            (uint64_t)curve->order[i] + (uint64_t)borrow;
        uint64_t minuend = (uint64_t)value[i];
        difference[i] = (uint32_t)(minuend - subtrahend);
        borrow = (uint32_t)(minuend < subtrahend);
        aggregate |= value[i];
    }

    nonzero = ((aggregate | (uint32_t)(0u - aggregate)) >> 31) & 1u;
    crypto_zeroize(value, sizeof(value));
    crypto_zeroize(difference, sizeof(difference));
    return (int)(nonzero & borrow);
}
