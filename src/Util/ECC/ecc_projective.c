/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "ecc_internal.h"

static void field_double(const CryptoEcCurve *curve,
                         CryptoEcFieldElement *out,
                         const CryptoEcFieldElement *value) {
    crypto_ec_field_add(curve, out, value, value);
}

static void field_triple(const CryptoEcCurve *curve,
                         CryptoEcFieldElement *out,
                         const CryptoEcFieldElement *value) {
    CryptoEcFieldElement doubled;
    field_double(curve, &doubled, value);
    crypto_ec_field_add(curve, out, &doubled, value);
}

static void field_multiply_small(const CryptoEcCurve *curve,
                                 CryptoEcFieldElement *out,
                                 const CryptoEcFieldElement *value,
                                 unsigned multiplier) {
    CryptoEcFieldElement result;
    unsigned index;
    crypto_ec_field_zero(&result);
    for (index = 0u; index < multiplier; ++index) {
        crypto_ec_field_add(curve, &result, &result, value);
    }
    *out = result;
}

void crypto_ec_affine_set_infinity(CryptoEcAffinePoint *point) {
    memset(point, 0, sizeof(*point));
    point->infinity = 1u;
}

void crypto_ec_jacobian_set_infinity(const CryptoEcCurve *curve,
                                     CryptoEcJacobianPoint *point) {
    crypto_ec_field_zero(&point->x);
    crypto_ec_field_one(curve, &point->y);
    crypto_ec_field_zero(&point->z);
}

void crypto_ec_affine_generator(const CryptoEcCurve *curve,
                                CryptoEcAffinePoint *point) {
    size_t index;
    crypto_ec_affine_set_infinity(point);
    crypto_ec_field_zero(&point->x);
    crypto_ec_field_zero(&point->y);
    for (index = 0u; index < curve->limbs; ++index) {
        point->x.limb[index] = curve->generator_x[index];
        point->y.limb[index] = curve->generator_y[index];
    }
    point->infinity = 0u;
}

int crypto_ec_affine_is_infinity(const CryptoEcAffinePoint *point) {
    return point->infinity != 0u;
}

int crypto_ec_jacobian_is_infinity(const CryptoEcCurve *curve,
                                   const CryptoEcJacobianPoint *point) {
    return crypto_ec_field_zero_mask(curve, &point->z) != 0u;
}

int crypto_ec_affine_is_on_curve(const CryptoEcCurve *curve,
                                 const CryptoEcAffinePoint *point) {
    CryptoEcFieldElement y_squared;
    CryptoEcFieldElement x_squared;
    CryptoEcFieldElement x_cubed;
    CryptoEcFieldElement three_x;
    CryptoEcFieldElement right;
    CryptoEcFieldElement b;
    size_t index;

    if (!curve || !point) {
        return 0;
    }
    if (point->infinity != 0u) {
        return 1;
    }
    crypto_ec_field_zero(&b);
    for (index = 0u; index < curve->limbs; ++index) {
        b.limb[index] = curve->b[index];
    }
    crypto_ec_field_square(curve, &y_squared, &point->y);
    crypto_ec_field_square(curve, &x_squared, &point->x);
    crypto_ec_field_multiply(curve, &x_cubed, &x_squared, &point->x);
    field_triple(curve, &three_x, &point->x);
    crypto_ec_field_sub(curve, &right, &x_cubed, &three_x);
    crypto_ec_field_add(curve, &right, &right, &b);
    return crypto_ec_field_equal_mask(curve, &y_squared, &right) != 0u;
}

void crypto_ec_affine_to_jacobian(const CryptoEcCurve *curve,
                                  CryptoEcJacobianPoint *out,
                                  const CryptoEcAffinePoint *in) {
    CryptoEcJacobianPoint result;
    result.x = in->x;
    result.y = in->y;
    crypto_ec_field_one(curve, &result.z);
    if (in->infinity != 0u) {
        crypto_ec_jacobian_set_infinity(curve, &result);
    }
    *out = result;
}

void crypto_ec_jacobian_to_affine(const CryptoEcCurve *curve,
                                  CryptoEcAffinePoint *out,
                                  const CryptoEcJacobianPoint *in) {
    CryptoEcFieldElement z_inverse;
    CryptoEcFieldElement z_inverse_squared;
    CryptoEcFieldElement z_inverse_cubed;
    CryptoEcAffinePoint result;

    if (crypto_ec_jacobian_is_infinity(curve, in)) {
        crypto_ec_affine_set_infinity(out);
        return;
    }
    crypto_ec_field_invert_fixed(curve, &z_inverse, &in->z);
    crypto_ec_field_square(curve, &z_inverse_squared, &z_inverse);
    crypto_ec_field_multiply(curve, &z_inverse_cubed, &z_inverse_squared,
                             &z_inverse);
    crypto_ec_field_multiply(curve, &result.x, &in->x, &z_inverse_squared);
    crypto_ec_field_multiply(curve, &result.y, &in->y, &z_inverse_cubed);
    result.infinity = 0u;
    *out = result;
}

void crypto_ec_jacobian_double(const CryptoEcCurve *curve,
                               CryptoEcJacobianPoint *out,
                               const CryptoEcJacobianPoint *point) {
    CryptoEcFieldElement delta;
    CryptoEcFieldElement gamma;
    CryptoEcFieldElement beta;
    CryptoEcFieldElement alpha;
    CryptoEcFieldElement x_minus_delta;
    CryptoEcFieldElement x_plus_delta;
    CryptoEcFieldElement alpha_squared;
    CryptoEcFieldElement eight_beta;
    CryptoEcFieldElement four_beta;
    CryptoEcFieldElement gamma_squared;
    CryptoEcFieldElement eight_gamma_squared;
    CryptoEcFieldElement temporary;
    CryptoEcJacobianPoint result;
    CryptoEcJacobianPoint infinity;
    uint32_t infinity_mask;

    crypto_ec_field_square(curve, &delta, &point->z);
    crypto_ec_field_square(curve, &gamma, &point->y);
    crypto_ec_field_multiply(curve, &beta, &point->x, &gamma);
    crypto_ec_field_sub(curve, &x_minus_delta, &point->x, &delta);
    crypto_ec_field_add(curve, &x_plus_delta, &point->x, &delta);
    crypto_ec_field_multiply(curve, &alpha, &x_minus_delta, &x_plus_delta);
    field_triple(curve, &alpha, &alpha);

    crypto_ec_field_square(curve, &alpha_squared, &alpha);
    field_multiply_small(curve, &eight_beta, &beta, 8u);
    crypto_ec_field_sub(curve, &result.x, &alpha_squared, &eight_beta);

    crypto_ec_field_add(curve, &temporary, &point->y, &point->z);
    crypto_ec_field_square(curve, &result.z, &temporary);
    crypto_ec_field_sub(curve, &result.z, &result.z, &gamma);
    crypto_ec_field_sub(curve, &result.z, &result.z, &delta);

    field_multiply_small(curve, &four_beta, &beta, 4u);
    crypto_ec_field_sub(curve, &temporary, &four_beta, &result.x);
    crypto_ec_field_multiply(curve, &result.y, &alpha, &temporary);
    crypto_ec_field_square(curve, &gamma_squared, &gamma);
    field_multiply_small(curve, &eight_gamma_squared, &gamma_squared, 8u);
    crypto_ec_field_sub(curve, &result.y, &result.y, &eight_gamma_squared);

    crypto_ec_jacobian_set_infinity(curve, &infinity);
    infinity_mask = crypto_ec_field_zero_mask(curve, &point->z) |
                    crypto_ec_field_zero_mask(curve, &point->y);
    crypto_ec_jacobian_select(curve, out, &result, &infinity, infinity_mask);
}

static void jacobian_add_generic(const CryptoEcCurve *curve,
                                 CryptoEcJacobianPoint *out,
                                 const CryptoEcJacobianPoint *a,
                                 const CryptoEcJacobianPoint *b,
                                 CryptoEcFieldElement *h_out,
                                 CryptoEcFieldElement *r_out) {
    CryptoEcFieldElement z1_squared;
    CryptoEcFieldElement z2_squared;
    CryptoEcFieldElement u1;
    CryptoEcFieldElement u2;
    CryptoEcFieldElement z1_cubed;
    CryptoEcFieldElement z2_cubed;
    CryptoEcFieldElement s1;
    CryptoEcFieldElement s2;
    CryptoEcFieldElement h;
    CryptoEcFieldElement doubled_h;
    CryptoEcFieldElement i;
    CryptoEcFieldElement j;
    CryptoEcFieldElement r;
    CryptoEcFieldElement v;
    CryptoEcFieldElement two_v;
    CryptoEcFieldElement temporary;
    CryptoEcJacobianPoint result;

    crypto_ec_field_square(curve, &z1_squared, &a->z);
    crypto_ec_field_square(curve, &z2_squared, &b->z);
    crypto_ec_field_multiply(curve, &u1, &a->x, &z2_squared);
    crypto_ec_field_multiply(curve, &u2, &b->x, &z1_squared);
    crypto_ec_field_multiply(curve, &z1_cubed, &z1_squared, &a->z);
    crypto_ec_field_multiply(curve, &z2_cubed, &z2_squared, &b->z);
    crypto_ec_field_multiply(curve, &s1, &a->y, &z2_cubed);
    crypto_ec_field_multiply(curve, &s2, &b->y, &z1_cubed);

    crypto_ec_field_sub(curve, &h, &u2, &u1);
    field_double(curve, &doubled_h, &h);
    crypto_ec_field_square(curve, &i, &doubled_h);
    crypto_ec_field_multiply(curve, &j, &h, &i);
    crypto_ec_field_sub(curve, &r, &s2, &s1);
    field_double(curve, &r, &r);
    crypto_ec_field_multiply(curve, &v, &u1, &i);

    crypto_ec_field_square(curve, &result.x, &r);
    crypto_ec_field_sub(curve, &result.x, &result.x, &j);
    field_double(curve, &two_v, &v);
    crypto_ec_field_sub(curve, &result.x, &result.x, &two_v);

    crypto_ec_field_sub(curve, &temporary, &v, &result.x);
    crypto_ec_field_multiply(curve, &result.y, &r, &temporary);
    crypto_ec_field_multiply(curve, &temporary, &s1, &j);
    field_double(curve, &temporary, &temporary);
    crypto_ec_field_sub(curve, &result.y, &result.y, &temporary);

    crypto_ec_field_add(curve, &temporary, &a->z, &b->z);
    crypto_ec_field_square(curve, &result.z, &temporary);
    crypto_ec_field_sub(curve, &result.z, &result.z, &z1_squared);
    crypto_ec_field_sub(curve, &result.z, &result.z, &z2_squared);
    crypto_ec_field_multiply(curve, &result.z, &result.z, &h);

    *out = result;
    *h_out = h;
    *r_out = r;
}

void crypto_ec_jacobian_add_complete(const CryptoEcCurve *curve,
                                     CryptoEcJacobianPoint *out,
                                     const CryptoEcJacobianPoint *a,
                                     const CryptoEcJacobianPoint *b) {
    CryptoEcJacobianPoint generic;
    CryptoEcJacobianPoint doubled;
    CryptoEcJacobianPoint infinity;
    CryptoEcJacobianPoint selected;
    CryptoEcFieldElement h;
    CryptoEcFieldElement r;
    uint32_t a_infinity;
    uint32_t b_infinity;
    uint32_t h_zero;
    uint32_t r_zero;
    uint32_t equal_mask;
    uint32_t opposite_mask;

    jacobian_add_generic(curve, &generic, a, b, &h, &r);
    crypto_ec_jacobian_double(curve, &doubled, a);
    crypto_ec_jacobian_set_infinity(curve, &infinity);

    a_infinity = crypto_ec_field_zero_mask(curve, &a->z);
    b_infinity = crypto_ec_field_zero_mask(curve, &b->z);
    h_zero = crypto_ec_field_zero_mask(curve, &h);
    r_zero = crypto_ec_field_zero_mask(curve, &r);
    equal_mask = h_zero & r_zero;
    opposite_mask = h_zero & ~r_zero;

    selected = generic;
    crypto_ec_jacobian_select(curve, &selected, &selected, &doubled,
                              equal_mask);
    crypto_ec_jacobian_select(curve, &selected, &selected, &infinity,
                              opposite_mask);
    crypto_ec_jacobian_select(curve, &selected, &selected, b, a_infinity);
    crypto_ec_jacobian_select(curve, &selected, &selected, a, b_infinity);
    *out = selected;
}

void crypto_ec_jacobian_select(const CryptoEcCurve *curve,
                               CryptoEcJacobianPoint *out,
                               const CryptoEcJacobianPoint *a,
                               const CryptoEcJacobianPoint *b,
                               uint32_t select_b_mask) {
    CryptoEcJacobianPoint result;
    crypto_ec_field_select(curve, &result.x, &a->x, &b->x, select_b_mask);
    crypto_ec_field_select(curve, &result.y, &a->y, &b->y, select_b_mask);
    crypto_ec_field_select(curve, &result.z, &a->z, &b->z, select_b_mask);
    *out = result;
}

void crypto_ec_jacobian_cswap(const CryptoEcCurve *curve,
                              CryptoEcJacobianPoint *a,
                              CryptoEcJacobianPoint *b,
                              uint32_t swap_mask) {
    size_t index;
    for (index = 0u; index < curve->limbs; ++index) {
        uint32_t temporary;
        temporary = (a->x.limb[index] ^ b->x.limb[index]) & swap_mask;
        a->x.limb[index] ^= temporary;
        b->x.limb[index] ^= temporary;
        temporary = (a->y.limb[index] ^ b->y.limb[index]) & swap_mask;
        a->y.limb[index] ^= temporary;
        b->y.limb[index] ^= temporary;
        temporary = (a->z.limb[index] ^ b->z.limb[index]) & swap_mask;
        a->z.limb[index] ^= temporary;
        b->z.limb[index] ^= temporary;
    }
}
