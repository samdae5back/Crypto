/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_INTERNAL_ECC_H
#define CRYPTO_INTERNAL_ECC_H

#include "Def.h"

#define CRYPTO_EC_MAX_LIMBS 17u
#define CRYPTO_EC_WINDOW_BITS 4u
#define CRYPTO_EC_WINDOW_SIZE (1u << CRYPTO_EC_WINDOW_BITS)

typedef enum CryptoEcCurveId {
    CRYPTO_EC_CURVE_P256 = 1,
    CRYPTO_EC_CURVE_P384 = 2,
    CRYPTO_EC_CURVE_P521 = 3
} CryptoEcCurveId;

typedef struct CryptoEcFieldElement {
    uint32_t limb[CRYPTO_EC_MAX_LIMBS];
} CryptoEcFieldElement;

typedef struct CryptoEcAffinePoint {
    CryptoEcFieldElement x;
    CryptoEcFieldElement y;
    uint32_t infinity;
} CryptoEcAffinePoint;

typedef struct CryptoEcJacobianPoint {
    CryptoEcFieldElement x;
    CryptoEcFieldElement y;
    CryptoEcFieldElement z;
} CryptoEcJacobianPoint;

typedef struct CryptoEcCurve {
    CryptoEcCurveId id;
    size_t field_bits;
    size_t field_bytes;
    size_t scalar_bits;
    size_t scalar_bytes;
    size_t limbs;
    uint32_t montgomery_factor;
    uint32_t p[CRYPTO_EC_MAX_LIMBS];
    uint32_t order[CRYPTO_EC_MAX_LIMBS];
    uint32_t montgomery_one[CRYPTO_EC_MAX_LIMBS];
    uint32_t montgomery_r2[CRYPTO_EC_MAX_LIMBS];
    uint32_t b[CRYPTO_EC_MAX_LIMBS];
    uint32_t generator_x[CRYPTO_EC_MAX_LIMBS];
    uint32_t generator_y[CRYPTO_EC_MAX_LIMBS];
    uint32_t inverse_exponent[CRYPTO_EC_MAX_LIMBS];
    uint32_t square_root_exponent[CRYPTO_EC_MAX_LIMBS];
} CryptoEcCurve;

/* Domain parameters. */
const CryptoEcCurve *crypto_ec_curve_get(CryptoEcCurveId id);

/* Fixed-width prime-field operations. Field values use Montgomery form. */
void crypto_ec_field_zero(CryptoEcFieldElement *out);
void crypto_ec_field_one(const CryptoEcCurve *curve,
                         CryptoEcFieldElement *out);
void crypto_ec_field_copy(CryptoEcFieldElement *out,
                          const CryptoEcFieldElement *in);
void crypto_ec_field_add(const CryptoEcCurve *curve,
                         CryptoEcFieldElement *out,
                         const CryptoEcFieldElement *a,
                         const CryptoEcFieldElement *b);
void crypto_ec_field_sub(const CryptoEcCurve *curve,
                         CryptoEcFieldElement *out,
                         const CryptoEcFieldElement *a,
                         const CryptoEcFieldElement *b);
void crypto_ec_field_negate(const CryptoEcCurve *curve,
                            CryptoEcFieldElement *out,
                            const CryptoEcFieldElement *a);
void crypto_ec_field_multiply(const CryptoEcCurve *curve,
                              CryptoEcFieldElement *out,
                              const CryptoEcFieldElement *a,
                              const CryptoEcFieldElement *b);
void crypto_ec_field_square(const CryptoEcCurve *curve,
                            CryptoEcFieldElement *out,
                            const CryptoEcFieldElement *a);
void crypto_ec_field_invert_fixed(const CryptoEcCurve *curve,
                                  CryptoEcFieldElement *out,
                                  const CryptoEcFieldElement *a);
int crypto_ec_field_square_root_fixed(const CryptoEcCurve *curve,
                                      CryptoEcFieldElement *out,
                                      const CryptoEcFieldElement *a);
uint32_t crypto_ec_field_equal_mask(const CryptoEcCurve *curve,
                                    const CryptoEcFieldElement *a,
                                    const CryptoEcFieldElement *b);
uint32_t crypto_ec_field_zero_mask(const CryptoEcCurve *curve,
                                   const CryptoEcFieldElement *a);
void crypto_ec_field_select(const CryptoEcCurve *curve,
                            CryptoEcFieldElement *out,
                            const CryptoEcFieldElement *a,
                            const CryptoEcFieldElement *b,
                            uint32_t select_b_mask);
LiberaCError crypto_ec_field_from_bytes(const CryptoEcCurve *curve,
                                        CryptoEcFieldElement *out,
                                        const uint8_t *input,
                                        size_t input_length);
void crypto_ec_field_to_bytes(const CryptoEcCurve *curve,
                              uint8_t *output,
                              const CryptoEcFieldElement *in);
uint32_t crypto_ec_field_lsb(const CryptoEcCurve *curve,
                             const CryptoEcFieldElement *in);

/* Affine and Jacobian point operations. */
void crypto_ec_affine_set_infinity(CryptoEcAffinePoint *point);
void crypto_ec_jacobian_set_infinity(const CryptoEcCurve *curve,
                                     CryptoEcJacobianPoint *point);
void crypto_ec_affine_generator(const CryptoEcCurve *curve,
                                CryptoEcAffinePoint *point);
int crypto_ec_affine_is_infinity(const CryptoEcAffinePoint *point);
int crypto_ec_jacobian_is_infinity(const CryptoEcCurve *curve,
                                   const CryptoEcJacobianPoint *point);
int crypto_ec_affine_is_on_curve(const CryptoEcCurve *curve,
                                 const CryptoEcAffinePoint *point);
void crypto_ec_affine_to_jacobian(const CryptoEcCurve *curve,
                                  CryptoEcJacobianPoint *out,
                                  const CryptoEcAffinePoint *in);
void crypto_ec_jacobian_to_affine(const CryptoEcCurve *curve,
                                  CryptoEcAffinePoint *out,
                                  const CryptoEcJacobianPoint *in);
void crypto_ec_jacobian_double(const CryptoEcCurve *curve,
                               CryptoEcJacobianPoint *out,
                               const CryptoEcJacobianPoint *point);
void crypto_ec_jacobian_add_complete(const CryptoEcCurve *curve,
                                     CryptoEcJacobianPoint *out,
                                     const CryptoEcJacobianPoint *a,
                                     const CryptoEcJacobianPoint *b);
void crypto_ec_jacobian_select(const CryptoEcCurve *curve,
                               CryptoEcJacobianPoint *out,
                               const CryptoEcJacobianPoint *a,
                               const CryptoEcJacobianPoint *b,
                               uint32_t select_b_mask);
void crypto_ec_jacobian_cswap(const CryptoEcCurve *curve,
                              CryptoEcJacobianPoint *a,
                              CryptoEcJacobianPoint *b,
                              uint32_t swap_mask);

/*
 * Production scalar-multiplication policy:
 *   vartime - windowed Jacobian path for public scalars only
 *   ct      - fixed-width ladder for secret scalars
 *
 * The textbook affine reference oracle is test-only under tests/ECC.
 */
LiberaCError crypto_ec_scalar_multiply_vartime(
    const CryptoEcCurve *curve, CryptoEcAffinePoint *out,
    const CryptoEcAffinePoint *point, const uint8_t *scalar,
    size_t scalar_length);
LiberaCError crypto_ec_scalar_multiply_ct(
    const CryptoEcCurve *curve, CryptoEcAffinePoint *out,
    const CryptoEcAffinePoint *point, const uint8_t *scalar,
    size_t scalar_length);
int crypto_ec_scalar_is_valid_ct(const CryptoEcCurve *curve,
                                 const uint8_t *scalar,
                                 size_t scalar_length);

/* SEC 1 point encoding and decoding. */
size_t crypto_ec_point_encoding_size(const CryptoEcCurve *curve,
                                     const CryptoEcAffinePoint *point,
                                     int compressed);
LiberaCError crypto_ec_point_encode(const CryptoEcCurve *curve,
                                    const CryptoEcAffinePoint *point,
                                    int compressed,
                                    uint8_t *output,
                                    size_t *output_length);
LiberaCError crypto_ec_point_decode(const CryptoEcCurve *curve,
                                    CryptoEcAffinePoint *point,
                                    const uint8_t *input,
                                    size_t input_length,
                                    int allow_infinity);

#endif
