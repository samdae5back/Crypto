/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef crypto_bignum_internal_h
#define crypto_bignum_internal_h

#include "Util.h"

void crypto_bignum_init(LiberaCBignum *value);
void crypto_bignum_free(LiberaCBignum *value);
LiberaCError crypto_bignum_copy(LiberaCBignum *out, const LiberaCBignum *in);
LiberaCError crypto_bignum_copy_secret_fixed(LiberaCBignum *out,
                                             const LiberaCBignum *in,
                                             size_t fixed_limbs);
LiberaCError crypto_bignum_set_u64(LiberaCBignum *out, uint64_t value);
LiberaCError crypto_bignum_from_bytes_be(LiberaCBignum *out, const uint8_t *bytes, size_t length);
LiberaCError crypto_bignum_from_bytes_le(LiberaCBignum *out, const uint8_t *bytes, size_t length);
LiberaCError crypto_bignum_to_bytes_be(const LiberaCBignum *in, uint8_t *out, size_t out_length);
LiberaCError crypto_bignum_to_bytes_le(const LiberaCBignum *in, uint8_t *out, size_t out_length);
size_t crypto_bignum_byte_length(const LiberaCBignum *value);
size_t crypto_bignum_bit_length(const LiberaCBignum *value);
int crypto_bignum_compare(const LiberaCBignum *a, const LiberaCBignum *b);
int crypto_bignum_is_zero(const LiberaCBignum *value);
LiberaCError crypto_bignum_add(LiberaCBignum *out, const LiberaCBignum *a, const LiberaCBignum *b);
LiberaCError crypto_bignum_sub(LiberaCBignum *out, const LiberaCBignum *a, const LiberaCBignum *b);
LiberaCError crypto_bignum_mul(LiberaCBignum *out, const LiberaCBignum *a, const LiberaCBignum *b);
LiberaCError crypto_bignum_square(LiberaCBignum *out, const LiberaCBignum *a);
LiberaCError crypto_bignum_mod(LiberaCBignum *out, const LiberaCBignum *a, const LiberaCBignum *modulus);
LiberaCError crypto_bignum_mod_mul(LiberaCBignum *out, const LiberaCBignum *a,
                                   const LiberaCBignum *b, const LiberaCBignum *modulus);
LiberaCError crypto_bignum_mod_square(LiberaCBignum *out,
                                      const LiberaCBignum *a,
                                      const LiberaCBignum *modulus);

/* Legacy generic variable-time exponentiation retained as an even-modulus
 * compatibility fallback.  New public/non-secret call sites should use the
 * explicitly named optimized vartime entry point below. */
LiberaCError crypto_bignum_mod_exp(LiberaCBignum *out, const LiberaCBignum *base,
                                   const LiberaCBignum *exponent, const LiberaCBignum *modulus);

/* Public/non-secret exponent path.  Uses early identities, sliding windows,
 * direct odd-power lookup tables, and public-data early exits. */
LiberaCError crypto_bignum_mod_exp_vartime(
    LiberaCBignum *out, const LiberaCBignum *base,
    const LiberaCBignum *exponent, const LiberaCBignum *modulus);

/* Secret-exponent path.  It executes one Montgomery square and one Montgomery
 * multiply for every modulus limb bit, then selects with a mask rather than a
 * secret-dependent branch or table index.  The exponent storage must have at
 * least modulus->LENGTH limbs so leading-zero limb count is not exposed by the
 * scan.  This is a software constant-schedule property; C cannot promise equal
 * physical timing on every possible processor. */
LiberaCError crypto_bignum_mod_exp_ct(LiberaCBignum *out,
                                      const LiberaCBignum *base,
                                      const LiberaCBignum *exponent,
                                      const LiberaCBignum *modulus);

/* Same secret exponent and modulus for two public bases.  Sharing Montgomery
 * setup avoids duplicated context/R^2 preparation in protocols such as
 * ElGamal encryption. */
LiberaCError crypto_bignum_mod_exp2_ct(LiberaCBignum *out1,
                                       const LiberaCBignum *base1,
                                       LiberaCBignum *out2,
                                       const LiberaCBignum *base2,
                                       const LiberaCBignum *exponent,
                                       const LiberaCBignum *modulus);

LiberaCError crypto_bignum_random_bits(LiberaCBignum *out, size_t bits, int set_top_bit, int set_odd);
LiberaCError crypto_bignum_random_range(LiberaCBignum *out, const LiberaCBignum *upper_exclusive);

int bignum_reserve(LiberaCBignum *a, size_t capacity);
void bignum_normalize(LiberaCBignum *a);
int bignum_get_bit(const LiberaCBignum *a, size_t bit);
int bignum_shift_left_one(LiberaCBignum *a);
int bignum_add_u32(LiberaCBignum *a, uint32_t v);
int bignum_mul_u32(LiberaCBignum *out, const LiberaCBignum *a, uint32_t v);
uint32_t bignum_mod_u32(const LiberaCBignum *a, uint32_t v);
int bignum_div_u32(LiberaCBignum *out, const LiberaCBignum *a, uint32_t v, uint32_t *remainder);
int bignum_sub_u32(LiberaCBignum *out, const LiberaCBignum *a, uint32_t v);
int bignum_add_u32_copy(LiberaCBignum *out, const LiberaCBignum *a, uint32_t v);

#endif
