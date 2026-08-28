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
LiberaCError crypto_bignum_mod(LiberaCBignum *out, const LiberaCBignum *a, const LiberaCBignum *modulus);
LiberaCError crypto_bignum_mod_mul(LiberaCBignum *out, const LiberaCBignum *a,
                                   const LiberaCBignum *b, const LiberaCBignum *modulus);
LiberaCError crypto_bignum_mod_square(LiberaCBignum *out,
                                      const LiberaCBignum *a,
                                      const LiberaCBignum *modulus);
LiberaCError crypto_bignum_mod_exp(LiberaCBignum *out, const LiberaCBignum *base,
                                   const LiberaCBignum *exponent, const LiberaCBignum *modulus);
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
