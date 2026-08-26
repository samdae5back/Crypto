#ifndef CRYPTO_BIGNUM_INTERNAL_H
#define CRYPTO_BIGNUM_INTERNAL_H

#include "BIGNUM.h"

int bignum_reserve(BIGNUM *a, size_t capacity);
void bignum_normalize(BIGNUM *a);
int bignum_get_bit(const BIGNUM *a, size_t bit);
int bignum_shift_left_one(BIGNUM *a);
int bignum_add_u32(BIGNUM *a, uint32_t v);
int bignum_mul_u32(BIGNUM *out, const BIGNUM *a, uint32_t v);
uint32_t bignum_mod_u32(const BIGNUM *a, uint32_t v);
int bignum_div_u32(BIGNUM *out, const BIGNUM *a, uint32_t v, uint32_t *remainder);
int bignum_sub_u32(BIGNUM *out, const BIGNUM *a, uint32_t v);
int bignum_add_u32_copy(BIGNUM *out, const BIGNUM *a, uint32_t v);

#endif
