/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "bignum_internal.h"

#include <string.h>

LiberaCError crypto_bignum_sub_secret_fixed(LiberaCBignum *out,
                                            const LiberaCBignum *a,
                                            const LiberaCBignum *b,
                                            size_t fixed_limbs) {
    LiberaCBignum tmp;
    uint32_t borrow = 0u;
    size_t i, length = 0u;

    if (!out || !a || !b || a->CAPACITY < fixed_limbs ||
        b->CAPACITY < fixed_limbs)
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    crypto_bignum_init(&tmp);
    if (fixed_limbs != 0u && bignum_reserve(&tmp, fixed_limbs) != 0)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    if (fixed_limbs != 0u)
        memset(tmp.LIMBS, 0, fixed_limbs * sizeof(uint32_t));

    /* Fixed-width subtraction: loop count and operand indices depend only on
     * the caller-supplied public width, not on either secret value's LENGTH. */
    for (i = 0u; i < fixed_limbs; ++i) {
        uint64_t av = a->LIMBS[i];
        uint64_t subtrahend = (uint64_t)b->LIMBS[i] + borrow;
        tmp.LIMBS[i] = (uint32_t)(av - subtrahend);
        borrow = (uint32_t)(av < subtrahend);
    }
    if (borrow != 0u) {
        crypto_bignum_free(&tmp);
        return LIBERAC_ERROR_ARITHMETIC;
    }

    /* Fixed-count normalization avoids a value-dependent early exit. */
    for (i = 0u; i < fixed_limbs; ++i) {
        uint32_t x = tmp.LIMBS[i];
        uint32_t nonzero = (x | (uint32_t)(0u - x)) >> 31;
        size_t mask = (size_t)0 - (size_t)nonzero;
        length = (length & ~mask) | ((i + 1u) & mask);
    }
    tmp.LENGTH = length;
    crypto_bignum_free(out);
    *out = tmp;
    return LIBERAC_SUCCESS;
}
