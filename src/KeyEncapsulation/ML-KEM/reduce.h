/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef ML_KEM_REDUCE_INTERNAL_H
#define ML_KEM_REDUCE_INTERNAL_H

#include <stdint.h>

#include "parameter.h"

/* floor(2^32 / 3329). */
#define MLKEM_BARRETT_MU UINT32_C(1290167)

/* Montgomery radix R = 2^16. */
#define MLKEM_MONTGOMERY_R_BITS 16u
#define MLKEM_MONTGOMERY_R_MASK UINT32_C(0xffff)
/* -q^{-1} mod 2^16 for q = 3329. */
#define MLKEM_MONTGOMERY_QINV UINT32_C(3327)
/* 2^16 mod q. */
#define MLKEM_MONTGOMERY_R_MOD_Q UINT32_C(2285)

/*
 * Reduce a value known to lie in [0, 2q) to [0, q).
 *
 * The subtraction is performed in uint32_t arithmetic.  If value < q,
 * subtraction wraps and therefore sets the high bit because q < 2^31 and
 * value < 2q.  The mask restores q in exactly that case.  The source-level
 * schedule is independent of the coefficient value.
 */
static inline uint32_t mlkem_reduce_once_u32(uint32_t value) {
    uint32_t reduced = value - (uint32_t)MLKEM_Q;
    uint32_t restore_mask = UINT32_C(0) - (reduced >> 31u);
    return reduced + ((uint32_t)MLKEM_Q & restore_mask);
}

/*
 * Barrett reduction for an arbitrary uint32_t value.
 *
 * Let B = 2^32 and mu = floor(B/q).  qhat = floor(value * mu / B) is either
 * floor(value/q) or one less because value < B.  Thus
 * remainder = value - qhat*q lies in [0, 2q), after which one fixed-shape
 * correction produces the canonical representative in [0, q).
 */
static inline uint32_t mlkem_barrett_reduce_u32(uint32_t value) {
    uint32_t quotient =
        (uint32_t)(((uint64_t)value * (uint64_t)MLKEM_BARRETT_MU) >> 32u);
    uint32_t remainder =
        value - quotient * (uint32_t)MLKEM_Q;
    return mlkem_reduce_once_u32(remainder);
}

/*
 * Montgomery REDC with R = 2^16.
 *
 * For value < qR, let m = value*(-q^{-1}) mod R.  Then value + m*q is
 * divisible by R, and
 *
 *     t = (value + m*q) / R == value*R^{-1} (mod q).
 *
 * Since 0 <= m < R and value < qR, t < 2q, so one fixed-shape correction
 * returns the canonical representative.  All ML-KEM uses below satisfy the
 * stronger bound value <= (q-1)^2 < qR.
 */
static inline uint32_t mlkem_montgomery_reduce_u32(uint32_t value) {
    uint32_t multiplier =
        (value * MLKEM_MONTGOMERY_QINV) & MLKEM_MONTGOMERY_R_MASK;
    uint32_t reduced =
        (value + multiplier * (uint32_t)MLKEM_Q) >>
        MLKEM_MONTGOMERY_R_BITS;
    return mlkem_reduce_once_u32(reduced);
}

/* Inputs to these helpers are canonical coefficients in [0, q). */
static inline int mlkem_add_mod_q(int first, int second) {
    uint32_t sum = (uint32_t)first + (uint32_t)second;
    return (int)mlkem_reduce_once_u32(sum);
}

static inline int mlkem_sub_mod_q(int first, int second) {
    uint32_t difference =
        (uint32_t)first + (uint32_t)MLKEM_Q - (uint32_t)second;
    return (int)mlkem_reduce_once_u32(difference);
}

static inline int mlkem_mul_mod_q(int first, int second) {
    uint32_t product = (uint32_t)first * (uint32_t)second;
    return (int)mlkem_barrett_reduce_u32(product);
}

/* Convert an ordinary canonical constant c to cR mod q. */
static inline int mlkem_to_montgomery(int value) {
    uint32_t product =
        (uint32_t)value * MLKEM_MONTGOMERY_R_MOD_Q;
    return (int)mlkem_barrett_reduce_u32(product);
}

/*
 * Multiply an ordinary canonical coefficient by a fixed constant already in
 * Montgomery form.  REDC((cR mod q) * a) = c*a mod q, so the returned value
 * remains in the ordinary canonical domain.
 */
static inline int mlkem_mul_montgomery_constant(int value,
                                                 int montgomery_constant) {
    uint32_t product =
        (uint32_t)value * (uint32_t)montgomery_constant;
    return (int)mlkem_montgomery_reduce_u32(product);
}

#endif
