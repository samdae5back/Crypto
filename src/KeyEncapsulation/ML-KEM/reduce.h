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

#endif
