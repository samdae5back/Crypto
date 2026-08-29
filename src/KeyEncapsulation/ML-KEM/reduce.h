/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef ML_KEM_REDUCE_INTERNAL_H
#define ML_KEM_REDUCE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "parameter.h"

/* floor(2^32 / 3329). Retained for ordinary-domain bounded reduction. */
#define MLKEM_BARRETT_MU UINT32_C(1290167)

/* Montgomery radix R = 2^16. */
#define MLKEM_MONTGOMERY_R_BITS 16u
#define MLKEM_MONTGOMERY_R_MASK UINT32_C(0xffff)
/* -q^{-1} mod 2^16 for q = 3329. */
#define MLKEM_MONTGOMERY_QINV UINT32_C(3327)
/* R mod q and R^2 mod q. */
#define MLKEM_MONTGOMERY_R_MOD_Q UINT32_C(2285)
#define MLKEM_MONTGOMERY_R2_MOD_Q UINT32_C(1353)

/* Reduce a value known to lie in [0, 2q) to [0, q). */
static inline uint32_t mlkem_reduce_once_u32(uint32_t value) {
    uint32_t reduced = value - (uint32_t)MLKEM_Q;
    uint32_t restore_mask = UINT32_C(0) - (reduced >> 31u);
    return reduced + ((uint32_t)MLKEM_Q & restore_mask);
}

/* Ordinary-domain Barrett reduction for an arbitrary uint32_t value. */
static inline uint32_t mlkem_barrett_reduce_u32(uint32_t value) {
    uint32_t quotient =
        (uint32_t)(((uint64_t)value * (uint64_t)MLKEM_BARRETT_MU) >> 32u);
    uint32_t remainder = value - quotient * (uint32_t)MLKEM_Q;
    return mlkem_reduce_once_u32(remainder);
}

/*
 * Montgomery REDC with R = 2^16. For value < qR this returns the canonical
 * representative of value*R^{-1} mod q. All ML-KEM products using this helper
 * are below (q-1)^2, well inside the precondition and uint32_t range.
 */
static inline uint32_t mlkem_montgomery_reduce_u32(uint32_t value) {
    uint32_t multiplier =
        (value * MLKEM_MONTGOMERY_QINV) & MLKEM_MONTGOMERY_R_MASK;
    uint32_t reduced =
        (value + multiplier * (uint32_t)MLKEM_Q) >>
        MLKEM_MONTGOMERY_R_BITS;
    return mlkem_reduce_once_u32(reduced);
}

/* Inputs are canonical representatives in [0, q), in either common domain. */
static inline int mlkem_add_mod_q(int first, int second) {
    uint32_t sum = (uint32_t)first + (uint32_t)second;
    return (int)mlkem_reduce_once_u32(sum);
}

static inline int mlkem_sub_mod_q(int first, int second) {
    uint32_t difference =
        (uint32_t)first + (uint32_t)MLKEM_Q - (uint32_t)second;
    return (int)mlkem_reduce_once_u32(difference);
}

/* Ordinary a*b mod q, used only at ordinary-domain boundaries/fallbacks. */
static inline int mlkem_mul_mod_q(int first, int second) {
    uint32_t product = (uint32_t)first * (uint32_t)second;
    return (int)mlkem_barrett_reduce_u32(product);
}

/*
 * Convert ordinary a to aR mod q. REDC(a*R^2) = aR, avoiding a 64-bit Barrett
 * multiply in the conversion path.
 */
static inline int mlkem_to_montgomery(int value) {
    uint32_t product =
        (uint32_t)value * MLKEM_MONTGOMERY_R2_MOD_Q;
    return (int)mlkem_montgomery_reduce_u32(product);
}

/* Convert canonical aR mod q back to ordinary a. */
static inline int mlkem_from_montgomery(int value) {
    return (int)mlkem_montgomery_reduce_u32((uint32_t)value);
}

/* (aR)(bR)R^{-1} = abR: Montgomery-domain multiplication. */
static inline int mlkem_montgomery_mul(int first, int second) {
    uint32_t product = (uint32_t)first * (uint32_t)second;
    return (int)mlkem_montgomery_reduce_u32(product);
}

static inline void mlkem_poly_to_montgomery(int *polynomial, size_t length) {
    size_t i;
    for (i = 0u; i < length; ++i)
        polynomial[i] = mlkem_to_montgomery(polynomial[i]);
}

static inline void mlkem_poly_from_montgomery(int *polynomial, size_t length) {
    size_t i;
    for (i = 0u; i < length; ++i)
        polynomial[i] = mlkem_from_montgomery(polynomial[i]);
}

#endif
