/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_BIT_INTERNAL_H
#define CRYPTO_BIT_INTERNAL_H

#include "Def.h"

static inline uint32_t crypto_rotl32(uint32_t value, unsigned int count) {
    count &= 31u;
    return (value << count) | (value >> ((32u - count) & 31u));
}

static inline uint64_t crypto_rotl64(uint64_t value, unsigned int count) {
    count &= 63u;
    return (value << count) | (value >> ((64u - count) & 63u));
}

static inline uint32_t crypto_rotr32(uint32_t value, unsigned int count) {
    count &= 31u;
    return (value >> count) | (value << ((32u - count) & 31u));
}

static inline uint64_t crypto_rotr64(uint64_t value, unsigned int count) {
    count &= 63u;
    return (value >> count) | (value << ((64u - count) & 63u));
}

/* Return floor(value / 2^count) without shifting a negative signed value. */
static inline int32_t crypto_floor_div_pow2_i32(
    int32_t value, unsigned int count) {
    const uint32_t negative = (uint32_t)(value < 0);
    const uint32_t negative_mask = 0u - negative;
    const uint32_t remainder_mask =
        (UINT32_C(1) << count) - UINT32_C(1);
    const uint32_t magnitude =
        ((uint32_t)value ^ negative_mask) + negative;
    const uint32_t quotient =
        (magnitude + (remainder_mask & negative_mask)) >> count;

    return (int32_t)quotient *
           (INT32_C(1) - INT32_C(2) * (int32_t)negative);
}

/* Return floor(value / 2^count) without shifting a negative signed value. */
static inline int64_t crypto_floor_div_pow2_i64(
    int64_t value, unsigned int count) {
    const uint64_t negative = (uint64_t)(value < 0);
    const uint64_t negative_mask = UINT64_C(0) - negative;
    const uint64_t remainder_mask =
        (UINT64_C(1) << count) - UINT64_C(1);
    const uint64_t magnitude =
        ((uint64_t)value ^ negative_mask) + negative;
    const uint64_t quotient =
        (magnitude + (remainder_mask & negative_mask)) >> count;

    if (count == 0u) {
        return value;
    }
    return (int64_t)quotient *
           (INT64_C(1) - INT64_C(2) * (int64_t)negative);
}

#endif
