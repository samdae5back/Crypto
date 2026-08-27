/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "pqc_internal.h"

void crypto_pqc_poly16_add(
    crypto_pqc_poly16 *result,
    const crypto_pqc_poly16 *left,
    const crypto_pqc_poly16 *right) {
    size_t i;

    for (i = 0u; i < CRYPTO_PQC_POLYNOMIAL_DEGREE; ++i)
        result->coeffs[i] = (int16_t)(left->coeffs[i] + right->coeffs[i]);
}

void crypto_pqc_poly16_sub(
    crypto_pqc_poly16 *result,
    const crypto_pqc_poly16 *left,
    const crypto_pqc_poly16 *right) {
    size_t i;

    for (i = 0u; i < CRYPTO_PQC_POLYNOMIAL_DEGREE; ++i)
        result->coeffs[i] = (int16_t)(left->coeffs[i] - right->coeffs[i]);
}

int crypto_pqc_verify(
    const uint8_t *left, const uint8_t *right, size_t length) {
    uint32_t difference = 0u;
    size_t i;

    for (i = 0u; i < length; ++i)
        difference |= (uint32_t)(left[i] ^ right[i]);

    return (int)((difference | (0u - difference)) >> 31);
}

void crypto_pqc_cmov(
    uint8_t *result, const uint8_t *source, size_t length, uint8_t select) {
    uint8_t mask = (uint8_t)(0u - (uint32_t)(select != 0u));
    size_t i;

    for (i = 0u; i < length; ++i)
        result[i] ^= (uint8_t)(mask & (uint8_t)(result[i] ^ source[i]));
}
