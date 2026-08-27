/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_PQC_INTERNAL_H
#define CRYPTO_PQC_INTERNAL_H

#include "Def.h"

#define CRYPTO_PQC_POLYNOMIAL_DEGREE 256u
#define CRYPTO_PQC_KEM_MAX_RANK 4u
#define CRYPTO_PQC_SIGNATURE_MAX_L 7u
#define CRYPTO_PQC_SIGNATURE_MAX_K 8u

typedef struct crypto_pqc_poly16 {
    int16_t coeffs[CRYPTO_PQC_POLYNOMIAL_DEGREE];
} crypto_pqc_poly16;

typedef struct crypto_pqc_poly32 {
    int32_t coeffs[CRYPTO_PQC_POLYNOMIAL_DEGREE];
} crypto_pqc_poly32;

typedef struct crypto_pqc_polyvec16 {
    crypto_pqc_poly16 vec[CRYPTO_PQC_KEM_MAX_RANK];
} crypto_pqc_polyvec16;

typedef struct crypto_pqc_polyvecl32 {
    crypto_pqc_poly32 vec[CRYPTO_PQC_SIGNATURE_MAX_L];
} crypto_pqc_polyvecl32;

typedef struct crypto_pqc_polyveck32 {
    crypto_pqc_poly32 vec[CRYPTO_PQC_SIGNATURE_MAX_K];
} crypto_pqc_polyveck32;

void crypto_pqc_poly16_add(
    crypto_pqc_poly16 *result,
    const crypto_pqc_poly16 *left,
    const crypto_pqc_poly16 *right);
void crypto_pqc_poly16_sub(
    crypto_pqc_poly16 *result,
    const crypto_pqc_poly16 *left,
    const crypto_pqc_poly16 *right);
int crypto_pqc_verify(
    const uint8_t *left, const uint8_t *right, size_t length);
void crypto_pqc_cmov(
    uint8_t *result, const uint8_t *source, size_t length, uint8_t select);

#endif
