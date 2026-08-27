/*
 * Runtime-parameter NTRU+ number-theoretic transform declarations.
 * Derived from the NTRU+ reference implementation.
 * SPDX-License-Identifier: MIT
 */

#ifndef CRYPTO_NTRU_PLUS_NTT_H
#define CRYPTO_NTRU_PLUS_NTT_H

#include <stdint.h>

#include "ntru_plus_parameter.h"

extern const int16_t crypto_ntru_plus_zetas_768[192];
extern const int16_t crypto_ntru_plus_zetas_864[288];
extern const int16_t crypto_ntru_plus_zetas_1152[288];

void crypto_ntru_plus_ntt(
    int16_t *result, const int16_t *input,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_invntt(
    int16_t *result, const int16_t *input,
    const crypto_ntru_plus_parameters *parameters);

int crypto_ntru_plus_baseinv4(
    int16_t result[4], const int16_t input[4], int16_t zeta);
void crypto_ntru_plus_basemul4(
    int16_t result[4], const int16_t left[4], const int16_t right[4],
    int16_t zeta);
void crypto_ntru_plus_basemul_add4(
    int16_t result[4], const int16_t left[4], const int16_t right[4],
    const int16_t addend[4], int16_t zeta);

int crypto_ntru_plus_baseinv3(
    int16_t result[3], const int16_t input[3], int16_t zeta);
void crypto_ntru_plus_basemul3(
    int16_t result[3], const int16_t left[3], const int16_t right[3],
    int16_t zeta);
void crypto_ntru_plus_basemul_add3(
    int16_t result[3], const int16_t left[3], const int16_t right[3],
    const int16_t addend[3], int16_t zeta);

#endif
