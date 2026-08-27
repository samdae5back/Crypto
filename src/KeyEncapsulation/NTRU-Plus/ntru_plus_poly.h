/*
 * Runtime-parameter NTRU+ polynomial declarations.
 * Derived from the NTRU+ reference implementation.
 * SPDX-License-Identifier: MIT
 */

#ifndef CRYPTO_NTRU_PLUS_POLY_H
#define CRYPTO_NTRU_PLUS_POLY_H

#include <stdint.h>

#include "ntru_plus_parameter.h"

typedef struct crypto_ntru_plus_poly {
    int16_t coeffs[CRYPTO_NTRU_PLUS_MAX_N];
} crypto_ntru_plus_poly;

void crypto_ntru_plus_poly_tobytes(
    uint8_t *output, const crypto_ntru_plus_poly *input,
    const crypto_ntru_plus_parameters *parameters);
int crypto_ntru_plus_poly_frombytes(
    crypto_ntru_plus_poly *output, const uint8_t *input,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_poly_cbd1(
    crypto_ntru_plus_poly *output, const uint8_t *input,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_poly_sotp_encode(
    crypto_ntru_plus_poly *output, const uint8_t *message,
    const uint8_t *mask,
    const crypto_ntru_plus_parameters *parameters);
int crypto_ntru_plus_poly_sotp_decode(
    uint8_t *message, const crypto_ntru_plus_poly *input,
    const uint8_t *mask,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_poly_ntt(
    crypto_ntru_plus_poly *output, const crypto_ntru_plus_poly *input,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_poly_invntt(
    crypto_ntru_plus_poly *output, const crypto_ntru_plus_poly *input,
    const crypto_ntru_plus_parameters *parameters);
int crypto_ntru_plus_poly_baseinv(
    crypto_ntru_plus_poly *output, const crypto_ntru_plus_poly *input,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_poly_basemul(
    crypto_ntru_plus_poly *output, const crypto_ntru_plus_poly *left,
    const crypto_ntru_plus_poly *right,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_poly_basemul_add(
    crypto_ntru_plus_poly *output, const crypto_ntru_plus_poly *left,
    const crypto_ntru_plus_poly *right,
    const crypto_ntru_plus_poly *addend,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_poly_sub(
    crypto_ntru_plus_poly *output, const crypto_ntru_plus_poly *left,
    const crypto_ntru_plus_poly *right,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_poly_triple(
    crypto_ntru_plus_poly *output, const crypto_ntru_plus_poly *input,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_poly_crepmod3(
    crypto_ntru_plus_poly *output, const crypto_ntru_plus_poly *input,
    const crypto_ntru_plus_parameters *parameters);

#endif
