/*
 * NTRU+ domain-separated hash declarations.
 * Derived from the NTRU+ reference implementation.
 * SPDX-License-Identifier: MIT
 */

#ifndef CRYPTO_NTRU_PLUS_HASH_H
#define CRYPTO_NTRU_PLUS_HASH_H

#include <stdint.h>

#include "ntru_plus_parameter.h"

void crypto_ntru_plus_hash_f(
    uint8_t output[CRYPTO_NTRU_PLUS_SEED_BYTES], const uint8_t *input,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_hash_g(
    uint8_t *output, const uint8_t *input,
    const crypto_ntru_plus_parameters *parameters);
void crypto_ntru_plus_hash_h(
    uint8_t *output, const uint8_t *input,
    const crypto_ntru_plus_parameters *parameters);

#endif
