/* SPDX-License-Identifier: MIT */

#ifndef CRYPTO_AIMER_BACKEND_AIMER_AIM2_H
#define CRYPTO_AIMER_BACKEND_AIMER_AIM2_H

#include <stddef.h>
#include <stdint.h>

#include "../aimer_params.h"
#include "aimer_field.h"



typedef struct crypto_aimer_mult_check
{
  crypto_aimer_gf pt_share;
  crypto_aimer_gf x_shares[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1];
  crypto_aimer_gf z_shares[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1];
} crypto_aimer_mult_check;

extern const crypto_aimer_gf crypto_aimer_aim2_constants_128[CRYPTO_AIMER_MAX_INPUT_SBOXES];
extern const uint64_t crypto_aimer_aim2_sbox_exponents_128[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1][CRYPTO_AIMER_FIELD_MAX_WORDS];
extern const size_t crypto_aimer_aim2_exponents_128[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1];

extern const crypto_aimer_gf crypto_aimer_aim2_constants_192[CRYPTO_AIMER_MAX_INPUT_SBOXES];
extern const uint64_t crypto_aimer_aim2_sbox_exponents_192[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1][CRYPTO_AIMER_FIELD_MAX_WORDS];
extern const size_t crypto_aimer_aim2_exponents_192[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1];

extern const crypto_aimer_gf crypto_aimer_aim2_constants_256[CRYPTO_AIMER_MAX_INPUT_SBOXES];
extern const uint64_t crypto_aimer_aim2_sbox_exponents_256[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1][CRYPTO_AIMER_FIELD_MAX_WORDS];
extern const size_t crypto_aimer_aim2_exponents_256[CRYPTO_AIMER_MAX_INPUT_SBOXES + 1];

CryptoError crypto_aimer_aim2_generate_linear(
    crypto_aimer_gf *matrix_A, crypto_aimer_gf vector_b,
    const uint8_t *iv, const crypto_aimer_params *alg);

void crypto_aimer_aim2_sbox_outputs(crypto_aimer_gf *sbox_outputs, const crypto_aimer_gf pt, const crypto_aimer_params *alg);

CryptoError crypto_aimer_aim2(
    uint8_t *ct, const uint8_t *pt, const uint8_t *iv,
    const crypto_aimer_params *alg);

void crypto_aimer_aim2_mpc(crypto_aimer_mult_check *mult_chk, const crypto_aimer_gf *matrix_A, const crypto_aimer_gf ct_gf,
              const crypto_aimer_params *alg);

#endif /* CRYPTO_AIMER_BACKEND_AIMER_AIM2_H */
