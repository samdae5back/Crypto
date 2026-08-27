/* SPDX-License-Identifier: MIT */

#ifndef CRYPTO_AIMER_BACKEND_AIMER_FIELD_H
#define CRYPTO_AIMER_BACKEND_AIMER_FIELD_H

#include <stddef.h>
#include <stdint.h>

#include "../aimer_params.h"

#define CRYPTO_AIMER_FIELD_MAX_WORDS 4
#define CRYPTO_AIMER_FIELD_MAX_BITS 256

typedef uint64_t crypto_aimer_gf[CRYPTO_AIMER_FIELD_MAX_WORDS];
#define CRYPTO_AIMER_FIELD_BITS CRYPTO_AIMER_FIELD_MAX_BITS

void crypto_aimer_field128_mul(
    uint64_t *output, const uint64_t *left, const uint64_t *right);
void crypto_aimer_field128_mul_add(
    uint64_t *output, const uint64_t *left, const uint64_t *right);
void crypto_aimer_field128_sqr(uint64_t *output, const uint64_t *input);
void crypto_aimer_field128_mat_vec_mul(
    uint64_t *output, const uint64_t *vector,
    const uint64_t (*matrix)[CRYPTO_AIMER_FIELD_MAX_WORDS]);
void crypto_aimer_field128_mat_vec_mul_add(
    uint64_t *output, const uint64_t *vector,
    const uint64_t (*matrix)[CRYPTO_AIMER_FIELD_MAX_WORDS]);

void crypto_aimer_field192_mul(
    uint64_t *output, const uint64_t *left, const uint64_t *right);
void crypto_aimer_field192_mul_add(
    uint64_t *output, const uint64_t *left, const uint64_t *right);
void crypto_aimer_field192_sqr(uint64_t *output, const uint64_t *input);
void crypto_aimer_field192_mat_vec_mul(
    uint64_t *output, const uint64_t *vector,
    const uint64_t (*matrix)[CRYPTO_AIMER_FIELD_MAX_WORDS]);
void crypto_aimer_field192_mat_vec_mul_add(
    uint64_t *output, const uint64_t *vector,
    const uint64_t (*matrix)[CRYPTO_AIMER_FIELD_MAX_WORDS]);

void crypto_aimer_field256_mul(
    uint64_t *output, const uint64_t *left, const uint64_t *right);
void crypto_aimer_field256_mul_add(
    uint64_t *output, const uint64_t *left, const uint64_t *right);
void crypto_aimer_field256_sqr(uint64_t *output, const uint64_t *input);
void crypto_aimer_field256_mat_vec_mul(
    uint64_t *output, const uint64_t *vector,
    const uint64_t (*matrix)[CRYPTO_AIMER_FIELD_MAX_WORDS]);
void crypto_aimer_field256_mat_vec_mul_add(
    uint64_t *output, const uint64_t *vector,
    const uint64_t (*matrix)[CRYPTO_AIMER_FIELD_MAX_WORDS]);

void crypto_aimer_field_set0(crypto_aimer_gf a);
void crypto_aimer_field_copy(crypto_aimer_gf out, const crypto_aimer_gf in);
void crypto_aimer_field_to_bytes(uint8_t *out, const crypto_aimer_gf in, const crypto_aimer_params *alg);
void crypto_aimer_field_from_bytes(crypto_aimer_gf out, const uint8_t *in, const crypto_aimer_params *alg);

void crypto_aimer_field_add(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_gf b);
void crypto_aimer_field_mul(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_gf b, const crypto_aimer_params *alg);
void crypto_aimer_field_mul_add(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_gf b, const crypto_aimer_params *alg);
void crypto_aimer_field_sqr(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_params *alg);
void crypto_aimer_field_exp(crypto_aimer_gf out, const crypto_aimer_gf in, const uint64_t *exp, const crypto_aimer_params *alg);

void crypto_aimer_field_mat_vec_mul(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_gf *b, const crypto_aimer_params *alg);
void crypto_aimer_field_mat_vec_mul_add(crypto_aimer_gf c, const crypto_aimer_gf a, const crypto_aimer_gf *b, const crypto_aimer_params *alg);

#endif /* CRYPTO_AIMER_BACKEND_AIMER_FIELD_H */
