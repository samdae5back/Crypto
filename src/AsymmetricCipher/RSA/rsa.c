/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "rsa_internal.h"
#include "Util/Bignum/bignum_internal.h"
#include "Util/Prime/prime_internal.h"

#include <stdint.h>

#define RSA_DEFAULT_E 65537u

void crypto_rsa_public_key_init_internal(LiberaCRsaPublicKey *KEY) {
    if (!KEY) return;
    crypto_bignum_init(&KEY->N); crypto_bignum_init(&KEY->E);
}
void crypto_rsa_public_key_free_internal(LiberaCRsaPublicKey *KEY) {
    if (!KEY) return;
    crypto_bignum_free(&KEY->N); crypto_bignum_free(&KEY->E);
}
void crypto_rsa_private_key_init_internal(LiberaCRsaPrivateKey *KEY) {
    if (!KEY) return;
    crypto_bignum_init(&KEY->N); crypto_bignum_init(&KEY->D); crypto_bignum_init(&KEY->P); crypto_bignum_init(&KEY->Q);
}
void crypto_rsa_private_key_free_internal(LiberaCRsaPrivateKey *KEY) {
    if (!KEY) return;
    crypto_bignum_free(&KEY->N); crypto_bignum_free(&KEY->D); crypto_bignum_free(&KEY->P); crypto_bignum_free(&KEY->Q);
}

uint32_t rsa_inverse_u32(uint32_t a, uint32_t m) {
    int64_t t = 0, new_t = 1;
    int64_t r = m, new_r = a;
    while (new_r) {
        int64_t q = r / new_r;
        int64_t tt = t - q * new_t;
        int64_t rr = r - q * new_r;
        t = new_t; new_t = tt; r = new_r; new_r = rr;
    }
    if (r != 1) return 0;
    if (t < 0) t += m;
    return (uint32_t)t;
}

static int make_private_exponent(LiberaCBignum *d, const LiberaCBignum *phi) {
    uint32_t r = bignum_mod_u32(phi, RSA_DEFAULT_E);
    uint32_t inv, k, rem;
    LiberaCBignum tmp, numerator;
    int rc = -1;
    if (r == 0) return -1;
    inv = rsa_inverse_u32(r, RSA_DEFAULT_E);
    if (inv == 0) return -1;
    k = RSA_DEFAULT_E - inv;
    if (k == RSA_DEFAULT_E) k = 0;
    crypto_bignum_init(&tmp); crypto_bignum_init(&numerator);
    if (bignum_mul_u32(&tmp, phi, k) != 0 || bignum_add_u32_copy(&numerator, &tmp, 1) != 0) goto done;
    if (bignum_div_u32(d, &numerator, RSA_DEFAULT_E, &rem) != 0 || rem != 0) goto done;
    rc = 0;
done:
    crypto_bignum_free(&tmp); crypto_bignum_free(&numerator);
    return rc;
}

LiberaCError crypto_rsa_keygen_internal(LiberaCAlgID ALG, LiberaCRsaPublicKey *PUBLIC_KEY, LiberaCRsaPrivateKey *PRIVATE_KEY, size_t MODULUS_BITS, unsigned PRIME_ROUNDS) {
    LiberaCBignum p, q, n, p1, q1, phi, d;
    size_t p_bits, q_bits;
    int attempts;
    LiberaCError err;
    if (ALG != LIBERAC_ALG_RSA_RAW && ALG != LIBERAC_ALG_RSA_OAEP &&
        ALG != LIBERAC_ALG_RSA_PSS)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!PUBLIC_KEY || !PRIVATE_KEY || MODULUS_BITS < 32)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (PRIME_ROUNDS == 0) PRIME_ROUNDS = 32;
    p_bits = MODULUS_BITS / 2u;
    q_bits = MODULUS_BITS - p_bits;
    crypto_bignum_init(&p); crypto_bignum_init(&q); crypto_bignum_init(&n); crypto_bignum_init(&p1); crypto_bignum_init(&q1); crypto_bignum_init(&phi); crypto_bignum_init(&d);

    for (attempts = 0; attempts < 128; ++attempts) {
        crypto_bignum_free(&p); crypto_bignum_init(&p); crypto_bignum_free(&q); crypto_bignum_init(&q);
        crypto_bignum_free(&n); crypto_bignum_init(&n); crypto_bignum_free(&p1); crypto_bignum_init(&p1); crypto_bignum_free(&q1); crypto_bignum_init(&q1); crypto_bignum_free(&phi); crypto_bignum_init(&phi); crypto_bignum_free(&d); crypto_bignum_init(&d);
        err = crypto_prime_generate_internal(&p, p_bits, PRIME_ROUNDS);
        if (err != LIBERAC_SUCCESS) goto prime_fail;
        err = crypto_prime_generate_internal(&q, q_bits, PRIME_ROUNDS);
        if (err != LIBERAC_SUCCESS) goto prime_fail;
        if (crypto_bignum_compare(&p, &q) == 0) continue;
        if (crypto_bignum_mul(&n, &p, &q) != 0) goto arithmetic_fail;
        if (crypto_bignum_bit_length(&n) != MODULUS_BITS) continue;
        if (bignum_sub_u32(&p1, &p, 1) != 0 || bignum_sub_u32(&q1, &q, 1) != 0 || crypto_bignum_mul(&phi, &p1, &q1) != 0) goto arithmetic_fail;
        if (bignum_mod_u32(&phi, RSA_DEFAULT_E) == 0) continue;
        if (make_private_exponent(&d, &phi) != 0) continue;

        /* Crossing from key-generation arithmetic into persistent secret state
         * is the one variable-length promotion.  Subsequent private-key copies
         * use the complete public modulus width. */
        if (crypto_bignum_copy_secret_fixed(&d, &d, n.LENGTH) != LIBERAC_SUCCESS)
            goto alloc_fail;

        crypto_rsa_public_key_free_internal(PUBLIC_KEY); crypto_rsa_public_key_init_internal(PUBLIC_KEY);
        crypto_rsa_private_key_free_internal(PRIVATE_KEY); crypto_rsa_private_key_init_internal(PRIVATE_KEY);
        if (crypto_bignum_copy(&PUBLIC_KEY->N, &n) != 0 || crypto_bignum_set_u64(&PUBLIC_KEY->E, RSA_DEFAULT_E) != 0 ||
            crypto_bignum_copy(&PRIVATE_KEY->N, &n) != 0 ||
            crypto_bignum_copy_secret_fixed_ct(&PRIVATE_KEY->D, &d, n.LENGTH) != LIBERAC_SUCCESS ||
            crypto_bignum_copy(&PRIVATE_KEY->P, &p) != 0 || crypto_bignum_copy(&PRIVATE_KEY->Q, &q) != 0) goto alloc_fail;
        crypto_bignum_free(&p); crypto_bignum_free(&q); crypto_bignum_free(&n); crypto_bignum_free(&p1); crypto_bignum_free(&q1); crypto_bignum_free(&phi); crypto_bignum_free(&d);
        return LIBERAC_SUCCESS;
    }
    err = LIBERAC_ERROR_PRIME_GENERATION_FAILED;
prime_fail:
    crypto_bignum_free(&p); crypto_bignum_free(&q); crypto_bignum_free(&n); crypto_bignum_free(&p1); crypto_bignum_free(&q1); crypto_bignum_free(&phi); crypto_bignum_free(&d);
    return err;
arithmetic_fail:
    crypto_bignum_free(&p); crypto_bignum_free(&q); crypto_bignum_free(&n); crypto_bignum_free(&p1); crypto_bignum_free(&q1); crypto_bignum_free(&phi); crypto_bignum_free(&d);
    return LIBERAC_ERROR_ARITHMETIC;
alloc_fail:
    crypto_bignum_free(&p); crypto_bignum_free(&q); crypto_bignum_free(&n); crypto_bignum_free(&p1); crypto_bignum_free(&q1); crypto_bignum_free(&phi); crypto_bignum_free(&d);
    return LIBERAC_ERROR_ALLOCATION_FAILED;
}

LiberaCError crypto_rsa_encrypt_internal(LiberaCAlgID ALG, LiberaCBignum *CIPHERTEXT, const LiberaCBignum *MESSAGE, const LiberaCRsaPublicKey *PUBLIC_KEY) {
    if (ALG != LIBERAC_ALG_RSA_RAW) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!CIPHERTEXT || !MESSAGE || !PUBLIC_KEY) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (crypto_bignum_compare(MESSAGE, &PUBLIC_KEY->N) >= 0) return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    return crypto_bignum_mod_exp_vartime(CIPHERTEXT, MESSAGE, &PUBLIC_KEY->E, &PUBLIC_KEY->N) == 0 ? LIBERAC_SUCCESS : LIBERAC_ERROR_ARITHMETIC;
}

LiberaCError crypto_rsa_decrypt_internal(LiberaCAlgID ALG, LiberaCBignum *MESSAGE, const LiberaCBignum *CIPHERTEXT, const LiberaCRsaPrivateKey *PRIVATE_KEY) {
    if (ALG != LIBERAC_ALG_RSA_RAW) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!MESSAGE || !CIPHERTEXT || !PRIVATE_KEY) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (crypto_bignum_compare(CIPHERTEXT, &PRIVATE_KEY->N) >= 0) return LIBERAC_ERROR_INVALID_ARGUMENT;
    return crypto_bignum_mod_exp_ct(MESSAGE, CIPHERTEXT, &PRIVATE_KEY->D, &PRIVATE_KEY->N) == 0 ? LIBERAC_SUCCESS : LIBERAC_ERROR_ARITHMETIC;
}
