/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "elgamal_internal.h"
#include "Util/Bignum/bignum_internal.h"
#include "Util/Prime/prime_internal.h"

void crypto_elgamal_public_key_init_internal(LiberaCElgamalPublicKey *key) {
    if (!key) return;
    crypto_bignum_init(&key->P); crypto_bignum_init(&key->Q); crypto_bignum_init(&key->G); crypto_bignum_init(&key->H);
}
void crypto_elgamal_public_key_free_internal(LiberaCElgamalPublicKey *key) {
    if (!key) return;
    crypto_bignum_free(&key->P); crypto_bignum_free(&key->Q); crypto_bignum_free(&key->G); crypto_bignum_free(&key->H);
}
void crypto_elgamal_private_key_init_internal(LiberaCElgamalPrivateKey *key) {
    if (!key) return;
    crypto_bignum_init(&key->X);
}
void crypto_elgamal_private_key_free_internal(LiberaCElgamalPrivateKey *key) {
    if (!key) return;
    crypto_bignum_free(&key->X);
}
void crypto_elgamal_ciphertext_init_internal(LiberaCElgamalCiphertext *ciphertext) {
    if (!ciphertext) return;
    crypto_bignum_init(&ciphertext->C1); crypto_bignum_init(&ciphertext->C2);
}
void crypto_elgamal_ciphertext_free_internal(LiberaCElgamalCiphertext *ciphertext) {
    if (!ciphertext) return;
    crypto_bignum_free(&ciphertext->C1); crypto_bignum_free(&ciphertext->C2);
}

LiberaCError elgamal_random_nonzero(LiberaCBignum *out,
                                    const LiberaCBignum *upper) {
    uint32_t tries;
    for (tries = 0; tries < 128u; ++tries) {
        LiberaCError err = crypto_bignum_random_range(out, upper);
        if (err != LIBERAC_SUCCESS) return err;
        if (!crypto_bignum_is_zero(out)) return LIBERAC_SUCCESS;
        crypto_bignum_free(out); crypto_bignum_init(out);
    }
    return LIBERAC_ERROR_INTERNAL;
}

LiberaCError crypto_elgamal_keygen_internal(LiberaCAlgID alg, LiberaCElgamalPublicKey *public_key, LiberaCElgamalPrivateKey *private_key, size_t modulus_bits, uint32_t prime_rounds) {
    LiberaCBignum p, q, hseed, g, x, h, p_minus_3;
    uint32_t tries;
    LiberaCError err = LIBERAC_ERROR_ARITHMETIC;
    if (alg != LIBERAC_ALG_ELGAMAL_SAFE_PRIME) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!public_key || !private_key || modulus_bits < 32u) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (prime_rounds == 0u) prime_rounds = 32u;

    crypto_bignum_init(&p); crypto_bignum_init(&q); crypto_bignum_init(&hseed); crypto_bignum_init(&g);
    crypto_bignum_init(&x); crypto_bignum_init(&h); crypto_bignum_init(&p_minus_3);
    err = crypto_prime_generate_safe_internal(
        &p, &q, modulus_bits, prime_rounds);
    if (err != LIBERAC_SUCCESS) goto fail;
    if (bignum_sub_u32(&p_minus_3, &p, 3u) != 0) {
        err = LIBERAC_ERROR_ALLOCATION_FAILED;
        goto fail;
    }

    for (tries = 0; tries < 128u; ++tries) {
        LiberaCBignum two;
        crypto_bignum_init(&two);
        crypto_bignum_free(&hseed); crypto_bignum_init(&hseed);
        crypto_bignum_free(&g); crypto_bignum_init(&g);
        err = crypto_bignum_random_range(&hseed, &p_minus_3);
        if (err != LIBERAC_SUCCESS) {
            crypto_bignum_free(&two);
            goto fail;
        }
        if (bignum_add_u32(&hseed, 2u) != 0 ||
            crypto_bignum_set_u64(&two, 2u) != LIBERAC_SUCCESS) {
            err = LIBERAC_ERROR_ALLOCATION_FAILED;
            crypto_bignum_free(&two);
            goto fail;
        }
        if (crypto_bignum_mod_exp(&g, &hseed, &two, &p) !=
            LIBERAC_SUCCESS) {
            err = LIBERAC_ERROR_ARITHMETIC;
            crypto_bignum_free(&two);
            goto fail;
        }
        crypto_bignum_free(&two);
        if (!(g.LENGTH == 1u && g.LIMBS[0] == 1u)) break;
    }
    if (tries == 128u) {
        err = LIBERAC_ERROR_INTERNAL;
        goto fail;
    }
    err = elgamal_random_nonzero(&x, &q);
    if (err != LIBERAC_SUCCESS) goto fail;
    if (crypto_bignum_mod_exp(&h, &g, &x, &p) != LIBERAC_SUCCESS) {
        err = LIBERAC_ERROR_ARITHMETIC;
        goto fail;
    }

    crypto_elgamal_public_key_free_internal(public_key); crypto_elgamal_public_key_init_internal(public_key);
    crypto_elgamal_private_key_free_internal(private_key); crypto_elgamal_private_key_init_internal(private_key);
    if (crypto_bignum_copy(&public_key->P, &p) != LIBERAC_SUCCESS || crypto_bignum_copy(&public_key->Q, &q) != LIBERAC_SUCCESS ||
        crypto_bignum_copy(&public_key->G, &g) != LIBERAC_SUCCESS || crypto_bignum_copy(&public_key->H, &h) != LIBERAC_SUCCESS ||
        crypto_bignum_copy(&private_key->X, &x) != LIBERAC_SUCCESS) {
        err = LIBERAC_ERROR_ALLOCATION_FAILED;
        goto fail;
    }

    crypto_bignum_free(&p); crypto_bignum_free(&q); crypto_bignum_free(&hseed); crypto_bignum_free(&g);
    crypto_bignum_free(&x); crypto_bignum_free(&h); crypto_bignum_free(&p_minus_3);
    return LIBERAC_SUCCESS;
fail:
    crypto_bignum_free(&p); crypto_bignum_free(&q); crypto_bignum_free(&hseed); crypto_bignum_free(&g);
    crypto_bignum_free(&x); crypto_bignum_free(&h); crypto_bignum_free(&p_minus_3);
    return err;
}

LiberaCError crypto_elgamal_encrypt_internal(LiberaCAlgID alg, LiberaCElgamalCiphertext *ciphertext, const LiberaCBignum *message, const LiberaCElgamalPublicKey *public_key) {
    LiberaCBignum y, shared, c1, c2;
    LiberaCError err = LIBERAC_ERROR_ARITHMETIC;
    if (alg != LIBERAC_ALG_ELGAMAL_SAFE_PRIME) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!ciphertext || !message || !public_key) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (crypto_bignum_compare(message, &public_key->P) >= 0) return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    crypto_bignum_init(&y); crypto_bignum_init(&shared); crypto_bignum_init(&c1); crypto_bignum_init(&c2);
    err = elgamal_random_nonzero(&y, &public_key->Q);
    if (err != LIBERAC_SUCCESS) goto done;
    if (crypto_bignum_mod_exp(&c1, &public_key->G, &y, &public_key->P) != LIBERAC_SUCCESS ||
        crypto_bignum_mod_exp(&shared, &public_key->H, &y, &public_key->P) != LIBERAC_SUCCESS ||
        crypto_bignum_mod_mul(&c2, message, &shared, &public_key->P) != LIBERAC_SUCCESS) {
        err = LIBERAC_ERROR_ARITHMETIC;
        goto done;
    }
    crypto_elgamal_ciphertext_free_internal(ciphertext); crypto_elgamal_ciphertext_init_internal(ciphertext);
    ciphertext->C1 = c1; crypto_bignum_init(&c1);
    ciphertext->C2 = c2; crypto_bignum_init(&c2);
    err = LIBERAC_SUCCESS;
done:
    crypto_bignum_free(&y); crypto_bignum_free(&shared); crypto_bignum_free(&c1); crypto_bignum_free(&c2);
    return err;
}

LiberaCError crypto_elgamal_decrypt_internal(LiberaCAlgID alg, LiberaCBignum *message, const LiberaCElgamalCiphertext *ciphertext, const LiberaCElgamalPublicKey *public_key, const LiberaCElgamalPrivateKey *private_key) {
    LiberaCBignum shared, exponent, inverse;
    LiberaCError err = LIBERAC_ERROR_ARITHMETIC;
    if (alg != LIBERAC_ALG_ELGAMAL_SAFE_PRIME) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!message || !ciphertext || !public_key || !private_key) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (crypto_bignum_compare(&ciphertext->C1, &public_key->P) >= 0 || crypto_bignum_compare(&ciphertext->C2, &public_key->P) >= 0) return LIBERAC_ERROR_INVALID_ARGUMENT;
    crypto_bignum_init(&shared); crypto_bignum_init(&exponent); crypto_bignum_init(&inverse);
    if (crypto_bignum_mod_exp(&shared, &ciphertext->C1, &private_key->X, &public_key->P) != LIBERAC_SUCCESS ||
        bignum_sub_u32(&exponent, &public_key->P, 2u) != 0 ||
        crypto_bignum_mod_exp(&inverse, &shared, &exponent, &public_key->P) != LIBERAC_SUCCESS ||
        crypto_bignum_mod_mul(message, &ciphertext->C2, &inverse, &public_key->P) != LIBERAC_SUCCESS) goto done;
    err = LIBERAC_SUCCESS;
done:
    crypto_bignum_free(&shared); crypto_bignum_free(&exponent); crypto_bignum_free(&inverse);
    return err;
}
