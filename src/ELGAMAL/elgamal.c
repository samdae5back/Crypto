#include "ELGAMAL.h"
#include "PRIME.h"
#include "elgamal_internal.h"
#include "../BIGNUM/bignum_internal.h"

void CRYPTO_ELGAMAL_PUBLIC_KEY_INIT(ELGAMAL_PUBLIC_KEY *key) {
    if (!key) return;
    CRYPTO_BIGNUM_INIT(&key->P); CRYPTO_BIGNUM_INIT(&key->Q); CRYPTO_BIGNUM_INIT(&key->G); CRYPTO_BIGNUM_INIT(&key->H);
}
void CRYPTO_ELGAMAL_PUBLIC_KEY_FREE(ELGAMAL_PUBLIC_KEY *key) {
    if (!key) return;
    CRYPTO_BIGNUM_FREE(&key->P); CRYPTO_BIGNUM_FREE(&key->Q); CRYPTO_BIGNUM_FREE(&key->G); CRYPTO_BIGNUM_FREE(&key->H);
}
void CRYPTO_ELGAMAL_PRIVATE_KEY_INIT(ELGAMAL_PRIVATE_KEY *key) {
    if (!key) return;
    CRYPTO_BIGNUM_INIT(&key->X);
}
void CRYPTO_ELGAMAL_PRIVATE_KEY_FREE(ELGAMAL_PRIVATE_KEY *key) {
    if (!key) return;
    CRYPTO_BIGNUM_FREE(&key->X);
}
void CRYPTO_ELGAMAL_CIPHERTEXT_INIT(ELGAMAL_CIPHERTEXT *ciphertext) {
    if (!ciphertext) return;
    CRYPTO_BIGNUM_INIT(&ciphertext->C1); CRYPTO_BIGNUM_INIT(&ciphertext->C2);
}
void CRYPTO_ELGAMAL_CIPHERTEXT_FREE(ELGAMAL_CIPHERTEXT *ciphertext) {
    if (!ciphertext) return;
    CRYPTO_BIGNUM_FREE(&ciphertext->C1); CRYPTO_BIGNUM_FREE(&ciphertext->C2);
}

int elgamal_random_nonzero(BIGNUM *out, const BIGNUM *upper) {
    uint32_t tries;
    for (tries = 0; tries < 128u; ++tries) {
        if (CRYPTO_BIGNUM_RANDOM_RANGE(out, upper) != CRYPTO_SUCCESS) return -1;
        if (!CRYPTO_BIGNUM_IS_ZERO(out)) return 0;
        CRYPTO_BIGNUM_FREE(out); CRYPTO_BIGNUM_INIT(out);
    }
    return -1;
}

CryptoError CRYPTO_ELGAMAL_KEYGEN(AlgID alg, ELGAMAL_PUBLIC_KEY *public_key, ELGAMAL_PRIVATE_KEY *private_key, size_t modulus_bits, uint32_t prime_rounds) {
    BIGNUM p, q, hseed, g, x, h, p_minus_3;
    uint32_t tries;
    CryptoError err = CRYPTO_ERROR_ARITHMETIC;
    if (alg != ALG_ELGAMAL_SAFE_PRIME) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!public_key || !private_key || modulus_bits < 32u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (prime_rounds == 0u) prime_rounds = 32u;

    CRYPTO_BIGNUM_INIT(&p); CRYPTO_BIGNUM_INIT(&q); CRYPTO_BIGNUM_INIT(&hseed); CRYPTO_BIGNUM_INIT(&g);
    CRYPTO_BIGNUM_INIT(&x); CRYPTO_BIGNUM_INIT(&h); CRYPTO_BIGNUM_INIT(&p_minus_3);
    if (CRYPTO_PRIME_GENERATE_SAFE(&p, &q, modulus_bits, prime_rounds) != CRYPTO_SUCCESS) {
        err = CRYPTO_ERROR_PRIME_GENERATION_FAILED;
        goto fail;
    }
    if (bignum_sub_u32(&p_minus_3, &p, 3u) != 0) goto fail;

    for (tries = 0; tries < 128u; ++tries) {
        BIGNUM two;
        CRYPTO_BIGNUM_INIT(&two);
        CRYPTO_BIGNUM_FREE(&hseed); CRYPTO_BIGNUM_INIT(&hseed);
        CRYPTO_BIGNUM_FREE(&g); CRYPTO_BIGNUM_INIT(&g);
        if (CRYPTO_BIGNUM_RANDOM_RANGE(&hseed, &p_minus_3) != CRYPTO_SUCCESS || bignum_add_u32(&hseed, 2u) != 0) {
            CRYPTO_BIGNUM_FREE(&two);
            goto fail;
        }
        if (CRYPTO_BIGNUM_SET_U64(&two, 2u) != CRYPTO_SUCCESS || CRYPTO_BIGNUM_MOD_EXP(&g, &hseed, &two, &p) != CRYPTO_SUCCESS) {
            CRYPTO_BIGNUM_FREE(&two);
            goto fail;
        }
        CRYPTO_BIGNUM_FREE(&two);
        if (!(g.LENGTH == 1u && g.LIMBS[0] == 1u)) break;
    }
    if (tries == 128u) goto fail;
    if (elgamal_random_nonzero(&x, &q) != 0 || CRYPTO_BIGNUM_MOD_EXP(&h, &g, &x, &p) != CRYPTO_SUCCESS) goto fail;

    CRYPTO_ELGAMAL_PUBLIC_KEY_FREE(public_key); CRYPTO_ELGAMAL_PUBLIC_KEY_INIT(public_key);
    CRYPTO_ELGAMAL_PRIVATE_KEY_FREE(private_key); CRYPTO_ELGAMAL_PRIVATE_KEY_INIT(private_key);
    if (CRYPTO_BIGNUM_COPY(&public_key->P, &p) != CRYPTO_SUCCESS || CRYPTO_BIGNUM_COPY(&public_key->Q, &q) != CRYPTO_SUCCESS ||
        CRYPTO_BIGNUM_COPY(&public_key->G, &g) != CRYPTO_SUCCESS || CRYPTO_BIGNUM_COPY(&public_key->H, &h) != CRYPTO_SUCCESS ||
        CRYPTO_BIGNUM_COPY(&private_key->X, &x) != CRYPTO_SUCCESS) {
        err = CRYPTO_ERROR_ALLOCATION_FAILED;
        goto fail;
    }

    CRYPTO_BIGNUM_FREE(&p); CRYPTO_BIGNUM_FREE(&q); CRYPTO_BIGNUM_FREE(&hseed); CRYPTO_BIGNUM_FREE(&g);
    CRYPTO_BIGNUM_FREE(&x); CRYPTO_BIGNUM_FREE(&h); CRYPTO_BIGNUM_FREE(&p_minus_3);
    return CRYPTO_SUCCESS;
fail:
    CRYPTO_BIGNUM_FREE(&p); CRYPTO_BIGNUM_FREE(&q); CRYPTO_BIGNUM_FREE(&hseed); CRYPTO_BIGNUM_FREE(&g);
    CRYPTO_BIGNUM_FREE(&x); CRYPTO_BIGNUM_FREE(&h); CRYPTO_BIGNUM_FREE(&p_minus_3);
    return err;
}

CryptoError CRYPTO_ELGAMAL_ENCRYPT(AlgID alg, ELGAMAL_CIPHERTEXT *ciphertext, const BIGNUM *message, const ELGAMAL_PUBLIC_KEY *public_key) {
    BIGNUM y, shared, c1, c2;
    CryptoError err = CRYPTO_ERROR_ARITHMETIC;
    if (alg != ALG_ELGAMAL_SAFE_PRIME) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!ciphertext || !message || !public_key) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (CRYPTO_BIGNUM_COMPARE(message, &public_key->P) >= 0) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    CRYPTO_BIGNUM_INIT(&y); CRYPTO_BIGNUM_INIT(&shared); CRYPTO_BIGNUM_INIT(&c1); CRYPTO_BIGNUM_INIT(&c2);
    if (elgamal_random_nonzero(&y, &public_key->Q) != 0 ||
        CRYPTO_BIGNUM_MOD_EXP(&c1, &public_key->G, &y, &public_key->P) != CRYPTO_SUCCESS ||
        CRYPTO_BIGNUM_MOD_EXP(&shared, &public_key->H, &y, &public_key->P) != CRYPTO_SUCCESS ||
        CRYPTO_BIGNUM_MOD_MUL(&c2, message, &shared, &public_key->P) != CRYPTO_SUCCESS) goto done;
    CRYPTO_ELGAMAL_CIPHERTEXT_FREE(ciphertext); CRYPTO_ELGAMAL_CIPHERTEXT_INIT(ciphertext);
    ciphertext->C1 = c1; CRYPTO_BIGNUM_INIT(&c1);
    ciphertext->C2 = c2; CRYPTO_BIGNUM_INIT(&c2);
    err = CRYPTO_SUCCESS;
done:
    CRYPTO_BIGNUM_FREE(&y); CRYPTO_BIGNUM_FREE(&shared); CRYPTO_BIGNUM_FREE(&c1); CRYPTO_BIGNUM_FREE(&c2);
    return err;
}

CryptoError CRYPTO_ELGAMAL_DECRYPT(AlgID alg, BIGNUM *message, const ELGAMAL_CIPHERTEXT *ciphertext, const ELGAMAL_PUBLIC_KEY *public_key, const ELGAMAL_PRIVATE_KEY *private_key) {
    BIGNUM shared, exponent, inverse;
    CryptoError err = CRYPTO_ERROR_ARITHMETIC;
    if (alg != ALG_ELGAMAL_SAFE_PRIME) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!message || !ciphertext || !public_key || !private_key) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (CRYPTO_BIGNUM_COMPARE(&ciphertext->C1, &public_key->P) >= 0 || CRYPTO_BIGNUM_COMPARE(&ciphertext->C2, &public_key->P) >= 0) return CRYPTO_ERROR_INVALID_ARGUMENT;
    CRYPTO_BIGNUM_INIT(&shared); CRYPTO_BIGNUM_INIT(&exponent); CRYPTO_BIGNUM_INIT(&inverse);
    if (CRYPTO_BIGNUM_MOD_EXP(&shared, &ciphertext->C1, &private_key->X, &public_key->P) != CRYPTO_SUCCESS ||
        bignum_sub_u32(&exponent, &public_key->P, 2u) != 0 ||
        CRYPTO_BIGNUM_MOD_EXP(&inverse, &shared, &exponent, &public_key->P) != CRYPTO_SUCCESS ||
        CRYPTO_BIGNUM_MOD_MUL(message, &ciphertext->C2, &inverse, &public_key->P) != CRYPTO_SUCCESS) goto done;
    err = CRYPTO_SUCCESS;
done:
    CRYPTO_BIGNUM_FREE(&shared); CRYPTO_BIGNUM_FREE(&exponent); CRYPTO_BIGNUM_FREE(&inverse);
    return err;
}
