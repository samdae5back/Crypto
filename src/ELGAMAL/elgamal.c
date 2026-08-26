#include "ELGAMAL.h"
#include "PRIME.h"
#include "elgamal_internal.h"
#include "../BIGNUM/bignum_internal.h"

void ELGAMAL_PUBLIC_KEY_INIT(ELGAMAL_PUBLIC_KEY *key) {
    if (!key) return;
    BIGNUM_INIT(&key->P); BIGNUM_INIT(&key->Q); BIGNUM_INIT(&key->G); BIGNUM_INIT(&key->H);
}
void ELGAMAL_PUBLIC_KEY_FREE(ELGAMAL_PUBLIC_KEY *key) {
    if (!key) return;
    BIGNUM_FREE(&key->P); BIGNUM_FREE(&key->Q); BIGNUM_FREE(&key->G); BIGNUM_FREE(&key->H);
}
void ELGAMAL_PRIVATE_KEY_INIT(ELGAMAL_PRIVATE_KEY *key) {
    if (!key) return;
    BIGNUM_INIT(&key->X);
}
void ELGAMAL_PRIVATE_KEY_FREE(ELGAMAL_PRIVATE_KEY *key) {
    if (!key) return;
    BIGNUM_FREE(&key->X);
}
void ELGAMAL_CIPHERTEXT_INIT(ELGAMAL_CIPHERTEXT *ciphertext) {
    if (!ciphertext) return;
    BIGNUM_INIT(&ciphertext->C1); BIGNUM_INIT(&ciphertext->C2);
}
void ELGAMAL_CIPHERTEXT_FREE(ELGAMAL_CIPHERTEXT *ciphertext) {
    if (!ciphertext) return;
    BIGNUM_FREE(&ciphertext->C1); BIGNUM_FREE(&ciphertext->C2);
}

int elgamal_random_nonzero(BIGNUM *out, const BIGNUM *upper) {
    uint32_t tries;
    for (tries = 0; tries < 128u; ++tries) {
        if (BIGNUM_RANDOM_RANGE(out, upper) != CRYPTO_SUCCESS) return -1;
        if (!BIGNUM_IS_ZERO(out)) return 0;
        BIGNUM_FREE(out); BIGNUM_INIT(out);
    }
    return -1;
}

CryptoError ELGAMAL_KEYGEN(AlgID alg, ELGAMAL_PUBLIC_KEY *public_key, ELGAMAL_PRIVATE_KEY *private_key, size_t modulus_bits, uint32_t prime_rounds) {
    BIGNUM p, q, hseed, g, x, h, p_minus_3;
    uint32_t tries;
    CryptoError err = CRYPTO_ERROR_ARITHMETIC;
    if (alg != ALG_ELGAMAL_SAFE_PRIME) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!public_key || !private_key || modulus_bits < 32u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (prime_rounds == 0u) prime_rounds = 32u;

    BIGNUM_INIT(&p); BIGNUM_INIT(&q); BIGNUM_INIT(&hseed); BIGNUM_INIT(&g);
    BIGNUM_INIT(&x); BIGNUM_INIT(&h); BIGNUM_INIT(&p_minus_3);
    if (PRIME_GENERATE_SAFE(&p, &q, modulus_bits, prime_rounds) != CRYPTO_SUCCESS) {
        err = CRYPTO_ERROR_PRIME_GENERATION_FAILED;
        goto fail;
    }
    if (bignum_sub_u32(&p_minus_3, &p, 3u) != 0) goto fail;

    for (tries = 0; tries < 128u; ++tries) {
        BIGNUM two;
        BIGNUM_INIT(&two);
        BIGNUM_FREE(&hseed); BIGNUM_INIT(&hseed);
        BIGNUM_FREE(&g); BIGNUM_INIT(&g);
        if (BIGNUM_RANDOM_RANGE(&hseed, &p_minus_3) != CRYPTO_SUCCESS || bignum_add_u32(&hseed, 2u) != 0) {
            BIGNUM_FREE(&two);
            goto fail;
        }
        if (BIGNUM_SET_U64(&two, 2u) != CRYPTO_SUCCESS || BIGNUM_MOD_EXP(&g, &hseed, &two, &p) != CRYPTO_SUCCESS) {
            BIGNUM_FREE(&two);
            goto fail;
        }
        BIGNUM_FREE(&two);
        if (!(g.LENGTH == 1u && g.LIMBS[0] == 1u)) break;
    }
    if (tries == 128u) goto fail;
    if (elgamal_random_nonzero(&x, &q) != 0 || BIGNUM_MOD_EXP(&h, &g, &x, &p) != CRYPTO_SUCCESS) goto fail;

    ELGAMAL_PUBLIC_KEY_FREE(public_key); ELGAMAL_PUBLIC_KEY_INIT(public_key);
    ELGAMAL_PRIVATE_KEY_FREE(private_key); ELGAMAL_PRIVATE_KEY_INIT(private_key);
    if (BIGNUM_COPY(&public_key->P, &p) != CRYPTO_SUCCESS || BIGNUM_COPY(&public_key->Q, &q) != CRYPTO_SUCCESS ||
        BIGNUM_COPY(&public_key->G, &g) != CRYPTO_SUCCESS || BIGNUM_COPY(&public_key->H, &h) != CRYPTO_SUCCESS ||
        BIGNUM_COPY(&private_key->X, &x) != CRYPTO_SUCCESS) {
        err = CRYPTO_ERROR_ALLOCATION_FAILED;
        goto fail;
    }

    BIGNUM_FREE(&p); BIGNUM_FREE(&q); BIGNUM_FREE(&hseed); BIGNUM_FREE(&g);
    BIGNUM_FREE(&x); BIGNUM_FREE(&h); BIGNUM_FREE(&p_minus_3);
    return CRYPTO_SUCCESS;
fail:
    BIGNUM_FREE(&p); BIGNUM_FREE(&q); BIGNUM_FREE(&hseed); BIGNUM_FREE(&g);
    BIGNUM_FREE(&x); BIGNUM_FREE(&h); BIGNUM_FREE(&p_minus_3);
    return err;
}

CryptoError ELGAMAL_ENCRYPT(AlgID alg, ELGAMAL_CIPHERTEXT *ciphertext, const BIGNUM *message, const ELGAMAL_PUBLIC_KEY *public_key) {
    BIGNUM y, shared, c1, c2;
    CryptoError err = CRYPTO_ERROR_ARITHMETIC;
    if (alg != ALG_ELGAMAL_SAFE_PRIME) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!ciphertext || !message || !public_key) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (BIGNUM_COMPARE(message, &public_key->P) >= 0) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    BIGNUM_INIT(&y); BIGNUM_INIT(&shared); BIGNUM_INIT(&c1); BIGNUM_INIT(&c2);
    if (elgamal_random_nonzero(&y, &public_key->Q) != 0 ||
        BIGNUM_MOD_EXP(&c1, &public_key->G, &y, &public_key->P) != CRYPTO_SUCCESS ||
        BIGNUM_MOD_EXP(&shared, &public_key->H, &y, &public_key->P) != CRYPTO_SUCCESS ||
        BIGNUM_MOD_MUL(&c2, message, &shared, &public_key->P) != CRYPTO_SUCCESS) goto done;
    ELGAMAL_CIPHERTEXT_FREE(ciphertext); ELGAMAL_CIPHERTEXT_INIT(ciphertext);
    ciphertext->C1 = c1; BIGNUM_INIT(&c1);
    ciphertext->C2 = c2; BIGNUM_INIT(&c2);
    err = CRYPTO_SUCCESS;
done:
    BIGNUM_FREE(&y); BIGNUM_FREE(&shared); BIGNUM_FREE(&c1); BIGNUM_FREE(&c2);
    return err;
}

CryptoError ELGAMAL_DECRYPT(AlgID alg, BIGNUM *message, const ELGAMAL_CIPHERTEXT *ciphertext, const ELGAMAL_PUBLIC_KEY *public_key, const ELGAMAL_PRIVATE_KEY *private_key) {
    BIGNUM shared, exponent, inverse;
    CryptoError err = CRYPTO_ERROR_ARITHMETIC;
    if (alg != ALG_ELGAMAL_SAFE_PRIME) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!message || !ciphertext || !public_key || !private_key) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (BIGNUM_COMPARE(&ciphertext->C1, &public_key->P) >= 0 || BIGNUM_COMPARE(&ciphertext->C2, &public_key->P) >= 0) return CRYPTO_ERROR_INVALID_ARGUMENT;
    BIGNUM_INIT(&shared); BIGNUM_INIT(&exponent); BIGNUM_INIT(&inverse);
    if (BIGNUM_MOD_EXP(&shared, &ciphertext->C1, &private_key->X, &public_key->P) != CRYPTO_SUCCESS ||
        bignum_sub_u32(&exponent, &public_key->P, 2u) != 0 ||
        BIGNUM_MOD_EXP(&inverse, &shared, &exponent, &public_key->P) != CRYPTO_SUCCESS ||
        BIGNUM_MOD_MUL(message, &ciphertext->C2, &inverse, &public_key->P) != CRYPTO_SUCCESS) goto done;
    err = CRYPTO_SUCCESS;
done:
    BIGNUM_FREE(&shared); BIGNUM_FREE(&exponent); BIGNUM_FREE(&inverse);
    return err;
}
