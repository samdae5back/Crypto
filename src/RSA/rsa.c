#include "RSA.h"
#include "PRIME.h"
#include "rsa_internal.h"
#include "../BIGNUM/bignum_internal.h"

#include <stdint.h>

#define RSA_DEFAULT_E 65537u

void CRYPTO_RSA_PUBLIC_KEY_INIT(RSA_PUBLIC_KEY *KEY) {
    if (!KEY) return;
    CRYPTO_BIGNUM_INIT(&KEY->N); CRYPTO_BIGNUM_INIT(&KEY->E);
}
void CRYPTO_RSA_PUBLIC_KEY_FREE(RSA_PUBLIC_KEY *KEY) {
    if (!KEY) return;
    CRYPTO_BIGNUM_FREE(&KEY->N); CRYPTO_BIGNUM_FREE(&KEY->E);
}
void CRYPTO_RSA_PRIVATE_KEY_INIT(RSA_PRIVATE_KEY *KEY) {
    if (!KEY) return;
    CRYPTO_BIGNUM_INIT(&KEY->N); CRYPTO_BIGNUM_INIT(&KEY->D); CRYPTO_BIGNUM_INIT(&KEY->P); CRYPTO_BIGNUM_INIT(&KEY->Q);
}
void CRYPTO_RSA_PRIVATE_KEY_FREE(RSA_PRIVATE_KEY *KEY) {
    if (!KEY) return;
    CRYPTO_BIGNUM_FREE(&KEY->N); CRYPTO_BIGNUM_FREE(&KEY->D); CRYPTO_BIGNUM_FREE(&KEY->P); CRYPTO_BIGNUM_FREE(&KEY->Q);
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

static int make_private_exponent(BIGNUM *d, const BIGNUM *phi) {
    uint32_t r = bignum_mod_u32(phi, RSA_DEFAULT_E);
    uint32_t inv, k, rem;
    BIGNUM tmp, numerator;
    int rc = -1;
    if (r == 0) return -1;
    inv = rsa_inverse_u32(r, RSA_DEFAULT_E);
    if (inv == 0) return -1;
    k = RSA_DEFAULT_E - inv;
    if (k == RSA_DEFAULT_E) k = 0;
    CRYPTO_BIGNUM_INIT(&tmp); CRYPTO_BIGNUM_INIT(&numerator);
    if (bignum_mul_u32(&tmp, phi, k) != 0 || bignum_add_u32_copy(&numerator, &tmp, 1) != 0) goto done;
    if (bignum_div_u32(d, &numerator, RSA_DEFAULT_E, &rem) != 0 || rem != 0) goto done;
    rc = 0;
done:
    CRYPTO_BIGNUM_FREE(&tmp); CRYPTO_BIGNUM_FREE(&numerator);
    return rc;
}

CryptoError CRYPTO_RSA_KEYGEN(AlgID ALG, RSA_PUBLIC_KEY *PUBLIC_KEY, RSA_PRIVATE_KEY *PRIVATE_KEY, size_t MODULUS_BITS, unsigned PRIME_ROUNDS) {
    BIGNUM p, q, n, p1, q1, phi, d;
    size_t p_bits, q_bits;
    int attempts;
    if (ALG != ALG_RSA_RAW) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!PUBLIC_KEY || !PRIVATE_KEY || MODULUS_BITS < 32) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (PRIME_ROUNDS == 0) PRIME_ROUNDS = 32;
    p_bits = MODULUS_BITS / 2u;
    q_bits = MODULUS_BITS - p_bits;
    CRYPTO_BIGNUM_INIT(&p); CRYPTO_BIGNUM_INIT(&q); CRYPTO_BIGNUM_INIT(&n); CRYPTO_BIGNUM_INIT(&p1); CRYPTO_BIGNUM_INIT(&q1); CRYPTO_BIGNUM_INIT(&phi); CRYPTO_BIGNUM_INIT(&d);

    for (attempts = 0; attempts < 128; ++attempts) {
        CRYPTO_BIGNUM_FREE(&p); CRYPTO_BIGNUM_INIT(&p); CRYPTO_BIGNUM_FREE(&q); CRYPTO_BIGNUM_INIT(&q);
        CRYPTO_BIGNUM_FREE(&n); CRYPTO_BIGNUM_INIT(&n); CRYPTO_BIGNUM_FREE(&p1); CRYPTO_BIGNUM_INIT(&p1); CRYPTO_BIGNUM_FREE(&q1); CRYPTO_BIGNUM_INIT(&q1); CRYPTO_BIGNUM_FREE(&phi); CRYPTO_BIGNUM_INIT(&phi); CRYPTO_BIGNUM_FREE(&d); CRYPTO_BIGNUM_INIT(&d);
        if (CRYPTO_PRIME_GENERATE(&p, p_bits, PRIME_ROUNDS) != CRYPTO_SUCCESS || CRYPTO_PRIME_GENERATE(&q, q_bits, PRIME_ROUNDS) != CRYPTO_SUCCESS) goto prime_fail;
        if (CRYPTO_BIGNUM_COMPARE(&p, &q) == 0) continue;
        if (CRYPTO_BIGNUM_MUL(&n, &p, &q) != 0) goto arithmetic_fail;
        if (CRYPTO_BIGNUM_BIT_LENGTH(&n) != MODULUS_BITS) continue;
        if (bignum_sub_u32(&p1, &p, 1) != 0 || bignum_sub_u32(&q1, &q, 1) != 0 || CRYPTO_BIGNUM_MUL(&phi, &p1, &q1) != 0) goto arithmetic_fail;
        if (bignum_mod_u32(&phi, RSA_DEFAULT_E) == 0) continue;
        if (make_private_exponent(&d, &phi) != 0) continue;

        CRYPTO_RSA_PUBLIC_KEY_FREE(PUBLIC_KEY); CRYPTO_RSA_PUBLIC_KEY_INIT(PUBLIC_KEY);
        CRYPTO_RSA_PRIVATE_KEY_FREE(PRIVATE_KEY); CRYPTO_RSA_PRIVATE_KEY_INIT(PRIVATE_KEY);
        if (CRYPTO_BIGNUM_COPY(&PUBLIC_KEY->N, &n) != 0 || CRYPTO_BIGNUM_SET_U64(&PUBLIC_KEY->E, RSA_DEFAULT_E) != 0 ||
            CRYPTO_BIGNUM_COPY(&PRIVATE_KEY->N, &n) != 0 || CRYPTO_BIGNUM_COPY(&PRIVATE_KEY->D, &d) != 0 ||
            CRYPTO_BIGNUM_COPY(&PRIVATE_KEY->P, &p) != 0 || CRYPTO_BIGNUM_COPY(&PRIVATE_KEY->Q, &q) != 0) goto alloc_fail;
        CRYPTO_BIGNUM_FREE(&p); CRYPTO_BIGNUM_FREE(&q); CRYPTO_BIGNUM_FREE(&n); CRYPTO_BIGNUM_FREE(&p1); CRYPTO_BIGNUM_FREE(&q1); CRYPTO_BIGNUM_FREE(&phi); CRYPTO_BIGNUM_FREE(&d);
        return CRYPTO_SUCCESS;
    }
prime_fail:
    CRYPTO_BIGNUM_FREE(&p); CRYPTO_BIGNUM_FREE(&q); CRYPTO_BIGNUM_FREE(&n); CRYPTO_BIGNUM_FREE(&p1); CRYPTO_BIGNUM_FREE(&q1); CRYPTO_BIGNUM_FREE(&phi); CRYPTO_BIGNUM_FREE(&d);
    return CRYPTO_ERROR_PRIME_GENERATION_FAILED;
arithmetic_fail:
    CRYPTO_BIGNUM_FREE(&p); CRYPTO_BIGNUM_FREE(&q); CRYPTO_BIGNUM_FREE(&n); CRYPTO_BIGNUM_FREE(&p1); CRYPTO_BIGNUM_FREE(&q1); CRYPTO_BIGNUM_FREE(&phi); CRYPTO_BIGNUM_FREE(&d);
    return CRYPTO_ERROR_ARITHMETIC;
alloc_fail:
    CRYPTO_BIGNUM_FREE(&p); CRYPTO_BIGNUM_FREE(&q); CRYPTO_BIGNUM_FREE(&n); CRYPTO_BIGNUM_FREE(&p1); CRYPTO_BIGNUM_FREE(&q1); CRYPTO_BIGNUM_FREE(&phi); CRYPTO_BIGNUM_FREE(&d);
    return CRYPTO_ERROR_ALLOCATION_FAILED;
}

CryptoError CRYPTO_RSA_ENCRYPT(AlgID ALG, BIGNUM *CIPHERTEXT, const BIGNUM *MESSAGE, const RSA_PUBLIC_KEY *PUBLIC_KEY) {
    if (ALG != ALG_RSA_RAW) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!CIPHERTEXT || !MESSAGE || !PUBLIC_KEY) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (CRYPTO_BIGNUM_COMPARE(MESSAGE, &PUBLIC_KEY->N) >= 0) return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    return CRYPTO_BIGNUM_MOD_EXP(CIPHERTEXT, MESSAGE, &PUBLIC_KEY->E, &PUBLIC_KEY->N) == 0 ? CRYPTO_SUCCESS : CRYPTO_ERROR_ARITHMETIC;
}

CryptoError CRYPTO_RSA_DECRYPT(AlgID ALG, BIGNUM *MESSAGE, const BIGNUM *CIPHERTEXT, const RSA_PRIVATE_KEY *PRIVATE_KEY) {
    if (ALG != ALG_RSA_RAW) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!MESSAGE || !CIPHERTEXT || !PRIVATE_KEY) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (CRYPTO_BIGNUM_COMPARE(CIPHERTEXT, &PRIVATE_KEY->N) >= 0) return CRYPTO_ERROR_INVALID_ARGUMENT;
    return CRYPTO_BIGNUM_MOD_EXP(MESSAGE, CIPHERTEXT, &PRIVATE_KEY->D, &PRIVATE_KEY->N) == 0 ? CRYPTO_SUCCESS : CRYPTO_ERROR_ARITHMETIC;
}
