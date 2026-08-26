#include "PRIME.h"
#include "prime_internal.h"
#include "../BIGNUM/bignum_internal.h"
#include "../INTERNAL/crypto_types.h"

static const uint16_t SMALL_PRIMES[] = {
    3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,
    101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,
    193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,
    293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,
    409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,
    521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,
    641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,
    757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,
    881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997
};

int prime_small_division(const BIGNUM *n) {
    size_t i;
    if (!n || n->LENGTH == 0u) return 0;
    if (n->LENGTH == 1u && n->LIMBS[0] == 2u) return 1;
    if (!(n->LIMBS[0] & 1u)) return 0;
    for (i = 0; i < sizeof(SMALL_PRIMES) / sizeof(SMALL_PRIMES[0]); ++i) {
        uint32_t p = SMALL_PRIMES[i];
        if (n->LENGTH == 1u && n->LIMBS[0] == p) return 1;
        if (bignum_mod_u32(n, p) == 0u) return 0;
    }
    return 1;
}

int CRYPTO_PRIME_IS_PROBABLE(const BIGNUM *value, uint32_t rounds) {
    BIGNUM n_minus_1, d, n_minus_3, a, x, tmp;
    size_t s = 0u;
    uint32_t round;
    int result = 0;

    if (!value || value->LENGTH == 0u) return 0;
    if (value->LENGTH == 1u && (value->LIMBS[0] == 2u || value->LIMBS[0] == 3u)) return 1;
    if (value->LENGTH == 1u && value->LIMBS[0] < 2u) return 0;
    if (!prime_small_division(value)) return 0;
    if (rounds == 0u) rounds = 32u;

    CRYPTO_BIGNUM_INIT(&n_minus_1); CRYPTO_BIGNUM_INIT(&d); CRYPTO_BIGNUM_INIT(&n_minus_3);
    CRYPTO_BIGNUM_INIT(&a); CRYPTO_BIGNUM_INIT(&x); CRYPTO_BIGNUM_INIT(&tmp);
    if (bignum_sub_u32(&n_minus_1, value, 1u) != 0 || CRYPTO_BIGNUM_COPY(&d, &n_minus_1) != CRYPTO_SUCCESS || bignum_sub_u32(&n_minus_3, value, 3u) != 0) goto done;
    while (d.LENGTH && !(d.LIMBS[0] & 1u)) {
        uint32_t carry = 0u;
        size_t i;
        for (i = d.LENGTH; i > 0u; --i) {
            uint32_t next = d.LIMBS[i - 1u] & 1u;
            d.LIMBS[i - 1u] = (d.LIMBS[i - 1u] >> 1) | (carry << 31);
            carry = next;
        }
        bignum_normalize(&d);
        ++s;
    }

    for (round = 0u; round < rounds; ++round) {
        size_t j;
        int witness = 1;
        CRYPTO_BIGNUM_FREE(&a); CRYPTO_BIGNUM_INIT(&a);
        if (CRYPTO_BIGNUM_RANDOM_RANGE(&a, &n_minus_3) != CRYPTO_SUCCESS || bignum_add_u32(&a, 2u) != 0) goto done;
        if (CRYPTO_BIGNUM_MOD_EXP(&x, &a, &d, value) != CRYPTO_SUCCESS) goto done;
        if ((x.LENGTH == 1u && x.LIMBS[0] == 1u) || CRYPTO_BIGNUM_COMPARE(&x, &n_minus_1) == 0) continue;
        for (j = 1u; j < s; ++j) {
            if (CRYPTO_BIGNUM_MOD_MUL(&tmp, &x, &x, value) != CRYPTO_SUCCESS) goto done;
            CRYPTO_BIGNUM_FREE(&x); x = tmp; CRYPTO_BIGNUM_INIT(&tmp);
            if (CRYPTO_BIGNUM_COMPARE(&x, &n_minus_1) == 0) { witness = 0; break; }
            if (x.LENGTH == 1u && x.LIMBS[0] == 1u) goto done;
        }
        if (witness) goto done;
    }
    result = 1;
done:
    CRYPTO_BIGNUM_FREE(&n_minus_1); CRYPTO_BIGNUM_FREE(&d); CRYPTO_BIGNUM_FREE(&n_minus_3);
    CRYPTO_BIGNUM_FREE(&a); CRYPTO_BIGNUM_FREE(&x); CRYPTO_BIGNUM_FREE(&tmp);
    return result;
}

CryptoError CRYPTO_PRIME_GENERATE(BIGNUM *out, size_t bits, uint32_t rounds) {
    BIGNUM candidate;
    size_t tries;
    if (!out || bits < 2u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (rounds == 0u) rounds = 32u;
    CRYPTO_BIGNUM_INIT(&candidate);
    for (tries = 0u; tries < 1000000u; ++tries) {
        if (CRYPTO_BIGNUM_RANDOM_BITS(&candidate, bits, 1, 1) != CRYPTO_SUCCESS) {
            CRYPTO_BIGNUM_FREE(&candidate);
            return CRYPTO_ERROR_RANDOM_FAILED;
        }
        if (prime_small_division(&candidate) && CRYPTO_PRIME_IS_PROBABLE(&candidate, rounds)) {
            CRYPTO_BIGNUM_FREE(out);
            *out = candidate;
            return CRYPTO_SUCCESS;
        }
        CRYPTO_BIGNUM_FREE(&candidate); CRYPTO_BIGNUM_INIT(&candidate);
    }
    CRYPTO_BIGNUM_FREE(&candidate);
    return CRYPTO_ERROR_PRIME_GENERATION_FAILED;
}

CryptoError CRYPTO_PRIME_GENERATE_SAFE(BIGNUM *p_out, BIGNUM *q_out, size_t p_bits, uint32_t rounds) {
    BIGNUM qv, pv, tmp;
    size_t tries;
    if (!p_out || !q_out || p_bits < 3u) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (rounds == 0u) rounds = 32u;
    CRYPTO_BIGNUM_INIT(&qv); CRYPTO_BIGNUM_INIT(&pv); CRYPTO_BIGNUM_INIT(&tmp);
    for (tries = 0u; tries < 1000000u; ++tries) {
        CryptoError e = CRYPTO_PRIME_GENERATE(&qv, p_bits - 1u, rounds);
        if (e != CRYPTO_SUCCESS) {
            CRYPTO_BIGNUM_FREE(&qv); CRYPTO_BIGNUM_FREE(&pv); CRYPTO_BIGNUM_FREE(&tmp);
            return e;
        }
        if (bignum_mul_u32(&tmp, &qv, 2u) != 0 || bignum_add_u32_copy(&pv, &tmp, 1u) != 0) {
            CRYPTO_BIGNUM_FREE(&qv); CRYPTO_BIGNUM_FREE(&pv); CRYPTO_BIGNUM_FREE(&tmp);
            return CRYPTO_ERROR_ARITHMETIC;
        }
        CRYPTO_BIGNUM_FREE(&tmp); CRYPTO_BIGNUM_INIT(&tmp);
        if (CRYPTO_BIGNUM_BIT_LENGTH(&pv) == p_bits && CRYPTO_PRIME_IS_PROBABLE(&pv, rounds)) {
            CRYPTO_BIGNUM_FREE(p_out); *p_out = pv; CRYPTO_BIGNUM_INIT(&pv);
            CRYPTO_BIGNUM_FREE(q_out); *q_out = qv; CRYPTO_BIGNUM_INIT(&qv);
            CRYPTO_BIGNUM_FREE(&tmp);
            return CRYPTO_SUCCESS;
        }
        CRYPTO_BIGNUM_FREE(&qv); CRYPTO_BIGNUM_INIT(&qv);
        CRYPTO_BIGNUM_FREE(&pv); CRYPTO_BIGNUM_INIT(&pv);
    }
    CRYPTO_BIGNUM_FREE(&qv); CRYPTO_BIGNUM_FREE(&pv); CRYPTO_BIGNUM_FREE(&tmp);
    return CRYPTO_ERROR_PRIME_GENERATION_FAILED;
}
