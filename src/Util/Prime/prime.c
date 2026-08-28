/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "prime_internal.h"
#include "Util/Bignum/bignum_internal.h"

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

int prime_small_division(const LiberaCBignum *n) {
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

static LiberaCError prime_is_probable_checked(const LiberaCBignum *value,
                                              uint32_t rounds,
                                              int *is_probable) {
    LiberaCBignum n_minus_1, d, n_minus_3, a, x, tmp;
    size_t s = 0u;
    uint32_t round;
    LiberaCError err = LIBERAC_SUCCESS;

    if (!is_probable) return LIBERAC_ERROR_INVALID_ARGUMENT;
    *is_probable = 0;
    if (!value || value->LENGTH == 0u) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (value->LENGTH == 1u &&
        (value->LIMBS[0] == 2u || value->LIMBS[0] == 3u)) {
        *is_probable = 1;
        return LIBERAC_SUCCESS;
    }
    if (value->LENGTH == 1u && value->LIMBS[0] < 2u)
        return LIBERAC_SUCCESS;
    if (!prime_small_division(value)) return LIBERAC_SUCCESS;
    if (rounds == 0u) rounds = 32u;

    crypto_bignum_init(&n_minus_1); crypto_bignum_init(&d); crypto_bignum_init(&n_minus_3);
    crypto_bignum_init(&a); crypto_bignum_init(&x); crypto_bignum_init(&tmp);
    if (bignum_sub_u32(&n_minus_1, value, 1u) != 0 ||
        crypto_bignum_copy(&d, &n_minus_1) != LIBERAC_SUCCESS ||
        bignum_sub_u32(&n_minus_3, value, 3u) != 0) {
        err = LIBERAC_ERROR_ALLOCATION_FAILED;
        goto done;
    }
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
        crypto_bignum_free(&a); crypto_bignum_init(&a);
        err = crypto_bignum_random_range(&a, &n_minus_3);
        if (err != LIBERAC_SUCCESS) goto done;
        if (bignum_add_u32(&a, 2u) != 0 ||
            crypto_bignum_mod_exp(&x, &a, &d, value) != LIBERAC_SUCCESS) {
            err = LIBERAC_ERROR_ALLOCATION_FAILED;
            goto done;
        }
        if ((x.LENGTH == 1u && x.LIMBS[0] == 1u) || crypto_bignum_compare(&x, &n_minus_1) == 0) continue;
        for (j = 1u; j < s; ++j) {
            if (crypto_bignum_mod_square(&tmp, &x, value) !=
                LIBERAC_SUCCESS) {
                err = LIBERAC_ERROR_ALLOCATION_FAILED;
                goto done;
            }
            crypto_bignum_free(&x); x = tmp; crypto_bignum_init(&tmp);
            if (crypto_bignum_compare(&x, &n_minus_1) == 0) { witness = 0; break; }
            if (x.LENGTH == 1u && x.LIMBS[0] == 1u) goto done;
        }
        if (witness) goto done;
    }
    *is_probable = 1;
done:
    crypto_bignum_free(&n_minus_1); crypto_bignum_free(&d); crypto_bignum_free(&n_minus_3);
    crypto_bignum_free(&a); crypto_bignum_free(&x); crypto_bignum_free(&tmp);
    return err;
}

int crypto_prime_is_probable_internal(const LiberaCBignum *value,
                                      uint32_t rounds) {
    int is_probable = 0;

    if (prime_is_probable_checked(value, rounds, &is_probable) !=
        LIBERAC_SUCCESS) {
        return 0;
    }
    return is_probable;
}

LiberaCError crypto_prime_generate_internal(LiberaCBignum *out, size_t bits, uint32_t rounds) {
    LiberaCBignum candidate;
    size_t tries;
    LiberaCError err;
    int is_probable;
    if (!out || bits < 2u) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (rounds == 0u) rounds = 32u;
    crypto_bignum_init(&candidate);
    for (tries = 0u; tries < 1000000u; ++tries) {
        err = crypto_bignum_random_bits(&candidate, bits, 1, 1);
        if (err != LIBERAC_SUCCESS) {
            crypto_bignum_free(&candidate);
            return err;
        }
        if (!prime_small_division(&candidate)) {
            crypto_bignum_free(&candidate);
            crypto_bignum_init(&candidate);
            continue;
        }
        err = prime_is_probable_checked(&candidate, rounds, &is_probable);
        if (err != LIBERAC_SUCCESS) {
            crypto_bignum_free(&candidate);
            return err;
        }
        if (is_probable) {
            crypto_bignum_free(out);
            *out = candidate;
            return LIBERAC_SUCCESS;
        }
        crypto_bignum_free(&candidate); crypto_bignum_init(&candidate);
    }
    crypto_bignum_free(&candidate);
    return LIBERAC_ERROR_PRIME_GENERATION_FAILED;
}

LiberaCError crypto_prime_generate_safe_internal(LiberaCBignum *p_out, LiberaCBignum *q_out, size_t p_bits, uint32_t rounds) {
    LiberaCBignum qv, pv, tmp;
    size_t tries;
    int is_probable;
    LiberaCError err;
    if (!p_out || !q_out || p_out == q_out || p_bits < 3u)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (rounds == 0u) rounds = 32u;
    crypto_bignum_init(&qv); crypto_bignum_init(&pv); crypto_bignum_init(&tmp);
    for (tries = 0u; tries < 1000000u; ++tries) {
        err = crypto_prime_generate_internal(&qv, p_bits - 1u, rounds);
        if (err != LIBERAC_SUCCESS) {
            crypto_bignum_free(&qv); crypto_bignum_free(&pv); crypto_bignum_free(&tmp);
            return err;
        }
        if (bignum_mul_u32(&tmp, &qv, 2u) != 0 || bignum_add_u32_copy(&pv, &tmp, 1u) != 0) {
            crypto_bignum_free(&qv); crypto_bignum_free(&pv); crypto_bignum_free(&tmp);
            return LIBERAC_ERROR_ALLOCATION_FAILED;
        }
        crypto_bignum_free(&tmp); crypto_bignum_init(&tmp);
        if (crypto_bignum_bit_length(&pv) == p_bits) {
            err = prime_is_probable_checked(&pv, rounds, &is_probable);
            if (err != LIBERAC_SUCCESS) {
                crypto_bignum_free(&qv); crypto_bignum_free(&pv);
                crypto_bignum_free(&tmp);
                return err;
            }
        } else {
            is_probable = 0;
        }
        if (is_probable) {
            crypto_bignum_free(p_out); *p_out = pv; crypto_bignum_init(&pv);
            crypto_bignum_free(q_out); *q_out = qv; crypto_bignum_init(&qv);
            crypto_bignum_free(&tmp);
            return LIBERAC_SUCCESS;
        }
        crypto_bignum_free(&qv); crypto_bignum_init(&qv);
        crypto_bignum_free(&pv); crypto_bignum_init(&pv);
    }
    crypto_bignum_free(&qv); crypto_bignum_free(&pv); crypto_bignum_free(&tmp);
    return LIBERAC_ERROR_PRIME_GENERATION_FAILED;
}
