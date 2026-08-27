// SPDX-License-Identifier: MIT

#include "haetae_reduce.h"

/*************************************************
 * Name:        montgomery_reduce for haetae
 *
 * Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
 *              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
 *
 * Arguments:   - long long: finite field element a
 *
 * Returns r.
 **************************************************/
int crypto_haetae_montgomery_reduce(long long a) {
    int t;

    t = (long long)(int)a * CRYPTO_HAETAE_Q_INVERSE;
    t = (a - (long long)t * CRYPTO_HAETAE_Q) >> 32;
    return t;
}

/*************************************************
 * Name:        caddq
 *
 * Description: Add Q if input coefficient is negative.
 *
 * Arguments:   - int: finite field element a
 *
 * Returns r.
 **************************************************/
int crypto_haetae_caddq(int a) {
    a += (a >> 31) & CRYPTO_HAETAE_Q;
    return a;
}

/*************************************************
 * Name:        freeze
 *
 * Description: For finite field element a, compute standard
 *              representative r = a mod^+ Q.
 *
 * Arguments:   - int: finite field element a
 *
 * Returns r.
 **************************************************/
int crypto_haetae_freeze(int a) {
    long long t = (long long)a * CRYPTO_HAETAE_Q_RECIPROCAL;
    t = t >> 32;
    t = a - t * CRYPTO_HAETAE_Q;             // -2Q <  t < 2Q
    t += (t >> 31) & CRYPTO_HAETAE_DOUBLE_Q;       //   0 <= t < 2Q
    t -= ~((t - CRYPTO_HAETAE_Q) >> 31) & CRYPTO_HAETAE_Q; //   0 <= t < Q
    return t;
}

/*************************************************
 * Name:        reduce32_2q
 *
 * Description: compute reduction with 2Q
 *
 * Arguments:   - int: finite field element a
 *
 * Returns r.
 **************************************************/
int crypto_haetae_reduce32_2q(int a) {
    long long t = (long long)a * CRYPTO_HAETAE_DOUBLE_Q_RECIPROCAL;
    t >>= 32;
    t = a - t * CRYPTO_HAETAE_DOUBLE_Q;              // -4Q <  t < 4Q
    t += (t >> 31) & (CRYPTO_HAETAE_DOUBLE_Q * 2);   //   0 <= t < 4Q
    t -= ~((t - CRYPTO_HAETAE_DOUBLE_Q) >> 31) & CRYPTO_HAETAE_DOUBLE_Q; //   0 <= t < Q
    t -= ~((t - CRYPTO_HAETAE_Q) >> 31) & CRYPTO_HAETAE_DOUBLE_Q;  // centered representation
    return (int)t;
}

/*************************************************
 * Name:        freeze2q
 *
 * Description: For finite field element a, compute standard
 *              representative r = a mod^+ 2Q.
 *
 * Arguments:   - int: finite field element a
 *
 * Returns r.
 **************************************************/
int crypto_haetae_freeze2q(int a) {
    long long t = (long long)a * CRYPTO_HAETAE_DOUBLE_Q_RECIPROCAL;
    t >>= 32;
    t = a - t * CRYPTO_HAETAE_DOUBLE_Q;              // -4Q <  t < 4Q
    t += (t >> 31) & (CRYPTO_HAETAE_DOUBLE_Q * 2);   //   0 <= t < 4Q
    t -= ~((t - CRYPTO_HAETAE_DOUBLE_Q) >> 31) & CRYPTO_HAETAE_DOUBLE_Q; //   0 <= t < Q
    return (int)t;
}
