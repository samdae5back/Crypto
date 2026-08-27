// SPDX-License-Identifier: MIT

#include "haetae_reduce.h"
#include "Util/Bit/bit_internal.h"

static inline int64_t crypto_haetae_sign_mask_i64(int64_t value) {
    return -(int64_t)((uint64_t)value >> 63);
}

static inline int32_t crypto_haetae_sign_mask_i32(int32_t value) {
    return -(int32_t)((uint32_t)value >> 31);
}

/*************************************************
 * Name:        montgomery_reduce for haetae
 *
 * Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
 *              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
 *
 * Arguments: - long long a: finite field element
 *
 * Returns r.
 **************************************************/
int crypto_haetae_montgomery_reduce(long long a) {
    const int64_t a64 = (int64_t)a;
    const uint32_t t_bits =
        (uint32_t)a64 * (uint32_t)CRYPTO_HAETAE_Q_INVERSE;
    const int64_t t =
        (int64_t)(t_bits & UINT32_C(0x7fffffff)) -
        (int64_t)(t_bits & UINT32_C(0x80000000));
    const int64_t numerator =
        a64 - t * (int64_t)CRYPTO_HAETAE_Q;
    const int64_t reduced =
        crypto_floor_div_pow2_i64(numerator, 32u);

    /* numerator is exactly divisible by 2^32 by construction. */
    return (int)reduced;
}

/*************************************************
 * Name:        caddq
 *
 * Description: Add Q if input coefficient is negative.
 **************************************************/
int crypto_haetae_caddq(int a) {
    const int32_t value = (int32_t)a;
    return (int)(value +
        (crypto_haetae_sign_mask_i32(value) & CRYPTO_HAETAE_Q));
}

/*************************************************
 * Name:        freeze
 *
 * Description: For finite field element a, compute standard
 *              representative r = a mod^+ Q.
 **************************************************/
int crypto_haetae_freeze(int a) {
    int64_t t = (int64_t)a * CRYPTO_HAETAE_Q_RECIPROCAL;

    t = crypto_floor_div_pow2_i64(t, 32u);
    t = (int64_t)a - t * CRYPTO_HAETAE_Q; /* -2Q < t < 2Q */
    t += crypto_haetae_sign_mask_i64(t) &
         CRYPTO_HAETAE_DOUBLE_Q;           /* 0 <= t < 2Q */
    t -= ~crypto_haetae_sign_mask_i64(t - CRYPTO_HAETAE_Q) &
         CRYPTO_HAETAE_Q;                  /* 0 <= t < Q */
    return (int)t;
}

/*************************************************
 * Name:        reduce32_2q
 *
 * Description: compute centered reduction modulo 2Q.
 **************************************************/
int crypto_haetae_reduce32_2q(int a) {
    int64_t t =
        (int64_t)a * CRYPTO_HAETAE_DOUBLE_Q_RECIPROCAL;

    t = crypto_floor_div_pow2_i64(t, 32u);
    t = (int64_t)a - t * CRYPTO_HAETAE_DOUBLE_Q; /* -4Q < t < 4Q */
    t += crypto_haetae_sign_mask_i64(t) &
         (CRYPTO_HAETAE_DOUBLE_Q * 2);            /* 0 <= t < 4Q */
    t -= ~crypto_haetae_sign_mask_i64(
   t - CRYPTO_HAETAE_DOUBLE_Q) &
         CRYPTO_HAETAE_DOUBLE_Q;                 /* 0 <= t < 2Q */
    t -= ~crypto_haetae_sign_mask_i64(t - CRYPTO_HAETAE_Q) &
         CRYPTO_HAETAE_DOUBLE_Q;                 /* -Q <= t < Q */
    return (int)t;
}

/*************************************************
 * Name:        freeze2q
 *
 * Description: For finite field element a, compute standard
 *              representative r = a mod^+ 2Q.
 **************************************************/
int crypto_haetae_freeze2q(int a) {
    int64_t t =
        (int64_t)a * CRYPTO_HAETAE_DOUBLE_Q_RECIPROCAL;

    t = crypto_floor_div_pow2_i64(t, 32u);
    t = (int64_t)a - t * CRYPTO_HAETAE_DOUBLE_Q; /* -4Q < t < 4Q */
    t += crypto_haetae_sign_mask_i64(t) &
         (CRYPTO_HAETAE_DOUBLE_Q * 2);            /* 0 <= t < 4Q */
    t -= ~crypto_haetae_sign_mask_i64(
   t - CRYPTO_HAETAE_DOUBLE_Q) &
         CRYPTO_HAETAE_DOUBLE_Q;                 /* 0 <= t < 2Q */
    return (int)t;
}
