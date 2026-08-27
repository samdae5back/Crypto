// SPDX-License-Identifier: MIT

#include "haetae_decompose.h"
#include "Util/Bit/bit_internal.h"

/*************************************************
 * Name:        crypto_haetae_decompose_z1
 *
 * Description: For finite field element r, compute high and lowbits
 *              hb, lb such that r = hb * b + lb with -b/4 < lb <= b/4.
 *
 * Arguments:   - int r: input element
 *              - int *lowbits: pointer to output element lb
 *              - int *highbits: pointer to output element hb
 **************************************************/
void crypto_haetae_decompose_z1(int *highbits, int *lowbits, const int r) {
    const int alpha = 256;
    const int log_alpha = 8;

    int lb, center;
    const int alpha_mask = alpha - 1;

    lb = r & alpha_mask;
    center = crypto_floor_div_pow2_i32(
        (alpha >> 1) - (lb + 1), 31u); // if lb >= HALF_ALPHA
    lb -= alpha & center;
    *lowbits = lb;
    *highbits = crypto_floor_div_pow2_i32(
        r + (alpha >> 1), (unsigned int)log_alpha);
}

/*************************************************
 * Name:        crypto_haetae_decompose_hint
 *
 * Description: For finite field element r, compute highbits
 *              hb, lb such that r = hb * b + lb with -b/4 < lb <= b/4.
 *
 * Arguments:   - int r: input element
 *              - int *highbits: pointer to output element hb
 **************************************************/

void crypto_haetae_decompose_hint(int *highbits, const int r, const crypto_haetae_parameters *parameters) {
    int hb, edgecase;

    const int alpha_hint = (int)parameters->alpha_hint;
    const unsigned int log_alpha_hint = parameters->log_alpha_hint;

    hb = crypto_floor_div_pow2_i32(
        r + (alpha_hint >> 1), log_alpha_hint);
    edgecase = crypto_floor_div_pow2_i32(
        (CRYPTO_HAETAE_DOUBLE_Q - 2) / alpha_hint - (hb + 1),
        31u); // if hb == (DQ-2)/ALPHA
    hb -= (CRYPTO_HAETAE_DOUBLE_Q - 2) / alpha_hint & edgecase;       // hb = 0

    *highbits = hb;
}

/*************************************************
 * Name:        crypto_haetae_decompose_vk
 *
 * Description: For finite field element a, compute a0, a1 such that
 *              a mod^+ Q = a1*2^D + a0 with -2^{D-1} <= a0 < 2^{D-1}.
 *              Assumes a to be standard representative.
 *
 * Arguments:   - int a: input element
 *              - int *a0: pointer to output element a0
 *
 * Returns a1
 **************************************************/
int crypto_haetae_decompose_vk(int *a0, const int a) {
#if CRYPTO_HAETAE_MAX_D > 1
#error "Only implemented for D = 1"
#endif
    *a0 = a & 1;
    *a0 -= (crypto_floor_div_pow2_i32(a, 1u) & *a0) << 1;
    return crypto_floor_div_pow2_i32(a - *a0, 1u);
}
