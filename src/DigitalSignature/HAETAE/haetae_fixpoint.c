// SPDX-License-Identifier: MIT

#include <string.h>

#include "haetae_fixpoint.h"

static void __cneg(crypto_haetae_fp96_76 *x, const uint8_t  sign) {
    x->limb48[0] ^=
        (uint64_t)(-(int64_t)sign) & ((UINT64_C(1) << 48) - 1);
    x->limb48[1] ^= (uint64_t)(-(int64_t)sign);
    x->limb48[0] += sign;
    renormalize(x);
}

static void __copy_cneg(crypto_haetae_fp96_76 *y, const crypto_haetae_fp96_76 *x, const uint8_t  sign) {
    y->limb48[0] =
        ((uint64_t)(-(int64_t)sign) & ((UINT64_C(1) << 48) - 1)) ^
        x->limb48[0];
    y->limb48[1] = x->limb48[1] ^ (uint64_t)(-(int64_t)sign);
    y->limb48[0] += sign;
    renormalize(y);
}

static void fixpoint_mul(crypto_haetae_fp96_76 *xy, const crypto_haetae_fp96_76 *x, const crypto_haetae_fp96_76 *y) {
    uint64_t tmp[2];
    mul48(&xy->limb48[0], x->limb48[0], y->limb48[0]);

    // shift right by 48, rounding
    xy->limb48[0] = xy->limb48[1] + (((xy->limb48[0] >> 47) + 1) >> 1);

    mul48(tmp, x->limb48[0], y->limb48[1]);
    xy->limb48[0] += tmp[0];
    xy->limb48[1] = tmp[1];
    mulacc48(&xy->limb48[0], x->limb48[1], y->limb48[0]);

    // shift right by 28, rounding
    xy->limb48[0] += UINT64_C(1) << 27;
    xy->limb48[0] >>= 28;
    xy->limb48[0] +=
        (xy->limb48[1] << 20) & ((UINT64_C(1) << 48) - 1);
    xy->limb48[1] >>= 28;

    mul64(tmp, x->limb48[1], y->limb48[1]);
    xy->limb48[0] +=
        (tmp[0] << 20) & ((UINT64_C(1) << 48) - 1);
    xy->limb48[1] += (tmp[0] >> 28) + (tmp[1] << 36);

    renormalize(xy);
}

static void fixpoint_unsigned_signed_mul(crypto_haetae_fp96_76 *xy, const crypto_haetae_fp96_76 *y) {
    crypto_haetae_fp96_76 x, z;
    uint8_t  sign = (y->limb48[1] >> 63) & 1;
    __copy_cneg(&x, y, sign);
    fixpoint_mul(&z, &x, xy);
    __copy_cneg(xy, &z, sign);
}

static void fixpoint_sub(crypto_haetae_fp96_76 *xminy, const crypto_haetae_fp96_76 *x, const crypto_haetae_fp96_76 *y) {
    crypto_haetae_fp96_76 yneg;
    __copy_cneg(&yneg, y, 1);
    crypto_haetae_fixpoint_add(xminy, x, &yneg);
}

static void fixpoint_sub_from_threehalves(crypto_haetae_fp96_76 *x) {
    __cneg(x, 1);
    x->limb48[1] +=
        UINT64_C(3) << 27; // left shift by 28 would be "3"
    renormalize(x);
}

void crypto_haetae_fixpoint_square(crypto_haetae_fp96_76 *sqx, const crypto_haetae_fp96_76 *x) {
    uint64_t tmp[2];
    sq48(&sqx->limb48[0], x->limb48[0]);

    // shift right by 48, rounding
    sqx->limb48[0] >>= 48;
    sqx->limb48[0] += sqx->limb48[1];

    // mul
    mul48(tmp, x->limb48[0], x->limb48[1]);
    sqx->limb48[0] += tmp[0] << 1;
    sqx->limb48[1] = tmp[1] << 1;

    // shift right by 28, rounding
    sqx->limb48[0] >>= 28;
    sqx->limb48[0] +=
        (sqx->limb48[1] << 20) & ((UINT64_C(1) << 48) - 1);
    sqx->limb48[1] >>= 28;

    sq64(tmp, x->limb48[1]);
    sqx->limb48[0] +=
        (tmp[0] << 20) & ((UINT64_C(1) << 48) - 1);
    sqx->limb48[1] += (tmp[0] >> 28) + (tmp[1] << 36);

    renormalize(sqx);
}

static const crypto_haetae_fp96_76 kStartCube_L4 = {
    {UINT64_C(0x770077e2e41a), UINT64_C(0x1162)}};
static const crypto_haetae_fp96_76 kStartT3H_L4 = {
    {UINT64_C(0x693861ad937b), UINT64_C(0x9caa56)}};

static const crypto_haetae_fp96_76 kStartCube_L6 = {
    {UINT64_C(0x1a2935cfae68), UINT64_C(0x978)}};
static const crypto_haetae_fp96_76 kStartT3H_L6 = {
    {UINT64_C(0x7ad215218533), UINT64_C(0x7ff1c9)}};

static const crypto_haetae_fp96_76 kStartCube_L7 = {
    {UINT64_C(0x700ff3e8890d), UINT64_C(0x702)}};
static const crypto_haetae_fp96_76 kStartT3H_L7 = {
    {UINT64_C(0x5768588eed31), UINT64_C(0x73bd40)}};

// implements Newton's method
void crypto_haetae_fixpoint_newton_invsqrt(crypto_haetae_fp96_76 *invsqrtx, const crypto_haetae_fp96_76 *xhalf, const crypto_haetae_parameters *parameters) {
    int i;
    const crypto_haetae_fp96_76 *start_cube = NULL;
    const crypto_haetae_fp96_76 *start_times_threehalves = NULL;

    crypto_haetae_fp96_76 tmp, tmp2;

    switch (parameters->l) {
    case 4:
        start_cube = &kStartCube_L4;
        start_times_threehalves = &kStartT3H_L4;
        break;
    case 6:
        start_cube = &kStartCube_L6;
        start_times_threehalves = &kStartT3H_L6;
        break;
    case 7:
        start_cube = &kStartCube_L7;
        start_times_threehalves = &kStartT3H_L7;
        break;
    default:
        memset(invsqrtx, 0, sizeof(*invsqrtx));
        return;
    }

    fixpoint_mul(&tmp, xhalf, start_cube); // definitely two positive values
    fixpoint_sub(invsqrtx, start_times_threehalves,
                 &tmp); // first Newton iteration done, might be negative (very
                        // improbable)

    for (i = 0; i < 6; i++) // 6 more iterations
    {
        crypto_haetae_fixpoint_square(&tmp, invsqrtx);  // tmp = y^2, never negative
        fixpoint_mul(&tmp2, xhalf, &tmp); // tmp2 = x/2 * y^2, never negative
        fixpoint_sub_from_threehalves(&tmp2);          // tmp = 3/2 - x/2 * y^2
        fixpoint_unsigned_signed_mul(invsqrtx, &tmp2); // y * (3/2 - x/2 * y^2)
    }
}

int32_t crypto_haetae_fixpoint_mul_rnd13(
    const uint64_t x, const crypto_haetae_fp96_76 *y,
    const uint8_t sign) {
    int64_t res;
    crypto_haetae_fp96_76 tmp, xx;
    xx.limb48[1] = x >> 32;
    xx.limb48[0] = (x & ((UINT64_C(1) << 32) - 1)) << 16;
    fixpoint_mul(&tmp, &xx, y);
    res = (int64_t)((tmp.limb48[1] + (UINT64_C(1) << 14)) >> 15);
    return (int32_t)((1 - 2 * (int32_t)sign) * res);
}

void crypto_haetae_fixpoint_add(crypto_haetae_fp96_76 *xy, const crypto_haetae_fp96_76 *x, const crypto_haetae_fp96_76 *y) {
    xy->limb48[0] = x->limb48[0] + y->limb48[0];
    xy->limb48[1] = x->limb48[1] + y->limb48[1];
}
