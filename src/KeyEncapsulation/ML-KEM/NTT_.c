/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdint.h>
#include <string.h>

#include "NTT_.h"
#include "parameter.h"
#include "reduce.h"

/*
 * FIPS 203 zeta values pre-scaled by R = 2^16 modulo q.  Keeping the table in
 * Montgomery form removes per-butterfly twiddle conversions and lets every NTT
 * multiplication stay in the same aR representation.
 */
static const int ZETA_MONTGOMERY_TABLE[256] = {
    2285, 2226, 1223, 817, 573, 3083, 2476, 2144, 3158, 422,
    516, 2114, 2648, 1739, 2931, 3221, 1493, 2078, 2036, 1322,
    2500, 2552, 107, 1819, 962, 3038, 1711, 2455, 1787, 418,
    448, 958, 2970, 555, 2777, 603, 264, 1159, 3058, 2051,
    1577, 177, 3009, 1218, 732, 2457, 1821, 996, 287, 1550,
    3047, 1864, 1727, 2727, 3082, 2459, 1855, 1574, 126, 2142,
    3124, 3173, 677, 1522, 2571, 430, 652, 1097, 2004, 778,
    3239, 1799, 622, 587, 3321, 3193, 1017, 644, 961, 3021,
    1422, 871, 1491, 2044, 1458, 1483, 1908, 2475, 2127, 2869,
    2167, 220, 411, 329, 2264, 1869, 1812, 843, 1015, 610,
    383, 3182, 830, 794, 182, 3094, 2663, 1994, 608, 349,
    2604, 991, 202, 105, 1785, 384, 3199, 1119, 2378, 478,
    1468, 1653, 1469, 1670, 1758, 3254, 2054, 1628, 1044, 1103,
    2106, 2512, 2756, 246, 853, 1185, 171, 2907, 2813, 1215,
    681, 1590, 398, 108, 1836, 1251, 1293, 2007, 829, 777,
    3222, 1510, 2367, 291, 1618, 874, 1542, 2911, 2881, 2371,
    359, 2774, 552, 2726, 3065, 2170, 271, 1278, 1752, 3152,
    320, 2111, 2597, 872, 1508, 2333, 3042, 1779, 282, 1465,
    1602, 602, 247, 870, 1474, 1755, 3203, 1187, 205, 156,
    2652, 1807, 758, 2899, 2677, 2232, 1325, 2551, 90, 1530,
    2707, 2742, 8, 136, 2312, 2685, 2368, 308, 1907, 2458,
    1838, 1285, 1871, 1846, 1421, 854, 1202, 460, 1162, 3109,
    2918, 3000, 1065, 1460, 1517, 2486, 2314, 2719, 2946, 147,
    2499, 2535, 3147, 235, 666, 1335, 2721, 2980, 725, 2338,
    3127, 3224, 1544, 2945, 130, 2210, 951, 2851, 1861, 1676,
    1860, 1659, 1571, 75, 1275, 1701
};

static unsigned int mlkem_bit_reverse_7(unsigned int value) {
    value &= 0x7fu;
    value = ((value & 0x55u) << 1u) | ((value >> 1u) & 0x55u);
    value = ((value & 0x33u) << 2u) | ((value >> 2u) & 0x33u);
    value = ((value & 0x0fu) << 4u) | ((value >> 4u) & 0x0fu);
    return value >> 1u;
}

/* Inputs, r, and outputs are canonical Montgomery representatives aR mod q. */
static inline void mlkem_multiply_basic(int a0, int a1, int b0, int b1,
                                        int *c0, int *c1, int r) {
    int first_product = mlkem_montgomery_mul(a0, b0);
    int second_product = mlkem_montgomery_mul(a1, b1);
    int twisted_product = mlkem_montgomery_mul(second_product, r);
    int first_cross = mlkem_montgomery_mul(a0, b1);
    int second_cross = mlkem_montgomery_mul(a1, b0);

    *c0 = mlkem_add_mod_q(first_product, twisted_product);
    *c1 = mlkem_add_mod_q(first_cross, second_cross);
}

const int* GenZeta(void) {
    return ZETA_MONTGOMERY_TABLE;
}

/* Reverse the low-order bits of an index. */
int bit_rev(int x) {
    int t[7] = { 0 };
    for (int i = 0; i < 7; i++) {
        t[i] = x % 2;
        x /= 2;
    }
    int r = 0;
    int j = 1;
    for (int i = 0; i < 7;i++) {
        r = r + t[6 - i] * j;
        j *= 2;
    }
    return r;
}

/*
 * Forward NTT boundary contract:
 *   input  f: ordinary canonical coefficients
 *   output g: Montgomery-domain NTT coefficients (aR mod q)
 */
void NTT(int* f, int* g, const int* zetas) {
    int i = 1;

    for (int index = 0; index < n; ++index)
        g[index] = mlkem_to_montgomery(f[index]);

    for (int len = n / 2; len >= 2; len = len / 2) {
        for (int start = 0; start < n; start = start + (2 * len)) {
            int z = zetas[mlkem_bit_reverse_7((unsigned int)i)];
            i++;
            for (int j = start; j < start + len; j++) {
                int first = g[j];
                int product = mlkem_montgomery_mul(z, g[j + len]);

                g[j + len] = mlkem_sub_mod_q(first, product);
                g[j] = mlkem_add_mod_q(first, product);
            }
        }
    }
}

/*
 * Inverse NTT boundary contract:
 *   input  f: Montgomery-domain NTT coefficients
 *   output g: ordinary canonical coefficients
 */
void NTT_inv(int* f, int* g, const int* zetas) {
    int i = 127;

    memcpy(g, f, n * sizeof(int));
    for (int len = 2; len <= 128; len = len * 2) {
        for (int start = 0; start < n; start = start + (2 * len)) {
            int z = zetas[mlkem_bit_reverse_7((unsigned int)i)];
            i--;
            for (int j = start; j < start + len; j++) {
                int first = g[j];
                int second = g[j + len];
                int difference = mlkem_sub_mod_q(second, first);

                g[j] = mlkem_add_mod_q(first, second);
                g[j + len] = mlkem_montgomery_mul(z, difference);
            }
        }
    }

    /*
     * g is still scaled by R. REDC((xR)*3303) simultaneously multiplies by
     * 128^{-1} and removes R, yielding the ordinary inverse-NTT coefficient.
     */
    for (int index = 0; index < n; index++) {
        uint32_t product = (uint32_t)g[index] * UINT32_C(3303);
        g[index] = (int)mlkem_montgomery_reduce_u32(product);
    }
}

void Multiply_basic(int a0, int a1, int b0, int b1,
                    int* c0, int* c1, int r) {
    mlkem_multiply_basic(a0, a1, b0, b1, c0, c1, r);
}

/* f, g, h, and zetas are all Montgomery-domain NTT representations. */
void Multiply_NTT(int* f, int* g, int* h, const int* zetas) {
    for (int i = 0; i < 128; i++) {
        unsigned int reversed = mlkem_bit_reverse_7((unsigned int)i);
        mlkem_multiply_basic(
            f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1],
            &h[2 * i], &h[2 * i + 1],
            zetas[(2u * reversed) + 1u]);
    }
}
