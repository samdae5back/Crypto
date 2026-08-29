/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdint.h>
#include <string.h>

#include "NTT_.h"
#include "parameter.h"
#include "reduce.h"


static const int ZETA_TABLE[256] = {
    1, 17, 289, 1584, 296, 1703, 2319, 2804, 1062, 1409,
    650, 1063, 1426, 939, 2647, 1722, 2642, 1637, 1197, 375,
    3046, 1847, 1438, 1143, 2786, 756, 2865, 2099, 2393, 733,
    2474, 2110, 2580, 583, 3253, 2037, 1339, 2789, 807, 403,
    193, 3281, 2513, 2773, 535, 2437, 1481, 1874, 1897, 2288,
    2277, 2090, 2240, 1461, 1534, 2775, 569, 3015, 1320, 2466,
    1974, 268, 1227, 885, 1729, 2761, 331, 2298, 2447, 1651,
    1435, 1092, 1919, 2662, 1977, 319, 2094, 2308, 2617, 1212,
    630, 723, 2304, 2549, 56, 952, 2868, 2150, 3260, 2156,
    33, 561, 2879, 2337, 3110, 2935, 3289, 2649, 1756, 3220,
    1476, 1789, 452, 1026, 797, 233, 632, 757, 2882, 2388,
    648, 1029, 848, 1100, 2055, 1645, 1333, 2687, 2402, 886,
    1746, 3050, 1915, 2594, 821, 641, 910, 2154, 3328, 3312,
    3040, 1745, 3033, 1626, 1010, 525, 2267, 1920, 2679, 2266,
    1903, 2390, 682, 1607, 687, 1692, 2132, 2954, 283, 1482,
    1891, 2186, 543, 2573, 464, 1230, 936, 2596, 855, 1219,
    749, 2746, 76, 1292, 1990, 540, 2522, 2926, 3136, 48, 816,
    556, 2794, 892, 1848, 1455, 1432, 1041, 1052, 1239, 1089,
    1868, 1795, 554, 2760, 314, 2009, 863, 1355, 3061, 2102,
    2444, 1600, 568, 2998, 1031, 882, 1678, 1894, 2237, 1410,
    667, 1352, 3010, 1235, 1021, 712, 2117, 2699, 2606, 1025,
    780, 3273, 2377, 461, 1179, 69, 1173, 3296, 2768, 450,
    992, 219, 394, 40, 680, 1573, 109, 1853, 1540, 2877,
    2303, 2532, 3096, 2697, 2572, 447, 941, 2681, 2300, 2481,
    2229, 1274, 1684, 1996, 642, 927, 2443, 1583, 279, 1414,
    735, 2508, 2688, 2419, 1175
};

static unsigned int mlkem_bit_reverse_7(unsigned int value) {
    value &= 0x7fu;
    value = ((value & 0x55u) << 1u) | ((value >> 1u) & 0x55u);
    value = ((value & 0x33u) << 2u) | ((value >> 2u) & 0x33u);
    value = ((value & 0x0fu) << 4u) | ((value >> 4u) & 0x0fu);
    return value >> 1u;
}

static inline void mlkem_multiply_basic(int a0, int a1, int b0, int b1,
                                        int *c0, int *c1, int r) {
    uint32_t first_product = (uint32_t)a0 * (uint32_t)b0;
    uint32_t second_product =
        (uint32_t)mlkem_mul_mod_q(a1, b1) * (uint32_t)r;
    uint32_t cross_products =
        (uint32_t)a0 * (uint32_t)b1 +
        (uint32_t)a1 * (uint32_t)b0;

    /*
     * Both operands vary here, so keep the ordinary-domain Barrett path rather
     * than paying to convert one operand to Montgomery form for every product.
     * All inputs are canonical coefficients below q.  first_product and
     * second_product are each at most (q-1)^2, so their sum is below 2q^2
     * (= 22,151,168 for q = 3329), comfortably inside uint32_t.
     */
    *c0 = (int)mlkem_barrett_reduce_u32(first_product + second_product);
    *c1 = (int)mlkem_barrett_reduce_u32(cross_products);
}

const int* GenZeta(void) {
    return ZETA_TABLE;
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

void NTT(int* f, int* g, const int* zetas) {//input, output, zeta
    memcpy(g, f, n * sizeof(int));
    int i = 1;
    for (int len = n / 2;len >= 2;len = len / 2) {
        for (int start = 0;start < n;start = start + (2 * len)) {
            int z = zetas[mlkem_bit_reverse_7((unsigned int)i)];
            int z_montgomery = mlkem_to_montgomery(z);
            i++;
            for (int j = start;j < start + len;j++) {
                int first = g[j];
                int product = mlkem_mul_montgomery_constant(
                    g[j + len], z_montgomery);

                /*
                 * z_montgomery represents zR, but REDC removes R again, so
                 * every butterfly output remains ordinary and canonical.
                 */
                g[j + len] = mlkem_sub_mod_q(first, product);
                g[j] = mlkem_add_mod_q(first, product);
            }
        }
    }
    return;
}


void NTT_inv(int* f, int* g, const int* zetas) {
    memcpy(g, f, n * sizeof(int));
    int i = 127;
    for (int len = 2;len <= 128;len = len * 2) {
        for (int start = 0;start < n;start = start + (2 * len)) {
            int z = zetas[mlkem_bit_reverse_7((unsigned int)i)];
            int z_montgomery = mlkem_to_montgomery(z);
            i--;
            for (int j = start;j < start + len;j++) {
                int first = g[j];
                int second = g[j + len];
                int difference = mlkem_sub_mod_q(second, first);

                g[j] = mlkem_add_mod_q(first, second);
                g[j + len] = mlkem_mul_montgomery_constant(
                    difference, z_montgomery);
            }
        }
    }
    {
        int scale_montgomery = mlkem_to_montgomery(3303);
        for (int index = 0;index < n;index++) {
            g[index] = mlkem_mul_montgomery_constant(
                g[index], scale_montgomery);
        }
    }
    return;
}

void Multiply_basic(int a0, int a1, int  b0, int b1, int* c0, int* c1, int r) {
    mlkem_multiply_basic(a0, a1, b0, b1, c0, c1, r);
    return;
}

void Multiply_NTT(int* f, int* g, int* h, const int* zetas) {
    for (int i = 0;i < 128;i++) {
        unsigned int reversed = mlkem_bit_reverse_7((unsigned int)i);
        mlkem_multiply_basic(
            f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1],
            &h[2 * i], &h[2 * i + 1],
            zetas[(2u * reversed) + 1u]);
    }
    return;
}
