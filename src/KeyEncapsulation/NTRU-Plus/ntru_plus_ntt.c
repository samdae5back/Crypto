/*
 * Runtime-parameter NTRU+ number-theoretic transform.
 * Derived from the NTRU+ reference implementation.
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include "ntru_plus_ntt.h"
#include "Util/Bit/bit_internal.h"

/* ------------------------------------------------------------------ */
/* Shared constants (all variants)                                      */
/* ------------------------------------------------------------------ */
#define CRYPTO_NTRU_PLUS_R            ((int16_t)(-147))   /* R = 2^16 mod q          */
#define CRYPTO_NTRU_PLUS_RINV         ((int16_t)(-682))   /* R^(-1) mod q            */
#define CRYPTO_NTRU_PLUS_RSQ          ((int16_t)( 867))   /* R^2 mod q               */
#define CRYPTO_NTRU_PLUS_QINV         ((int16_t)(12929))  /* q^(-1) mod 2^16         */
#define CRYPTO_NTRU_PLUS_OMEGA        ((int16_t)(-886))   /* omega * R mod q         */
#define CRYPTO_NTRU_PLUS_ZMINUSZ5INV  ((int16_t)(-1665))  /* (z-z^5)^-1 * R mod q   */

/* ------------------------------------------------------------------ */
/* Zeta tables                                                          */
/* ------------------------------------------------------------------ */

/* NTRU+768 — degree-4 base, 192 twiddle factors */
const int16_t crypto_ntru_plus_zetas_768[192] = {
	 -147, -1033,  -682,  -248,  -708,   682,     1,  -722,
	 -723,  -257, -1124,  -867,  -256,  1484,  1262, -1590,
	 1611,   222,  1164, -1346,  1716, -1521,  -357,   395,
	 -455,   639,   502,   655,  -699,   541,    95, -1577,
	-1241,   550,   -44,    39,  -820,  -216,  -121,  -757,
	 -348,   937,   893,   387,  -603,  1713, -1105,  1058,
	 1449,   837,   901,  1637,  -569, -1617, -1530,  1199,
	   50,  -830,  -625,     4,   176,  -156,  1257, -1507,
	 -380,  -606,  1293,   661,  1428, -1580,  -565,  -992,
	  548,  -800,    64,  -371,   961,   641,    87,   630,
	  675,  -834,   205,    54, -1081,  1351,  1413, -1331,
	-1673, -1267, -1558,   281, -1464,  -588,  1015,   436,
	  223,  1138, -1059,  -397,  -183,  1655,   559, -1674,
	  277,   933,  1723,   437, -1514,   242,  1640,   432,
	-1583,   696,   774,  1671,   927,   514,   512,   489,
	  297,   601,  1473,  1130,  1322,   871,   760,  1212,
	 -312,  -352,   443,   943,     8,  1250,  -100,  1660,
	  -31,  1206, -1341, -1247,   444,   235,  1364, -1209,
	  361,   230,   673,   582,  1409,  1501,  1401,   251,
	 1022, -1063,  1053,  1188,   417, -1391,   -27, -1626,
	 1685,  -315,  1408, -1248,   400,   274, -1543,    32,
	-1550,  1531, -1367,  -124,  1458,  1379,  -940, -1681,
	   22,  1709,  -275,  1108,   354, -1728,  -968,   858,
	 1221,  -218,   294,  -732, -1095,   892,  1588,  -779
};

/* NTRU+864 — degree-3 base, 288 twiddle factors */
const int16_t crypto_ntru_plus_zetas_864[288] = {
	 -147, -1033, -1265,   708,   460,  1265,  -467,   727,
	  556,  1307,  -773,  -161,  1200, -1612,   570,  1529,
	 1135,  -556,  1120,   298,  -822, -1556,   -93,  1463,
	  532,  -377,  -909,    58,  -392,  -450,  1722,  1236,
	 -486,  -491, -1569, -1078,    36,  1289, -1443,  1628,
	 1664,  -725,  -952,    99, -1020,   353,  -599,  1119,
	  592,   839,  1622,   652,  1244,  -783, -1085,  -726,
	  566,  -284, -1369, -1292,   268,  -391,   781,  -172,
	   96, -1172,   211,   737,   473,  -445,  -234,   264,
	-1536,  1467,  -676, -1542,  -170,   635,  -705, -1332,
	 -658,   831, -1712,  1311,  1488,  -881,  1087, -1315,
	 1245,   -75,   791,    -6,  -875,  -697,   -70, -1162,
	  287,  -767,  -945,  1598,  -882,  1261,   206,   654,
	-1421,   -81,   716, -1251,   838, -1300,  1035,  -104,
	  966,  -558,   -61, -1704,   404,  -899,   862, -1593,
	-1460,   -37,  1266,   965, -1584, -1404,  -265,  -942,
	  905,  1195,  -619,   787,   118,   576,   286, -1475,
	 -194,   928,  1229, -1032,  1608,  1111, -1669,   642,
	-1323,   163,   309,   981,  -557,  -258,   232, -1680,
	-1657, -1233,   144,  1699,   311, -1060,   578,  1298,
	 -403,  1607,  1074,  -148,   447, -1568,  1142,  -402,
	-1412,  -623,   855,   365,   -98,  -244,   407,  1225,
	  416,   683,  -105,  1714, -1019,  1061,  1163,   638,
	  798,  1493,  -351,   396,  -542,    -9,  1616,  -139,
	 -987,  -482,   889,   238, -1513,   466, -1089,  -101,
	  849,  -426,  1589,  1487,   671,  1459,  -776,   255,
	-1014,  1144,   472, -1153,  -325,  1519,   -26, -1123,
	  324,  1230,  1547,  -593,  -428,  1192,  1072, -1564,
	  688,  -333,  1023, -1686,   841,   824,   -71,  1587,
	  522,  -323,  1148,   389,  1231,   384,  1343,   169,
	  628, -1329, -1056,  -936,    24,  -293,  1523,  -300,
	-1654,   891,  -962,   -67,   179, -1177,   844,  -509,
	-1677, -1565,  -549, -1508,  1191,  -280,   -43,   669,
	 -746,   753,   770, -1046,  1711,  1438,   690,  1083,
	 1062,  1727,  -883,   553,  1670,    66,   825,  -133,
	-1586,   637,  -680,  -917,   644,  -372, -1193, -1136
};

/* NTRU+1152 — degree-4 base, 288 twiddle factors */
const int16_t crypto_ntru_plus_zetas_1152[288] = {
	 -147, -1033, -1265,   708,   460,  1265,  -467,   727,
	  556,  1307,  -773,  -161,  1200, -1612,   570,  1529,
	 1135,  -556,  1120,   298,  -822, -1556,   -93,  1463,
	  532,  -377,  -909,    58,  -392,  -450,  1722,  1236,
	 -486,  -491, -1569, -1078,    36,  1289, -1443,  1628,
	 1664,  -725,  -952,    99, -1020,   353,  -599,  1119,
	  592,   839,  1622,   652,  1244,  -783, -1085,  -726,
	  566,  -284, -1369, -1292,   268,  -391,   781,  -172,
	   96, -1172,   211,   737,   473,  -445,  -234,   264,
	-1536,  1467,  -676, -1542,  -170,   635,  -705, -1332,
	 -658,   831, -1712,  1311,  1488,  -881,  1087, -1315,
	 1245,   -75,   791,    -6,  -875,  -697,   -70, -1162,
	  287,  -767,  -945,  1598,  -882,  1261,   206,   654,
	-1421,   -81,   716, -1251,   838, -1300,  1035,  -104,
	  966,  -558,   -61, -1704,   404,  -899,   862, -1593,
	-1460,   -37,  1266,   965, -1584, -1404,  -265,  -942,
	  905,  1195,  -619,   787,   118,   576,   286, -1475,
	 -194,   928,  1229, -1032,  1608,  1111, -1669,   642,
	-1323,   163,   309,   981,  -557,  -258,   232, -1680,
	-1657, -1233,   144,  1699,   311, -1060,   578,  1298,
	 -403,  1607,  1074,  -148,   447, -1568,  1142,  -402,
	-1412,  -623,   855,   365,   -98,  -244,   407,  1225,
	  416,   683,  -105,  1714, -1019,  1061,  1163,   638,
	  798,  1493,  -351,   396,  -542,    -9,  1616,  -139,
	 -987,  -482,   889,   238, -1513,   466, -1089,  -101,
	  849,  -426,  1589,  1487,   671,  1459,  -776,   255,
	-1014,  1144,   472, -1153,  -325,  1519,   -26, -1123,
	  324,  1230,  1547,  -593,  -428,  1192,  1072, -1564,
	  688,  -333,  1023, -1686,   841,   824,   -71,  1587,
	  522,  -323,  1148,   389,  1231,   384,  1343,   169,
	  628, -1329, -1056,  -936,    24,  -293,  1523,  -300,
	-1654,   891,  -962,   -67,   179, -1177,   844,  -509,
	-1677, -1565,  -549, -1508,  1191,  -280,   -43,   669,
	 -746,   753,   770, -1046,  1711,  1438,   690,  1083,
	 1062,  1727,  -883,   553,  1670,    66,   825,  -133,
	-1586,   637,  -680,  -917,   644,  -372, -1193, -1136
};

/* ------------------------------------------------------------------ */
/* Shared field arithmetic (appears once)                             */
/* ------------------------------------------------------------------ */

static inline int16_t montgomery_reduce(int32_t a)
{
    int16_t t;
    t = (int16_t)a * CRYPTO_NTRU_PLUS_QINV;
    t = (int16_t)crypto_floor_div_pow2_i32(
        a - (int32_t)t * CRYPTO_NTRU_PLUS_Q, 16u);
    return t;
}

static inline int16_t barrett_reduce(int16_t a)
{
    int16_t t;
    const int16_t v = ((1 << 26) + CRYPTO_NTRU_PLUS_Q / 2) / CRYPTO_NTRU_PLUS_Q;
    t = (int16_t)crypto_floor_div_pow2_i32(
        (int32_t)v * a + ((int32_t)1 << 25), 26u);
    t *= CRYPTO_NTRU_PLUS_Q;
    return a - t;
}

static inline int16_t fqmul(int16_t a, int16_t b)
{
    return montgomery_reduce((int32_t)a * b);
}

static inline int16_t fqinv(int16_t a)
{
    int16_t t1, t2, t3;

    t1 = fqmul(a, a);    /* 10           */
    t2 = fqmul(t1, t1);  /* 100          */
    t2 = fqmul(t2, t2);  /* 1000         */
    t3 = fqmul(t2, t2);  /* 10000        */

    t1 = fqmul(t1, t2);  /* 1010         */

    t2 = fqmul(t1, t3);  /* 11010        */
    t2 = fqmul(t2, t2);  /* 110100       */
    t2 = fqmul(t2, a);   /* 110101       */

    t1 = fqmul(t1, t2);  /* 111111       */

    t2 = fqmul(t2, t2);  /* 1101010      */
    t2 = fqmul(t2, t2);  /* 11010100     */
    t2 = fqmul(t2, t2);  /* 110101000    */
    t2 = fqmul(t2, t2);  /* 1101010000   */
    t2 = fqmul(t2, t2);  /* 11010100000  */
    t2 = fqmul(t2, t2);  /* 110101000000 */
    t2 = fqmul(t2, t1);  /* 110101111111 */

    t2 = fqmul(CRYPTO_NTRU_PLUS_RINV, t2);
    return t2;
}

/* ------------------------------------------------------------------ */
/* NTT 768 — degree-4 base                                              */
/* ------------------------------------------------------------------ */
static void ntt_768(int16_t *r, const int16_t *a)
{
    int16_t t1, t2, t3;
    int16_t zeta1, zeta2;
    int i, start, step;
    int k = 1;
    const int16_t *zetas = crypto_ntru_plus_zetas_768;

    zeta1 = zetas[k++];

    for (i = 0; i < 768 / 2; i++) {
        t1 = fqmul(zeta1, a[i + 768 / 2]);
        r[i + 768 / 2] = (int16_t)(a[i] + a[i + 768 / 2] - t1);
        r[i           ] = (int16_t)(a[i] + t1);
    }

    for (start = 0; start < 768; start += 384) {
        zeta1 = zetas[k++];
        zeta2 = zetas[k++];

        for (i = start; i < start + 128; i++) {
            t1 = fqmul(zeta1, r[i + 128]);
            t2 = fqmul(zeta2, r[i + 256]);
            t3 = fqmul(CRYPTO_NTRU_PLUS_OMEGA, t1 - t2);

            r[i + 256] = (int16_t)(r[i] - t1 - t3);
            r[i + 128] = (int16_t)(r[i] - t2 + t3);
            r[i      ] = (int16_t)(r[i] + t1 + t2);
        }
    }

    for (step = 64; step >= 4; step >>= 1) {
        for (start = 0; start < 768; start += (step << 1)) {
            zeta1 = zetas[k++];
            for (i = start; i < start + step; i++) {
                t1 = fqmul(zeta1, r[i + step]);
                r[i + step] = barrett_reduce(r[i] - t1);
                r[i       ] = barrett_reduce(r[i] + t1);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* InvNTT 768 — degree-4 base                                           */
/* ------------------------------------------------------------------ */
static void invntt_768(int16_t *r, const int16_t *a)
{
    int16_t t1, t2, t3;
    int16_t zeta1, zeta2;
    int i, start, step;
    int k = 191;
    const int16_t *zetas = crypto_ntru_plus_zetas_768;

    for (i = 0; i < 768; i++)
        r[i] = a[i];

    for (step = 4; step <= 64; step <<= 1) {
        for (start = 0; start < 768; start += (step << 1)) {
            zeta1 = zetas[k--];
            for (i = start; i < start + step; i++) {
                t1 = r[i + step];
                r[i + step] = fqmul(zeta1, t1 - r[i]);
                r[i       ] = barrett_reduce(r[i] + t1);
            }
        }
    }

    for (start = 0; start < 768; start += 384) {
        zeta2 = zetas[k--];
        zeta1 = zetas[k--];

        for (i = start; i < start + 128; i++) {
            t1 = fqmul(CRYPTO_NTRU_PLUS_OMEGA, r[i + 128] - r[i]);
            t2 = fqmul(zeta1, (int16_t)(r[i + 256] - r[i] + t1));
            t3 = fqmul(zeta2, (int16_t)(r[i + 256] - r[i + 128] - t1));

            r[i      ] = (int16_t)(r[i] + r[i + 128] + r[i + 256]);
            r[i + 128] = t2;
            r[i + 256] = t3;
        }
    }

    for (i = 0; i < 768 / 2; i++) {
        t1 = r[i] + r[i + 768 / 2];
        t2 = fqmul(CRYPTO_NTRU_PLUS_ZMINUSZ5INV, r[i] - r[i + 768 / 2]);

        r[i           ] = fqmul((int16_t)(-811),  t1 - t2);
        r[i + 768 / 2] = fqmul((int16_t)(-1622), t2);
    }
}

/* ------------------------------------------------------------------ */
/* NTT 864 — degree-3 base                                              */
/* ------------------------------------------------------------------ */
static void ntt_864(int16_t *r, const int16_t *a)
{
    int16_t t1, t2, t3;
    int16_t zeta1, zeta2;
    int i, start, step;
    int k = 1;
    const int16_t *zetas = crypto_ntru_plus_zetas_864;

    zeta1 = zetas[k++];

    for (i = 0; i < 864 / 2; i++) {
        t1 = fqmul(zeta1, a[i + 864 / 2]);
        r[i + 864 / 2] = (int16_t)(a[i] + a[i + 864 / 2] - t1);
        r[i           ] = (int16_t)(a[i] + t1);
    }

    for (step = 864 / 6; step >= 48; step = step / 3) {
        for (start = 0; start < 864; start += 3 * step) {
            zeta1 = zetas[k++];
            zeta2 = zetas[k++];

            for (i = start; i < start + step; i++) {
                t1 = fqmul(zeta1, r[i +   step]);
                t2 = fqmul(zeta2, r[i + 2*step]);
                t3 = fqmul(CRYPTO_NTRU_PLUS_OMEGA, t1 - t2);

                r[i + 2*step] = (int16_t)(r[i] - t1 - t3);
                r[i +   step] = (int16_t)(r[i] - t2 + t3);
                r[i          ] = (int16_t)(r[i] + t1 + t2);
            }
        }
    }

    for (step = 24; step >= 3; step >>= 1) {
        for (start = 0; start < 864; start += (step << 1)) {
            zeta1 = zetas[k++];
            for (i = start; i < start + step; i++) {
                t1 = fqmul(zeta1, r[i + step]);
                r[i + step] = barrett_reduce(r[i] - t1);
                r[i       ] = barrett_reduce(r[i] + t1);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* InvNTT 864 — degree-3 base                                           */
/* ------------------------------------------------------------------ */
static void invntt_864(int16_t *r, const int16_t *a)
{
    int16_t t1, t2, t3;
    int16_t zeta1, zeta2;
    int i, start, step;
    int k = 287;
    const int16_t *zetas = crypto_ntru_plus_zetas_864;

    for (i = 0; i < 864; i++)
        r[i] = a[i];

    for (step = 3; step <= 24; step <<= 1) {
        for (start = 0; start < 864; start += (step << 1)) {
            zeta1 = zetas[k--];
            for (i = start; i < start + step; i++) {
                t1 = r[i + step];
                r[i + step] = fqmul(zeta1, t1 - r[i]);
                r[i       ] = barrett_reduce(r[i] + t1);
            }
        }
    }

    for (step = 48; step <= 864 / 6; step = 3 * step) {
        for (start = 0; start < 864; start += 3 * step) {
            zeta2 = zetas[k--];
            zeta1 = zetas[k--];

            for (i = start; i < start + step; i++) {
                t1 = fqmul(CRYPTO_NTRU_PLUS_OMEGA, r[i +   step] - r[i]);
                t2 = fqmul(zeta1, (int16_t)(r[i + 2*step] - r[i] + t1));
                t3 = fqmul(zeta2, (int16_t)(r[i + 2*step] - r[i + step] - t1));

                r[i          ] = barrett_reduce((int16_t)(
                    r[i] + r[i + step] + r[i + 2*step]));
                r[i +   step] = t2;
                r[i + 2*step] = t3;
            }
        }
    }

    for (i = 0; i < 864 / 2; i++) {
        t1 = r[i] + r[i + 864 / 2];
        t2 = fqmul(CRYPTO_NTRU_PLUS_ZMINUSZ5INV, r[i] - r[i + 864 / 2]);

        r[i           ] = fqmul((int16_t)(-1693), t1 - t2);
        r[i + 864 / 2] = fqmul((int16_t)(71),    t2);
    }
}

/* ------------------------------------------------------------------ */
/* NTT 1152 — degree-4 base                                             */
/* ------------------------------------------------------------------ */
static void ntt_1152(int16_t *r, const int16_t *a)
{
    int16_t t1, t2, t3;
    int16_t zeta1, zeta2;
    int i, start, step;
    int k = 1;
    const int16_t *zetas = crypto_ntru_plus_zetas_1152;

    zeta1 = zetas[k++];

    for (i = 0; i < 1152 / 2; i++) {
        t1 = fqmul(zeta1, a[i + 1152 / 2]);
        r[i + 1152 / 2] = (int16_t)(a[i] + a[i + 1152 / 2] - t1);
        r[i            ] = (int16_t)(a[i] + t1);
    }

    for (step = 1152 / 6; step >= 64; step = step / 3) {
        for (start = 0; start < 1152; start += 3 * step) {
            zeta1 = zetas[k++];
            zeta2 = zetas[k++];

            for (i = start; i < start + step; i++) {
                t1 = fqmul(zeta1, r[i +   step]);
                t2 = fqmul(zeta2, r[i + 2*step]);
                t3 = fqmul(CRYPTO_NTRU_PLUS_OMEGA, t1 - t2);

                r[i + 2*step] = (int16_t)(r[i] - t1 - t3);
                r[i +   step] = (int16_t)(r[i] - t2 + t3);
                r[i          ] = (int16_t)(r[i] + t1 + t2);
            }
        }
    }

    for (step = 32; step >= 4; step >>= 1) {
        for (start = 0; start < 1152; start += (step << 1)) {
            zeta1 = zetas[k++];
            for (i = start; i < start + step; i++) {
                t1 = fqmul(zeta1, r[i + step]);
                r[i + step] = barrett_reduce(r[i] - t1);
                r[i       ] = barrett_reduce(r[i] + t1);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* InvNTT 1152 — degree-4 base                                          */
/* ------------------------------------------------------------------ */
static void invntt_1152(int16_t *r, const int16_t *a)
{
    int16_t t1, t2, t3;
    int16_t zeta1, zeta2;
    int i, start, step;
    int k = 287;
    const int16_t *zetas = crypto_ntru_plus_zetas_1152;

    for (i = 0; i < 1152; i++)
        r[i] = a[i];

    for (step = 4; step <= 32; step <<= 1) {
        for (start = 0; start < 1152; start += (step << 1)) {
            zeta1 = zetas[k--];
            for (i = start; i < start + step; i++) {
                t1 = r[i + step];
                r[i + step] = fqmul(zeta1, t1 - r[i]);
                r[i       ] = barrett_reduce(r[i] + t1);
            }
        }
    }

    for (step = 64; step <= 1152 / 6; step = 3 * step) {
        for (start = 0; start < 1152; start += 3 * step) {
            zeta2 = zetas[k--];
            zeta1 = zetas[k--];

            for (i = start; i < start + step; i++) {
                t1 = fqmul(CRYPTO_NTRU_PLUS_OMEGA, r[i +   step] - r[i]);
                t2 = fqmul(zeta1, (int16_t)(r[i + 2*step] - r[i] + t1));
                t3 = fqmul(zeta2, (int16_t)(r[i + 2*step] - r[i + step] - t1));

                r[i          ] = barrett_reduce((int16_t)(
                    r[i] + r[i + step] + r[i + 2*step]));
                r[i +   step] = t2;
                r[i + 2*step] = t3;
            }
        }
    }

    for (i = 0; i < 1152 / 2; i++) {
        t1 = r[i] + r[i + 1152 / 2];
        t2 = fqmul(CRYPTO_NTRU_PLUS_ZMINUSZ5INV, r[i] - r[i + 1152 / 2]);

        r[i            ] = fqmul((int16_t)(-1693), t1 - t2);
        r[i + 1152 / 2] = fqmul((int16_t)(71),    t2);
    }
}

/* ------------------------------------------------------------------ */
/* Public dispatch wrappers                                              */
/* ------------------------------------------------------------------ */

void crypto_ntru_plus_ntt(int16_t *r, const int16_t *a, const crypto_ntru_plus_parameters *alg)
{
    if (alg->n == CRYPTO_NTRU_PLUS_768_N)
        ntt_768(r, a);
    else if (alg->n == CRYPTO_NTRU_PLUS_864_N)
        ntt_864(r, a);
    else
        ntt_1152(r, a);
}

void crypto_ntru_plus_invntt(int16_t *r, const int16_t *a, const crypto_ntru_plus_parameters *alg)
{
    if (alg->n == CRYPTO_NTRU_PLUS_768_N)
        invntt_768(r, a);
    else if (alg->n == CRYPTO_NTRU_PLUS_864_N)
        invntt_864(r, a);
    else
        invntt_1152(r, a);
}

/* ------------------------------------------------------------------ */
/* Degree-4 base operations (768 / 1152)                                */
/* ------------------------------------------------------------------ */

int crypto_ntru_plus_baseinv4(int16_t r[4], const int16_t a[4], int16_t zeta)
{
    int16_t t0, t1, t2, t3;

    t0 = montgomery_reduce(a[2]*a[2] - 2*a[1]*a[3]);            /* R^-1 */
    t1 = montgomery_reduce(a[3]*a[3]);                          /* R^-1 */
    t0 = montgomery_reduce(a[0]*a[0] + t0*zeta);                /* R^-1 */
    t1 = montgomery_reduce(a[1]*a[1] + t1*zeta - 2*a[0]*a[2]); /* R^-1 */
    t2 = montgomery_reduce(t1*zeta);                            /* R^-1 */

    t3 = montgomery_reduce(t0*t0 - t1*t2); /* R^-3 */

    if (t3 == 0) return 1;

    r[0] = montgomery_reduce(a[0]*t0 + a[2]*t2); /* R^-2 */
    r[1] = montgomery_reduce(a[3]*t2 + a[1]*t0); /* R^-2 */
    r[2] = montgomery_reduce(a[2]*t0 + a[0]*t1); /* R^-2 */
    r[3] = montgomery_reduce(a[1]*t1 + a[3]*t0); /* R^-2 */

    t3 = fqinv(t3); /* R^5 */

    r[0] =  montgomery_reduce(r[0]*t3); /* R^0 */
    r[1] = -montgomery_reduce(r[1]*t3); /* R^0 */
    r[2] =  montgomery_reduce(r[2]*t3); /* R^0 */
    r[3] = -montgomery_reduce(r[3]*t3); /* R^0 */

    return 0;
}

void crypto_ntru_plus_basemul4(int16_t r[4], const int16_t a[4], const int16_t b[4],
              int16_t zeta)
{
    r[0] = montgomery_reduce(a[1]*b[3]+a[2]*b[2]+a[3]*b[1]); /* R^-1 */
    r[1] = montgomery_reduce(a[2]*b[3]+a[3]*b[2]);           /* R^-1 */
    r[2] = montgomery_reduce(a[3]*b[3]);                     /* R^-1 */

    r[0] = montgomery_reduce(r[0]*zeta+a[0]*b[0]);                      /* R^-1 */
    r[1] = montgomery_reduce(r[1]*zeta+a[0]*b[1]+a[1]*b[0]);            /* R^-1 */
    r[2] = montgomery_reduce(r[2]*zeta+a[0]*b[2]+a[1]*b[1]+a[2]*b[0]); /* R^-1 */
    r[3] = montgomery_reduce(a[0]*b[3]+a[1]*b[2]+a[2]*b[1]+a[3]*b[0]); /* R^-1 */

    r[0] = montgomery_reduce(r[0]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
    r[1] = montgomery_reduce(r[1]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
    r[2] = montgomery_reduce(r[2]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
    r[3] = montgomery_reduce(r[3]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
}

void crypto_ntru_plus_basemul_add4(int16_t r[4], const int16_t a[4], const int16_t b[4],
                  const int16_t c[4], int16_t zeta)
{
    r[0] = montgomery_reduce(a[1]*b[3]+a[2]*b[2]+a[3]*b[1]); /* R^-1 */
    r[1] = montgomery_reduce(a[2]*b[3]+a[3]*b[2]);           /* R^-1 */
    r[2] = montgomery_reduce(a[3]*b[3]);                     /* R^-1 */

    r[0] = montgomery_reduce(r[0]*zeta+a[0]*b[0]);                      /* R^-1 */
    r[1] = montgomery_reduce(r[1]*zeta+a[0]*b[1]+a[1]*b[0]);            /* R^-1 */
    r[2] = montgomery_reduce(r[2]*zeta+a[0]*b[2]+a[1]*b[1]+a[2]*b[0]); /* R^-1 */
    r[3] = montgomery_reduce(a[0]*b[3]+a[1]*b[2]+a[2]*b[1]+a[3]*b[0]); /* R^-1 */

    r[0] = montgomery_reduce(c[0]*CRYPTO_NTRU_PLUS_R + r[0]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
    r[1] = montgomery_reduce(c[1]*CRYPTO_NTRU_PLUS_R + r[1]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
    r[2] = montgomery_reduce(c[2]*CRYPTO_NTRU_PLUS_R + r[2]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
    r[3] = montgomery_reduce(c[3]*CRYPTO_NTRU_PLUS_R + r[3]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
}

/* ------------------------------------------------------------------ */
/* Degree-3 base operations (864)                                       */
/* ------------------------------------------------------------------ */

int crypto_ntru_plus_baseinv3(int16_t r[3], const int16_t a[3], int16_t zeta)
{
    int16_t t;

    r[0] = montgomery_reduce(a[1]*a[2]);           /* R^-1 */
    r[1] = montgomery_reduce(a[2]*a[2]);           /* R^-1 */
    r[2] = montgomery_reduce(a[1]*a[1]-a[0]*a[2]); /* R^-1 */
    r[0] = montgomery_reduce(a[0]*a[0]-r[0]*zeta); /* R^-1 */
    r[1] = montgomery_reduce(r[1]*zeta-a[0]*a[1]); /* R^-1 */

    t  = montgomery_reduce(r[2]*a[1]+r[1]*a[2]); /* R^-2 */
    t  = montgomery_reduce(t*zeta+r[0]*a[0]);    /* R^-2 */

    if (t == 0) return 1;

    t = fqinv(t); /* R^4 */

    r[0] = montgomery_reduce(r[0]*t); /* R^0 */
    r[1] = montgomery_reduce(r[1]*t); /* R^0 */
    r[2] = montgomery_reduce(r[2]*t); /* R^0 */

    return 0;
}

void crypto_ntru_plus_basemul3(int16_t r[3], const int16_t a[3], const int16_t b[3],
              int16_t zeta)
{
    r[0] = montgomery_reduce(a[2]*b[1]+a[1]*b[2]); /* R^-1 */
    r[1] = montgomery_reduce(a[2]*b[2]);           /* R^-1 */

    r[0] = montgomery_reduce(r[0]*zeta+a[0]*b[0]);              /* R^-1 */
    r[1] = montgomery_reduce(r[1]*zeta+a[0]*b[1]+a[1]*b[0]);    /* R^-1 */
    r[2] = montgomery_reduce(a[2]*b[0]+a[1]*b[1]+a[0]*b[2]);    /* R^-1 */

    r[0] = montgomery_reduce(r[0]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
    r[1] = montgomery_reduce(r[1]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
    r[2] = montgomery_reduce(r[2]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
}

void crypto_ntru_plus_basemul_add3(int16_t r[3], const int16_t a[3], const int16_t b[3],
                  const int16_t c[3], int16_t zeta)
{
    r[0] = montgomery_reduce(a[2]*b[1]+a[1]*b[2]); /* R^-1 */
    r[1] = montgomery_reduce(a[2]*b[2]);           /* R^-1 */

    r[0] = montgomery_reduce(r[0]*zeta+a[0]*b[0]);              /* R^-1 */
    r[1] = montgomery_reduce(r[1]*zeta+a[0]*b[1]+a[1]*b[0]);    /* R^-1 */
    r[2] = montgomery_reduce(a[2]*b[0]+a[1]*b[1]+a[0]*b[2]);    /* R^-1 */

    r[0] = montgomery_reduce(c[0]*CRYPTO_NTRU_PLUS_R + r[0]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
    r[1] = montgomery_reduce(c[1]*CRYPTO_NTRU_PLUS_R + r[1]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
    r[2] = montgomery_reduce(c[2]*CRYPTO_NTRU_PLUS_R + r[2]*CRYPTO_NTRU_PLUS_RSQ); /* R^0 */
}
