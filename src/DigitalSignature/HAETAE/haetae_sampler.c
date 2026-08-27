// SPDX-License-Identifier: MIT

#include "haetae_symmetric.h"

#include "haetae_sampler.h"
#include "haetae_reduce.h"

/*************************************************
 * Name:        rej_uniform
 *
 * Description: Sample uniformly random coefficients in [0, Q-1] by
 *              performing rejection sampling on array of random bytes.
 *
 * Arguments:   - int *a: pointer to output array (allocated)
 *              - unsigned int len: number of coefficients to be sampled
 *              - const uint8_t  *buf: array of random bytes
 *              - unsigned int buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
unsigned int crypto_haetae_rej_uniform(int *a, unsigned int len, const uint8_t  *buf,
                         unsigned int buflen) {
    unsigned int ctr, pos;
    uint32_t t;

    ctr = pos = 0;
    while (ctr < len && pos + 2 <= buflen) {
        t = crypto_load16_le(buf + pos);
        pos += 2u;

        if (t < CRYPTO_HAETAE_Q)
            a[ctr++] = t;
    }
    return ctr;
}

/*************************************************
 * Name:        rej_eta
 *
 * Description: Sample uniformly random coefficients in [-ETA, ETA] by
 *              performing rejection sampling on array of random bytes.
 *
 * Arguments:   - int *a: pointer to output array (allocated)
 *              - unsigned int len: number of coefficients to be sampled
 *              - const uint8_t  *buf: array of random bytes
 *              - unsigned int buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
static int mod3(uint8_t  t) {
    int r;
    r = (t >> 4) + (t & 0xf);
    r = (r >> 2) + (r & 3);
    r = (r >> 2) + (r & 3);
    r = (r >> 2) + (r & 3);
    return r - (3 * (r >> 1));
}
static int mod3_leq26(uint8_t  t) {
    int r;
    r = (t >> 4) + (t & 0xf);
    r = (r >> 2) + (r & 3);
    r = (r >> 2) + (r & 3);
    return r - (3 * (r >> 1));
}
static int mod3_leq8(uint8_t  t) {
    int r;
    r = (t >> 2) + (t & 3);
    r = (r >> 2) + (r & 3);
    return r - (3 * (r >> 1));
}
unsigned int crypto_haetae_rej_eta(int *a, unsigned int len, const uint8_t  *buf,
                     unsigned int buflen) {
    unsigned int ctr, pos;

    ctr = pos = 0;
    while (ctr < len && pos < buflen) {
#if CRYPTO_HAETAE_ETA == 1
        uint32_t t = buf[pos++];
        if (t < 243) {
            // reduce mod 3
            a[ctr++] = mod3(t);

            if (ctr >= len)
                break;

            t *= 171; // 171*3 = 1 mod 256
            t >>= 9;
            a[ctr++] = mod3(t);

            if (ctr >= len)
                break;

            t *= 171;
            t >>= 9;
            a[ctr++] = mod3_leq26(t);

            if (ctr >= len)
                break;

            t *= 171;
            t >>= 9;
            a[ctr++] = mod3_leq8(t);

            if (ctr >= len)
                break;

            t *= 171;
            t >>= 9;
            a[ctr++] = (int)t - (int)3 * (t >> 1);
        }
#elif CRYPTO_HAETAE_ETA == 2
        uint32_t t0, t1;
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos++] >> 4;
        if (t0 < 15) {
            t0 = t0 - (205 * t0 >> 10) * 5;
            a[ctr++] = 2 - t0;
        }
        if (t1 < 15 && ctr < len) {
            t1 = t1 - (205 * t1 >> 10) * 5;
            a[ctr++] = 2 - t1;
        }
#endif
    }
    return ctr;
}

/*
 * GALACTICS [Rossi23] degree-10 polynomial for exp(-z), where z = xi/2^48.
 * The constant term is lifted by one 2^-48 unit so the polynomial is an
 * upper approximation throughout the sampler's input interval.
 */
static uint64_t approx_exp(const uint64_t xi) {
    int64_t result = INT64_C(55868746);
    result = smulh48(result, xi) - INT64_C(743564434);
    result = smulh48(result, xi) + INT64_C(6953427278);
    result = smulh48(result, xi) - INT64_C(55833338892);
    result = smulh48(result, xi) + INT64_C(390932311155);
    result = smulh48(result, xi) - INT64_C(2345623661771);
    result = smulh48(result, xi) + INT64_C(11728123872951);
    result = smulh48(result, xi) - INT64_C(46912496106200);
    result = smulh48(result, xi) + INT64_C(140737488354861);
    result = smulh48(result, xi) - INT64_C(281474976710650);
    result = smulh48(result, xi) + INT64_C(281474976710657);
    return (uint64_t)result;
}

#define CRYPTO_HAETAE_CDT_LENGTH 166u
#define CRYPTO_HAETAE_CDT_HIGH_LENGTH 76u

/*
 * 83-bit CDT for the D_{Z,16} half-Gaussian. Each threshold is split into
 * its upper 19 bits and lower 64 bits to support compilers without __int128.
 */
static const uint32_t crypto_haetae_cdt83_high[
    CRYPTO_HAETAE_CDT_HIGH_LENGTH] = {
    UINT32_C(0x063a5), UINT32_C(0x0c718), UINT32_C(0x129f6), UINT32_C(0x18bdf),
    UINT32_C(0x1ec73), UINT32_C(0x24b59), UINT32_C(0x2a83a), UINT32_C(0x302c6),
    UINT32_C(0x35ab6), UINT32_C(0x3afc7), UINT32_C(0x401be), UINT32_C(0x4506a),
    UINT32_C(0x49ba1), UINT32_C(0x4e343), UINT32_C(0x52736), UINT32_C(0x5676c),
    UINT32_C(0x5a3dc), UINT32_C(0x5dc86), UINT32_C(0x61172), UINT32_C(0x642ad),
    UINT32_C(0x6704c), UINT32_C(0x69a68), UINT32_C(0x6c120), UINT32_C(0x6e496),
    UINT32_C(0x704ef), UINT32_C(0x72255), UINT32_C(0x73cf1), UINT32_C(0x754f0),
    UINT32_C(0x76a7c), UINT32_C(0x77dc4), UINT32_C(0x78ef2), UINT32_C(0x79e32),
    UINT32_C(0x7abaf), UINT32_C(0x7b78f), UINT32_C(0x7c1fb), UINT32_C(0x7cb17),
    UINT32_C(0x7d304), UINT32_C(0x7d9e4), UINT32_C(0x7dfd4), UINT32_C(0x7e4f0),
    UINT32_C(0x7e950), UINT32_C(0x7ed0d), UINT32_C(0x7f03b), UINT32_C(0x7f2ec),
    UINT32_C(0x7f531), UINT32_C(0x7f71a), UINT32_C(0x7f8b3), UINT32_C(0x7fa08),
    UINT32_C(0x7fb24), UINT32_C(0x7fc0e), UINT32_C(0x7fccf), UINT32_C(0x7fd6e),
    UINT32_C(0x7fdf0), UINT32_C(0x7fe5a), UINT32_C(0x7feaf), UINT32_C(0x7fef5),
    UINT32_C(0x7ff2c), UINT32_C(0x7ff59), UINT32_C(0x7ff7d), UINT32_C(0x7ff99),
    UINT32_C(0x7ffb0), UINT32_C(0x7ffc2), UINT32_C(0x7ffd0), UINT32_C(0x7ffdb),
    UINT32_C(0x7ffe3), UINT32_C(0x7ffea), UINT32_C(0x7ffef), UINT32_C(0x7fff3),
    UINT32_C(0x7fff6), UINT32_C(0x7fff8), UINT32_C(0x7fffa), UINT32_C(0x7fffb),
    UINT32_C(0x7fffd), UINT32_C(0x7fffd), UINT32_C(0x7fffe), UINT32_C(0x7fffe)
};

static const uint64_t crypto_haetae_cdt83_low[
    CRYPTO_HAETAE_CDT_LENGTH] = {
    UINT64_C(0x0aa572bc88db1e28), UINT64_C(0x4f3820e69064b2ee),
    UINT64_C(0xd68dc44dd1418704), UINT64_C(0x6587a04d9b97b1dd),
    UINT64_C(0x9b843ce0a65d0050), UINT64_C(0x02b62cb869003e7d),
    UINT64_C(0x0d44f194f8bf43c6), UINT64_C(0xfaa0c7acb211b4db),
    UINT64_C(0xa11387f7f524be80), UINT64_C(0x18526ca6f2ceb77f),
    UINT64_C(0x42a01a906b7dad17), UINT64_C(0x32e5337a1966b9a7),
    UINT64_C(0x6f00f7ac9735f58a), UINT64_C(0x0e6c48f40642ba60),
    UINT64_C(0xb6192fa1afb5e4ec), UINT64_C(0x7339dba8ffc2fcf5),
    UINT64_C(0x7746cbe1ac90c9eb), UINT64_C(0xb83004341d78466f),
    UINT64_C(0x781dcca572bb3d8a), UINT64_C(0xb880376cc82a5384),
    UINT64_C(0x9c68a5c477dfecb9), UINT64_C(0xbe45ceb02a25fef3),
    UINT64_C(0x7d1a8ccd208dbaa1), UINT64_C(0x452c002b9085e7db),
    UINT64_C(0xd7ef361c5551378d), UINT64_C(0x96b4ff49d9e5a8bb),
    UINT64_C(0xd337c94ede732d83), UINT64_C(0x28c75b8d3fe83c38),
    UINT64_C(0xe05d7bd130fe20e0), UINT64_C(0x6170e60b76d85108),
    UINT64_C(0xb0e59892414901ff), UINT64_C(0xff05cf70b911f3de),
    UINT64_C(0x4501460fdfd508c9), UINT64_C(0xf20b1303a2a54906),
    UINT64_C(0xa7d3badbeb04b20c), UINT64_C(0x05ce666b741b666d),
    UINT64_C(0x826e689fded20430), UINT64_C(0x5155d1354fcf6ff6),
    UINT64_C(0x55469226a1d318f6), UINT64_C(0x1c8d3820cfa9cabc),
    UINT64_C(0xe68d83bbf700fc40), UINT64_C(0xb1152d8944042803),
    UINT64_C(0x4c1e741aabe53700), UINT64_C(0x72b94c56e0f9a967),
    UINT64_C(0xe7e5a80a79e4539c), UINT64_C(0x9641c5d11feb4d12),
    UINT64_C(0xb18b71598b73dde0), UINT64_C(0xd9112fb5a7904d7e),
    UINT64_C(0x3a4f57cbefabc820), UINT64_C(0xb314025fd5022976),
    UINT64_C(0xf2a2b228aab1981b), UINT64_C(0x996ce1e60378cd98),
    UINT64_C(0x570ec64b38e3ca90), UINT64_C(0x0657269615dcd7c6),
    UINT64_C(0xc7360038bdc85312), UINT64_C(0x167fa02a57a8ae1a),
    UINT64_C(0xe380fab2ea9b2bef), UINT64_C(0xa36e6abd6509b5a2),
    UINT64_C(0x62bfcf1d6ba81c37), UINT64_C(0xd4946e8bf96caa93),
    UINT64_C(0x603e6262ea8cda2d), UINT64_C(0x2d18c8b333ae9203),
    UINT64_C(0x2ccdedb5a7718d61), UINT64_C(0x24333ecab8497c0a),
    UINT64_C(0xb2e06eb33bf2b7d9), UINT64_C(0x59a5f6c550dfe7e2),
    UINT64_C(0x800548f3927f906e), UINT64_C(0x78cac146b573bc40),
    UINT64_C(0x85e6dadec4b6aff1), UINT64_C(0xdba17dfa17def8ec),
    UINT64_C(0xa33f84d06ce20a93), UINT64_C(0xfd2fe967c5186746),
    UINT64_C(0x02d37ecd7e9b180f), UINT64_C(0xc7efafa8bd33f0bb),
    UINT64_C(0x5bda826341e791cc), UINT64_C(0xca6c1c6ce045599f),
    UINT64_C(0x1cc02c0faa9a526e), UINT64_C(0x59d002901a4a4e52),
    UINT64_C(0x86ecbd139ce07540), UINT64_C(0xa81f9f15ffb47f4c),
    UINT64_C(0xc075b17481687af0), UINT64_C(0xd23ad13e68301c65),
    UINT64_C(0xdf27955fae1c84cb), UINT64_C(0xe884cdb07368c266),
    UINT64_C(0xef46d4f897fc83f6), UINT64_C(0xf4227e46663ec049),
    UINT64_C(0xf79d091c1b5aff07), UINT64_C(0xfa183c533c3890a6),
    UINT64_C(0xfbdb8a602066b0f2), UINT64_C(0xfd1af06df3db86b7),
    UINT64_C(0xfdfc1a818587e2aa), UINT64_C(0xfe9a37a348ac2a93),
    UINT64_C(0xff08d0797970dbfe), UINT64_C(0xff55df73fd7a00bc),
    UINT64_C(0xff8b5aa573bca5ce), UINT64_C(0xffb053c109f51681),
    UINT64_C(0xffc9c9bd39a036ec), UINT64_C(0xffdb40bd4ee1f846),
    UINT64_C(0xffe72fa859b20a4a), UINT64_C(0xffef4edda93d266d),
    UINT64_C(0xfff4d07a9fb0d4e0), UINT64_C(0xfff88868ef31b1cc),
    UINT64_C(0xfffb08c16a3f5f0c), UINT64_C(0xfffcb5d30be5cabf),
    UINT64_C(0xfffdd43465d95fe6), UINT64_C(0xfffe929a538ad2fa),
    UINT64_C(0xffff10b1c2119732), UINT64_C(0xffff63df8795a2c9),
    UINT64_C(0xffff9a87a0a9f2af), UINT64_C(0xffffbe4df6f0f4a9),
    UINT64_C(0xffffd5a10f204910), UINT64_C(0xffffe4c6f1668b32),
    UINT64_C(0xffffee939680bfaf), UINT64_C(0xfffff4e4216290db),
    UINT64_C(0xfffff8f1c044613e), UINT64_C(0xfffffb892dc2b174),
    UINT64_C(0xfffffd2fb4188608), UINT64_C(0xfffffe3bc0a56eba),
    UINT64_C(0xfffffee523b218c6), UINT64_C(0xffffff4fc31097e3),
    UINT64_C(0xffffff929d76dbeb), UINT64_C(0xffffffbc5e7c0350),
    UINT64_C(0xffffffd6586c6684), UINT64_C(0xffffffe6716865f7),
    UINT64_C(0xfffffff0613c76e2), UINT64_C(0xfffffff67d62ab64),
    UINT64_C(0xfffffffa3b6664c0), UINT64_C(0xfffffffc83e13d66),
    UINT64_C(0xfffffffde713ef71), UINT64_C(0xfffffffebe18936f),
    UINT64_C(0xffffffff3fbfc997), UINT64_C(0xffffffff8d9fa29a),
    UINT64_C(0xffffffffbc372590), UINT64_C(0xffffffffd7fb7dfd),
    UINT64_C(0xffffffffe87747f9), UINT64_C(0xfffffffff2368b89),
    UINT64_C(0xfffffffff7f44d88), UINT64_C(0xfffffffffb52a49b),
    UINT64_C(0xfffffffffd4a9ffb), UINT64_C(0xfffffffffe700579),
    UINT64_C(0xffffffffff1a287f), UINT64_C(0xffffffffff7c6f06),
    UINT64_C(0xffffffffffb4fa99), UINT64_C(0xffffffffffd56300),
    UINT64_C(0xffffffffffe7e364), UINT64_C(0xfffffffffff268d7),
    UINT64_C(0xfffffffffff85e8e), UINT64_C(0xfffffffffffbbb6f),
    UINT64_C(0xfffffffffffd9f49), UINT64_C(0xfffffffffffeae2c),
    UINT64_C(0xffffffffffff453d), UINT64_C(0xffffffffffff9928),
    UINT64_C(0xffffffffffffc797), UINT64_C(0xffffffffffffe12f),
    UINT64_C(0xffffffffffffef3c), UINT64_C(0xfffffffffffff6eb),
    UINT64_C(0xfffffffffffffb1b), UINT64_C(0xfffffffffffffd60),
    UINT64_C(0xfffffffffffffe9a), UINT64_C(0xffffffffffffff43),
    UINT64_C(0xffffffffffffff9e), UINT64_C(0xffffffffffffffce),
    UINT64_C(0xffffffffffffffe7), UINT64_C(0xfffffffffffffff4),
    UINT64_C(0xfffffffffffffffb), UINT64_C(0xfffffffffffffffe)
};

static uint64_t sample_gauss83(
    const uint64_t random_low, const uint32_t random_high) {
    unsigned int index;
    uint64_t result = 0u;

    for (index = 0u; index < CRYPTO_HAETAE_CDT_HIGH_LENGTH; ++index) {
#if defined(__SIZEOF_INT128__) && \
    !defined(CRYPTO_HAETAE_FORCE_NO_INT128)
        uint128 threshold =
            ((uint128)crypto_haetae_cdt83_high[index] << 64) |
            crypto_haetae_cdt83_low[index];
        uint128 random_value =
            ((uint128)random_high << 64) | random_low;
        result += (uint64_t)((threshold - random_value) >> 127);
#else
        uint64_t borrow = random_low > crypto_haetae_cdt83_low[index];
        uint64_t high_difference =
            (uint64_t)crypto_haetae_cdt83_high[index] -
            random_high - borrow;
        result += high_difference >> 63;
#endif
    }

#if defined(__SIZEOF_INT128__) && \
    !defined(CRYPTO_HAETAE_FORCE_NO_INT128)
    {
        uint128 random_value =
            ((uint128)random_high << 64) | random_low;
        for (index = CRYPTO_HAETAE_CDT_HIGH_LENGTH;
             index < CRYPTO_HAETAE_CDT_LENGTH;
             ++index) {
            uint128 threshold =
                ((uint128)UINT64_C(0x7ffff) << 64) |
                crypto_haetae_cdt83_low[index];
            result += (uint64_t)((threshold - random_value) >> 127);
        }
    }
#else
    for (index = CRYPTO_HAETAE_CDT_HIGH_LENGTH;
         index < CRYPTO_HAETAE_CDT_LENGTH;
         ++index) {
        uint64_t borrow = random_low > crypto_haetae_cdt83_low[index];
        uint64_t high_difference =
            UINT64_C(0x7ffff) - random_high - borrow;
        result += high_difference >> 63;
    }
#endif

    return result;
}

#define CRYPTO_HAETAE_GAUSS_RANDOM_BITS (72u + 83u + 48u)
#define CRYPTO_HAETAE_GAUSS_RANDOM_BYTES \
    ((CRYPTO_HAETAE_GAUSS_RANDOM_BITS + 7u) / 8u)

static int sample_gauss_sigma76(
    uint64_t *result,
    crypto_haetae_fp96_76 *square,
    const uint8_t random[CRYPTO_HAETAE_GAUSS_RANDOM_BYTES]) {
    const uint64_t random_gauss_low = crypto_load64_le(random);
    const uint32_t random_gauss_high =
        crypto_load24_le(random + 8u) & UINT32_C(0x7ffff);
    const uint64_t random_rejection =
        (uint64_t)crypto_load32_le(random + 11u) |
        ((uint64_t)crypto_load16_le(random + 15u) << 32);
    uint64_t x;
    uint64_t exponent_input;
    crypto_haetae_fp96_76 y;

    x = sample_gauss83(random_gauss_low, random_gauss_high);
    y.limb48[0] =
        (uint64_t)crypto_load32_le(random + 17u) |
        ((uint64_t)crypto_load16_le(random + 21u) << 32);
    y.limb48[1] = (uint64_t)crypto_load24_le(random + 23u) | (x << 24);

    /* Split the rounding so coefficients up to 165 cannot overflow uint64_t. */
    *result = ((y.limb48[0] >> 15) + 1u) >> 1;
    *result += y.limb48[1] << 32;

    crypto_haetae_fixpoint_square(square, &y);
    exponent_input = square->limb48[1] - ((x * x) << (68 - 48));
    exponent_input <<= 20;
    exponent_input |= square->limb48[0] >> 28;
    exponent_input = (exponent_input + 1u) >> 1;

    return ((((int64_t)(random_rejection ^ (random_rejection & 1u)) -
               (int64_t)approx_exp(exponent_input)) >> 63) &
            (((*result | -*result) >> 63) | random_rejection)) & 1;
}


int crypto_haetae_sample_gauss(uint64_t *r, crypto_haetae_fp96_76 *sqsum, const uint8_t  *buf, const size_t buflen, const size_t len, const int dont_write_last)
{
    const uint8_t  *pos = buf;
    crypto_haetae_fp96_76 sqr;
    size_t bytecnt = buflen, coefcnt = 0;
    int accepted;
    uint64_t dummy;

    while (coefcnt < len) {
        if (bytecnt < CRYPTO_HAETAE_GAUSS_RANDOM_BYTES) {
          renormalize(sqsum);
          return coefcnt;
        }

        if (dont_write_last && coefcnt == len-1)
        {
          accepted = sample_gauss_sigma76(&dummy, &sqr, pos);
        } else {
          accepted = sample_gauss_sigma76(&r[coefcnt], &sqr, pos);
        }
        coefcnt += accepted;
        pos += CRYPTO_HAETAE_GAUSS_RANDOM_BYTES;
        bytecnt -= CRYPTO_HAETAE_GAUSS_RANDOM_BYTES;

        sqsum->limb48[0] += sqr.limb48[0] & -(long long)accepted;
        sqsum->limb48[1] += sqr.limb48[1] & -(long long)accepted;
    }
    renormalize(sqsum);

    return len;
}

#define POLY_HYPERBALL_BUFLEN \
    (CRYPTO_HAETAE_GAUSS_RANDOM_BYTES * CRYPTO_HAETAE_N)
#define POLY_HYPERBALL_NBLOCKS ((POLY_HYPERBALL_BUFLEN + CRYPTO_HAETAE_SHAKE256_RATE - 1) / CRYPTO_HAETAE_SHAKE256_RATE)
void crypto_haetae_sample_gauss_N(uint64_t *r, uint8_t  *signs, crypto_haetae_fp96_76 *sqsum,
                    const uint8_t  seed[CRYPTO_HAETAE_CRH_BYTES], const uint16_t nonce,
                    const size_t len) {
    uint64_t buf_aligned64[
        (POLY_HYPERBALL_NBLOCKS * CRYPTO_HAETAE_SHAKE256_RATE + 7u) /
        8u] = {0};
    uint8_t  *buf = (uint8_t  *)buf_aligned64;

    size_t bytecnt, coefcnt, firstflag = 1;
    size_t i;

    crypto_sha3_context context;

    crypto_haetae_shake256_stream_init(&context, seed, nonce);
    crypto_haetae_shake256_squeeze_blocks(&context, buf, POLY_HYPERBALL_NBLOCKS);


    for (i = 0; i < len / 8; i++) {
        signs[i] = buf[i];
    }
    bytecnt = POLY_HYPERBALL_NBLOCKS * CRYPTO_HAETAE_SHAKE256_RATE - len / 8;
    coefcnt = crypto_haetae_sample_gauss(r, sqsum, buf + len / 8, bytecnt, len, len % CRYPTO_HAETAE_N);

    while (coefcnt < len) {
        size_t off = bytecnt % CRYPTO_HAETAE_GAUSS_RANDOM_BYTES;
        for (i = 0; i < off; i++) {
            buf[i] = buf[bytecnt + len/8*firstflag - off + i];
        }

        crypto_haetae_shake256_squeeze_blocks(&context, buf + off, 1);
        bytecnt = CRYPTO_HAETAE_SHAKE256_RATE + off;

        coefcnt += crypto_haetae_sample_gauss(r + coefcnt, sqsum, buf, bytecnt, len - coefcnt, len % CRYPTO_HAETAE_N);
        firstflag = 0;
    }
    crypto_sha3_clear(&context);
    crypto_zeroize(buf_aligned64, sizeof(buf_aligned64));
}
