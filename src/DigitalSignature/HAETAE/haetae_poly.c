// SPDX-License-Identifier: MIT

#include "haetae_symmetric.h"

#include "haetae_reduce.h"
#include "haetae_sampler.h"
#include "haetae_decompose.h"
#include "haetae_ntt.h"
#include "haetae_poly.h"

/*************************************************
 * Name:        poly_add
 *
 * Description: Add polynomials. No modular reduction is performed.
 *
 * Arguments:   - crypto_haetae_poly *c: pointer to output polynomial
 *              - const crypto_haetae_poly *a: pointer to first summand
 *              - const crypto_haetae_poly *b: pointer to second summand
 **************************************************/
void crypto_haetae_poly_add(crypto_haetae_poly *c, const crypto_haetae_poly *a, const crypto_haetae_poly *b) {
    unsigned int i;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
 * Name:        poly_sub
 *
 * Description: Subtract polynomials. No modular reduction is
 *              performed.
 *
 * Arguments:   - crypto_haetae_poly *c: pointer to output polynomial
 *              - const crypto_haetae_poly *a: pointer to first input polynomial
 *              - const crypto_haetae_poly *b: pointer to second input polynomial to be
 *                               subtraced from first input polynomial
 **************************************************/
void crypto_haetae_poly_sub(crypto_haetae_poly *c, const crypto_haetae_poly *a, const crypto_haetae_poly *b) {
    unsigned int i;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/*************************************************
 * Name:        poly_pointwise_montgomery
 *
 * Description: Pointwise multiplication of polynomials in NTT domain
 *              representation and multiplication of resulting polynomial
 *              by 2^{-32}.
 *
 * Arguments:   - crypto_haetae_poly *c: pointer to output polynomial
 *              - const crypto_haetae_poly *a: pointer to first input polynomial
 *              - const crypto_haetae_poly *b: pointer to second input polynomial
 **************************************************/
void crypto_haetae_poly_pointwise_montgomery(crypto_haetae_poly *c, const crypto_haetae_poly *a, const crypto_haetae_poly *b) {
    unsigned int i;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        c->coeffs[i] = crypto_haetae_montgomery_reduce((long long)a->coeffs[i] * b->coeffs[i]);
}

/*************************************************
 * Name:        crypto_haetae_poly_reduce2q
 *
 * Description: Inplace reduction of all coefficients of polynomial to 2q
 *
 * Arguments:   - crypto_haetae_poly *a: pointer to input/output polynomial
 **************************************************/
void crypto_haetae_poly_reduce2q(crypto_haetae_poly *a) {
    unsigned int i;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        a->coeffs[i] = crypto_haetae_reduce32_2q(a->coeffs[i]);
}

/*************************************************
 * Name:        crypto_haetae_poly_freeze2q
 *
 * Description: For all coefficients of in/out polynomial compute standard
 *              representative r = a mod^+ 2Q
 *
 * Arguments:   - crypto_haetae_poly *a: pointer to input/output polynomial
 **************************************************/
void crypto_haetae_poly_freeze2q(crypto_haetae_poly *a) {
    unsigned int i;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        a->coeffs[i] = crypto_haetae_freeze2q(a->coeffs[i]);
}

/*************************************************
 * Name:        crypto_haetae_poly_freeze
 *
 * Description: For all coefficients of in/out polynomial compute standard
 *              representative r = a mod^+ Q
 *
 * Arguments:   - crypto_haetae_poly *a: pointer to input/output polynomial
 **************************************************/
void crypto_haetae_poly_freeze(crypto_haetae_poly *a) {
    unsigned int i;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        a->coeffs[i] = crypto_haetae_freeze(a->coeffs[i]);
}

/*************************************************
 * Name:        crypto_haetae_poly_highbits
 *
 * Description: Compute HighBits of polynomial
 *
 * Arguments:   - crypto_haetae_poly *a2: pointer to output polynomial
 *              - const crypto_haetae_poly *a: pointer to input polynomial
 **************************************************/
void crypto_haetae_poly_highbits(crypto_haetae_poly *a2, const crypto_haetae_poly *a) {
    unsigned int i;
    int a1tmp;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        crypto_haetae_decompose_z1(&a2->coeffs[i], &a1tmp, a->coeffs[i]);
}

/*************************************************
 * Name:        crypto_haetae_poly_lowbits
 *
 * Description: Compute LowBits of polynomial
 *
 * Arguments:   - crypto_haetae_poly *a1: pointer to output polynomial
 *              - const crypto_haetae_poly *a: pointer to input polynomial
 **************************************************/
void crypto_haetae_poly_lowbits(crypto_haetae_poly *a1, const crypto_haetae_poly *a) {
    unsigned int i = 0;
    int a2tmp = 0;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        crypto_haetae_decompose_z1(&a2tmp, &a1->coeffs[i], a->coeffs[i]);
}

/*************************************************
 * Name:        crypto_haetae_poly_compose
 *
 * Description: Compose HighBits and LowBits to recreate the polynomial
 *
 * Arguments:   - crypto_haetae_poly *a3: pointer to output polynomial
 *              - const crypto_haetae_poly *ha: pointer to HighBits polynomial
 *              - const crypto_haetae_poly *la: pointer to HighBits polynomial
 **************************************************/
void crypto_haetae_poly_compose(crypto_haetae_poly *a, const crypto_haetae_poly *ha, const crypto_haetae_poly *la) {
    unsigned int i = 0;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        a->coeffs[i] = (int)((long long int)ha->coeffs[i] * 256 + la->coeffs[i]);
        //a->coeffs[i] = (ha->coeffs[i] * 256) + la->coeffs[i];
}

/*************************************************
 * Name:        crypto_haetae_poly_lsb
 *
 * Description: Compute least significant bits of polynomial
 *
 * Arguments:   - crypto_haetae_poly *a0: pointer to output polynomial
 *              - const crypto_haetae_poly *a: pointer to input polynomial
 **************************************************/
void crypto_haetae_poly_lsb(crypto_haetae_poly *a0, const crypto_haetae_poly *a) {
    unsigned int i;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        a0->coeffs[i] = a->coeffs[i] & 1;
}

/*************************************************
 * Name:        poly_uniform
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [0,Q-1] by performing rejection sampling on the
 *              output stream of crypto_shake256(seed|nonce)
 *
 * Arguments:   - crypto_haetae_poly *a: pointer to output polynomial
 *              - const uint8_t  seed[]: byte array with seed of length SEEDBYTES
 *              - uint16_t nonce: 2-byte nonce
 **************************************************/
#define POLY_UNIFORM_NBLOCKS                                                   \
    ((512 + CRYPTO_HAETAE_SHAKE128_RATE - 1) / CRYPTO_HAETAE_SHAKE128_RATE)
// N * 2(random bytes for [0, Q - 1])

void crypto_haetae_poly_uniform(crypto_haetae_poly *a,
                         const uint8_t  seed[CRYPTO_HAETAE_SEED_BYTES],
                         uint16_t nonce) {
    unsigned int i, ctr, off;
    unsigned int buflen = POLY_UNIFORM_NBLOCKS * CRYPTO_HAETAE_SHAKE128_RATE;
    uint8_t buf[POLY_UNIFORM_NBLOCKS * CRYPTO_HAETAE_SHAKE128_RATE + 1u] = {0};

    crypto_sha3_context context;

    crypto_haetae_shake128_stream_init(&context, seed, nonce);
    crypto_haetae_shake128_squeeze_blocks(&context, buf, POLY_UNIFORM_NBLOCKS);

    ctr = crypto_haetae_rej_uniform(a->coeffs, CRYPTO_HAETAE_N, buf, buflen);

    while (ctr < CRYPTO_HAETAE_N) {
        off = buflen % 2;
        for (i = 0; i < off; ++i)
            buf[i] = buf[buflen - off + i];

        crypto_haetae_shake128_squeeze_blocks(&context, buf + off, 1);
        buflen = CRYPTO_HAETAE_SHAKE128_RATE + off;
        ctr += crypto_haetae_rej_uniform(a->coeffs + ctr, CRYPTO_HAETAE_N - ctr, buf, buflen);
    }

    crypto_sha3_clear(&context);
}

/*************************************************
 * Name:        poly_uniform_eta
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [-ETA,ETA] by performing rejection sampling on the
 *              output stream from crypto_shake256(seed|nonce)
 *
 * Arguments:   - crypto_haetae_poly *a: pointer to output polynomial
 *              - const uint8_t  seed[]: byte array with seed of length CRHBYTES
 *              - uint16_t nonce: 2-byte nonce
 **************************************************/
#if CRYPTO_HAETAE_ETA == 1
#define POLY_UNIFORM_ETA_NBLOCKS                                               \
    ((136 + CRYPTO_HAETAE_SHAKE256_RATE - 1) / CRYPTO_HAETAE_SHAKE256_RATE)
#elif CRYPTO_HAETAE_ETA == 2
#define POLY_UNIFORM_ETA_NBLOCKS                                               \
    ((136 + CRYPTO_HAETAE_SHAKE256_RATE - 1) / CRYPTO_HAETAE_SHAKE256_RATE)
#endif

void crypto_haetae_poly_uniform_eta(crypto_haetae_poly *a, const uint8_t  seed[CRYPTO_HAETAE_CRH_BYTES], uint16_t nonce) {
    unsigned int ctr;
    unsigned int buflen = POLY_UNIFORM_ETA_NBLOCKS * CRYPTO_HAETAE_SHAKE256_RATE;
    uint8_t  buf[POLY_UNIFORM_ETA_NBLOCKS * CRYPTO_HAETAE_SHAKE256_RATE];

    crypto_sha3_context context;

    crypto_haetae_shake256_stream_init(&context, seed, nonce);
    crypto_haetae_shake256_squeeze_blocks(&context, buf, POLY_UNIFORM_ETA_NBLOCKS);

    ctr = crypto_haetae_rej_eta(a->coeffs, CRYPTO_HAETAE_N, buf, buflen);

    while (ctr < CRYPTO_HAETAE_N) {
        crypto_haetae_shake256_squeeze_blocks(&context, buf, 1);
        ctr += crypto_haetae_rej_eta(a->coeffs + ctr, CRYPTO_HAETAE_N - ctr, buf, CRYPTO_HAETAE_SHAKE256_RATE);
    }

    crypto_sha3_clear(&context);
}

uint8_t  crypto_haetae_hammingWeight_8(uint8_t  x) {
    x = (x & 0x55) + (x >> 1 & 0x55);
    x = (x & 0x33) + (x >> 2 & 0x33);
    x = (x & 0x0F) + (x >> 4 & 0x0F);

    return x;
}

/*************************************************
 * Name:        poly_challenge
 *
 * Description: Implementation of challenge. Samples polynomial with TAU 1
 *              coefficients using the output stream of crypto_shake256(seed).
 *
 * Arguments:   - crypto_haetae_poly *c: pointer to output polynomial
 *              - const uint8_t  highbits_lsb[]: packed highbits and lsb
 *              - const uint8_t  mu[]: hash of pk and message
 **************************************************/
void crypto_haetae_poly_challenge(crypto_haetae_poly *c,
                           const uint8_t  highbits_lsb[CRYPTO_HAETAE_MAX_HIGH_BITS_BUFFER_BYTES + CRYPTO_HAETAE_POLY_CHALLENGE_PACKED_BYTES],
                           const uint8_t  mu[CRYPTO_HAETAE_SEED_BYTES],
                           const crypto_haetae_parameters *parameters) {

    crypto_sha3_context context;

    // H(HighBits(A * y mod 2q), LSB(round(y0) * j), M)
    crypto_shake256_init(&context);
    crypto_sha3_update(&context, highbits_lsb, (size_t)parameters->polyveck_high_bits_packed_bytes + CRYPTO_HAETAE_POLY_CHALLENGE_PACKED_BYTES);
    crypto_sha3_update(&context, mu, CRYPTO_HAETAE_SEED_BYTES);
    crypto_sha3_finalize(&context);

    switch (parameters->mode) {

        case 2:
        case 3:
        {
            unsigned int i, b, pos = 0;
            uint8_t buf[CRYPTO_HAETAE_SHAKE256_RATE];

            // init challenge c
            for (i = 0; i < CRYPTO_HAETAE_N; ++i)
                c->coeffs[i] = 0;

            crypto_haetae_shake256_squeeze_blocks(&context, buf, 1);

            for (i = CRYPTO_HAETAE_N - parameters->tau; i < CRYPTO_HAETAE_N; ++i) {
                do {
                    if (pos >= CRYPTO_HAETAE_SHAKE256_RATE) {
                        crypto_haetae_shake256_squeeze_blocks(&context, buf, 1);
                        pos = 0;
                    }

                    b = (unsigned int)(uint8_t)buf[pos++];
                } while (b > i);

                c->coeffs[i] = c->coeffs[b];
                c->coeffs[b] = 1;
            }
        } break;

        case 5:
        {
            unsigned int i, hwt = 0, cond = 0;
            uint8_t  mask = 0, w0 = 0;
            uint8_t buf[32] = {0};

            crypto_sha3_squeeze(&context, buf, 32);

            for (i = 0; i < 32; ++i)
                hwt += crypto_haetae_hammingWeight_8(buf[i]);

            cond = (128 - hwt);
            mask = 0xff & (cond >> 8);
            w0 = -(buf[0] & 1);
            mask = w0 ^ ((-(!!cond & 1)) & (mask ^ w0)); // mask = !!cond ? mask : w0
            for (i = 0; i < 32; ++i) {
                buf[i] ^= mask;
                c->coeffs[8 * i] = buf[i] & 1;
                c->coeffs[8 * i + 1] = (buf[i] >> 1) & 1;
                c->coeffs[8 * i + 2] = (buf[i] >> 2) & 1;
                c->coeffs[8 * i + 3] = (buf[i] >> 3) & 1;
                c->coeffs[8 * i + 4] = (buf[i] >> 4) & 1;
                c->coeffs[8 * i + 5] = (buf[i] >> 5) & 1;
                c->coeffs[8 * i + 6] = (buf[i] >> 6) & 1;
                c->coeffs[8 * i + 7] = (buf[i] >> 7) & 1;

            }
        } break;

        default:
            memset(c, 0, sizeof(*c));
            break;
    }
    crypto_sha3_clear(&context);
}

void crypto_haetae_poly_decomposed_pack(uint8_t  *buf, const crypto_haetae_poly *a) {
    unsigned int i;
    for (i = 0; i < CRYPTO_HAETAE_N; i++) {
        buf[i] = a->coeffs[i];
    }
}

//The type "char" is "unsigned char" by default in AIX-Power. If you need "signed char", use "signed char" instead of "char".
void crypto_haetae_poly_decomposed_unpack(crypto_haetae_poly *a, const uint8_t  *buf) {
    unsigned int i;
    for (i = 0; i < CRYPTO_HAETAE_N; i++) {
        a->coeffs[i] = (signed char)buf[i];
    }
}

void crypto_haetae_poly_pack_highbits(uint8_t *buf, const crypto_haetae_poly *a, const crypto_haetae_parameters *parameters) {
  unsigned int i;
  switch(parameters->mode) {
    case 2:
    case 3:
    {
        for (i = 0; i < CRYPTO_HAETAE_N; i++) {
        // if ((uint32_t)a->coeffs[i] > 0xFF) {
        // }
        buf[i] = (uint8_t)a->coeffs[i];
        }
    } break;
    case 5:
    {
        for (i = 0; i < CRYPTO_HAETAE_N / 8; i++) {
            buf[9 * i + 0] = a->coeffs[8 * i + 0] & 0xff;

            buf[9 * i + 1] = (a->coeffs[8 * i + 0] >> 8) & 0x01;
            buf[9 * i + 1] |= (a->coeffs[8 * i + 1] << 1) & 0xff;

            buf[9 * i + 2] = (a->coeffs[8 * i + 1] >> 7) & 0x03;
            buf[9 * i + 2] |= (a->coeffs[8 * i + 2] << 2) & 0xff;

            buf[9 * i + 3] = (a->coeffs[8 * i + 2] >> 6) & 0x07;
            buf[9 * i + 3] |= (a->coeffs[8 * i + 3] << 3) & 0xff;

            buf[9 * i + 4] = (a->coeffs[8 * i + 3] >> 5) & 0x0f;
            buf[9 * i + 4] |= (a->coeffs[8 * i + 4] << 4) & 0xff;

            buf[9 * i + 5] = (a->coeffs[8 * i + 4] >> 4) & 0x1f;
            buf[9 * i + 5] |= (a->coeffs[8 * i + 5] << 5) & 0xff;

            buf[9 * i + 6] = (a->coeffs[8 * i + 5] >> 3) & 0x3f;
            buf[9 * i + 6] |= (a->coeffs[8 * i + 6] << 6) & 0xff;

            buf[9 * i + 7] = (a->coeffs[8 * i + 6] >> 2) & 0x7f;
            buf[9 * i + 7] |= (a->coeffs[8 * i + 7] << 7) & 0xff;

            buf[9 * i + 8] = (a->coeffs[8 * i + 7] >> 1) & 0xff;
        }
    } break;
  }
}

void crypto_haetae_poly_pack_lsb(uint8_t  *buf, const crypto_haetae_poly *a) {
    unsigned int i;
    for (i = 0; i < CRYPTO_HAETAE_N; i++) {
        if ((i % 8) == 0) {
            buf[i / 8] = 0;
        }
        buf[i / 8] |= (a->coeffs[i] & 1) << (i % 8);
    }
}

/*************************************************
 * Name:        crypto_haetae_polyq_pack
 *
 * Description: Bit-pack polynomial with coefficients in [0, Q - 1].
 *
 * Arguments:   - uint8_t  *r: pointer to output byte array with at least
 *                            POLYQ_PACKEDBYTES bytes
 *              - const crypto_haetae_poly *a: pointer to input polynomial
 **************************************************/
void crypto_haetae_polyq_pack(uint8_t  *r, const crypto_haetae_poly *a, const crypto_haetae_parameters *parameters) {
    unsigned int i;

    if(parameters->d == 1) { // mode == 2 || mode == 3
        int b_idx = 0, d_idx = 0;

        for (i = 0; i < (CRYPTO_HAETAE_N >> 3); ++i) {
            b_idx = 15 * i;
            d_idx = 8 * i;

            r[b_idx] = (a->coeffs[d_idx] & 0xff);
            r[b_idx + 1] = ((a->coeffs[d_idx] >> 8) & 0x7f) |
                        ((a->coeffs[d_idx + 1] & 0x1) << 7);
            r[b_idx + 2] = ((a->coeffs[d_idx + 1] >> 1) & 0xff);
            r[b_idx + 3] = ((a->coeffs[d_idx + 1] >> 9) & 0x3f) |
                        ((a->coeffs[d_idx + 2] & 0x3) << 6);
            r[b_idx + 4] = ((a->coeffs[d_idx + 2] >> 2) & 0xff);
            r[b_idx + 5] = ((a->coeffs[d_idx + 2] >> 10) & 0x1f) |
                        ((a->coeffs[d_idx + 3] & 0x7) << 5);
            r[b_idx + 6] = ((a->coeffs[d_idx + 3] >> 3) & 0xff);
            r[b_idx + 7] = ((a->coeffs[d_idx + 3] >> 11) & 0xf) |
                        ((a->coeffs[d_idx + 4] & 0xf) << 4);
            r[b_idx + 8] = ((a->coeffs[d_idx + 4] >> 4) & 0xff);
            r[b_idx + 9] = ((a->coeffs[d_idx + 4] >> 12) & 0x7) |
                        ((a->coeffs[d_idx + 5] & 0x1f) << 3);
            r[b_idx + 10] = ((a->coeffs[d_idx + 5] >> 5) & 0xff);
            r[b_idx + 11] = ((a->coeffs[d_idx + 5] >> 13) & 0x3) |
                            ((a->coeffs[d_idx + 6] & 0x3f) << 2);
            r[b_idx + 12] = ((a->coeffs[d_idx + 6] >> 6) & 0xff);
            r[b_idx + 13] = ((a->coeffs[d_idx + 6] >> 14) & 0x1) |
                            (a->coeffs[d_idx + 7] & 0x7f) << 1;
            r[b_idx + 14] = ((a->coeffs[d_idx + 7] >> 7) & 0xff);
        }
    }

    else { // mode == 5
        for (i = 0; i < CRYPTO_HAETAE_N / 1; ++i) {
            crypto_store16_le(
                r + 2u * i, (uint16_t)a->coeffs[i]);
        }
    }
}

/*************************************************
 * Name:        crypto_haetae_polyq_unpack
 *
 * Description: Unpack polynomial with coefficients in [0, Q - 1].
 *
 * Arguments:   - crypto_haetae_poly *r: pointer to output polynomial
 *              - const uint8_t  *a: byte array with bit-packed polynomial
 **************************************************/
void crypto_haetae_polyq_unpack(crypto_haetae_poly *r, const uint8_t  *a, const crypto_haetae_parameters *parameters) {
    unsigned int i;

    if(parameters->d == 1) { // mode == 2 || mode == 3
        int b_idx = 0, d_idx = 0;

        for (i = 0; i < (CRYPTO_HAETAE_N >> 3); ++i) {
            b_idx = 15 * i;
            d_idx = 8 * i;

            r->coeffs[d_idx] = (a[b_idx] & 0xff) | ((a[b_idx + 1] & 0x7f) << 8);
            r->coeffs[d_idx + 1] = ((a[b_idx + 1] >> 7) & 0x1) |
                                ((a[b_idx + 2] & 0xff) << 1) |
                                ((a[b_idx + 3] & 0x3f) << 9);
            r->coeffs[d_idx + 2] = ((a[b_idx + 3] >> 6) & 0x3) |
                                ((a[b_idx + 4] & 0xff) << 2) |
                                ((a[b_idx + 5] & 0x1f) << 10);
            r->coeffs[d_idx + 3] = ((a[b_idx + 5] >> 5) & 0x7) |
                                ((a[b_idx + 6] & 0xff) << 3) |
                                ((a[b_idx + 7] & 0xf) << 11);
            r->coeffs[d_idx + 4] = ((a[b_idx + 7] >> 4) & 0xf) |
                                ((a[b_idx + 8] & 0xff) << 4) |
                                ((a[b_idx + 9] & 0x7) << 12);
            r->coeffs[d_idx + 5] = ((a[b_idx + 9] >> 3) & 0x1f) |
                                ((a[b_idx + 10] & 0xff) << 5) |
                                ((a[b_idx + 11] & 0x3) << 13);
            r->coeffs[d_idx + 6] = ((a[b_idx + 11] >> 2) & 0x3f) |
                                ((a[b_idx + 12] & 0xff) << 6) |
                                ((a[b_idx + 13] & 0x1) << 14);
            r->coeffs[d_idx + 7] =
                ((a[b_idx + 13] >> 1) & 0x7f) | ((a[b_idx + 14] & 0xff) << 7);
        }
    }
    else { // mode == 5
        for (i = 0; i < CRYPTO_HAETAE_N / 1; ++i) {
            r->coeffs[i] = crypto_load16_le(a + 2u * i);
        }
    }
}

/*************************************************
 * Name:        polyeta_pack
 *
 * Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - uint8_t  *r: pointer to output byte array with at least
 *                            POLYETA_PACKEDBYTES bytes
 *              - const crypto_haetae_poly *a: pointer to input polynomial
 **************************************************/
void crypto_haetae_polyeta_pack(uint8_t  *r, const crypto_haetae_poly *a) {
    unsigned int i;
    uint8_t  t[8];

#if CRYPTO_HAETAE_ETA == 1
    for (i = 0; i < CRYPTO_HAETAE_N / 4; ++i) {
        t[0] = CRYPTO_HAETAE_ETA - a->coeffs[4 * i + 0];
        t[1] = CRYPTO_HAETAE_ETA - a->coeffs[4 * i + 1];
        t[2] = CRYPTO_HAETAE_ETA - a->coeffs[4 * i + 2];
        t[3] = CRYPTO_HAETAE_ETA - a->coeffs[4 * i + 3];
        r[i] = t[0] >> 0;
        r[i] |= t[1] << 2;
        r[i] |= t[2] << 4;
        r[i] |= t[3] << 6;
    }
#elif CRYPTO_HAETAE_ETA == 2
    for (i = 0; i < CRYPTO_HAETAE_N / 8; ++i) {
        t[0] = CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 0];
        t[1] = CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 1];
        t[2] = CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 2];
        t[3] = CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 3];
        t[4] = CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 4];
        t[5] = CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 5];
        t[6] = CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 6];
        t[7] = CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 7];

        r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
        r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
#endif
}

/*************************************************
 * Name:        polyeta_unpack
 *
 * Description: Unpack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - crypto_haetae_poly *r: pointer to output polynomial
 *              - const uint8_t  *a: byte array with bit-packed polynomial
 **************************************************/
void crypto_haetae_polyeta_unpack(crypto_haetae_poly *r, const uint8_t  *a) {
    unsigned int i;

#if CRYPTO_HAETAE_ETA == 1
    for (i = 0; i < CRYPTO_HAETAE_N / 4; ++i) {
        r->coeffs[4 * i + 0] = a[i] >> 0;
        r->coeffs[4 * i + 0] &= 0x3;

        r->coeffs[4 * i + 1] = a[i] >> 2;
        r->coeffs[4 * i + 1] &= 0x3;

        r->coeffs[4 * i + 2] = a[i] >> 4;
        r->coeffs[4 * i + 2] &= 0x3;

        r->coeffs[4 * i + 3] = a[i] >> 6;
        r->coeffs[4 * i + 3] &= 0x3;

        r->coeffs[4 * i + 0] = CRYPTO_HAETAE_ETA - r->coeffs[4 * i + 0];
        r->coeffs[4 * i + 1] = CRYPTO_HAETAE_ETA - r->coeffs[4 * i + 1];
        r->coeffs[4 * i + 2] = CRYPTO_HAETAE_ETA - r->coeffs[4 * i + 2];
        r->coeffs[4 * i + 3] = CRYPTO_HAETAE_ETA - r->coeffs[4 * i + 3];
    }

#elif CRYPTO_HAETAE_ETA == 2
    for (i = 0; i < CRYPTO_HAETAE_N / 8; ++i) {
        r->coeffs[8 * i + 0] = (a[3 * i + 0] >> 0) & 7;
        r->coeffs[8 * i + 1] = (a[3 * i + 0] >> 3) & 7;
        r->coeffs[8 * i + 2] = ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7;
        r->coeffs[8 * i + 3] = (a[3 * i + 1] >> 1) & 7;
        r->coeffs[8 * i + 4] = (a[3 * i + 1] >> 4) & 7;
        r->coeffs[8 * i + 5] = ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7;
        r->coeffs[8 * i + 6] = (a[3 * i + 2] >> 2) & 7;
        r->coeffs[8 * i + 7] = (a[3 * i + 2] >> 5) & 7;

        r->coeffs[8 * i + 0] = CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 0];
        r->coeffs[8 * i + 1] = CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 1];
        r->coeffs[8 * i + 2] = CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 2];
        r->coeffs[8 * i + 3] = CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 3];
        r->coeffs[8 * i + 4] = CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 4];
        r->coeffs[8 * i + 5] = CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 5];
        r->coeffs[8 * i + 6] = CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 6];
        r->coeffs[8 * i + 7] = CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 7];
    }
#endif
}

/*************************************************
 * Name:        crypto_haetae_poly2eta_pack
 *
 * Description: Bit-pack polynomial with coefficients in [-ETA-1,ETA+1].
 *
 * Arguments:   - uint8_t  *r: pointer to output byte array with at least
 *                            POLYETA_PACKEDBYTES bytes
 *              - const crypto_haetae_poly *a: pointer to input polynomial
 **************************************************/
void crypto_haetae_poly2eta_pack(uint8_t  *r, const crypto_haetae_poly *a) {
    unsigned int i;
    uint8_t  t[8];

#if CRYPTO_HAETAE_ETA == 1
    for (i = 0; i < CRYPTO_HAETAE_N / 8; ++i) {
        t[0] = 2 * CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 0];
        t[1] = 2 * CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 1];
        t[2] = 2 * CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 2];
        t[3] = 2 * CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 3];
        t[4] = 2 * CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 4];
        t[5] = 2 * CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 5];
        t[6] = 2 * CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 6];
        t[7] = 2 * CRYPTO_HAETAE_ETA - a->coeffs[8 * i + 7];

        r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
        r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
#elif CRYPTO_HAETAE_ETA == 2
#error "not yet implemented"
#endif
}

/*************************************************
 * Name:        crypto_haetae_poly2eta_unpack
 *
 * Description: Unpack polynomial with coefficients in [-ETA-1,ETA+1].
 *
 * Arguments:   - crypto_haetae_poly *r: pointer to output polynomial
 *              - const uint8_t  *a: byte array with bit-packed polynomial
 **************************************************/
void crypto_haetae_poly2eta_unpack(crypto_haetae_poly *r, const uint8_t  *a) {
    unsigned int i;

#if CRYPTO_HAETAE_ETA == 1
    for (i = 0; i < CRYPTO_HAETAE_N / 8; ++i) {
        r->coeffs[8 * i + 0] = (a[3 * i + 0] >> 0) & 7;
        r->coeffs[8 * i + 1] = (a[3 * i + 0] >> 3) & 7;
        r->coeffs[8 * i + 2] = ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7;
        r->coeffs[8 * i + 3] = (a[3 * i + 1] >> 1) & 7;
        r->coeffs[8 * i + 4] = (a[3 * i + 1] >> 4) & 7;
        r->coeffs[8 * i + 5] = ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7;
        r->coeffs[8 * i + 6] = (a[3 * i + 2] >> 2) & 7;
        r->coeffs[8 * i + 7] = (a[3 * i + 2] >> 5) & 7;

        r->coeffs[8 * i + 0] = 2 * CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 0];
        r->coeffs[8 * i + 1] = 2 * CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 1];
        r->coeffs[8 * i + 2] = 2 * CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 2];
        r->coeffs[8 * i + 3] = 2 * CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 3];
        r->coeffs[8 * i + 4] = 2 * CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 4];
        r->coeffs[8 * i + 5] = 2 * CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 5];
        r->coeffs[8 * i + 6] = 2 * CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 6];
        r->coeffs[8 * i + 7] = 2 * CRYPTO_HAETAE_ETA - r->coeffs[8 * i + 7];
    }
#elif CRYPTO_HAETAE_ETA == 2
#error "not yet implemented"
#endif
}

void crypto_haetae_poly_fromcrt(crypto_haetae_poly *w, const crypto_haetae_poly *u, const crypto_haetae_poly *v) {
    unsigned int i;
    int xq, x2;

    for (i = 0; i < CRYPTO_HAETAE_N; i++) {
        xq = u->coeffs[i];
        x2 = v->coeffs[i];
        w->coeffs[i] = xq + (CRYPTO_HAETAE_Q & -((xq ^ x2) & 1));
    }
}

void crypto_haetae_poly_fromcrt0(crypto_haetae_poly *w, const crypto_haetae_poly *u) {
    unsigned int i;
    int xq;

    for (i = 0; i < CRYPTO_HAETAE_N; i++) {
        xq = u->coeffs[i];
        w->coeffs[i] = xq + (CRYPTO_HAETAE_Q & -(xq & 1));
    }
}

void crypto_haetae_poly_ntt(crypto_haetae_poly *a) {
    crypto_haetae_ntt(&a->coeffs[0]);
}

void crypto_haetae_poly_invntt_tomont(crypto_haetae_poly *a) {
    crypto_haetae_invntt_tomont(&a->coeffs[0]);
}
