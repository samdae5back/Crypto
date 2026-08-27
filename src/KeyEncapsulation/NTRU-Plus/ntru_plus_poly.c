/*
 * Runtime-parameter NTRU+ polynomial operations.
 * Derived from the NTRU+ reference implementation.
 * SPDX-License-Identifier: MIT
 */
#include "ntru_plus_poly.h"
#include "ntru_plus_ntt.h"
#include "Util/Bit/bit_internal.h"
#include "Util/Core/secure_zero.h"

/*************************************************
* Name:        crepmod3
*
* Description: Compute modulus 3 operation
*
* Arguments: - int16_t a: input integer to be reduced
*
* Returns:     integer in {-1,0,1} congruent to a modulo 3.
**************************************************/
static inline int16_t crepmod3(int16_t a)
{
    int16_t t;
    const int16_t v = ((1 << 15) + 3 / 2) / 3;

    a = (int16_t)(a +
        (crypto_floor_div_pow2_i32(a, 15u) & CRYPTO_NTRU_PLUS_Q));
    a -= (CRYPTO_NTRU_PLUS_Q + 1) / 2;
    a = (int16_t)(a +
        (crypto_floor_div_pow2_i32(a, 15u) & CRYPTO_NTRU_PLUS_Q));
    a -= (CRYPTO_NTRU_PLUS_Q - 1) / 2;

    t = (int16_t)crypto_floor_div_pow2_i32(
        (int32_t)v * a + (INT32_C(1) << 14), 15u);
    t *= 3;
    return a - t;
}

/*************************************************
* Name:        poly_tobytes
*
* Description: Serialization of a polynomial
*
* Arguments:   - uint8_t *r:               pointer to output byte array
*              - const crypto_ntru_plus_poly *a:            pointer to input polynomial
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
**************************************************/
void crypto_ntru_plus_poly_tobytes(uint8_t *r, const crypto_ntru_plus_poly *a, const crypto_ntru_plus_parameters *alg)
{
    int16_t t[2];
    size_t i;

    for (i = 0; i < alg->n / 2; i++) {
        t[0] = a->coeffs[2*i];
        t[0] = (int16_t)(t[0] +
            (crypto_floor_div_pow2_i32(t[0], 15u) &
             CRYPTO_NTRU_PLUS_Q));
        t[1] = a->coeffs[2*i+1];
        t[1] = (int16_t)(t[1] +
            (crypto_floor_div_pow2_i32(t[1], 15u) &
             CRYPTO_NTRU_PLUS_Q));

        r[3*i+0] = (uint8_t)(t[0] >> 0);
        r[3*i+1] = (uint8_t)((t[0] >> 8) | (t[1] << 4));
        r[3*i+2] = (uint8_t)(t[1] >> 4);
    }
}

/*************************************************
* Name:        poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of poly_tobytes
*
* Arguments:   - crypto_ntru_plus_poly *r:                  pointer to output polynomial
*              - const uint8_t *a:         pointer to input byte array
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
**************************************************/
int crypto_ntru_plus_poly_frombytes(crypto_ntru_plus_poly *r, const uint8_t *a, const crypto_ntru_plus_parameters *alg)
{
    uint32_t fail = 0u;
    size_t i;

    for (i = 0; i < alg->n / 2; i++) {
        uint16_t first = (uint16_t)(((uint16_t)a[3*i] |
            ((uint16_t)a[3*i+1] << 8)) & 0x0fffu);
        uint16_t second = (uint16_t)(((uint16_t)a[3*i+1] >> 4) |
            ((uint16_t)a[3*i+2] << 4));

        r->coeffs[2*i] = (int16_t)first;
        r->coeffs[2*i+1] = (int16_t)second;
        fail |= (uint32_t)(CRYPTO_NTRU_PLUS_Q - 1) - first;
        fail |= (uint32_t)(CRYPTO_NTRU_PLUS_Q - 1) - second;
    }

    return (int)(fail >> 31);
}

/*************************************************
* Name:        poly_cbd1
*
* Description: Sample a polynomial deterministically from a random byte
*              stream, with output close to a centered binomial distribution.
*
* Arguments:   - crypto_ntru_plus_poly *r:                  pointer to output polynomial
*              - const uint8_t *buf:       pointer to input random
*                                          (of length alg->n/4 bytes)
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
**************************************************/
void crypto_ntru_plus_poly_cbd1(crypto_ntru_plus_poly *r, const uint8_t *buf, const crypto_ntru_plus_parameters *alg)
{
    uint8_t t1, t2;
    size_t i, j;

    for (i = 0; i < alg->n / 8; i++) {
        t1 = buf[i];
        t2 = buf[i + alg->n / 8];

        for (j = 0; j < 8; j++) {
            r->coeffs[8*i + j] = (int16_t)((t1 & 0x1) - (t2 & 0x1));
            t1 >>= 1;
            t2 >>= 1;
        }
    }
}

/*************************************************
* Name:        poly_sotp_encode
*
* Description: Encode a message deterministically using SOTP.
*
* Arguments:   - crypto_ntru_plus_poly *r:                  pointer to output polynomial
*              - const uint8_t *msg:       pointer to input message
*              - const uint8_t *buf:       pointer to input random
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
**************************************************/
void crypto_ntru_plus_poly_sotp_encode(crypto_ntru_plus_poly *r, const uint8_t *msg, const uint8_t *buf,
                      const crypto_ntru_plus_parameters *alg)
{
    uint8_t tmp[CRYPTO_NTRU_PLUS_MAX_N / 4];
    size_t i;

    for (i = 0; i < alg->n / 8; i++)
        tmp[i] = buf[i] ^ msg[i];

    for (i = alg->n / 8; i < alg->n / 4; i++)
        tmp[i] = buf[i];

    crypto_ntru_plus_poly_cbd1(r, tmp, alg);
    crypto_zeroize(tmp, sizeof(tmp));
}

/*************************************************
* Name:        poly_sotp_decode
*
* Description: Decode a message deterministically using SOTP_INV.
*
* Arguments:   - uint8_t *msg:             pointer to output message
*              - const crypto_ntru_plus_poly *a:            pointer to input polynomial
*              - const uint8_t *buf:       pointer to input random
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
*
* Returns 0 (success) or 1 (failure).
**************************************************/
int crypto_ntru_plus_poly_sotp_decode(uint8_t *msg, const crypto_ntru_plus_poly *a, const uint8_t *buf,
                     const crypto_ntru_plus_parameters *alg)
{
    uint8_t t1, t2, t3;
    uint16_t t4;
    uint32_t result = 0;
    uint8_t mask;
    size_t i, j;

    for (i = 0; i < alg->n / 8; i++) {
        t1 = buf[i];
        t2 = buf[i + alg->n / 8];
        t3 = 0;

        for (j = 0; j < 8; j++) {
            t4 = t2 & 0x1;
            t4 = (uint16_t)(t4 + a->coeffs[8*i + j]);
            result |= t4;
            t4 = (uint16_t)((t4 ^ t1) & 0x1);
            t3 ^= (uint8_t)(t4 << j);

            t1 >>= 1;
            t2 >>= 1;
        }

        msg[i] = t3;
    }

    result = result >> 1;
    result = (UINT32_C(0) - result) >> 31;

    mask = (uint8_t)(result - 1);

    for (i = 0; i < alg->n / 8; i++)
        msg[i] &= mask;

    return (int)result;
}

/*************************************************
* Name:        poly_ntt
*
* Description: Computes number-theoretic transform (NTT)
*
* Arguments:   - crypto_ntru_plus_poly *r:                  pointer to output polynomial
*              - const crypto_ntru_plus_poly *a:            pointer to input polynomial
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
**************************************************/
void crypto_ntru_plus_poly_ntt(crypto_ntru_plus_poly *r, const crypto_ntru_plus_poly *a, const crypto_ntru_plus_parameters *alg)
{
    crypto_ntru_plus_ntt(r->coeffs, a->coeffs, alg);
}

/*************************************************
* Name:        poly_invntt
*
* Description: Computes inverse of number-theoretic transform (NTT)
*
* Arguments:   - crypto_ntru_plus_poly *r:                  pointer to output polynomial
*              - const crypto_ntru_plus_poly *a:            pointer to input polynomial
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
**************************************************/
void crypto_ntru_plus_poly_invntt(crypto_ntru_plus_poly *r, const crypto_ntru_plus_poly *a, const crypto_ntru_plus_parameters *alg)
{
    crypto_ntru_plus_invntt(r->coeffs, a->coeffs, alg);
}

/*************************************************
* Name:        poly_baseinv
*
* Description: Inversion of polynomial in NTT domain
*
* Arguments:   - crypto_ntru_plus_poly *r:                  pointer to output polynomial
*              - const crypto_ntru_plus_poly *a:            pointer to input polynomial
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
*
* Returns:     0 on success, 1 on failure (polynomial not invertible).
**************************************************/
int crypto_ntru_plus_poly_baseinv(crypto_ntru_plus_poly *r, const crypto_ntru_plus_poly *a, const crypto_ntru_plus_parameters *alg)
{
    size_t i, j;
    size_t zeta_offset =
        (alg->n == CRYPTO_NTRU_PLUS_768_N) ? 96u : 144u;

    if (alg->n == CRYPTO_NTRU_PLUS_864_N) {
        const int16_t *zetas = crypto_ntru_plus_zetas_864;

        for (i = 0; i < alg->n / 6; i++) {
            if (crypto_ntru_plus_baseinv3(r->coeffs + 6*i, a->coeffs + 6*i,
                         zetas[zeta_offset + i])) {
                for (j = 0; j < alg->n; j++)
                    r->coeffs[j] = 0;
                return 1;
            }
            if (crypto_ntru_plus_baseinv3(r->coeffs + 6*i + 3, a->coeffs + 6*i + 3,
                         -zetas[zeta_offset + i])) {
                for (j = 0; j < alg->n; j++)
                    r->coeffs[j] = 0;
                return 1;
            }
        }
    } else {
        const int16_t *zetas = (alg->n == CRYPTO_NTRU_PLUS_768_N)
                               ? crypto_ntru_plus_zetas_768
                               : crypto_ntru_plus_zetas_1152;

        for (i = 0; i < alg->n / 8; i++) {
            if (crypto_ntru_plus_baseinv4(r->coeffs + 8*i, a->coeffs + 8*i,
                         zetas[zeta_offset + i])) {
                for (j = 0; j < alg->n; j++)
                    r->coeffs[j] = 0;
                return 1;
            }
            if (crypto_ntru_plus_baseinv4(r->coeffs + 8*i + 4, a->coeffs + 8*i + 4,
                         -zetas[zeta_offset + i])) {
                for (j = 0; j < alg->n; j++)
                    r->coeffs[j] = 0;
                return 1;
            }
        }
    }

    return 0;
}

/*************************************************
* Name:        poly_basemul
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - crypto_ntru_plus_poly *r:                  pointer to output polynomial
*              - const crypto_ntru_plus_poly *a:            pointer to first input polynomial
*              - const crypto_ntru_plus_poly *b:            pointer to second input polynomial
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
**************************************************/
void crypto_ntru_plus_poly_basemul(crypto_ntru_plus_poly *r, const crypto_ntru_plus_poly *a, const crypto_ntru_plus_poly *b,
                  const crypto_ntru_plus_parameters *alg)
{
    size_t i;
    size_t zeta_offset =
        (alg->n == CRYPTO_NTRU_PLUS_768_N) ? 96u : 144u;

    if (alg->n == CRYPTO_NTRU_PLUS_864_N) {
        const int16_t *zetas = crypto_ntru_plus_zetas_864;

        for (i = 0; i < alg->n / 6; i++) {
            crypto_ntru_plus_basemul3(r->coeffs + 6*i,
                     a->coeffs + 6*i,
                     b->coeffs + 6*i,
                     zetas[zeta_offset + i]);
            crypto_ntru_plus_basemul3(r->coeffs + 6*i + 3,
                     a->coeffs + 6*i + 3,
                     b->coeffs + 6*i + 3,
                     -zetas[zeta_offset + i]);
        }
    } else {
        const int16_t *zetas = (alg->n == CRYPTO_NTRU_PLUS_768_N)
                               ? crypto_ntru_plus_zetas_768
                               : crypto_ntru_plus_zetas_1152;

        for (i = 0; i < alg->n / 8; i++) {
            crypto_ntru_plus_basemul4(r->coeffs + 8*i,
                     a->coeffs + 8*i,
                     b->coeffs + 8*i,
                     zetas[zeta_offset + i]);
            crypto_ntru_plus_basemul4(r->coeffs + 8*i + 4,
                     a->coeffs + 8*i + 4,
                     b->coeffs + 8*i + 4,
                     -zetas[zeta_offset + i]);
        }
    }
}

/*************************************************
* Name:        poly_basemul_add
*
* Description: Multiplication then addition of three polynomials in NTT domain
*
* Arguments:   - crypto_ntru_plus_poly *r:                  pointer to output polynomial
*              - const crypto_ntru_plus_poly *a:            pointer to first input polynomial
*              - const crypto_ntru_plus_poly *b:            pointer to second input polynomial
*              - const crypto_ntru_plus_poly *c:            pointer to third input polynomial
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
**************************************************/
void crypto_ntru_plus_poly_basemul_add(crypto_ntru_plus_poly *r, const crypto_ntru_plus_poly *a, const crypto_ntru_plus_poly *b, const crypto_ntru_plus_poly *c,
                      const crypto_ntru_plus_parameters *alg)
{
    size_t i;
    size_t zeta_offset =
        (alg->n == CRYPTO_NTRU_PLUS_768_N) ? 96u : 144u;

    if (alg->n == CRYPTO_NTRU_PLUS_864_N) {
        const int16_t *zetas = crypto_ntru_plus_zetas_864;

        for (i = 0; i < alg->n / 6; i++) {
            crypto_ntru_plus_basemul_add3(r->coeffs + 6*i,
                         a->coeffs + 6*i,
                         b->coeffs + 6*i,
                         c->coeffs + 6*i,
                         zetas[zeta_offset + i]);
            crypto_ntru_plus_basemul_add3(r->coeffs + 6*i + 3,
                         a->coeffs + 6*i + 3,
                         b->coeffs + 6*i + 3,
                         c->coeffs + 6*i + 3,
                         -zetas[zeta_offset + i]);
        }
    } else {
        const int16_t *zetas = (alg->n == CRYPTO_NTRU_PLUS_768_N)
                               ? crypto_ntru_plus_zetas_768
                               : crypto_ntru_plus_zetas_1152;

        for (i = 0; i < alg->n / 8; i++) {
            crypto_ntru_plus_basemul_add4(r->coeffs + 8*i,
                         a->coeffs + 8*i,
                         b->coeffs + 8*i,
                         c->coeffs + 8*i,
                         zetas[zeta_offset + i]);
            crypto_ntru_plus_basemul_add4(r->coeffs + 8*i + 4,
                         a->coeffs + 8*i + 4,
                         b->coeffs + 8*i + 4,
                         c->coeffs + 8*i + 4,
                         -zetas[zeta_offset + i]);
        }
    }
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract two polynomials; no modular reduction is performed
*
* Arguments:   - crypto_ntru_plus_poly *r:                  pointer to output polynomial
*              - const crypto_ntru_plus_poly *a:            pointer to first input polynomial
*              - const crypto_ntru_plus_poly *b:            pointer to second input polynomial
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
**************************************************/
void crypto_ntru_plus_poly_sub(crypto_ntru_plus_poly *r, const crypto_ntru_plus_poly *a, const crypto_ntru_plus_poly *b, const crypto_ntru_plus_parameters *alg)
{
    size_t i;

    for (i = 0; i < alg->n; i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/*************************************************
* Name:        poly_triple
*
* Description: Multiply polynomial by 3; no modular reduction is performed
*
* Arguments:   - crypto_ntru_plus_poly *r:                  pointer to output polynomial
*              - const crypto_ntru_plus_poly *a:            pointer to input polynomial
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
**************************************************/
void crypto_ntru_plus_poly_triple(crypto_ntru_plus_poly *r, const crypto_ntru_plus_poly *a, const crypto_ntru_plus_parameters *alg)
{
    size_t i;

    for (i = 0; i < alg->n; i++)
        r->coeffs[i] = (int16_t)(3 * a->coeffs[i]);
}

/*************************************************
* Name:        poly_crepmod3
*
* Description: Compute modulus 3 operation on all coefficients
*
* Arguments:   - crypto_ntru_plus_poly *r:                  pointer to output polynomial
*              - const crypto_ntru_plus_poly *a:            pointer to input polynomial
*              - const crypto_ntru_plus_parameters *alg: algorithm parameters
**************************************************/
void crypto_ntru_plus_poly_crepmod3(crypto_ntru_plus_poly *r, const crypto_ntru_plus_poly *a, const crypto_ntru_plus_parameters *alg)
{
    size_t i;

    for (i = 0; i < alg->n; i++)
        r->coeffs[i] = crepmod3(a->coeffs[i]);
}
