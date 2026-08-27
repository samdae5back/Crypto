// SPDX-License-Identifier: MIT

#include "haetae_symmetric.h"
#include "Util/Bit/bit_internal.h"

#include "haetae_fixpoint.h"
#include "haetae_sampler.h"
#include "haetae_polyfix.h"

#define SAMPLES_MAX \
    (CRYPTO_HAETAE_N * (CRYPTO_HAETAE_MAX_L + CRYPTO_HAETAE_MAX_K))
#define SIGNS_MAX (SAMPLES_MAX >> 3)

/*************************************************
 * Name:        crypto_haetae_polyfix_add
 *
 * Description: Add double polynomial and integer polynomial.
 *              No modular reduction is performed.
 *
 * Arguments:   - crypto_haetae_polyfix *c: pointer to output double polynomial
 *              - const crypto_haetae_polyfix *a: pointer to first summand
 *              - const crypto_haetae_poly*b: pointer to second summand
 **************************************************/
void crypto_haetae_polyfix_add(crypto_haetae_polyfix *c, const crypto_haetae_polyfix *a, const crypto_haetae_poly*b) {
    unsigned int i;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        c->coeffs[i] =
            a->coeffs[i] + INT32_C(8192) * b->coeffs[i];
}

/*************************************************
 * Name:        crypto_haetae_polyfixfix_sub
 *
 * Description: Subtract fixed polynomial and fixed polynomial.
 *              No modular reduction is performed.
 *
 * Arguments:   - crypto_haetae_polyfix *c: pointer to output fixed polynomial
 *              - const crypto_haetae_polyfix *a: pointer to first summand
 *              - const crypto_haetae_polyfix *b: pointer to second summand
 **************************************************/
void crypto_haetae_polyfixfix_sub(crypto_haetae_polyfix *c, const crypto_haetae_polyfix *a, const crypto_haetae_polyfix *b) {
    unsigned int i;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

int32_t crypto_haetae_fix_round(int32_t num) {
  return crypto_floor_div_pow2_i32(
      num + INT32_C(4096), CRYPTO_HAETAE_LARGE_N_BITS);
}

/*************************************************
 * Name:        crypto_haetae_polyfix_round
 *
 * Description: rounds a fixed polynomial to integer polynomial
 *
 * Arguments:   - crypto_haetae_poly *a: output integer polynomial
 *              - crypto_haetae_poly *b: input fixed polynomial
 **************************************************/
void crypto_haetae_polyfix_round(crypto_haetae_poly *a, const crypto_haetae_polyfix *b) {
    unsigned i;

    for (i = 0; i < CRYPTO_HAETAE_N; ++i)
        a->coeffs[i] = crypto_haetae_fix_round(b->coeffs[i]);
}

/**************************************************************/
/********* Double Vectors of polynomials of length K **********/
/**************************************************************/

/*************************************************
 * Name:        crypto_haetae_polyfixveck_add
 *
 * Description: Add vector to a vector of double polynomials of length K.
 *              No modular reduction is performed.
 *
 * Arguments:   - crypto_haetae_polyveck *w: pointer to output vector
 *              - const crypto_haetae_polyveck *u: pointer to first summand
 *              - const crypto_haetae_polyveck *v: pointer to second summand
 **************************************************/
void crypto_haetae_polyfixveck_add(crypto_haetae_polyfixveck *w, const crypto_haetae_polyfixveck *u,
                     const crypto_haetae_polyveck *v, const crypto_haetae_parameters *parameters) {
    unsigned int i;

    for (i = 0; i < parameters->k; ++i)
        crypto_haetae_polyfix_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
 * Name:        crypto_haetae_polyfixfixveck_sub
 *
 * Description: subtract vector to a vector of fixed polynomials of length k.
 *              No modular reduction is performed.
 *
 * Arguments:   - crypto_haetae_polyveck *w: pointer to output vector
 *              - const crypto_haetae_polyfixveck *u: pointer to first summand
 *              - const crypto_haetae_polyfixveck *v: pointer to second summand
 **************************************************/
void crypto_haetae_polyfixfixveck_sub(crypto_haetae_polyfixveck *w, const crypto_haetae_polyfixveck *u,
                        const crypto_haetae_polyfixveck *v, const crypto_haetae_parameters *parameters) {
    unsigned int i;

    for (i = 0; i < parameters->k; ++i)
        crypto_haetae_polyfixfix_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
 * Name:        crypto_haetae_polyfixveck_double
 *
 * Description: Double vector of polynomials of length K.
 *
 * Arguments:   - crypto_haetae_polyveck *b: pointer to output vector
 *              - crypto_haetae_polyveck *a: pointer to input vector
 **************************************************/
void crypto_haetae_polyfixveck_double(crypto_haetae_polyfixveck *b, const crypto_haetae_polyfixveck *a, const crypto_haetae_parameters *parameters) {
    unsigned int i, j;

    for (i = 0; i < parameters->k; ++i)
        for (j = 0; j < CRYPTO_HAETAE_N; ++j)
            b->vec[i].coeffs[j] = 2 * a->vec[i].coeffs[j];
}

/*************************************************
 * Name:        crypto_haetae_polyfixveck_round
 *
 * Description: rounds a fixed polynomial vector of length K
 *
 * Arguments:   - crypto_haetae_polyveck *a: output integer polynomial vector
 *              - crypto_haetae_polyfixveck *b: input fixed polynomial vector
 **************************************************/
void crypto_haetae_polyfixveck_round(crypto_haetae_polyveck *a, const crypto_haetae_polyfixveck *b, const crypto_haetae_parameters *parameters) {
    unsigned i;

    for (i = 0; i < parameters->k; ++i)
        crypto_haetae_polyfix_round(&a->vec[i], &b->vec[i]);
}

/**************************************************************/
/********* Double Vectors of polynomials of length L **********/
/**************************************************************/

/*************************************************
 * Name:        crypto_haetae_polyfixvecl_add
 *
 * Description: Add vector to a vector of double polynomials of length L.
 *              No modular reduction is performed.
 *
 * Arguments:   - crypto_haetae_polyvecl *w: pointer to output vector
 *              - const crypto_haetae_polyfixvecl *u: pointer to first summand
 *              - const crypto_haetae_polyvecl *v: pointer to second summand
 **************************************************/
void crypto_haetae_polyfixvecl_add(crypto_haetae_polyfixvecl *w, const crypto_haetae_polyfixvecl *u,
                     const crypto_haetae_polyvecl *v, const crypto_haetae_parameters *parameters) {
    unsigned int i;

    for (i = 0; i < parameters->l; ++i)
        crypto_haetae_polyfix_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
 * Name:        crypto_haetae_polyfixfixvecl_sub
 *
 * Description: subtract vector to a vector of fixed polynomials of length l.
 *              No modular reduction is performed.
 *
 * Arguments:   - crypto_haetae_polyvecl *w: pointer to output vector
 *              - const crypto_haetae_polyfixvecl *u: pointer to first summand
 *              - const crypto_haetae_polyfixvecl *v: pointer to second summand
 **************************************************/
void crypto_haetae_polyfixfixvecl_sub(crypto_haetae_polyfixvecl *w, const crypto_haetae_polyfixvecl *u,
                        const crypto_haetae_polyfixvecl *v, const crypto_haetae_parameters *parameters) {
    unsigned int i;

    for (i = 0; i < parameters->l; ++i)
        crypto_haetae_polyfixfix_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}
/*************************************************
 * Name:        crypto_haetae_polyfixvecl_double
 *
 * Description: Double vector of polynomials of length L.
 *
 * Arguments:   - crypto_haetae_polyveck *b: pointer to output vector
 *              - crypto_haetae_polyveck *a: pointer to input vector
 **************************************************/
void crypto_haetae_polyfixvecl_double(crypto_haetae_polyfixvecl *b, const crypto_haetae_polyfixvecl *a, const crypto_haetae_parameters *parameters) {
    unsigned int i, j;

    for (i = 0; i < parameters->l; ++i)
        for (j = 0; j < CRYPTO_HAETAE_N; ++j)
            b->vec[i].coeffs[j] = 2 * a->vec[i].coeffs[j];
}

/*************************************************
 * Name:        crypto_haetae_polyfixvecl_round
 *
 * Description: rounds a fixed polynomial vector of length L
 *
 * Arguments:   - crypto_haetae_polyvecl *a: output integer polynomial vector
 *              - crypto_haetae_polyfixvecl *b: input fixed polynomial vector
 **************************************************/
void crypto_haetae_polyfixvecl_round(crypto_haetae_polyvecl *a, const crypto_haetae_polyfixvecl *b, const crypto_haetae_parameters *parameters) {
    unsigned i;

    for (i = 0; i < parameters->l; ++i)
        crypto_haetae_polyfix_round(&a->vec[i], &b->vec[i]);
}

/*************************************************
 * Name:        polyfixveclk_norm2
 *
 * Description: Calculates L2 norm of a fixed point polynomial vector with
 *length L + K The result is L2 norm * LN similar to the way polynomial is
 *usually stored
 *
 * Arguments:   - crypto_haetae_polyfixvecl *a: polynomial vector with length L to calculate
 *                norm
 *              - crypto_haetae_polyfixveck *a: polynomial vector with length K to calculate
 *                norm
 **************************************************/
uint64_t crypto_haetae_polyfixveclk_sqnorm2(const crypto_haetae_polyfixvecl *a, const crypto_haetae_polyfixveck *b,
                              const crypto_haetae_parameters *parameters) {
    unsigned int i, j;
    uint64_t ret = 0;

    for (i = 0; i < parameters->l; ++i) {
        for (j = 0; j < CRYPTO_HAETAE_N; ++j)
            ret += (long long)a->vec[i].coeffs[j] * a->vec[i].coeffs[j];
    }

    for (i = 0; i < parameters->k; ++i) {
        for (j = 0; j < CRYPTO_HAETAE_N; ++j)
            ret += (long long)b->vec[i].coeffs[j] * b->vec[i].coeffs[j];
    }

    return ret;
}



uint16_t crypto_haetae_polyfixveclk_sample_hyperball(crypto_haetae_polyfixvecl *y1, crypto_haetae_polyfixveck *y2,
                                  uint8_t  *b, const uint8_t  seed[CRYPTO_HAETAE_CRH_BYTES],
                                  const uint16_t nonce,
                                  const crypto_haetae_parameters *parameters) {
    const uint32_t haetae_K = parameters->k;
    const uint32_t haetae_L = parameters->l;
    const double haetae_B0 = parameters->b0;
    const uint64_t haetae_B0SQ = (uint64_t)(haetae_B0*haetae_B0);
    const double haetae_SQNM = parameters->sqrt_nm;
    uint16_t ni = nonce;

    uint64_t samples[SAMPLES_MAX] = {0};
    crypto_haetae_fp96_76 sqsum, invsqrt;
    unsigned int i, j;

    uint8_t  signs[SIGNS_MAX];

    uint64_t tmp1 = 0;
    uint64_t tmp2 = haetae_B0SQ * CRYPTO_HAETAE_LARGE_N * CRYPTO_HAETAE_LARGE_N;

    do {
        sqsum.limb48[0] = 0;
        sqsum.limb48[1] = 0;

        crypto_haetae_sample_gauss_N(&samples[0], &signs[0], &sqsum, seed, ni++, CRYPTO_HAETAE_N + 1);
        crypto_haetae_sample_gauss_N(&samples[CRYPTO_HAETAE_N], &signs[CRYPTO_HAETAE_N / 8], &sqsum, seed, ni++, CRYPTO_HAETAE_N + 1);

        for (i = 2; i < haetae_L + haetae_K; i++)
            crypto_haetae_sample_gauss_N(&samples[CRYPTO_HAETAE_N * i], &signs[CRYPTO_HAETAE_N / 8 * i], &sqsum, seed,
                           ni++, CRYPTO_HAETAE_N);

        // divide sqsum by 2 and approximate inverse square root
        sqsum.limb48[0] += 1; // rounding
        sqsum.limb48[0] >>= 1;
        sqsum.limb48[0] += (sqsum.limb48[1] & 1) << 47;
        sqsum.limb48[1] >>= 1;
        sqsum.limb48[1] += sqsum.limb48[0] >> 48;
        sqsum.limb48[0] &= (UINT64_C(1) << 48) - 1;

        crypto_haetae_fixpoint_newton_invsqrt(&invsqrt, &sqsum, parameters);
        fixpoint_mul_high(&sqsum, &invsqrt,
                          (uint64_t)(haetae_B0 * CRYPTO_HAETAE_LARGE_N + haetae_SQNM / 2) << (28 - 13));

        for (i = 0; i < haetae_L; i++) {
            for (j = 0; j < CRYPTO_HAETAE_N; j++)
                y1->vec[i].coeffs[j] = crypto_haetae_fixpoint_mul_rnd13(
                    samples[(i * CRYPTO_HAETAE_N + j)], &sqsum,
                    (signs[(i * CRYPTO_HAETAE_N + j) / 8] >> ((i * CRYPTO_HAETAE_N + j) % 8)) & 1);
        }

        for (i = haetae_L; i < haetae_K + haetae_L; i++) {
            for (j = 0; j < CRYPTO_HAETAE_N; j++)
                y2->vec[i - haetae_L].coeffs[j] = crypto_haetae_fixpoint_mul_rnd13(
                    samples[(i * CRYPTO_HAETAE_N + j)], &sqsum,
                    (signs[(i * CRYPTO_HAETAE_N + j) / 8] >> ((i * CRYPTO_HAETAE_N + j) % 8)) & 1);
        }

        tmp1 = crypto_haetae_polyfixveclk_sqnorm2(y1, y2, parameters);

    } while (tmp1 > tmp2);

    {
      uint8_t  tmp[CRYPTO_HAETAE_CRH_BYTES + 2];
      for (i = 0; i < CRYPTO_HAETAE_CRH_BYTES; i++)
      {
        tmp[i] = seed[i];
      }
      crypto_store16_le(tmp + CRYPTO_HAETAE_CRH_BYTES, ni);

      crypto_shake256(b, 1, tmp, CRYPTO_HAETAE_CRH_BYTES+2);
      crypto_zeroize(tmp, sizeof(tmp));
    }

    crypto_zeroize(samples, sizeof(samples));
    crypto_zeroize(signs, sizeof(signs));
    return ni;
}
