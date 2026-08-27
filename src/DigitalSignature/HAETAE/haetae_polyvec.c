// SPDX-License-Identifier: MIT

#include <string.h>

#include "haetae_decompose.h"
#include "haetae_fft.h"
#include "haetae_reduce.h"
#include "haetae_poly.h"
#include "haetae_polyvec.h"


#define BESTM_MAX_SIZE CRYPTO_HAETAE_N / CRYPTO_HAETAE_MIN_TAU + 1

/**************************************************************/
/************ Vectors of polynomials of length K **************/
/**************************************************************/

/*************************************************
 * Name:        polyveck_add
 *
 * Description: Add vectors of polynomials of length K.
 *              No modular reduction is performed.
 *
 * Arguments:   - crypto_haetae_polyveck *w: pointer to output vector
 *              - const crypto_haetae_polyveck *u: pointer to first summand
 *              - const crypto_haetae_polyveck *v: pointer to second summand
 **************************************************/
void crypto_haetae_polyveck_add(crypto_haetae_polyveck* w, const crypto_haetae_polyveck* u, const crypto_haetae_polyveck* v,
	const crypto_haetae_parameters *parameters) {
	unsigned int i;

	for (i = 0; i < parameters->k; ++i)
		crypto_haetae_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
 * Name:        polyveck_sub
 *
 * Description: Subtract vectors of polynomials of length K.
 *              No modular reduction is performed.
 *
 * Arguments:   - crypto_haetae_polyveck *w: pointer to output vector
 *              - const crypto_haetae_polyveck *u: pointer to first input vector
 *              - const crypto_haetae_polyveck *v: pointer to second input vector to be
 *                                   subtracted from first input vector
 **************************************************/
void crypto_haetae_polyveck_sub(crypto_haetae_polyveck* w, const crypto_haetae_polyveck* u, const crypto_haetae_polyveck* v,
	const crypto_haetae_parameters *parameters) {
	unsigned int i;

	for (i = 0; i < parameters->k; ++i)
		crypto_haetae_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
 * Name:        crypto_haetae_polyveck_double
 *
 * Description: Double vector of polynomials of length K.
 *              No modular reduction is performed.
 *
 * Arguments:   - crypto_haetae_polyveck *w: pointer to output vector
 **************************************************/
void crypto_haetae_polyveck_double(crypto_haetae_polyveck* b, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;

	for (i = 0; i < parameters->k; ++i)
		for (j = 0; j < CRYPTO_HAETAE_N; ++j)
			b->vec[i].coeffs[j] *= 2;
}

/*************************************************
 * Name:        crypto_haetae_polyveck_reduce2q
 *
 * Description: Reduce coefficients to 2q
 *
 * Arguments:   - crypto_haetae_polyveck *v: pointer to input/output vector
 **************************************************/
void crypto_haetae_polyveck_reduce2q(crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	unsigned int i;

	for (i = 0; i < parameters->k; ++i)
		crypto_haetae_poly_reduce2q(&v->vec[i]);
}

/*************************************************
 * Name:        crypto_haetae_polyveck_freeze
 *
 * Description: For all coefficients of polynomials in vector of length K
 *              compute standard representative r = a mod^+ Q.
 *
 * Arguments:   - crypto_haetae_polyveck *v: pointer to input/output vector
 **************************************************/
void crypto_haetae_polyveck_freeze(crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	unsigned int i;

	for (i = 0; i < parameters->k; ++i)
		crypto_haetae_poly_freeze(&v->vec[i]);
}

/*************************************************
 * Name:        crypto_haetae_polyveck_freeze2q
 *
 * Description: For all coefficients of polynomials in vector of length K
 *              compute standard representative r = a mod^+ 2Q.
 *
 * Arguments:   - crypto_haetae_polyveck *v: pointer to input/output vector
 **************************************************/
void crypto_haetae_polyveck_freeze2q(crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	unsigned int i;

	for (i = 0; i < parameters->k; ++i)
		crypto_haetae_poly_freeze2q(&v->vec[i]);
}

/*************************************************
 * Name:        crypto_haetae_polyveck_expand
 *
 * Description: Sample a vector of polynomials with uniformly random
 *              coefficients in Zq by rejection sampling on the
 *              output stream from SHAKE128(seed|nonce)
 *
 * Arguments:   - crypto_haetae_polyveck *v: pointer to output a vector of polynomials of
 *                             length K
 *              - const uint8_t  seed[]: byte array with seed of length SEEDBYTES
 **************************************************/
void crypto_haetae_polyveck_expand(crypto_haetae_polyveck* v, const uint8_t  seed[CRYPTO_HAETAE_SEED_BYTES],
	const crypto_haetae_parameters *parameters) {

	const int haetae_m = parameters->l - 1;
	unsigned int i, nonce = (parameters->k << 8) + haetae_m;
	for (i = 0; i < parameters->k; ++i)
		crypto_haetae_poly_uniform(&v->vec[i], seed, nonce++);
}


/*************************************************
 * Name:        crypto_haetae_polyveck_double_negate
 *
 * Description: multiply each coefficient with -2
 *
 * Arguments:   - crypto_haetae_polyveck *v: pointer to output vector of polynomials of
 *                              length K
 **************************************************/
void crypto_haetae_polyveck_double_negate(crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;

	for (i = 0; i < parameters->k; ++i)
		for (j = 0; j < CRYPTO_HAETAE_N; j++)
			v->vec[i].coeffs[j] =
			crypto_haetae_montgomery_reduce((long long)v->vec[i].coeffs[j] * CRYPTO_HAETAE_MONT * -2);
}

/*************************************************
 * Name:        crypto_haetae_polyveck_frommont
 *
 * Description: multiply each coefficient with MONT
 *
 * Arguments:   - crypto_haetae_polyveck *v: pointer to output vector of polynomials of
 *                              length K
 **************************************************/
void crypto_haetae_polyveck_frommont(crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;

	for (i = 0; i < parameters->k; ++i)
		for (j = 0; j < CRYPTO_HAETAE_N; j++)
			v->vec[i].coeffs[j] =
			crypto_haetae_montgomery_reduce((long long)v->vec[i].coeffs[j] * CRYPTO_HAETAE_MONT_SQUARED);
}

void crypto_haetae_polyveck_poly_pointwise_montgomery(crypto_haetae_polyveck* w, const crypto_haetae_polyveck* u,
	const crypto_haetae_poly* v, const crypto_haetae_parameters *parameters) {
	unsigned int i;
	for (i = 0; i < parameters->k; i++) {
		crypto_haetae_poly_pointwise_montgomery(&w->vec[i], &u->vec[i], v);
	}
}

/*************************************************
 * Name:        polyveck_poly_fromcrt
 *
 * Description: recover polynomials from CRT domain, where all "mod q"
 *              polynomials are known and only the uppermost "mod 2" polynomial
 *              is non-zero
 *
 * Arguments:   - crypto_haetae_polyveck *w: pointer to output vector of polynomials of
 *                             length K
 *              - const crypto_haetae_polyveck *u: pointer to the input vector of polynomials
 *                                   of length K
 *              - const crypto_haetae_poly *v: pointer to the input polynomial ("mod 2")
 **************************************************/
void crypto_haetae_polyveck_poly_fromcrt(crypto_haetae_polyveck* w, const crypto_haetae_polyveck* u,
	const crypto_haetae_poly* v, const crypto_haetae_parameters *parameters) {
	unsigned int i;

	crypto_haetae_poly_fromcrt(&w->vec[0], &u->vec[0], v);

	for (i = 1; i < parameters->k; i++) {
		crypto_haetae_poly_fromcrt0(&w->vec[i], &u->vec[i]);
	}
}

void crypto_haetae_polyveck_highbits_hint(crypto_haetae_polyveck* w, const crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;
	for (i = 0; i < parameters->k; i++) {
		for (j = 0; j < CRYPTO_HAETAE_N; j++) {
			crypto_haetae_decompose_hint(&w->vec[i].coeffs[j], v->vec[i].coeffs[j], parameters);
		}
	}
}

void crypto_haetae_polyveck_pack_highbits(uint8_t *buf, const crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	unsigned int i;
	for (i = 0; i < parameters->k; i++) {
		crypto_haetae_poly_pack_highbits(buf + i * CRYPTO_HAETAE_POLY_HIGH_BITS_PACKED_BYTES, &v->vec[i], parameters);
	}
}

void crypto_haetae_polyveck_cneg(crypto_haetae_polyveck* v, const uint8_t  b, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;
	for (i = 0; i < parameters->k; i++) {
		for (j = 0; j < CRYPTO_HAETAE_N; j++) {
			v->vec[i].coeffs[j] *= 1 - 2 * b;
		}
	}
}

void crypto_haetae_polyveck_caddDQ2ALPHA(crypto_haetae_polyveck* h, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;
	const int alpha_hint = parameters->alpha_hint;

	for (i = 0; i < parameters->k; i++) {
		for (j = 0; j < CRYPTO_HAETAE_N; j++) {
			int32_t value = h->vec[i].coeffs[j];
			int32_t negative_mask =
				-(int32_t)((uint32_t)value >> 31);
			h->vec[i].coeffs[j] = value +
				(negative_mask &
				 ((CRYPTO_HAETAE_DOUBLE_Q - 2) / alpha_hint));
		}
	}
}

void crypto_haetae_polyveck_csubDQ2ALPHA(crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	const int alpha_hint = parameters->alpha_hint;           // assume > 0
	const int T = (int)((CRYPTO_HAETAE_DOUBLE_Q - 2) / alpha_hint);
	uint32_t i, j;
	for (i = 0; i < (unsigned)parameters->k; i++) {
		for (j = 0; j < (unsigned)CRYPTO_HAETAE_N; j++) {
			int32_t x = v->vec[i].coeffs[j];
			uint32_t negative = (uint32_t)(x - T) >> 31;
			int ge_mask = -(int32_t)(negative ^ 1u);
			x -= (ge_mask & T);
			v->vec[i].coeffs[j] = (int)x;
		}
	}
}
/*
void crypto_haetae_polyveck_csubDQ2ALPHA(crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;
	const int alpha_hint = parameters->alpha_hint;

	for (i = 0; i < parameters->k; i++) {
		for (j = 0; j < CRYPTO_HAETAE_N; j++) {
			v->vec[i].coeffs[j] -=
				~((v->vec[i].coeffs[j] - (CRYPTO_HAETAE_DOUBLE_Q - 2) / alpha_hint) >> 31) &
				((CRYPTO_HAETAE_DOUBLE_Q - 2) / alpha_hint);
		}
	}
}
*/
void crypto_haetae_polyveck_mul_alpha(crypto_haetae_polyveck* v, const crypto_haetae_polyveck* u, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;
	const int alpha_hint = parameters->alpha_hint;

	for (i = 0; i < parameters->k; i++) {
		for (j = 0; j < CRYPTO_HAETAE_N; j++) {
			v->vec[i].coeffs[j] = u->vec[i].coeffs[j] * alpha_hint;
		}
	}
}

void crypto_haetae_polyveck_div2(crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;
	for (i = 0; i < parameters->k; ++i)
		for (j = 0; j < CRYPTO_HAETAE_N; ++j)
			v->vec[i].coeffs[j] >>= 1;
}

void crypto_haetae_polyveck_caddq(crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;
	for (i = 0; i < parameters->k; ++i)
		for (j = 0; j < CRYPTO_HAETAE_N; ++j)
			v->vec[i].coeffs[j] = crypto_haetae_caddq(v->vec[i].coeffs[j]);
}

void crypto_haetae_polyveck_decompose_vk(crypto_haetae_polyveck* v0, crypto_haetae_polyveck* v, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;
	for (i = 0; i < parameters->k; i++) {
		for (j = 0; j < CRYPTO_HAETAE_N; j++) {
			v->vec[i].coeffs[j] =
				crypto_haetae_decompose_vk(&v0->vec[i].coeffs[j], v->vec[i].coeffs[j]);
		}
	}
}

void crypto_haetae_polyveck_ntt(crypto_haetae_polyveck* x, const crypto_haetae_parameters *parameters) {
	unsigned int i;
	for (i = 0; i < parameters->k; i++) {
		crypto_haetae_poly_ntt(&x->vec[i]);
	}
}

void crypto_haetae_polyveck_invntt_tomont(crypto_haetae_polyveck* x, const crypto_haetae_parameters *parameters) {
	unsigned int i;
	for (i = 0; i < parameters->k; i++) {
		crypto_haetae_poly_invntt_tomont(&x->vec[i]);
	}
}

/*************************************************
 * Name:        crypto_haetae_polyveck_sqnorm2
 *
 * Description: Calculates L2 norm of a polynomial vector with length k
 *
 * Arguments:   - crypto_haetae_polyveck *b: polynomial vector with length k to calculate
 *norm
 **************************************************/
uint64_t crypto_haetae_polyveck_sqnorm2(const crypto_haetae_polyveck* b, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;
	uint64_t ret = 0;

	for (i = 0; i < parameters->k; ++i) {
		for (j = 0; j < CRYPTO_HAETAE_N; ++j) {
			ret += (uint64_t)b->vec[i].coeffs[j] * b->vec[i].coeffs[j];
		}
	}
	return ret;
}




/**************************************************************/
/************ Vectors of polynomials of length L **************/
/**************************************************************/

/*************************************************
 * Name:        crypto_haetae_polyvecl_highbits
 *
 * Description: Compute HighBits of a vector of polynomials
 *
 * Arguments:   - crypto_haetae_polyvecl *v2: pointer to output vector of polynomials of
 *                              length L
 *              - const crypto_haetae_polyvecl *v: pointer to input vector of polynomials of
 *                                   length L
 **************************************************/
void crypto_haetae_polyvecl_highbits(crypto_haetae_polyvecl* v2, const crypto_haetae_polyvecl* v, const crypto_haetae_parameters *parameters) {
	unsigned int i;

	for (i = 0; i < parameters->l; ++i)
		crypto_haetae_poly_highbits(&v2->vec[i], &v->vec[i]);
}

/*************************************************
 * Name:        crypto_haetae_polyvecl_lowbits
 *
 * Description: Compute LowBits of a vector of polynomials
 *
 * Arguments:   - crypto_haetae_polyvecl *v1: pointer to output vector of polynomials of
 *                              length L
 *              - const crypto_haetae_polyvecl *v: pointer to input vector of polynomials of
 *                                   length L
 **************************************************/
void crypto_haetae_polyvecl_lowbits(crypto_haetae_polyvecl* v1, const crypto_haetae_polyvecl* v, const crypto_haetae_parameters *parameters) {
	unsigned int i;

	for (i = 0; i < parameters->l; ++i)
		crypto_haetae_poly_lowbits(&v1->vec[i], &v->vec[i]);
}

void crypto_haetae_polyvecl_cneg(crypto_haetae_polyvecl* v, const uint8_t  b, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;
	for (i = 0; i < parameters->l; i++) {
		for (j = 0; j < CRYPTO_HAETAE_N; j++) {
			v->vec[i].coeffs[j] *= 1 - 2 * b;
		}
	}
}

/*************************************************
 * Name:        crypto_haetae_polyvecl_sqnorm2
 *
 * Description: Calculates L2 norm of a polynomial vector with length l
 *
 * Arguments:   - crypto_haetae_polyvecl *a: polynomial vector with length l to calculate
 *norm
 **************************************************/
uint64_t crypto_haetae_polyvecl_sqnorm2(const crypto_haetae_polyvecl* a, const crypto_haetae_parameters *parameters) {
	unsigned int i, j;
	uint64_t ret = 0;

	for (i = 0; i < parameters->l; ++i) {
		for (j = 0; j < CRYPTO_HAETAE_N; ++j) {
			ret += (uint64_t)a->vec[i].coeffs[j] * (uint64_t)a->vec[i].coeffs[j];
		}
	}

	return ret;
}

/*************************************************
 * Name:        polyvecl_pointwise_acc_montgomery
 *
 * Description: Pointwise multiply vectors of polynomials of length L, multiply
 *              resulting vector by 2^{-32} and add (accumulate) polynomials
 *              in it. Input/output vectors are in NTT domain representation.
 *
 * Arguments:   - crypto_haetae_poly *w: output polynomial
 *              - const crypto_haetae_polyvecl *u: pointer to first input vector
 *              - const crypto_haetae_polyvecl *v: pointer to second input vector
 **************************************************/
void crypto_haetae_polyvecl_pointwise_acc_montgomery(crypto_haetae_poly* w,
	const crypto_haetae_polyvecl* u, const crypto_haetae_polyvecl* v,
	const crypto_haetae_parameters *parameters) {
	unsigned int i;
	crypto_haetae_poly t;

	crypto_haetae_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
	for (i = 1; i < parameters->l; ++i) {
		crypto_haetae_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
		crypto_haetae_poly_add(w, w, &t);
	}
}

void crypto_haetae_polyvecl_ntt(crypto_haetae_polyvecl* x, const crypto_haetae_parameters *parameters) {
	unsigned int i;
	for (i = 0; i < parameters->l; i++) {
		crypto_haetae_poly_ntt(&x->vec[i]);
	}
}

/**************************************************************/
/************ Vectors of polynomials of length M **************/
/**************************************************************/

/*************************************************
 * Name:        crypto_haetae_polyvecm_pointwise_acc_montgomery
 *
 * Description: Pointwise multiply vectors of polynomials of length L, multiply
 *              resulting vector by 2^{-32} and add (accumulate) polynomials
 *              in it. Input/output vectors are in NTT domain representation.
 *
 * Arguments:   - crypto_haetae_poly *w: output polynomial
 *              - const crypto_haetae_polyvecm *u: pointer to first input vector
 *              - const crypto_haetae_polyvecm *v: pointer to second input vector
 **************************************************/
void crypto_haetae_polyvecm_pointwise_acc_montgomery(crypto_haetae_poly* w,
	const crypto_haetae_polyvecm* u, const crypto_haetae_polyvecm* v,
	const crypto_haetae_parameters *parameters) {
	uint32_t i;
	crypto_haetae_poly t;
	const uint32_t haetae_m = parameters->l - 1u;

	crypto_haetae_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
	for (i = 1; i < haetae_m; ++i) {
		crypto_haetae_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
		crypto_haetae_poly_add(w, w, &t);
	}
}

void crypto_haetae_polyvecm_ntt(crypto_haetae_polyvecm* x, const crypto_haetae_parameters *parameters) {
	uint32_t i;
	const uint32_t haetae_m = parameters->l - 1u;

	for (i = 0; i < haetae_m; i++) {
		crypto_haetae_poly_ntt(&x->vec[i]);
	}
}

static void minmax(int* x, int* y) // taken from djbsort
{
	int a = *x;
	int b = *y;
	int ab = b ^ a;
	int c = b - a;
	c ^= ab & (c ^ b);
	c = -(int32_t)((uint32_t)c >> 31);
	c &= ab;
	*x = a ^ c;
	*y = b ^ c;
}

long long crypto_haetae_polyvecmk_sqsing_value(const crypto_haetae_polyvecm* s1, const crypto_haetae_polyveck* s2, const crypto_haetae_parameters *parameters) {
	int res = 0;
	crypto_haetae_complex_fp32_16 input[CRYPTO_HAETAE_FFT_N] = {{0, 0}};

	size_t i, j;
	const uint32_t haetae_k = parameters->k;
	const uint32_t haetae_m = parameters->l - 1u;
	const uint32_t haetae_tau = parameters->tau;
	const size_t bestm_size = CRYPTO_HAETAE_N / haetae_tau + 1;

	int sum[CRYPTO_HAETAE_N] = {0};
	int min = 0;
	int bestm[BESTM_MAX_SIZE] = {0};
	memset(bestm, 0, bestm_size * sizeof(int));

	for (i = 0; i < haetae_m; ++i) {
		crypto_haetae_fft_bitrev(input, &s1->vec[i]);
		crypto_haetae_fft(input);

		// cumulative sum
		for (j = 0; j < CRYPTO_HAETAE_N; j++) {
			sum[j] += crypto_haetae_complex_fp_sqabs(input[j]);
		}
	}

	for (i = 0; i < haetae_k; ++i) {
		crypto_haetae_fft_bitrev(input, &s2->vec[i]);
		crypto_haetae_fft(input);

		// cumulative sum
		for (j = 0; j < CRYPTO_HAETAE_N; j++) {
			sum[j] += crypto_haetae_complex_fp_sqabs(input[j]);
		}
	}

	// compute max m
	for (i = 0; i < CRYPTO_HAETAE_N / haetae_tau + 1; ++i) {
		bestm[i] = sum[i];
	}
	for (i = CRYPTO_HAETAE_N / haetae_tau + 1; i < CRYPTO_HAETAE_N; i++) {
		for (j = 0; j < CRYPTO_HAETAE_N / haetae_tau + 1; j++) {
		minmax(&sum[i], &bestm[j]);
    }
	}
	// find minimum in bestm
	min = bestm[0];
	for (i = 1; i < CRYPTO_HAETAE_N / haetae_tau + 1; i++) {
		int tmp = bestm[i];
		minmax(&min, &tmp);
	}
	// multiply all but the minimum by N mod TAU
	for (i = 0; i < CRYPTO_HAETAE_N / haetae_tau + 1; i++) {
		int32_t difference = min - bestm[i];
		int fac = -(int32_t)((uint32_t)difference >> 31);
		fac = (fac & (haetae_tau)) ^ ((~fac) & (CRYPTO_HAETAE_N % haetae_tau)); // fac = TAU for all != min and N%TAU for min
		bestm[i] +=
			0x10200;     // add 1 for the "1 poly" in S, and prepare rounding
		bestm[i] >>= 10; // round off 10 bits
		bestm[i] *= fac;
		res += bestm[i];
	}
	return (res + (1 << 5)) >> 6; // return rounded, squared value
}

/*************************************************
 * Name:        crypto_haetae_polyvecmk_uniform_eta
 *
 * Description: Sample a vector of polynomials with uniformly random
 *              coefficients in [-ETA,ETA] by rejection sampling on the
 *              output stream from crypto_shake256(seed|nonce)
 *
 * Arguments:   - crypto_haetae_polyveck *v: pointer to output a vector of polynomials of
 *                             length K
 *              - const uint8_t  seed[]: byte array with seed of length CRHBYTES
 *              - uint16_t nonce: 2-byte nonce
 **************************************************/
void crypto_haetae_polyvecmk_uniform_eta(crypto_haetae_polyvecm* u, crypto_haetae_polyveck* v,
	const uint8_t  seed[CRYPTO_HAETAE_CRH_BYTES], uint16_t nonce,
	const crypto_haetae_parameters *parameters) {
	uint32_t i;
	uint16_t n = nonce;
	const uint32_t haetae_m = parameters->l - 1u;
	const uint32_t haetae_k = parameters->k;

	for (i = 0; i < haetae_m; i++)
		crypto_haetae_poly_uniform_eta(&u->vec[i], seed, n++);

	for (i = 0; i < haetae_k; ++i)
		crypto_haetae_poly_uniform_eta(&v->vec[i], seed, n++);

}
