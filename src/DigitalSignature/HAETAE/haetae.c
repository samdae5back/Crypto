// SPDX-License-Identifier: MIT

#include <stdlib.h>
#include <string.h>

#include "RandomNumberGeneration/KAT/pqc_kat_rng_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"

#include "haetae_internal.h"
#include "haetae_poly.h"
#include "haetae_polyfix.h"
#include "haetae_polyvec.h"
#include "haetae_polymat.h"
#include "haetae_packing.h"
#include "haetae_sign.h"
#include "haetae_symmetric.h"

static const crypto_haetae_parameters crypto_haetae_parameter_table[] = {
    {ALG_HAETAE_120, 992u, 1408u, 1474u, 2u, 2u, 4u, 58u,
     9846.02, 9838.98, 12777.52, 48.858, 39.191835884530846,
     1u, 132u, 7u, 512u, 9u, 480u, 576u},
    {ALG_HAETAE_180, 1472u, 2112u, 2349u, 3u, 3u, 6u, 80u,
     18314.98, 18307.70, 21906.65, 57.707, 48.0,
     1u, 376u, 127u, 512u, 9u, 480u, 864u},
    {ALG_HAETAE_260, 2080u, 2752u, 2948u, 5u, 4u, 7u, 128u,
     22343.66, 22334.95, 24441.49, 55.13, 53.0659966456864,
     0u, 501u, 358u, 256u, 8u, 512u, 1152u}
};

typedef struct crypto_haetae_keygen_workspace {
    crypto_haetae_polyvecm matrix[CRYPTO_HAETAE_MAX_K];
    crypto_haetae_polyvecm s1;
    crypto_haetae_polyvecm s1_hat;
    crypto_haetae_polyveck a;
    crypto_haetae_polyveck b;
    crypto_haetae_polyveck b0;
    crypto_haetae_polyveck s2;
    crypto_haetae_polyveck s2_hat;
} crypto_haetae_keygen_workspace;

const crypto_haetae_parameters *crypto_haetae_parameters_from_algorithm(
    AlgID algorithm) {
    size_t index;

    for (index = 0u;
         index < sizeof(crypto_haetae_parameter_table) /
                     sizeof(crypto_haetae_parameter_table[0]);
         ++index) {
        if (crypto_haetae_parameter_table[index].algorithm == algorithm) {
            return &crypto_haetae_parameter_table[index];
        }
    }
    return NULL;
}

static CryptoError crypto_haetae_keygen_core(
    uint8_t *public_key,
    uint8_t *private_key,
    const crypto_haetae_parameters *parameters) {
    crypto_haetae_keygen_workspace *workspace;
    crypto_sha3_context hash_context = {0};
    uint8_t seed_buffer[2u * CRYPTO_HAETAE_SEED_BYTES +
                        CRYPTO_HAETAE_CRH_BYTES] = {0};
    const uint8_t *rho_prime;
    const uint8_t *sigma;
    const uint8_t *key;
    uint16_t nonce = 0u;
    long long squared_singular_value;
    CryptoError result;

    workspace = calloc(1u, sizeof(*workspace));
    if (workspace == NULL) {
        return CRYPTO_ERROR_ALLOCATION_FAILED;
    }

    result = crypto_pqc_random_bytes_internal(
        seed_buffer, CRYPTO_HAETAE_SEED_BYTES);
    if (result != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    crypto_shake256_init(&hash_context);
    crypto_sha3_update(
        &hash_context, seed_buffer, CRYPTO_HAETAE_SEED_BYTES);
    crypto_sha3_finalize(&hash_context);
    crypto_sha3_squeeze(&hash_context, seed_buffer, sizeof(seed_buffer));
    crypto_sha3_clear(&hash_context);

    rho_prime = seed_buffer;
    sigma = rho_prime + CRYPTO_HAETAE_SEED_BYTES;
    key = sigma + CRYPTO_HAETAE_CRH_BYTES;

    crypto_haetae_polymatkm_expand(
        workspace->matrix, rho_prime, parameters);

    if (parameters->d != 0u) {
        crypto_haetae_polyveck_expand(&workspace->a, rho_prime, parameters);

reject_with_rounding:
        crypto_haetae_polyvecmk_uniform_eta(
            &workspace->s1, &workspace->s2, sigma, nonce, parameters);
        nonce = (uint16_t)(nonce + parameters->l - 1u + parameters->k);

        workspace->s1_hat = workspace->s1;
        crypto_haetae_polyvecm_ntt(&workspace->s1_hat, parameters);
        crypto_haetae_polymatkm_pointwise_montgomery(
            &workspace->b, workspace->matrix, &workspace->s1_hat,
            parameters);
        crypto_haetae_polyveck_invntt_tomont(&workspace->b, parameters);
        crypto_haetae_polyveck_add(
            &workspace->b, &workspace->b, &workspace->s2, parameters);
        crypto_haetae_polyveck_add(
            &workspace->b, &workspace->b, &workspace->a, parameters);
        crypto_haetae_polyveck_freeze(&workspace->b, parameters);
        crypto_haetae_polyveck_decompose_vk(
            &workspace->b0, &workspace->b, parameters);
        crypto_haetae_polyveck_sub(
            &workspace->s2, &workspace->s2, &workspace->b0, parameters);

        squared_singular_value = crypto_haetae_polyvecmk_sqsing_value(
            &workspace->s1, &workspace->s2, parameters);
        if ((double)squared_singular_value >
            parameters->gamma * parameters->gamma *
                (double)CRYPTO_HAETAE_N) {
            goto reject_with_rounding;
        }
    } else {
reject_without_rounding:
        crypto_haetae_polyvecmk_uniform_eta(
            &workspace->s1, &workspace->s2, sigma, nonce, parameters);
        nonce = (uint16_t)(nonce + parameters->l - 1u + parameters->k);
        squared_singular_value = crypto_haetae_polyvecmk_sqsing_value(
            &workspace->s1, &workspace->s2, parameters);
        if ((double)squared_singular_value >
            parameters->gamma * parameters->gamma *
                (double)CRYPTO_HAETAE_N) {
            goto reject_without_rounding;
        }

        workspace->s1_hat = workspace->s1;
        workspace->s2_hat = workspace->s2;
        crypto_haetae_polyvecm_ntt(&workspace->s1_hat, parameters);
        crypto_haetae_polyveck_ntt(&workspace->s2_hat, parameters);
        crypto_haetae_polymatkm_pointwise_montgomery(
            &workspace->b, workspace->matrix, &workspace->s1_hat,
            parameters);
        crypto_haetae_polyveck_frommont(&workspace->b, parameters);
        crypto_haetae_polyveck_add(
            &workspace->b, &workspace->b, &workspace->s2_hat, parameters);
        crypto_haetae_polyveck_double_negate(&workspace->b, parameters);
        crypto_haetae_polyveck_caddq(&workspace->b, parameters);
    }

    crypto_haetae_pack_pk(
        public_key, &workspace->b, rho_prime, parameters);
    crypto_haetae_pack_sk(
        private_key, public_key, &workspace->s1, &workspace->s2, key,
        parameters);
    result = CRYPTO_SUCCESS;

cleanup:
    crypto_sha3_clear(&hash_context);
    crypto_zeroize(seed_buffer, sizeof(seed_buffer));
    crypto_zeroize(workspace, sizeof(*workspace));
    free(workspace);
    return result;
}

typedef struct crypto_haetae_sign_workspace {
    uint8_t buffer[CRYPTO_HAETAE_MAX_HIGH_BITS_BUFFER_BYTES +
                   CRYPTO_HAETAE_POLY_CHALLENGE_PACKED_BYTES];
    crypto_haetae_polyvecm s1;
    crypto_haetae_polyvecl cs1;
    crypto_haetae_polyveck s2;
    crypto_haetae_polyveck cs2;
    crypto_haetae_polyveck high_bits;
    crypto_haetae_polyveck ay;
    crypto_haetae_polyvecl a1[CRYPTO_HAETAE_MAX_K];
    crypto_haetae_polyfixvecl y1;
    crypto_haetae_polyfixvecl z1;
    crypto_haetae_polyfixvecl z1_temporary;
    crypto_haetae_polyfixveck y2;
    crypto_haetae_polyfixveck z2;
    crypto_haetae_polyfixveck z2_temporary;
    crypto_haetae_polyvecl z1_rounded;
    crypto_haetae_polyvecl z1_high_bits;
    crypto_haetae_polyvecl z1_low_bits;
    crypto_haetae_polyveck z2_rounded;
    crypto_haetae_polyveck hint;
    crypto_haetae_polyveck hint_temporary;
} crypto_haetae_sign_workspace;

CryptoError crypto_haetae_sign_core(
    uint8_t *sig,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pre,
    size_t prelen,
    const uint8_t rnd[CRYPTO_HAETAE_SEED_BYTES],
    const uint8_t *sk,
    const crypto_haetae_parameters *parameters) {
    crypto_haetae_sign_workspace *workspace;
	const size_t haetae_polyveck_highbits_packedbytes =
        parameters->polyveck_high_bits_packed_bytes;
	const size_t haetae_pk_size = parameters->public_key_bytes;

	const double haetae_B0 = parameters->b0;
	const double haetae_B1 = parameters->b1;
	const uint64_t haetae_B0SQ = (uint64_t)(haetae_B0 * haetae_B0);
	const uint64_t haetae_B1SQ = (uint64_t)(haetae_B1 * haetae_B1);

	const uint32_t haetae_l = parameters->l;

	uint8_t seedbuf[CRYPTO_HAETAE_CRH_BYTES] = { 0 }, key[CRYPTO_HAETAE_SEED_BYTES] = { 0 };
	uint8_t mu[CRYPTO_HAETAE_CRH_BYTES] = { 0 };
	uint8_t b = 0;                  // one bit
	uint16_t counter = 0;
	uint64_t reject1, reject2;
	uint8_t *buf;
	crypto_haetae_polyvecm *s1;
	crypto_haetae_polyvecl *cs1;
	crypto_haetae_polyveck *s2;
	crypto_haetae_polyveck *cs2;
	crypto_haetae_polyveck *highbits;
	crypto_haetae_polyveck *Ay;
	crypto_haetae_polyvecl *A1;
	crypto_haetae_polyfixvecl *y1;
	crypto_haetae_polyfixvecl *z1;
	crypto_haetae_polyfixvecl *z1tmp;
	crypto_haetae_polyfixveck *y2;
	crypto_haetae_polyfixveck *z2;
	crypto_haetae_polyfixveck *z2tmp;
	crypto_haetae_polyvecl *z1rnd;
	crypto_haetae_polyvecl *hb_z1;
	crypto_haetae_polyvecl *lb_z1;
	crypto_haetae_polyveck *z2rnd;
	crypto_haetae_polyveck *h;
	crypto_haetae_polyveck *htmp;
	crypto_haetae_poly c, chat, z1rnd0, lsb;

	crypto_sha3_context context = {0};

	uint32_t i;

	workspace = calloc(1u, sizeof(*workspace));
	if (workspace == NULL) {
		return CRYPTO_ERROR_ALLOCATION_FAILED;
	}
	buf = workspace->buffer;
	s1 = &workspace->s1;
	cs1 = &workspace->cs1;
	s2 = &workspace->s2;
	cs2 = &workspace->cs2;
	highbits = &workspace->high_bits;
	Ay = &workspace->ay;
	A1 = workspace->a1;
	y1 = &workspace->y1;
	z1 = &workspace->z1;
	z1tmp = &workspace->z1_temporary;
	y2 = &workspace->y2;
	z2 = &workspace->z2;
	z2tmp = &workspace->z2_temporary;
	z1rnd = &workspace->z1_rounded;
	hb_z1 = &workspace->z1_high_bits;
	lb_z1 = &workspace->z1_low_bits;
	z2rnd = &workspace->z2_rounded;
	h = &workspace->hint;
	htmp = &workspace->hint_temporary;


	// Unpack secret key
	crypto_haetae_unpack_sk(A1, s1, s2, key, sk, parameters);

	// mu = H_gen(seed_A, b1, M)
	crypto_shake256_init(&context);
    crypto_sha3_update(&context, sk, haetae_pk_size);
	crypto_sha3_update(&context, pre, prelen);
    crypto_sha3_update(&context, m, mlen);
    crypto_sha3_finalize(&context);

	crypto_sha3_squeeze(&context, mu, CRYPTO_HAETAE_CRH_BYTES);

	crypto_sha3_clear(&context);

	// seed_ybb = H_gen(K, mu)
	crypto_shake256_init(&context);
    crypto_sha3_update(&context, key, CRYPTO_HAETAE_SEED_BYTES);
	crypto_sha3_update(&context, rnd, CRYPTO_HAETAE_SEED_BYTES);
    crypto_sha3_update(&context, mu, CRYPTO_HAETAE_CRH_BYTES);
    crypto_sha3_finalize(&context);

	crypto_sha3_squeeze(&context, seedbuf, CRYPTO_HAETAE_CRH_BYTES);

	crypto_sha3_clear(&context);

	crypto_haetae_polyvecm_ntt(s1, parameters);
	crypto_haetae_polyveck_ntt(s2, parameters);

reject:

	/*------------------ 1. Sample y1 and y2 from hyperball ------------------*/
	counter = crypto_haetae_polyfixveclk_sample_hyperball(y1, y2, &b, seedbuf, counter, parameters);

	/*------------------- 2. Compute a chanllenge c --------------------------*/
	// Round y1 and y2
	crypto_haetae_polyfixvecl_round(z1rnd, y1, parameters);
	crypto_haetae_polyfixveck_round(z2rnd, y2, parameters);

	// A * round(y) mod q = A1 * round(y1) + 2 * round(y2) mod q
	z1rnd0 = z1rnd->vec[0];
	crypto_haetae_polyvecl_ntt(z1rnd, parameters);
	crypto_haetae_polymatkl_pointwise_montgomery(Ay, A1, z1rnd, parameters);
	crypto_haetae_polyveck_invntt_tomont(Ay, parameters);
	crypto_haetae_polyveck_double(z2rnd, parameters);
	crypto_haetae_polyveck_add(Ay, Ay, z2rnd, parameters);

	// recover A * round(y) mod 2q
	crypto_haetae_polyveck_poly_fromcrt(Ay, Ay, &z1rnd0, parameters);
	crypto_haetae_polyveck_freeze2q(Ay, parameters);


	// HighBits of (A * round(y) mod 2q)
	crypto_haetae_polyveck_highbits_hint(highbits, Ay, parameters);

	// LSB(round(y_0) * j)
	crypto_haetae_poly_lsb(&lsb, &z1rnd0);

	// Pack HighBits of A * round(y) mod 2q and LSB of round(y0)
	crypto_haetae_polyveck_pack_highbits(buf, highbits, parameters);
	crypto_haetae_poly_pack_lsb(buf + haetae_polyveck_highbits_packedbytes, &lsb);


	// c = challenge(highbits, lsb, mu)
	crypto_haetae_poly_challenge(&c, buf, mu, parameters);

	/*------------------- 3. Compute z = y + (-1)^b c * s --------------------*/
	// cs = c * s = c * (si1 || s2)
	cs1->vec[0] = c;
	chat = c;
	crypto_haetae_poly_ntt(&chat);

	for (i = 1; i < haetae_l; ++i) {
		crypto_haetae_poly_pointwise_montgomery(&(cs1->vec[i]), &chat, &(s1->vec[i - 1]));
		crypto_haetae_poly_invntt_tomont(&(cs1->vec[i]));
	}
	crypto_haetae_polyveck_poly_pointwise_montgomery(cs2, s2, &chat, parameters);
	crypto_haetae_polyveck_invntt_tomont(cs2, parameters);

	// z = y + (-1)^b cs = z1 + z2
	crypto_haetae_polyvecl_cneg(cs1, b & 1, parameters);
	crypto_haetae_polyveck_cneg(cs2, b & 1, parameters);
	crypto_haetae_polyfixvecl_add(z1, y1, cs1, parameters);
	crypto_haetae_polyfixveck_add(z2, y2, cs2, parameters);

	// reject if norm(z) >= B'
	reject1 = (((uint64_t)haetae_B1SQ) * CRYPTO_HAETAE_LARGE_N * CRYPTO_HAETAE_LARGE_N - crypto_haetae_polyfixveclk_sqnorm2(z1, z2, parameters)) >> 63;
	reject1 &= 1;

	crypto_haetae_polyfixvecl_double(z1tmp, z1, parameters);
	crypto_haetae_polyfixveck_double(z2tmp, z2, parameters);

	crypto_haetae_polyfixfixvecl_sub(z1tmp, z1tmp, y1, parameters);
	crypto_haetae_polyfixfixveck_sub(z2tmp, z2tmp, y2, parameters);

	// reject if norm(2z-y) < B and b' = 0
	reject2 =
		(crypto_haetae_polyfixveclk_sqnorm2(z1tmp, z2tmp, parameters) - ((uint64_t)haetae_B0SQ) * CRYPTO_HAETAE_LARGE_N * CRYPTO_HAETAE_LARGE_N) >> 63;
	reject2 &= 1;
	reject2 &= (b & 0x2) >> 1;
	if (reject1 | reject2) {
		goto reject;
	}

	/*------------------- 4. Make a hint -------------------------------------*/
	// Round z1 and z2
	crypto_haetae_polyfixvecl_round(z1rnd, z1, parameters);
	crypto_haetae_polyfixveck_round(z2rnd, z2, parameters);

	// recover A1 * round(z1) - qcj mod 2q
	crypto_haetae_polyveck_double(z2rnd, parameters);
	crypto_haetae_polyveck_sub(htmp, Ay, z2rnd, parameters);
	crypto_haetae_polyveck_freeze2q(htmp, parameters);

	// HighBits of (A * round(z) - qcj mod 2q) and (A1 * round(z1) - qcj mod 2q)
	crypto_haetae_polyveck_highbits_hint(htmp, htmp, parameters);
	crypto_haetae_polyveck_sub(h, highbits, htmp, parameters);
	crypto_haetae_polyveck_caddDQ2ALPHA(h, parameters);

	/*------------------ Decompose(z1) and Pack signature -------------------*/
	crypto_haetae_polyvecl_lowbits(lb_z1, z1rnd, parameters);
	crypto_haetae_polyvecl_highbits(hb_z1, z1rnd, parameters);

	if (crypto_haetae_pack_sig(sig, &c, lb_z1, hb_z1, h, parameters))
	{ // reject if signature is too big
		goto reject;
	}

	crypto_sha3_clear(&context);
	crypto_zeroize(seedbuf, sizeof(seedbuf));
	crypto_zeroize(key, sizeof(key));
	crypto_zeroize(mu, sizeof(mu));
	crypto_zeroize(&c, sizeof(c));
	crypto_zeroize(&chat, sizeof(chat));
	crypto_zeroize(&z1rnd0, sizeof(z1rnd0));
	crypto_zeroize(&lsb, sizeof(lsb));
	crypto_zeroize(workspace, sizeof(*workspace));
	free(workspace);
	return CRYPTO_SUCCESS;
}

typedef struct crypto_haetae_verify_workspace {
    uint8_t buffer[CRYPTO_HAETAE_MAX_HIGH_BITS_BUFFER_BYTES +
                   CRYPTO_HAETAE_POLY_CHALLENGE_PACKED_BYTES];
    crypto_haetae_polyvecl a1[CRYPTO_HAETAE_MAX_K];
    crypto_haetae_polyvecl z1;
    crypto_haetae_polyveck b;
    crypto_haetae_polyveck high_bits;
    crypto_haetae_polyveck hint;
    crypto_haetae_polyveck z2;
    crypto_haetae_polyveck w;
    crypto_haetae_polyveck a;
    crypto_haetae_poly challenge;
    crypto_haetae_poly challenge_prime;
    crypto_haetae_poly w_prime;
} crypto_haetae_verify_workspace;

CryptoError crypto_haetae_verify_core(
    const uint8_t *signature,
    size_t signature_length,
    const uint8_t *message,
    size_t message_length,
    const uint8_t *prefix,
    size_t prefix_length,
    const uint8_t *public_key,
    const crypto_haetae_parameters *parameters) {
    crypto_haetae_verify_workspace *workspace;
    crypto_sha3_context hash_context = {0};
    uint8_t rho_prime[CRYPTO_HAETAE_SEED_BYTES] = {0};
    uint8_t mu[CRYPTO_HAETAE_SEED_BYTES] = {0};
    uint64_t squared_norm;
    uint64_t b2_squared = (uint64_t)(parameters->b2 * parameters->b2);
    size_t high_bits_bytes = parameters->polyveck_high_bits_packed_bytes;
    uint32_t index;
    CryptoError result = CRYPTO_ERROR_SIGNATURE_INVALID;

    if (signature_length != parameters->signature_bytes) {
        return CRYPTO_ERROR_SIGNATURE_INVALID;
    }

    workspace = calloc(1u, sizeof(*workspace));
    if (workspace == NULL) {
        return CRYPTO_ERROR_ALLOCATION_FAILED;
    }

    crypto_haetae_unpack_pk(
        &workspace->b, rho_prime, public_key, parameters);
    if (crypto_haetae_unpack_sig(
            &workspace->challenge, workspace->a1, &workspace->z1,
            &workspace->hint, signature, parameters) != 0) {
        goto cleanup;
    }

    for (index = 0u; index < parameters->l; ++index) {
        crypto_haetae_poly_compose(
            &workspace->z1.vec[index], &workspace->z1.vec[index],
            &workspace->a1[0].vec[index]);
    }

    crypto_haetae_polymatkl_expand(
        workspace->a1, rho_prime, parameters);
    crypto_haetae_polymatkl_double(workspace->a1, parameters);

    if (parameters->d != 0u) {
        crypto_haetae_polyveck_expand(
            &workspace->a, rho_prime, parameters);
        crypto_haetae_polyveck_double(&workspace->b, parameters);
        crypto_haetae_polyveck_sub(
            &workspace->b, &workspace->a, &workspace->b, parameters);
        crypto_haetae_polyveck_double(&workspace->b, parameters);
        crypto_haetae_polyveck_ntt(&workspace->b, parameters);
    }

    for (index = 0u; index < parameters->k; ++index) {
        workspace->a1[index].vec[0] = workspace->b.vec[index];
    }

    squared_norm = crypto_haetae_polyvecl_sqnorm2(
        &workspace->z1, parameters);
    crypto_haetae_poly_sub(
        &workspace->w_prime, &workspace->z1.vec[0],
        &workspace->challenge);
    crypto_haetae_poly_lsb(&workspace->w_prime, &workspace->w_prime);

    crypto_haetae_polyvecl_ntt(&workspace->z1, parameters);
    crypto_haetae_polymatkl_pointwise_montgomery(
        &workspace->high_bits, workspace->a1, &workspace->z1, parameters);
    crypto_haetae_polyveck_invntt_tomont(
        &workspace->high_bits, parameters);
    crypto_haetae_polyveck_poly_fromcrt(
        &workspace->high_bits, &workspace->high_bits,
        &workspace->w_prime, parameters);
    crypto_haetae_polyveck_freeze2q(&workspace->high_bits, parameters);

    crypto_haetae_polyveck_highbits_hint(
        &workspace->w, &workspace->high_bits, parameters);
    crypto_haetae_polyveck_add(
        &workspace->w, &workspace->w, &workspace->hint, parameters);
    crypto_haetae_polyveck_csubDQ2ALPHA(&workspace->w, parameters);

    crypto_haetae_polyveck_mul_alpha(
        &workspace->z2, &workspace->w, parameters);
    crypto_haetae_polyveck_sub(
        &workspace->z2, &workspace->z2, &workspace->high_bits,
        parameters);
    crypto_haetae_poly_add(
        &workspace->z2.vec[0], &workspace->z2.vec[0],
        &workspace->w_prime);
    crypto_haetae_polyveck_reduce2q(&workspace->z2, parameters);
    crypto_haetae_polyveck_div2(&workspace->z2, parameters);

    if (squared_norm +
            crypto_haetae_polyveck_sqnorm2(&workspace->z2, parameters) >
        b2_squared) {
        goto cleanup;
    }

    crypto_haetae_polyveck_pack_highbits(
        workspace->buffer, &workspace->w, parameters);
    crypto_haetae_poly_pack_lsb(
        workspace->buffer + high_bits_bytes, &workspace->w_prime);

    crypto_shake256_init(&hash_context);
    crypto_sha3_update(
        &hash_context, public_key, parameters->public_key_bytes);
    crypto_sha3_update(&hash_context, prefix, prefix_length);
    crypto_sha3_update(&hash_context, message, message_length);
    crypto_sha3_finalize(&hash_context);
    crypto_sha3_squeeze(&hash_context, mu, sizeof(mu));
    crypto_sha3_clear(&hash_context);

    crypto_haetae_poly_challenge(
        &workspace->challenge_prime, workspace->buffer, mu, parameters);
    if (crypto_pqc_verify(
            (const uint8_t *)workspace->challenge.coeffs,
            (const uint8_t *)workspace->challenge_prime.coeffs,
            sizeof(workspace->challenge.coeffs)) == 0) {
        result = CRYPTO_SUCCESS;
    }

cleanup:
    crypto_sha3_clear(&hash_context);
    crypto_zeroize(rho_prime, sizeof(rho_prime));
    crypto_zeroize(mu, sizeof(mu));
    crypto_zeroize(workspace, sizeof(*workspace));
    free(workspace);
    return result;
}

size_t crypto_haetae_public_key_size_internal(AlgID alg) {
    const crypto_haetae_parameters *parameters =
        crypto_haetae_parameters_from_algorithm(alg);
    return parameters != NULL ? parameters->public_key_bytes : 0u;
}

size_t crypto_haetae_private_key_size_internal(AlgID alg) {
    const crypto_haetae_parameters *parameters =
        crypto_haetae_parameters_from_algorithm(alg);
    return parameters != NULL ? parameters->private_key_bytes : 0u;
}

size_t crypto_haetae_signature_size_internal(AlgID alg) {
    const crypto_haetae_parameters *parameters =
        crypto_haetae_parameters_from_algorithm(alg);
    return parameters != NULL ? parameters->signature_bytes : 0u;
}

CryptoError crypto_haetae_keygen_internal(
    AlgID alg,
    uint8_t *public_key,
    size_t public_key_length,
    uint8_t *private_key,
    size_t private_key_length) {
    const crypto_haetae_parameters *parameters =
        crypto_haetae_parameters_from_algorithm(alg);
    CryptoError result;

    if (parameters == NULL) {
        return CRYPTO_ERROR_INVALID_ALG_ID;
    }
    if (public_key == NULL || private_key == NULL) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    if (public_key_length < parameters->public_key_bytes ||
        private_key_length < parameters->private_key_bytes) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(
            public_key, parameters->public_key_bytes,
            private_key, parameters->private_key_bytes) != 0) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }

    result = crypto_haetae_keygen_core(
        public_key, private_key, parameters);
    if (result != CRYPTO_SUCCESS) {
        crypto_zeroize(public_key, parameters->public_key_bytes);
        crypto_zeroize(private_key, parameters->private_key_bytes);
    }
    return result;
}

CryptoError crypto_haetae_sign_internal(
    AlgID alg,
    const uint8_t *private_key,
    size_t private_key_length,
    const uint8_t *message,
    size_t message_length,
    const uint8_t *context,
    size_t context_length,
    uint8_t *signature,
    size_t signature_length) {
    const crypto_haetae_parameters *parameters =
        crypto_haetae_parameters_from_algorithm(alg);
    uint8_t prefix[256] = {0};
    uint8_t randomness[CRYPTO_HAETAE_SEED_BYTES] = {0};
    CryptoError result;

    if (parameters == NULL) {
        return CRYPTO_ERROR_INVALID_ALG_ID;
    }
    if (private_key == NULL || signature == NULL ||
        (message == NULL && message_length != 0u) ||
        (context == NULL && context_length != 0u)) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    if (context_length > 255u) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    if (private_key_length != parameters->private_key_bytes) {
        return CRYPTO_ERROR_INVALID_KEY;
    }
    if (signature_length < parameters->signature_bytes) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(
            signature, parameters->signature_bytes,
            private_key, parameters->private_key_bytes) != 0 ||
        crypto_ranges_overlap(
            signature, parameters->signature_bytes,
            message, message_length) != 0 ||
        crypto_ranges_overlap(
            signature, parameters->signature_bytes,
            context, context_length) != 0) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }

    prefix[0] = (uint8_t)context_length;
    if (context_length != 0u) {
        memcpy(prefix + 1u, context, context_length);
    }

    result = crypto_pqc_random_bytes_internal(
        randomness, CRYPTO_HAETAE_SEED_BYTES);
    if (result == CRYPTO_SUCCESS) {
        result = crypto_haetae_sign_core(
            signature, message, message_length, prefix, context_length + 1u,
            randomness, private_key, parameters);
    }
    if (result != CRYPTO_SUCCESS) {
        crypto_zeroize(signature, parameters->signature_bytes);
    }
    crypto_zeroize(prefix, sizeof(prefix));
    crypto_zeroize(randomness, sizeof(randomness));
    return result;
}

CryptoError crypto_haetae_verify_internal(
    AlgID alg,
    const uint8_t *public_key,
    size_t public_key_length,
    const uint8_t *message,
    size_t message_length,
    const uint8_t *context,
    size_t context_length,
    const uint8_t *signature,
    size_t signature_length) {
    const crypto_haetae_parameters *parameters =
        crypto_haetae_parameters_from_algorithm(alg);
    uint8_t prefix[256] = {0};
    CryptoError result;

    if (parameters == NULL) {
        return CRYPTO_ERROR_INVALID_ALG_ID;
    }
    if (public_key == NULL || signature == NULL ||
        (message == NULL && message_length != 0u) ||
        (context == NULL && context_length != 0u)) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    if (context_length > 255u) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    if (public_key_length != parameters->public_key_bytes) {
        return CRYPTO_ERROR_INVALID_KEY;
    }
    if (signature_length != parameters->signature_bytes) {
        return CRYPTO_ERROR_SIGNATURE_INVALID;
    }

    prefix[0] = (uint8_t)context_length;
    if (context_length != 0u) {
        memcpy(prefix + 1u, context, context_length);
    }
    result = crypto_haetae_verify_core(
        signature, signature_length, message, message_length,
        prefix, context_length + 1u, public_key, parameters);
    crypto_zeroize(prefix, sizeof(prefix));
    return result;
}
