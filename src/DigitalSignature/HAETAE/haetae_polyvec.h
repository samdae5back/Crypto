// SPDX-License-Identifier: MIT

#ifndef _HAETAE_POLYVEC_H_
#define _HAETAE_POLYVEC_H_


#include "haetae.h"


void crypto_haetae_polyveck_add(crypto_haetae_polyveck *w, const crypto_haetae_polyveck *u, const crypto_haetae_polyveck *v,
                         const crypto_haetae_parameters *parameters);
void crypto_haetae_polyveck_sub(crypto_haetae_polyveck *w, const crypto_haetae_polyveck *u, const crypto_haetae_polyveck *v,
                         const crypto_haetae_parameters *parameters);
void crypto_haetae_polyveck_double(crypto_haetae_polyveck *b, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_reduce2q(crypto_haetae_polyveck *v, const crypto_haetae_parameters *parameters);
void crypto_haetae_polyveck_freeze(crypto_haetae_polyveck *v, const crypto_haetae_parameters *parameters);
void crypto_haetae_polyveck_freeze2q(crypto_haetae_polyveck *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_expand(crypto_haetae_polyveck *v, const uint8_t  seed[CRYPTO_HAETAE_SEED_BYTES],
                     const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_double_negate(crypto_haetae_polyveck *x, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_frommont(crypto_haetae_polyveck *x, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_poly_pointwise_montgomery(crypto_haetae_polyveck *w, const crypto_haetae_polyveck *u,
                                        const crypto_haetae_poly *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_poly_fromcrt(crypto_haetae_polyveck *w, const crypto_haetae_polyveck *u,
                           const crypto_haetae_poly *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_highbits_hint(crypto_haetae_polyveck *w, const crypto_haetae_polyveck *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_pack_highbits(uint8_t  *buf, const crypto_haetae_polyveck *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_cneg(crypto_haetae_polyveck *v, const uint8_t  b, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_caddDQ2ALPHA(crypto_haetae_polyveck *h, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_csubDQ2ALPHA(crypto_haetae_polyveck *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_mul_alpha(crypto_haetae_polyveck *v, const crypto_haetae_polyveck *u, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_div2(crypto_haetae_polyveck *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_caddq(crypto_haetae_polyveck *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_decompose_vk(crypto_haetae_polyveck *v0, crypto_haetae_polyveck *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_ntt(crypto_haetae_polyveck *x, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyveck_invntt_tomont(crypto_haetae_polyveck *x, const crypto_haetae_parameters *parameters);

uint64_t crypto_haetae_polyveck_sqnorm2(const crypto_haetae_polyveck *b, const crypto_haetae_parameters *parameters);


void crypto_haetae_polyvecl_highbits(crypto_haetae_polyvecl *v2, const crypto_haetae_polyvecl *v, const crypto_haetae_parameters *parameters);
void crypto_haetae_polyvecl_lowbits(crypto_haetae_polyvecl *v2, const crypto_haetae_polyvecl *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyvecl_cneg(crypto_haetae_polyvecl *v, const uint8_t  b, const crypto_haetae_parameters *parameters);

uint64_t crypto_haetae_polyvecl_sqnorm2(const crypto_haetae_polyvecl *a, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyvecl_pointwise_acc_montgomery(crypto_haetae_poly *w,
                                              const crypto_haetae_polyvecl *u, const crypto_haetae_polyvecl *v,
                                              const crypto_haetae_parameters *parameters);

void crypto_haetae_polyvecl_ntt(crypto_haetae_polyvecl *x, const crypto_haetae_parameters *parameters);


void crypto_haetae_polyvecm_pointwise_acc_montgomery(crypto_haetae_poly *w,
                                       const crypto_haetae_polyvecm *u, const crypto_haetae_polyvecm *v,
                                       const crypto_haetae_parameters *parameters);

void crypto_haetae_polyvecm_ntt(crypto_haetae_polyvecm *x, const crypto_haetae_parameters *parameters);

uint64_t crypto_haetae_polyvecmk_sqsing_value(
    const crypto_haetae_polyvecm *s1,
    const crypto_haetae_polyveck *s2,
    const crypto_haetae_parameters *parameters);

long long crypto_haetae_polyvecmk_sing_value(const crypto_haetae_polyvecm *s1, const crypto_haetae_polyveck *s2, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyvecmk_uniform_eta(crypto_haetae_polyvecm *u, crypto_haetae_polyveck *v,
                           const uint8_t  seed[CRYPTO_HAETAE_CRH_BYTES], uint16_t nonce,
                           const crypto_haetae_parameters *parameters);


#endif /* _HAETAE_POLYVEC_H_ */
