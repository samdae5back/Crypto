// SPDX-License-Identifier: MIT

#ifndef _HAETAE_POLY_H_
#define _HAETAE_POLY_H_


#include "haetae.h"

void crypto_haetae_poly_add(crypto_haetae_poly *c, const crypto_haetae_poly *a, const crypto_haetae_poly *b);
void crypto_haetae_poly_sub(crypto_haetae_poly *c, const crypto_haetae_poly *a, const crypto_haetae_poly *b);
void crypto_haetae_poly_pointwise_montgomery(crypto_haetae_poly *c, const crypto_haetae_poly *a, const crypto_haetae_poly *b);

void crypto_haetae_poly_reduce2q(crypto_haetae_poly *a);
void crypto_haetae_poly_freeze2q(crypto_haetae_poly *a);
void crypto_haetae_poly_freeze(crypto_haetae_poly *a);

void crypto_haetae_poly_highbits(crypto_haetae_poly *a2, const crypto_haetae_poly *a);
void crypto_haetae_poly_lowbits(crypto_haetae_poly *a1, const crypto_haetae_poly *a);
void crypto_haetae_poly_compose(crypto_haetae_poly *a, const crypto_haetae_poly *ha, const crypto_haetae_poly *la);
void crypto_haetae_poly_lsb(crypto_haetae_poly *a0, const crypto_haetae_poly *a);

void crypto_haetae_poly_uniform(crypto_haetae_poly *a, const uint8_t  seed[CRYPTO_HAETAE_SEED_BYTES], uint16_t nonce);
void crypto_haetae_poly_uniform_eta(crypto_haetae_poly *a, const uint8_t  seed[CRYPTO_HAETAE_CRH_BYTES], uint16_t nonce);
void crypto_haetae_poly_challenge(crypto_haetae_poly *c,
                           const uint8_t  highbits_lsb[CRYPTO_HAETAE_MAX_HIGH_BITS_BUFFER_BYTES + CRYPTO_HAETAE_POLY_CHALLENGE_PACKED_BYTES],
                           const uint8_t  mu[CRYPTO_HAETAE_SEED_BYTES],
                           const crypto_haetae_parameters *parameters);

void crypto_haetae_poly_decomposed_pack(uint8_t  *buf, const crypto_haetae_poly *a);
void crypto_haetae_poly_decomposed_unpack(crypto_haetae_poly *a, const uint8_t  *buf);

void crypto_haetae_poly_pack_highbits(uint8_t  *buf, const crypto_haetae_poly *a, const crypto_haetae_parameters *parameters);
void crypto_haetae_poly_pack_lsb(uint8_t  *buf, const crypto_haetae_poly *a);

void crypto_haetae_polyq_pack(uint8_t  *r, const crypto_haetae_poly *a, const crypto_haetae_parameters *parameters);
void crypto_haetae_polyq_unpack(crypto_haetae_poly *r, const uint8_t  *a, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyeta_pack(uint8_t  *r, const crypto_haetae_poly *a);
void crypto_haetae_polyeta_unpack(crypto_haetae_poly *r, const uint8_t  *a);
void crypto_haetae_poly2eta_pack(uint8_t  *r, const crypto_haetae_poly *a);
void crypto_haetae_poly2eta_unpack(crypto_haetae_poly *r, const uint8_t  *a);

void crypto_haetae_poly_fromcrt(crypto_haetae_poly *w, const crypto_haetae_poly *u, const crypto_haetae_poly *v);
void crypto_haetae_poly_fromcrt0(crypto_haetae_poly *w, const crypto_haetae_poly *u);

void crypto_haetae_poly_ntt(crypto_haetae_poly *a);
void crypto_haetae_poly_invntt_tomont(crypto_haetae_poly *a);

#endif /* _HAETAE_POLY_H_ */
