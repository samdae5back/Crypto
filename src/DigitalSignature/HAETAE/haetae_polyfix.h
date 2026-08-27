// SPDX-License-Identifier: MIT

#ifndef HAETAE_POLYFIX_H
#define HAETAE_POLYFIX_H


#include "haetae.h"

typedef struct {
    int coeffs[CRYPTO_HAETAE_N];
} crypto_haetae_polyfix;

void crypto_haetae_polyfix_round(crypto_haetae_poly *a, const crypto_haetae_polyfix *b);

void crypto_haetae_polyfix_add(crypto_haetae_polyfix *c, const crypto_haetae_polyfix *a, const crypto_haetae_poly *b);

typedef struct {
    crypto_haetae_polyfix vec[CRYPTO_HAETAE_MAX_K];
} crypto_haetae_polyfixveck;

void crypto_haetae_polyfixveck_add(crypto_haetae_polyfixveck *w, const crypto_haetae_polyfixveck *u,
                     const crypto_haetae_polyveck *v, const crypto_haetae_parameters *parameters);
void crypto_haetae_polyfixfixveck_sub(crypto_haetae_polyfixveck *w, const crypto_haetae_polyfixveck *u,
                        const crypto_haetae_polyfixveck *v, const crypto_haetae_parameters *parameters);
void crypto_haetae_polyfixveck_double(crypto_haetae_polyfixveck *b, const crypto_haetae_polyfixveck *a, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyfixveck_round(crypto_haetae_polyveck *a, const crypto_haetae_polyfixveck *b, const crypto_haetae_parameters *parameters);

typedef struct {
    crypto_haetae_polyfix vec[CRYPTO_HAETAE_MAX_L];
} crypto_haetae_polyfixvecl;

void crypto_haetae_polyfixvecl_add(crypto_haetae_polyfixvecl *w, const crypto_haetae_polyfixvecl *u,
                     const crypto_haetae_polyvecl *v, const crypto_haetae_parameters *parameters);
void crypto_haetae_polyfixfixvecl_sub(crypto_haetae_polyfixvecl *w, const crypto_haetae_polyfixvecl *u,
                        const crypto_haetae_polyfixvecl *v, const crypto_haetae_parameters *parameters);
void crypto_haetae_polyfixvecl_double(crypto_haetae_polyfixvecl *b, const crypto_haetae_polyfixvecl *a, const crypto_haetae_parameters *parameters);

void crypto_haetae_polyfixvecl_round(crypto_haetae_polyvecl *a, const crypto_haetae_polyfixvecl *b, const crypto_haetae_parameters *parameters);



uint64_t crypto_haetae_polyfixveclk_sqnorm2(const crypto_haetae_polyfixvecl *a, const crypto_haetae_polyfixveck *b,
                              const crypto_haetae_parameters *parameters);

uint16_t crypto_haetae_polyfixveclk_sample_hyperball(crypto_haetae_polyfixvecl *y1, crypto_haetae_polyfixveck *y2,
                                  uint8_t  *b, const uint8_t  seed[CRYPTO_HAETAE_CRH_BYTES],
                                  const uint16_t nonce,
                                  const crypto_haetae_parameters *parameters);

#endif /* HAETAE_POLYFIX_H */
