// SPDX-License-Identifier: MIT

#include "haetae_poly.h"
#include "haetae_polyvec.h"
#include "haetae_polymat.h"

/*************************************************
 * Name:        polymat_expand
 *
 * Description: Implementation of ExpandA. Generates matrix A with uniformly
 *              random coefficients a_{i,j} by performing rejection
 *              sampling on the output stream of SHAKE128(rho|j|i)
 *              or AES256CTR(rho,j|i).
 *
 * Arguments:   - crypto_haetae_polyvecm mat[K]: output matrix k \times m
 *              - const uint8_t  rho[]: byte array containing seed rho
 **************************************************/
void crypto_haetae_polymatkl_expand(crypto_haetae_polyvecl mat[CRYPTO_HAETAE_MAX_K],
                      const uint8_t  rho[CRYPTO_HAETAE_SEED_BYTES],
                      const crypto_haetae_parameters *parameters) {
    uint32_t i, j;
    const uint32_t haetae_k = parameters->k;
    const uint32_t haetae_m = parameters->l - 1u;

    for (i = 0; i < haetae_k; ++i)
        for (j = 0; j < haetae_m; ++j)
            crypto_haetae_poly_uniform(
                &mat[i].vec[j + 1u], rho,
                (uint16_t)((i << 8) + j));
}

/*************************************************
 * Name:        polymat_expand
 *
 * Description: Implementation of ExpandA. Generates matrix A with uniformly
 *              random coefficients a_{i,j} by performing rejection
 *              sampling on the output stream of SHAKE128(rho|j|i)
 *              or AES256CTR(rho,j|i).
 *
 * Arguments:   - crypto_haetae_polyvecm mat[K]: output matrix k \times m
 *              - const uint8_t  rho[]: byte array containing seed rho
 **************************************************/
void crypto_haetae_polymatkm_expand(crypto_haetae_polyvecm mat[CRYPTO_HAETAE_MAX_K],
                      const uint8_t  rho[CRYPTO_HAETAE_SEED_BYTES],
                      const crypto_haetae_parameters *parameters) {
    uint32_t i, j;
    const uint32_t haetae_k = parameters->k;
    const uint32_t haetae_m = parameters->l - 1u;

    for (i = 0; i < haetae_k; ++i)
        for (j = 0; j < haetae_m; ++j)
            crypto_haetae_poly_uniform(
                &mat[i].vec[j], rho,
                (uint16_t)((i << 8) + j));
}


void crypto_haetae_polymatkl_pointwise_montgomery(crypto_haetae_polyveck *t, const crypto_haetae_polyvecl mat[CRYPTO_HAETAE_MAX_K],
                                    const crypto_haetae_polyvecl *v, const crypto_haetae_parameters *parameters) {
    uint32_t i;
    const uint32_t haetae_k = parameters->k;

    for (i = 0; i < haetae_k; ++i) {
        crypto_haetae_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v, parameters);
    }
}

void crypto_haetae_polymatkm_pointwise_montgomery(crypto_haetae_polyveck *t, const crypto_haetae_polyvecm mat[CRYPTO_HAETAE_MAX_K],
                                    const crypto_haetae_polyvecm *v, const crypto_haetae_parameters *parameters) {
    uint32_t i;
    const uint32_t haetae_k = parameters->k;

    for (i = 0; i < haetae_k; ++i) {
        crypto_haetae_polyvecm_pointwise_acc_montgomery(&t->vec[i], &mat[i], v, parameters);
    }
}


// doubles k * m sub-matrix of k * l mat
void crypto_haetae_polymatkl_double(crypto_haetae_polyvecl mat[CRYPTO_HAETAE_MAX_K], const crypto_haetae_parameters *parameters) {
    uint32_t i, j, k;
    const uint32_t haetae_k = parameters->k;
    const uint32_t haetae_l = parameters->l;

    for (i = 0; i < haetae_k; ++i) {
        for (j = 1; j < haetae_l; ++j) {
            for (k = 0; k < CRYPTO_HAETAE_N; ++k) {
                mat[i].vec[j].coeffs[k] *= 2;
            }
        }
    }
}
