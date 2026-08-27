// SPDX-License-Identifier: MIT

#ifndef _HAETAE_POLYMAT_H_
#define _HAETAE_POLYMAT_H_


#include "haetae.h"

void crypto_haetae_polymatkl_expand(crypto_haetae_polyvecl mat[CRYPTO_HAETAE_MAX_K],
                      const uint8_t  rho[CRYPTO_HAETAE_SEED_BYTES],
                      const crypto_haetae_parameters *parameters);

void crypto_haetae_polymatkm_expand(crypto_haetae_polyvecm mat[CRYPTO_HAETAE_MAX_K],
                      const uint8_t  rho[CRYPTO_HAETAE_SEED_BYTES],
                      const crypto_haetae_parameters *parameters);

void crypto_haetae_polymatkm_pointwise_montgomery(crypto_haetae_polyveck *t, const crypto_haetae_polyvecm mat[CRYPTO_HAETAE_MAX_K],
                                    const crypto_haetae_polyvecm *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polymatkl_pointwise_montgomery(crypto_haetae_polyveck *t, const crypto_haetae_polyvecl mat[CRYPTO_HAETAE_MAX_K],
                                    const crypto_haetae_polyvecl *v, const crypto_haetae_parameters *parameters);

void crypto_haetae_polymatkl_double(crypto_haetae_polyvecl mat[CRYPTO_HAETAE_MAX_K], const crypto_haetae_parameters *parameters);

#endif /* _HAETAE_POLYMAT_H_ */
