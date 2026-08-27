// SPDX-License-Identifier: MIT

#ifndef _HAETAE_PACKING_H_
#define _HAETAE_PACKING_H_


#include "haetae.h"


void crypto_haetae_pack_pk(uint8_t  pk[CRYPTO_HAETAE_MAX_PUBLIC_KEY_BYTES],
                    crypto_haetae_polyveck *b, const uint8_t  seed[CRYPTO_HAETAE_SEED_BYTES],
                    const crypto_haetae_parameters *parameters);

void crypto_haetae_unpack_pk(crypto_haetae_polyveck *b, uint8_t  seed[CRYPTO_HAETAE_SEED_BYTES],
                      const uint8_t  pk[CRYPTO_HAETAE_MAX_PUBLIC_KEY_BYTES],
                      const crypto_haetae_parameters *parameters);

void crypto_haetae_pack_sk(uint8_t  sk[CRYPTO_HAETAE_MAX_PRIVATE_KEY_BYTES],
                    const uint8_t  pk[CRYPTO_HAETAE_MAX_PUBLIC_KEY_BYTES],
                    const crypto_haetae_polyvecm *s0, const crypto_haetae_polyveck *s1,
                    const uint8_t  key[CRYPTO_HAETAE_SEED_BYTES],
                    const crypto_haetae_parameters *parameters);

void crypto_haetae_unpack_sk(crypto_haetae_polyvecl A[CRYPTO_HAETAE_MAX_K],
                      crypto_haetae_polyvecm *s0, crypto_haetae_polyveck *s1, uint8_t  *key,
                      const uint8_t  sk[CRYPTO_HAETAE_MAX_PRIVATE_KEY_BYTES],
                      const crypto_haetae_parameters *parameters);

int crypto_haetae_pack_sig(uint8_t  *sig,
                    const crypto_haetae_poly *c, const crypto_haetae_polyvecl *lowbits_z1,
                    const crypto_haetae_polyvecl *highbits_z1, const crypto_haetae_polyveck *h,
                    const crypto_haetae_parameters *parameters);

int crypto_haetae_unpack_sig(crypto_haetae_poly *c,
                      crypto_haetae_polyvecl *lowbits_z1, crypto_haetae_polyvecl *highbits_z1, crypto_haetae_polyveck *h,
                      const uint8_t  sig[CRYPTO_HAETAE_MAX_SIGNATURE_BYTES],
                      const crypto_haetae_parameters *parameters);

#endif /* _HAETAE_PACKING_H_ */
