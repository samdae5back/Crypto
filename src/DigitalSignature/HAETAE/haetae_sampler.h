// SPDX-License-Identifier: MIT

#ifndef _HAETAE_SAMPLER_H_
#define _HAETAE_SAMPLER_H_

#include "haetae_fixpoint.h"


unsigned int crypto_haetae_rej_uniform(int *a, unsigned int len, const uint8_t  *buf,
                         unsigned int buflen);
unsigned int crypto_haetae_rej_eta(int *a, unsigned int len, const uint8_t  *buf,
                     unsigned int buflen);

void crypto_haetae_sample_gauss_N(uint64_t *r, uint8_t  *signs, crypto_haetae_fp96_76 *sqsum,
                    const uint8_t  seed[CRYPTO_HAETAE_CRH_BYTES], const uint16_t nonce,
                    const size_t len);

#endif /* _HAETAE_SAMPLER_H_ */
