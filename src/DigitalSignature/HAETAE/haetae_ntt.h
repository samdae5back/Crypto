// SPDX-License-Identifier: MIT

#ifndef _HAETAE_NTT_H_
#define _HAETAE_NTT_H_

#include "haetae.h"


void crypto_haetae_ntt(int a[CRYPTO_HAETAE_N]);

void crypto_haetae_invntt_tomont(int a[CRYPTO_HAETAE_N]);

#endif /* _HAETAE_NTT_H_ */
