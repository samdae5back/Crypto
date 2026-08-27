// SPDX-License-Identifier: MIT

#ifndef _HAETAE_ROUNDING_H_
#define _HAETAE_ROUNDING_H_

#include "haetae.h"

void crypto_haetae_decompose_z1(int *highbits, int *lowbits, const int r);

void crypto_haetae_decompose_hint(int *highbits, const int r, const crypto_haetae_parameters *parameters);

int crypto_haetae_decompose_vk(int *a0, const int a);

#endif /* _HAETAE_ROUNDING_H_ */
