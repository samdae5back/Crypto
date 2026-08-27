/* SPDX-License-Identifier: MIT */

#ifndef CRYPTO_AIMER_BACKEND_AIMER_POLY_H
#define CRYPTO_AIMER_BACKEND_AIMER_POLY_H

#include <stddef.h>
#include <stdint.h>

#include "aimer_field.h"

void crypto_aimer_poly64_mul(uint64_t *z1, uint64_t *z0, uint64_t x0, uint64_t y0);
void crypto_aimer_poly64_sqr(uint64_t *z1, uint64_t *z0, uint64_t x);

#endif
