/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_PRIME_INTERNAL_H
#define CRYPTO_PRIME_INTERNAL_H

#include "Util.h"

int prime_small_division(const LiberaCBignum *n);
int crypto_prime_is_probable_internal(const LiberaCBignum *value, uint32_t rounds);
LiberaCError crypto_prime_generate_internal(LiberaCBignum *out, size_t bits, uint32_t rounds);
LiberaCError crypto_prime_generate_safe_internal(LiberaCBignum *p, LiberaCBignum *q,
                                                 size_t p_bits, uint32_t rounds);

#endif
