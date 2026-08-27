/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_PRIME_INTERNAL_H
#define CRYPTO_PRIME_INTERNAL_H

#include "Util.h"

int prime_small_division(const CRYPTO_BIGNUM *n);
int crypto_prime_is_probable_internal(const CRYPTO_BIGNUM *value, uint32_t rounds);
CryptoError crypto_prime_generate_internal(CRYPTO_BIGNUM *out, size_t bits, uint32_t rounds);
CryptoError crypto_prime_generate_safe_internal(CRYPTO_BIGNUM *p, CRYPTO_BIGNUM *q,
                                                 size_t p_bits, uint32_t rounds);

#endif
