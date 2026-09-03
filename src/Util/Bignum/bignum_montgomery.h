/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBERAC_BIGNUM_MONTGOMERY_H
#define LIBERAC_BIGNUM_MONTGOMERY_H

#include "bignum_internal.h"
#include "Util/Core/secure_zero.h"

#include <stdlib.h>
#include <string.h>

/* Shared fixed-width Montgomery building blocks.  The multiply core has a
 * fixed source-level loop schedule for a public width n; public and secret
 * callers deliberately keep separate final-reduction policies. */

static uint32_t bignum_mont_n0inv(uint32_t n0) {
    uint32_t x = 1u;
    unsigned i;
    for (i = 0u; i < 5u; ++i) x *= 2u - n0 * x;
    return (uint32_t)(0u - x);
}

/* Compute R^2 mod modulus for R = 2^(32*n).  The modulus and width are public
 * setup data, so the generic variable-time reduction is appropriate here. */
static int bignum_mont_compute_r2_words(uint32_t *r2, size_t n,
                                        const LiberaCBignum *modulus) {
    LiberaCBignum power, reduced;
    size_t power_limbs;
    int rc = -1;

    if (!r2 || !modulus || n == 0u || modulus->LENGTH != n)
        return -1;
    if (n > (SIZE_MAX - 1u) / 2u)
        return -1;
    power_limbs = 2u * n + 1u;

    crypto_bignum_init(&power);
    crypto_bignum_init(&reduced);
    if (bignum_reserve(&power, power_limbs) != 0)
        goto done;
    memset(power.LIMBS, 0, power_limbs * sizeof(uint32_t));
    power.LIMBS[2u * n] = 1u;
    power.LENGTH = power_limbs;

    if (crypto_bignum_mod(&reduced, &power, modulus) != LIBERAC_SUCCESS ||
        reduced.LENGTH > n)
        goto done;

    memset(r2, 0, n * sizeof(uint32_t));
    if (reduced.LENGTH != 0u)
        memcpy(r2, reduced.LIMBS, reduced.LENGTH * sizeof(uint32_t));
    rc = 0;

done:
    crypto_bignum_free(&power);
    crypto_bignum_free(&reduced);
    return rc;
}

/* Shift-free coarsely integrated operand scanning Montgomery core.
 *
 * The previous implementation accumulated one product/reduction row and then
 * copied n+1 limbs down by one position on every outer iteration.  This form
 * folds that logical division by 2^32 into the reduction write-back: reduced
 * limb j is written directly to slot j-1.  work must contain n+2 limbs and is
 * left holding the unreduced Montgomery candidate in work[0..n].
 */
static int bignum_mont_cios_candidate(uint32_t *work,
                                      const uint32_t *a, size_t a_length,
                                      const uint32_t *b, size_t b_length,
                                      const uint32_t *modulus, size_t n,
                                      uint32_t n0inv) {
    size_t i, j;

    if (!work || !a || !b || !modulus || n == 0u ||
        a_length > n || b_length > n)
        return -1;

    memset(work, 0, (n + 2u) * sizeof(uint32_t));
    for (i = 0u; i < n; ++i) {
        uint64_t carry = 0u;
        uint32_t bi = i < b_length ? b[i] : 0u;

        for (j = 0u; j < n; ++j) {
            uint32_t aj = j < a_length ? a[j] : 0u;
            uint64_t z = (uint64_t)aj * bi + work[j] + carry;
            work[j] = (uint32_t)z;
            carry = z >> 32;
        }
        {
            uint64_t z = (uint64_t)work[n] + carry;
            work[n] = (uint32_t)z;
            work[n + 1u] = (uint32_t)(z >> 32);
        }

        {
            uint32_t m = work[0] * n0inv;
            uint64_t z = (uint64_t)work[0] +
                         (uint64_t)m * modulus[0];
            carry = z >> 32;

            for (j = 1u; j < n; ++j) {
                z = (uint64_t)work[j] +
                    (uint64_t)m * modulus[j] + carry;
                work[j - 1u] = (uint32_t)z;
                carry = z >> 32;
            }

            z = (uint64_t)work[n] + carry;
            work[n - 1u] = (uint32_t)z;
            work[n] = (uint32_t)((uint64_t)work[n + 1u] + (z >> 32));
            work[n + 1u] = 0u;
        }
    }
    return 0;
}

#endif
