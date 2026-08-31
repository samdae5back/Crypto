/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBERAC_TEST_ECC_REFERENCE_H
#define LIBERAC_TEST_ECC_REFERENCE_H

#include "Util/ECC/ecc_internal.h"

/* Test-only textbook affine oracle. Never linked into LiberaCrypt. */
LiberaCError crypto_ec_scalar_multiply_reference(
    const CryptoEcCurve *curve, CryptoEcAffinePoint *out,
    const CryptoEcAffinePoint *point, const uint8_t *scalar,
    size_t scalar_length);

#endif
