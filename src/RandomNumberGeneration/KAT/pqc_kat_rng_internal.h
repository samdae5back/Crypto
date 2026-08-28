/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_PQC_KAT_RNG_INTERNAL_H
#define CRYPTO_PQC_KAT_RNG_INTERNAL_H

#include "Def.h"

#define CRYPTO_PQC_KAT_SEED_BYTES 48u

LiberaCError crypto_pqc_random_bytes_internal(
    uint8_t *output, size_t output_length);

#if defined(CRYPTO_ENABLE_PQC_KAT)
LiberaCError crypto_pqc_kat_initialize_internal(
    const uint8_t seed[CRYPTO_PQC_KAT_SEED_BYTES]);
void crypto_pqc_kat_finalize_internal(void);
#endif

#endif
