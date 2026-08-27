/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_LSH_INTERNAL_H
#define CRYPTO_LSH_INTERNAL_H

#include "Def.h"

CryptoError crypto_lsh_hash(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    AlgID ALG);

#endif
