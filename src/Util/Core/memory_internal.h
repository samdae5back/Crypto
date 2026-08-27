/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_MEMORY_INTERNAL_H
#define CRYPTO_MEMORY_INTERNAL_H

#include "Def.h"

int crypto_ranges_overlap(
    const void *first, size_t first_length,
    const void *second, size_t second_length);

#endif
