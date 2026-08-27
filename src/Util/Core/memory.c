/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "memory_internal.h"

int crypto_ranges_overlap(
    const void *first, size_t first_length,
    const void *second, size_t second_length) {
    uintptr_t first_address;
    uintptr_t second_address;

    if (first_length == 0u || second_length == 0u) return 0;

    first_address = (uintptr_t)first;
    second_address = (uintptr_t)second;
    if (first_address <= second_address)
        return second_address - first_address < first_length;
    return first_address - second_address < second_length;
}
