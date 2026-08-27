/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "secure_zero.h"

void crypto_zeroize(void *TARGET, size_t LENGTH) {
    volatile uint8_t *target = (volatile uint8_t *)TARGET;
    if (!TARGET) return;
    while (LENGTH--) {
        *target++ = 0u;
    }
}
