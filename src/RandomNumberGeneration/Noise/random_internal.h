/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_RANDOM_INTERNAL_H
#define CRYPTO_RANDOM_INTERNAL_H
#include "Def.h"

int random_os_bytes(uint8_t *out, size_t length);
LiberaCError crypto_random_bytes_internal(uint8_t *out, size_t length);
#endif
