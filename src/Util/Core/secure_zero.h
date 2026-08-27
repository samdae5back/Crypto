/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_INTERNAL_SECURE_ZERO_H
#define CRYPTO_INTERNAL_SECURE_ZERO_H

#include "Def.h"

void crypto_zeroize(void *TARGET, size_t LENGTH);

#endif
