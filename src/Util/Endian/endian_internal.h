/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_ENDIAN_INTERNAL_H
#define CRYPTO_ENDIAN_INTERNAL_H

#include "Def.h"

uint16_t crypto_load16_le(const uint8_t *p);
uint32_t crypto_load32_le(const uint8_t *p);
uint64_t crypto_load64_le(const uint8_t *p);
uint16_t crypto_load16_be(const uint8_t *p);
uint32_t crypto_load32_be(const uint8_t *p);
uint64_t crypto_load64_be(const uint8_t *p);
void crypto_store16_le(uint8_t *p, uint16_t x);
void crypto_store32_le(uint8_t *p, uint32_t x);
void crypto_store64_le(uint8_t *p, uint64_t x);
void crypto_store16_be(uint8_t *p, uint16_t x);
void crypto_store32_be(uint8_t *p, uint32_t x);
void crypto_store64_be(uint8_t *p, uint64_t x);

#endif
