/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "endian_internal.h"

uint16_t crypto_load16_le(const uint8_t *input) {
    return (uint16_t)input[0] | ((uint16_t)input[1] << 8);
}

uint32_t crypto_load32_le(const uint8_t *input) {
    return (uint32_t)input[0] |
           ((uint32_t)input[1] << 8) |
           ((uint32_t)input[2] << 16) |
           ((uint32_t)input[3] << 24);
}

uint64_t crypto_load64_le(const uint8_t *input) {
    return (uint64_t)crypto_load32_le(input) |
           ((uint64_t)crypto_load32_le(input + 4) << 32);
}

uint16_t crypto_load16_be(const uint8_t *input) {
    return ((uint16_t)input[0] << 8) | (uint16_t)input[1];
}

uint32_t crypto_load32_be(const uint8_t *input) {
    return ((uint32_t)input[0] << 24) |
           ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] << 8) |
           (uint32_t)input[3];
}

uint64_t crypto_load64_be(const uint8_t *input) {
    return ((uint64_t)crypto_load32_be(input) << 32) |
           (uint64_t)crypto_load32_be(input + 4);
}

void crypto_store16_le(uint8_t *output, uint16_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

void crypto_store32_le(uint8_t *output, uint32_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

void crypto_store64_le(uint8_t *output, uint64_t value) {
    crypto_store32_le(output, (uint32_t)value);
    crypto_store32_le(output + 4, (uint32_t)(value >> 32));
}

void crypto_store16_be(uint8_t *output, uint16_t value) {
    output[0] = (uint8_t)(value >> 8);
    output[1] = (uint8_t)value;
}

void crypto_store32_be(uint8_t *output, uint32_t value) {
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

void crypto_store64_be(uint8_t *output, uint64_t value) {
    crypto_store32_be(output, (uint32_t)(value >> 32));
    crypto_store32_be(output + 4, (uint32_t)value);
}
