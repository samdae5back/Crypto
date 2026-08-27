/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_TEST_KAT_READER_H
#define CRYPTO_TEST_KAT_READER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
    FILE *stream;
    const char *path;
    size_t record;
} CRYPTO_TEST_KAT_READER;

int crypto_test_kat_open(
    CRYPTO_TEST_KAT_READER *reader, const char *path);
int crypto_test_kat_close(CRYPTO_TEST_KAT_READER *reader);
int crypto_test_kat_read_size(
    CRYPTO_TEST_KAT_READER *reader, const char *label, size_t *value);
int crypto_test_kat_read_hex(
    CRYPTO_TEST_KAT_READER *reader, const char *label,
    uint8_t *output, size_t output_length);
int crypto_test_kat_expect_eof(CRYPTO_TEST_KAT_READER *reader);
int crypto_test_kat_compare(
    const CRYPTO_TEST_KAT_READER *reader, const char *field,
    const uint8_t *expected, const uint8_t *actual, size_t length);

#endif
