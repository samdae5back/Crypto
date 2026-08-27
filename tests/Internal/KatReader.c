/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "KatReader.h"

#include <stdlib.h>

static int kat_error(
    const CRYPTO_TEST_KAT_READER *reader, const char *message,
    const char *field) {
    fprintf(stderr, "%s: record %zu: %s%s%s\n",
            reader->path, reader->record, message,
            field != NULL ? ": " : "", field != NULL ? field : "");
    return -1;
}

static int consume_line_ending(FILE *stream) {
    int character = fgetc(stream);

    if (character == '\n') return 0;
    if (character == '\r' && fgetc(stream) == '\n') return 0;
    return -1;
}

static int skip_ignored_lines(CRYPTO_TEST_KAT_READER *reader) {
    int character;

    for (;;) {
        character = fgetc(reader->stream);
        if (character == EOF) return ferror(reader->stream) ? -1 : 1;
        if (character == '\n') continue;
        if (character == '\r') {
            if (fgetc(reader->stream) != '\n')
                return kat_error(reader, "invalid line ending", NULL);
            continue;
        }
        if (character == '#') {
            do {
                character = fgetc(reader->stream);
            } while (character != EOF && character != '\n' && character != '\r');
            if (character == '\r' && fgetc(reader->stream) != '\n')
                return kat_error(reader, "invalid comment line ending", NULL);
            if (character == EOF && ferror(reader->stream))
                return kat_error(reader, "failed while reading comment", NULL);
            continue;
        }
        if (ungetc(character, reader->stream) == EOF)
            return kat_error(reader, "failed to unread field prefix", NULL);
        return 0;
    }
}

static int expect_literal(
    CRYPTO_TEST_KAT_READER *reader, const char *literal, const char *field) {
    while (*literal != '\0') {
        if (fgetc(reader->stream) != (unsigned char)*literal)
            return kat_error(reader, "unexpected field or malformed value", field);
        ++literal;
    }
    return 0;
}

static int begin_field(
    CRYPTO_TEST_KAT_READER *reader, const char *label) {
    int status = skip_ignored_lines(reader);

    if (status == 1) return kat_error(reader, "unexpected end of file", label);
    if (status != 0) return -1;
    if (expect_literal(reader, label, label) != 0 ||
        expect_literal(reader, " = ", label) != 0) {
        return -1;
    }
    return 0;
}

static int hex_value(int character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

int crypto_test_kat_open(
    CRYPTO_TEST_KAT_READER *reader, const char *path) {
    if (reader == NULL || path == NULL) return -1;
    reader->stream = fopen(path, "rb");
    reader->path = path;
    reader->record = 0u;
    if (reader->stream == NULL) {
        fprintf(stderr, "%s: cannot open KAT vector file\n", path);
        return -1;
    }
    return 0;
}

int crypto_test_kat_close(CRYPTO_TEST_KAT_READER *reader) {
    int status;

    if (reader == NULL || reader->stream == NULL) return 0;
    status = fclose(reader->stream);
    reader->stream = NULL;
    if (status != 0) {
        fprintf(stderr, "%s: failed to close KAT vector file\n", reader->path);
        return -1;
    }
    return 0;
}

int crypto_test_kat_read_size(
    CRYPTO_TEST_KAT_READER *reader, const char *label, size_t *value) {
    size_t parsed = 0u;
    const size_t maximum = (size_t)-1;
    int character;
    int have_digit = 0;

    if (reader == NULL || label == NULL || value == NULL ||
        reader->stream == NULL) {
        return -1;
    }
    if (begin_field(reader, label) != 0) return -1;

    character = fgetc(reader->stream);
    while (character >= '0' && character <= '9') {
        const size_t digit = (size_t)(character - '0');
        have_digit = 1;
        if (parsed > (maximum - digit) / 10u)
            return kat_error(reader, "decimal value is too large", label);
        parsed = parsed * 10u + digit;
        character = fgetc(reader->stream);
    }
    if (!have_digit) return kat_error(reader, "missing decimal value", label);
    if (character == '\r') {
        if (fgetc(reader->stream) != '\n')
            return kat_error(reader, "invalid line ending", label);
    } else if (character != '\n') {
        return kat_error(reader, "trailing data after decimal value", label);
    }
    *value = parsed;
    return 0;
}

int crypto_test_kat_read_hex(
    CRYPTO_TEST_KAT_READER *reader, const char *label,
    uint8_t *output, size_t output_length) {
    size_t index;

    if (reader == NULL || label == NULL || reader->stream == NULL ||
        (output == NULL && output_length != 0u)) {
        return -1;
    }
    if (begin_field(reader, label) != 0) return -1;

    for (index = 0u; index < output_length; ++index) {
        const int high = hex_value(fgetc(reader->stream));
        const int low = hex_value(fgetc(reader->stream));
        if (high < 0 || low < 0)
            return kat_error(reader, "invalid or short hexadecimal value", label);
        output[index] = (uint8_t)((high << 4) | low);
    }
    if (consume_line_ending(reader->stream) != 0)
        return kat_error(reader, "wrong hexadecimal length or line ending", label);
    return 0;
}

int crypto_test_kat_expect_eof(CRYPTO_TEST_KAT_READER *reader) {
    int status;

    if (reader == NULL || reader->stream == NULL) return -1;
    status = skip_ignored_lines(reader);
    if (status == 1) return 0;
    if (status == 0) return kat_error(reader, "unexpected data after final record", NULL);
    return -1;
}

int crypto_test_kat_compare(
    const CRYPTO_TEST_KAT_READER *reader, const char *field,
    const uint8_t *expected, const uint8_t *actual, size_t length) {
    size_t index;

    if (reader == NULL || field == NULL ||
        (length != 0u && (expected == NULL || actual == NULL))) {
        return -1;
    }
    for (index = 0u; index < length; ++index) {
        if (expected[index] != actual[index]) {
            fprintf(stderr,
                    "%s: record %zu: %s mismatch at byte %zu "
                    "(expected %02x, got %02x)\n",
                    reader->path, reader->record, field, index,
                    (unsigned int)expected[index],
                    (unsigned int)actual[index]);
            return -1;
        }
    }
    return 0;
}

int crypto_test_kat_reserve(
    uint8_t **buffer, size_t *capacity, size_t required_length) {
    uint8_t *resized;

    if (buffer == NULL || capacity == NULL) return -1;
    if (required_length <= *capacity) return 0;

    resized = (uint8_t *)realloc(*buffer, required_length);
    if (resized == NULL) return -1;
    *buffer = resized;
    *capacity = required_length;
    return 0;
}
