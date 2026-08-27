/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdio.h>

#include "KeyEncapsulation.h"
#include "KeyEncapsulation/ML-KEM/ML-KEM.h"
#include "KeyEncapsulation/ML-KEM/parameter.h"
#include "Util/Core/secure_zero.h"

enum {
    MLKEM_KAT_RECORD_COUNT = 100,
    MLKEM_KAT_SEED_BYTES = 32
};

typedef struct {
    uint8_t d[MLKEM_KAT_SEED_BYTES];
    uint8_t z[MLKEM_KAT_SEED_BYTES];
    uint8_t public_key[CRYPTO_ML_KEM_512_PUBLIC_KEY_BYTES];
    uint8_t private_key[CRYPTO_ML_KEM_512_PRIVATE_KEY_BYTES];
    uint8_t message[MLKEM_KAT_SEED_BYTES];
    uint8_t ciphertext[CRYPTO_ML_KEM_512_CIPHERTEXT_BYTES];
    uint8_t shared_secret[CRYPTO_ML_KEM_SHARED_SECRET_BYTES];
} mlkem_kat_record;

static int hex_value(int character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f')
        return character - 'a' + 10;
    if (character >= 'A' && character <= 'F')
        return character - 'A' + 10;
    return -1;
}

static int expect_literal(FILE *input, const char *literal) {
    while (*literal != '\0') {
        if (fgetc(input) != (unsigned char)*literal) return -1;
        ++literal;
    }
    return 0;
}

static int expect_line_ending(FILE *input) {
    int character = fgetc(input);

    if (character == '\n') return 0;
    if (character == '\r' && fgetc(input) == '\n') return 0;
    return -1;
}

static int read_hex_field(FILE *input, const char *label,
                          uint8_t *output, size_t output_length) {
    size_t i;

    if (expect_literal(input, label) != 0 ||
        expect_literal(input, " = ") != 0) {
        return -1;
    }

    for (i = 0; i < output_length; ++i) {
        int high = hex_value(fgetc(input));
        int low = hex_value(fgetc(input));

        if (high < 0 || low < 0) return -1;
        output[i] = (uint8_t)((high << 4) | low);
    }

    return expect_line_ending(input);
}

static int read_record(FILE *input, mlkem_kat_record *record,
                       size_t record_number) {
    const char *failed_field = NULL;

    if (read_hex_field(input, "d", record->d, sizeof(record->d)) != 0)
        failed_field = "d";
    else if (read_hex_field(input, "z", record->z,
                            sizeof(record->z)) != 0)
        failed_field = "z";
    else if (read_hex_field(input, "pk", record->public_key,
                            sizeof(record->public_key)) != 0)
        failed_field = "pk";
    else if (read_hex_field(input, "sk", record->private_key,
                            sizeof(record->private_key)) != 0)
        failed_field = "sk";
    else if (read_hex_field(input, "m", record->message,
                            sizeof(record->message)) != 0)
        failed_field = "m";
    else if (read_hex_field(input, "ct", record->ciphertext,
                            sizeof(record->ciphertext)) != 0)
        failed_field = "ct";
    else if (read_hex_field(input, "ss", record->shared_secret,
                            sizeof(record->shared_secret)) != 0)
        failed_field = "ss";

    if (failed_field != NULL) {
        fprintf(stderr,
                "ml_kem_kat: malformed %s field in record %zu\n",
                failed_field, record_number);
        return -1;
    }
    return 0;
}

static int consume_record_separator(FILE *input, int final_record) {
    int character;

    if (!final_record) return expect_line_ending(input);

    character = fgetc(input);
    if (character == EOF) return ferror(input) ? -1 : 0;
    if (character == '\r') {
        if (fgetc(input) != '\n') return -1;
    } else if (character != '\n') {
        return -1;
    }

    character = fgetc(input);
    return character == EOF && !ferror(input) ? 0 : -1;
}

static int compare_bytes(const char *name, const uint8_t *expected,
                         const uint8_t *actual, size_t length,
                         size_t record_number) {
    size_t i;

    for (i = 0; i < length; ++i) {
        if (expected[i] != actual[i]) {
            fprintf(stderr,
                    "ml_kem_kat: record %zu %s mismatch at byte %zu "
                    "(expected %02x, got %02x)\n",
                    record_number, name, i, (unsigned int)expected[i],
                    (unsigned int)actual[i]);
            return -1;
        }
    }
    return 0;
}

static int run_record(const mlkem_kat_record *record,
                      size_t record_number) {
    uint8_t public_key[CRYPTO_ML_KEM_512_PUBLIC_KEY_BYTES] = { 0 };
    uint8_t private_key[CRYPTO_ML_KEM_512_PRIVATE_KEY_BYTES] = { 0 };
    uint8_t ciphertext[CRYPTO_ML_KEM_512_CIPHERTEXT_BYTES] = { 0 };
    uint8_t encapsulated_secret[CRYPTO_ML_KEM_SHARED_SECRET_BYTES] = { 0 };
    uint8_t decapsulated_secret[CRYPTO_ML_KEM_SHARED_SECRET_BYTES] = { 0 };
    CryptoError result;
    int status = -1;

    result = ML_KEM_KeyGen_internal(record->d, record->z, public_key,
                                    private_key);
    if (result != CRYPTO_SUCCESS) {
        fprintf(stderr,
                "ml_kem_kat: record %zu key generation failed (%d)\n",
                record_number, (int)result);
        goto cleanup;
    }
    if (compare_bytes("public key", record->public_key, public_key,
                      sizeof(public_key), record_number) != 0 ||
        compare_bytes("private key", record->private_key, private_key,
                      sizeof(private_key), record_number) != 0) {
        goto cleanup;
    }

    result = ML_KEM_Encaps_internal(public_key, record->message,
                                    encapsulated_secret, ciphertext);
    if (result != CRYPTO_SUCCESS) {
        fprintf(stderr,
                "ml_kem_kat: record %zu encapsulation failed (%d)\n",
                record_number, (int)result);
        goto cleanup;
    }
    if (compare_bytes("ciphertext", record->ciphertext, ciphertext,
                      sizeof(ciphertext), record_number) != 0 ||
        compare_bytes("encapsulated shared secret", record->shared_secret,
                      encapsulated_secret, sizeof(encapsulated_secret),
                      record_number) != 0) {
        goto cleanup;
    }

    result = ML_KEM_Decaps_internal(private_key, ciphertext,
                                    decapsulated_secret);
    if (result != CRYPTO_SUCCESS) {
        fprintf(stderr,
                "ml_kem_kat: record %zu decapsulation failed (%d)\n",
                record_number, (int)result);
        goto cleanup;
    }
    if (compare_bytes("decapsulated shared secret", record->shared_secret,
                      decapsulated_secret, sizeof(decapsulated_secret),
                      record_number) != 0 ||
        compare_bytes("shared-secret round trip", encapsulated_secret,
                      decapsulated_secret, sizeof(decapsulated_secret),
                      record_number) != 0) {
        goto cleanup;
    }

    status = 0;

cleanup:
    crypto_zeroize(public_key, sizeof(public_key));
    crypto_zeroize(private_key, sizeof(private_key));
    crypto_zeroize(ciphertext, sizeof(ciphertext));
    crypto_zeroize(encapsulated_secret, sizeof(encapsulated_secret));
    crypto_zeroize(decapsulated_secret, sizeof(decapsulated_secret));
    return status;
}

int main(int argc, char **argv) {
    mlkem_kat_record record = { 0 };
    FILE *input;
    size_t index;
    int status = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: ml_kem_kat <ml_kem_512.kat>\n");
        return 2;
    }

    input = fopen(argv[1], "rb");
    if (input == NULL) {
        fprintf(stderr, "ml_kem_kat: cannot open vector file: %s\n",
                argv[1]);
        return 2;
    }

    mlkem_active_parameters = mlkem_parameters_for(ALG_ML_KEM_512);
    if (mlkem_active_parameters == NULL ||
        k != 2 || d_u != 10 || d_v != 4) {
        fprintf(stderr, "ml_kem_kat: ML-KEM-512 parameters unavailable\n");
        goto cleanup;
    }

    for (index = 0; index < MLKEM_KAT_RECORD_COUNT; ++index) {
        size_t record_number = index + 1u;

        if (read_record(input, &record, record_number) != 0) goto cleanup;
        if (run_record(&record, record_number) != 0) goto cleanup;
        crypto_zeroize(&record, sizeof(record));

        if (consume_record_separator(
                input, index + 1u == MLKEM_KAT_RECORD_COUNT) != 0) {
            fprintf(stderr,
                    "ml_kem_kat: invalid separator after record %zu\n",
                    record_number);
            goto cleanup;
        }
    }

    printf("ML-KEM-512 KAT passed: %d records\n",
           MLKEM_KAT_RECORD_COUNT);
    status = 0;

cleanup:
    crypto_zeroize(&record, sizeof(record));
    if (fclose(input) != 0 && status == 0) {
        fprintf(stderr, "ml_kem_kat: failed to close vector file\n");
        status = 1;
    }
    return status;
}
