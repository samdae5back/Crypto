/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Internal/KatReader.h"
#include "KeyEncapsulation.h"
#include "RandomNumberGeneration/KAT/pqc_kat_rng_internal.h"
#include "Util/Core/secure_zero.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { ML_KEM_KAT_RECORDS = 100 };

typedef struct {
    const char *name;
    AlgID alg;
} ML_KEM_KAT_CASE;

static const ML_KEM_KAT_CASE ml_kem_cases[] = {
    { "ML-KEM-512", ALG_ML_KEM_512 },
    { "ML-KEM-768", ALG_ML_KEM_768 },
    { "ML-KEM-1024", ALG_ML_KEM_1024 }
};

static int report_crypto_error(
    const CRYPTO_TEST_KAT_READER *reader, const char *operation,
    CryptoError error) {
    fprintf(stderr, "%s: record %zu: %s failed (%d)\n",
            reader->path, reader->record, operation, (int)error);
    return -1;
}

static int run_kat(const char *path, const ML_KEM_KAT_CASE *test_case) {
    CRYPTO_TEST_KAT_READER reader = { NULL, NULL, 0u };
    uint8_t seed[CRYPTO_PQC_KAT_SEED_BYTES] = { 0 };
    uint8_t expected_shared_secret[CRYPTO_ML_KEM_SHARED_SECRET_BYTES] = { 0 };
    uint8_t encapsulated_secret[CRYPTO_ML_KEM_SHARED_SECRET_BYTES] = { 0 };
    uint8_t decapsulated_secret[CRYPTO_ML_KEM_SHARED_SECRET_BYTES] = { 0 };
    uint8_t *expected_public_key = NULL;
    uint8_t *expected_private_key = NULL;
    uint8_t *expected_ciphertext = NULL;
    uint8_t *actual_public_key = NULL;
    uint8_t *actual_private_key = NULL;
    uint8_t *actual_ciphertext = NULL;
    size_t public_key_length;
    size_t private_key_length;
    size_t ciphertext_length;
    size_t index;
    int kat_active = 0;
    int status = 1;

    public_key_length = CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(test_case->alg);
    private_key_length = CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(test_case->alg);
    ciphertext_length = CRYPTO_ML_KEM_CIPHERTEXT_SIZE(test_case->alg);
    if (public_key_length == 0u || private_key_length == 0u ||
        ciphertext_length == 0u) {
        fprintf(stderr, "%s: unsupported ML-KEM algorithm\n", test_case->name);
        return 2;
    }

    expected_public_key = (uint8_t *)malloc(public_key_length);
    expected_private_key = (uint8_t *)malloc(private_key_length);
    expected_ciphertext = (uint8_t *)malloc(ciphertext_length);
    actual_public_key = (uint8_t *)malloc(public_key_length);
    actual_private_key = (uint8_t *)malloc(private_key_length);
    actual_ciphertext = (uint8_t *)malloc(ciphertext_length);
    if (expected_public_key == NULL || expected_private_key == NULL ||
        expected_ciphertext == NULL || actual_public_key == NULL ||
        actual_private_key == NULL || actual_ciphertext == NULL) {
        fprintf(stderr, "%s: allocation failed\n", test_case->name);
        goto cleanup;
    }
    if (crypto_test_kat_open(&reader, path) != 0) goto cleanup;

    for (index = 0u; index < ML_KEM_KAT_RECORDS; ++index) {
        size_t count;
        CryptoError error;

        reader.record = index;
        if (crypto_test_kat_read_size(&reader, "count", &count) != 0)
            goto close_reader;
        if (count != index) {
            fprintf(stderr, "%s: record %zu: non-sequential count (%zu)\n",
                    path, index, count);
            goto close_reader;
        }
        if (crypto_test_kat_read_hex(
                &reader, "seed", seed, sizeof(seed)) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "pk", expected_public_key,
                public_key_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "sk", expected_private_key,
                private_key_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "ct", expected_ciphertext,
                ciphertext_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "ss", expected_shared_secret,
                sizeof(expected_shared_secret)) != 0) {
            goto close_reader;
        }

        error = crypto_pqc_kat_initialize_internal(seed);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "KAT DRBG initialization", error);
            goto close_reader;
        }
        kat_active = 1;
        error = CRYPTO_ML_KEM_KEYGEN(
            actual_public_key, public_key_length,
            actual_private_key, private_key_length, test_case->alg);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "key generation", error);
            goto close_reader;
        }
        error = CRYPTO_ML_KEM_ENCAPS(
            actual_public_key, public_key_length,
            encapsulated_secret, actual_ciphertext,
            ciphertext_length, test_case->alg);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "encapsulation", error);
            goto close_reader;
        }
        crypto_pqc_kat_finalize_internal();
        kat_active = 0;

        if (crypto_test_kat_compare(
                &reader, "public key", expected_public_key,
                actual_public_key, public_key_length) != 0 ||
            crypto_test_kat_compare(
                &reader, "private key", expected_private_key,
                actual_private_key, private_key_length) != 0 ||
            crypto_test_kat_compare(
                &reader, "ciphertext", expected_ciphertext,
                actual_ciphertext, ciphertext_length) != 0 ||
            crypto_test_kat_compare(
                &reader, "encapsulated shared secret",
                expected_shared_secret, encapsulated_secret,
                sizeof(encapsulated_secret)) != 0) {
            goto close_reader;
        }

        error = CRYPTO_ML_KEM_DECAPS(
            actual_private_key, private_key_length,
            actual_ciphertext, ciphertext_length,
            decapsulated_secret, test_case->alg);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "decapsulation", error);
            goto close_reader;
        }
        if (crypto_test_kat_compare(
                &reader, "decapsulated shared secret",
                expected_shared_secret, decapsulated_secret,
                sizeof(decapsulated_secret)) != 0 ||
            crypto_test_kat_compare(
                &reader, "shared-secret round trip",
                encapsulated_secret, decapsulated_secret,
                sizeof(decapsulated_secret)) != 0) {
            goto close_reader;
        }
    }

    if (crypto_test_kat_expect_eof(&reader) != 0) goto close_reader;
    printf("%s KAT passed: %d records\n",
           test_case->name, ML_KEM_KAT_RECORDS);
    status = 0;

close_reader:
    if (kat_active != 0) crypto_pqc_kat_finalize_internal();
    if (crypto_test_kat_close(&reader) != 0) status = 1;
cleanup:
    crypto_zeroize(seed, sizeof(seed));
    crypto_zeroize(expected_shared_secret, sizeof(expected_shared_secret));
    crypto_zeroize(encapsulated_secret, sizeof(encapsulated_secret));
    crypto_zeroize(decapsulated_secret, sizeof(decapsulated_secret));
    if (expected_public_key != NULL)
        crypto_zeroize(expected_public_key, public_key_length);
    if (expected_private_key != NULL)
        crypto_zeroize(expected_private_key, private_key_length);
    if (expected_ciphertext != NULL)
        crypto_zeroize(expected_ciphertext, ciphertext_length);
    if (actual_public_key != NULL)
        crypto_zeroize(actual_public_key, public_key_length);
    if (actual_private_key != NULL)
        crypto_zeroize(actual_private_key, private_key_length);
    if (actual_ciphertext != NULL)
        crypto_zeroize(actual_ciphertext, ciphertext_length);
    free(actual_ciphertext);
    free(actual_private_key);
    free(actual_public_key);
    free(expected_ciphertext);
    free(expected_private_key);
    free(expected_public_key);
    return status;
}

int main(int argc, char **argv) {
    size_t index;

    if (argc != 3) {
        fprintf(stderr, "usage: ml_kem_kat <vector.kat> <algorithm-name>\n");
        return 2;
    }
    for (index = 0u; index < sizeof(ml_kem_cases) / sizeof(ml_kem_cases[0]);
         ++index) {
        if (strcmp(argv[2], ml_kem_cases[index].name) == 0)
            return run_kat(argv[1], &ml_kem_cases[index]);
    }
    fprintf(stderr, "unsupported ML-KEM KAT selector: %s\n", argv[2]);
    return 2;
}
