/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "DigitalSignature.h"
#include "Internal/KatReader.h"
#include "RandomNumberGeneration/KAT/pqc_kat_rng_internal.h"
#include "Util/Core/secure_zero.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct crypto_test_aimer_case {
    const char *name;
    AlgID alg;
} CRYPTO_TEST_AIMER_CASE;

static const CRYPTO_TEST_AIMER_CASE aimer_cases[] = {
    { "AIMer-128f", ALG_AIMER_128F },
    { "AIMer-128s", ALG_AIMER_128S },
    { "AIMer-192f", ALG_AIMER_192F },
    { "AIMer-192s", ALG_AIMER_192S },
    { "AIMer-256f", ALG_AIMER_256F },
    { "AIMer-256s", ALG_AIMER_256S }
};

static int report_crypto_error(
    const CRYPTO_TEST_KAT_READER *reader, const char *operation,
    CryptoError error) {
    fprintf(stderr, "%s: record %zu: %s failed (%d)\n",
            reader->path, reader->record, operation, (int)error);
    return -1;
}

static int run_kat(const char *path, const CRYPTO_TEST_AIMER_CASE *test_case) {
    CRYPTO_TEST_KAT_READER reader = { NULL, NULL, 0u };
    uint8_t seed[CRYPTO_PQC_KAT_SEED_BYTES] = { 0 };
    uint8_t *message = NULL;
    uint8_t *expected_signed_message = NULL;
    uint8_t *expected_public_key = NULL;
    uint8_t *expected_private_key = NULL;
    uint8_t *actual_public_key = NULL;
    uint8_t *actual_private_key = NULL;
    uint8_t *actual_signature = NULL;
    size_t public_key_length;
    size_t private_key_length;
    size_t signature_length;
    size_t message_length = 0u;
    size_t message_capacity = 0u;
    size_t signed_message_capacity = 0u;
    size_t index;
    int kat_active = 0;
    int status = 1;

    public_key_length = CRYPTO_AIMER_PUBLIC_KEY_SIZE(test_case->alg);
    private_key_length = CRYPTO_AIMER_PRIVATE_KEY_SIZE(test_case->alg);
    signature_length = CRYPTO_AIMER_SIGNATURE_SIZE(test_case->alg);
    if (public_key_length == 0u || private_key_length == 0u ||
        signature_length == 0u) {
        fprintf(stderr, "%s: unsupported AIMer algorithm\n", test_case->name);
        return 2;
    }

    expected_public_key = (uint8_t *)malloc(public_key_length);
    expected_private_key = (uint8_t *)malloc(private_key_length);
    actual_public_key = (uint8_t *)malloc(public_key_length);
    actual_private_key = (uint8_t *)malloc(private_key_length);
    actual_signature = (uint8_t *)malloc(signature_length);
    if (expected_public_key == NULL || expected_private_key == NULL ||
        actual_public_key == NULL || actual_private_key == NULL ||
        actual_signature == NULL) {
        fprintf(stderr, "%s: allocation failed\n", test_case->name);
        goto cleanup;
    }
    if (crypto_test_kat_open(&reader, path) != 0) goto cleanup;

    for (index = 0u; index < 100u; ++index) {
        size_t count;
        size_t signed_message_length;
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
            crypto_test_kat_read_size(
                &reader, "mlen", &message_length) != 0 ||
            crypto_test_kat_reserve(
                &message, &message_capacity, message_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "msg", message, message_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "pk", expected_public_key,
                public_key_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "sk", expected_private_key,
                private_key_length) != 0 ||
            crypto_test_kat_read_size(
                &reader, "smlen", &signed_message_length) != 0 ||
            message_length > SIZE_MAX - signature_length ||
            signed_message_length != signature_length + message_length ||
            crypto_test_kat_reserve(
                &expected_signed_message, &signed_message_capacity,
                signed_message_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "sm", expected_signed_message,
                signed_message_length) != 0) {
            goto close_reader;
        }
        if (crypto_test_kat_compare(
                &reader, "attached message", message,
                expected_signed_message,
                message_length) != 0) {
            goto close_reader;
        }

        error = crypto_pqc_kat_initialize_internal(seed);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "KAT DRBG initialization", error);
            goto close_reader;
        }
        kat_active = 1;
        error = CRYPTO_AIMER_KEYGEN(
            actual_public_key, public_key_length,
            actual_private_key, private_key_length,
            test_case->alg);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "key generation", error);
            goto close_reader;
        }
        error = CRYPTO_AIMER_SIGN(
            actual_private_key, private_key_length,
            message, message_length, NULL, 0u,
            actual_signature, signature_length,
            test_case->alg);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "signature generation", error);
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
                &reader, "signature",
                expected_signed_message + message_length,
                actual_signature, signature_length) != 0) {
            goto close_reader;
        }
        error = CRYPTO_AIMER_VERIFY(
            actual_public_key, public_key_length,
            message, message_length, NULL, 0u,
            actual_signature, signature_length,
            test_case->alg);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "signature verification", error);
            goto close_reader;
        }
    }

    if (crypto_test_kat_expect_eof(&reader) != 0) goto close_reader;
    printf("%s KAT passed: 100 records\n", test_case->name);
    status = 0;

close_reader:
    if (kat_active != 0) crypto_pqc_kat_finalize_internal();
    if (crypto_test_kat_close(&reader) != 0) status = 1;
cleanup:
    crypto_zeroize(seed, sizeof(seed));
    if (expected_public_key != NULL)
        crypto_zeroize(expected_public_key, public_key_length);
    if (expected_private_key != NULL)
        crypto_zeroize(expected_private_key, private_key_length);
    if (actual_public_key != NULL)
        crypto_zeroize(actual_public_key, public_key_length);
    if (actual_private_key != NULL)
        crypto_zeroize(actual_private_key, private_key_length);
    if (actual_signature != NULL)
        crypto_zeroize(actual_signature, signature_length);
    if (expected_signed_message != NULL)
        crypto_zeroize(expected_signed_message, signed_message_capacity);
    if (message != NULL) crypto_zeroize(message, message_capacity);
    free(actual_signature);
    free(actual_private_key);
    free(actual_public_key);
    free(expected_private_key);
    free(expected_public_key);
    free(expected_signed_message);
    free(message);
    return status;
}

int main(int argc, char **argv) {
    size_t index;

    if (argc != 3) {
        fprintf(stderr, "usage: aimer_kat <vector.kat> <algorithm-name>\n");
        return 2;
    }
    for (index = 0u; index < sizeof(aimer_cases) / sizeof(aimer_cases[0]);
         ++index) {
        if (strcmp(argv[2], aimer_cases[index].name) == 0)
            return run_kat(argv[1], &aimer_cases[index]);
    }
    fprintf(stderr, "unsupported AIMer KAT selector: %s\n", argv[2]);
    return 2;
}
