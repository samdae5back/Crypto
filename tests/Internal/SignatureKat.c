/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "SignatureKat.h"

#include "Internal/KatReader.h"
#include "RandomNumberGeneration/KAT/pqc_kat_rng_internal.h"
#include "Util/Core/secure_zero.h"

#include <stdio.h>
#include <stdlib.h>

static int resize_buffer(uint8_t **buffer, size_t length) {
    uint8_t *resized;

    if (length == 0u) {
        free(*buffer);
        *buffer = NULL;
        return 0;
    }
    resized = (uint8_t *)realloc(*buffer, length);
    if (resized == NULL) return -1;
    *buffer = resized;
    return 0;
}

static int report_crypto_error(
    const CRYPTO_TEST_KAT_READER *reader, const char *operation,
    CryptoError error) {
    fprintf(stderr, "%s: record %zu: %s failed (%d)\n",
            reader->path, reader->record, operation, (int)error);
    return -1;
}

int crypto_test_run_signature_kat(
    const char *path, const char *algorithm_name, AlgID alg,
    const CRYPTO_TEST_SIGNATURE_API *api, size_t record_count) {
    CRYPTO_TEST_KAT_READER reader;
    uint8_t seed[CRYPTO_PQC_KAT_SEED_BYTES];
    uint8_t *message = NULL;
    uint8_t *context = NULL;
    uint8_t *expected_public_key = NULL;
    uint8_t *expected_private_key = NULL;
    uint8_t *expected_signature = NULL;
    uint8_t *actual_public_key = NULL;
    uint8_t *actual_private_key = NULL;
    uint8_t *actual_signature = NULL;
    size_t public_key_length;
    size_t private_key_length;
    size_t signature_length;
    size_t message_length;
    size_t context_length;
    size_t index;
    int kat_active = 0;
    int status = 1;

    if (path == NULL || algorithm_name == NULL || api == NULL ||
        api->public_key_size == NULL || api->private_key_size == NULL ||
        api->signature_size == NULL || api->keygen == NULL ||
        api->sign == NULL || api->verify == NULL) {
        return 2;
    }

    public_key_length = api->public_key_size(alg);
    private_key_length = api->private_key_size(alg);
    signature_length = api->signature_size(alg);
    if (public_key_length == 0u || private_key_length == 0u ||
        signature_length == 0u) {
        fprintf(stderr, "%s: unsupported signature algorithm\n", algorithm_name);
        return 2;
    }

    expected_public_key = (uint8_t *)malloc(public_key_length);
    expected_private_key = (uint8_t *)malloc(private_key_length);
    expected_signature = (uint8_t *)malloc(signature_length);
    actual_public_key = (uint8_t *)malloc(public_key_length);
    actual_private_key = (uint8_t *)malloc(private_key_length);
    actual_signature = (uint8_t *)malloc(signature_length);
    if (expected_public_key == NULL || expected_private_key == NULL ||
        expected_signature == NULL || actual_public_key == NULL ||
        actual_private_key == NULL || actual_signature == NULL) {
        fprintf(stderr, "%s: allocation failed\n", algorithm_name);
        goto cleanup;
    }
    if (crypto_test_kat_open(&reader, path) != 0) goto cleanup;

    for (index = 0u; index < record_count; ++index) {
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
            crypto_test_kat_read_size(
                &reader, "mlen", &message_length) != 0 ||
            resize_buffer(&message, message_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "msg", message, message_length) != 0 ||
            crypto_test_kat_read_size(
                &reader, "ctxlen", &context_length) != 0 ||
            context_length > CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES ||
            resize_buffer(&context, context_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "ctx", context, context_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "pk", expected_public_key,
                public_key_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "sk", expected_private_key,
                private_key_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "sig", expected_signature,
                signature_length) != 0) {
            goto close_reader;
        }

        error = crypto_pqc_kat_initialize_internal(seed);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "KAT DRBG initialization", error);
            goto close_reader;
        }
        kat_active = 1;
        error = api->keygen(
            actual_public_key, public_key_length,
            actual_private_key, private_key_length, alg);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "key generation", error);
            goto close_reader;
        }
        error = api->sign(
            actual_private_key, private_key_length,
            message, message_length, context, context_length,
            actual_signature, signature_length, alg);
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
                &reader, "signature", expected_signature,
                actual_signature, signature_length) != 0) {
            goto close_reader;
        }
        error = api->verify(
            actual_public_key, public_key_length,
            message, message_length, context, context_length,
            actual_signature, signature_length, alg);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "signature verification", error);
            goto close_reader;
        }
    }

    if (crypto_test_kat_expect_eof(&reader) != 0) goto close_reader;
    printf("%s KAT passed: %zu records\n", algorithm_name, record_count);
    status = 0;

close_reader:
    if (kat_active != 0) crypto_pqc_kat_finalize_internal();
    if (crypto_test_kat_close(&reader) != 0) status = 1;
cleanup:
    crypto_zeroize(seed, sizeof(seed));
    if (actual_signature != NULL)
        crypto_zeroize(actual_signature, signature_length);
    if (actual_private_key != NULL)
        crypto_zeroize(actual_private_key, private_key_length);
    if (actual_public_key != NULL)
        crypto_zeroize(actual_public_key, public_key_length);
    if (expected_signature != NULL)
        crypto_zeroize(expected_signature, signature_length);
    if (expected_private_key != NULL)
        crypto_zeroize(expected_private_key, private_key_length);
    if (expected_public_key != NULL)
        crypto_zeroize(expected_public_key, public_key_length);
    free(actual_signature);
    free(actual_private_key);
    free(actual_public_key);
    free(expected_signature);
    free(expected_private_key);
    free(expected_public_key);
    free(context);
    free(message);
    return status;
}
