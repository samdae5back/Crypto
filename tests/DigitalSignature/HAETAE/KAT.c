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

typedef enum crypto_test_haetae_kat_format {
    CRYPTO_TEST_HAETAE_KAT_OFFICIAL_1_2,
    CRYPTO_TEST_HAETAE_KAT_LEGACY_CONTEXT
} CRYPTO_TEST_HAETAE_KAT_FORMAT;

typedef struct crypto_test_haetae_case {
    const char *name;
    AlgID alg;
    CRYPTO_TEST_HAETAE_KAT_FORMAT format;
} CRYPTO_TEST_HAETAE_CASE;

static const CRYPTO_TEST_HAETAE_CASE haetae_cases[] = {
    { "HAETAE-120", ALG_HAETAE_120,
      CRYPTO_TEST_HAETAE_KAT_OFFICIAL_1_2 },
    { "HAETAE-180", ALG_HAETAE_180,
      CRYPTO_TEST_HAETAE_KAT_OFFICIAL_1_2 },
    { "HAETAE-260", ALG_HAETAE_260,
      CRYPTO_TEST_HAETAE_KAT_OFFICIAL_1_2 },
    { "HAETAE-120-legacy", ALG_HAETAE_120,
      CRYPTO_TEST_HAETAE_KAT_LEGACY_CONTEXT },
    { "HAETAE-180-legacy", ALG_HAETAE_180,
      CRYPTO_TEST_HAETAE_KAT_LEGACY_CONTEXT },
    { "HAETAE-260-legacy", ALG_HAETAE_260,
      CRYPTO_TEST_HAETAE_KAT_LEGACY_CONTEXT }
};

static int report_crypto_error(
    const CRYPTO_TEST_KAT_READER *reader, const char *operation,
    CryptoError error) {
    fprintf(stderr, "%s: record %zu: %s failed (%d)\n",
            reader->path, reader->record, operation, (int)error);
    return -1;
}

static int initialize_kat(
    const CRYPTO_TEST_KAT_READER *reader,
    const uint8_t seed[CRYPTO_PQC_KAT_SEED_BYTES], int *kat_active) {
    const CryptoError error = crypto_pqc_kat_initialize_internal(seed);

    if (error != CRYPTO_SUCCESS) {
        return report_crypto_error(
            reader, "KAT DRBG initialization", error);
    }
    *kat_active = 1;
    return 0;
}

static void finalize_kat(int *kat_active) {
    if (*kat_active != 0) {
        crypto_pqc_kat_finalize_internal();
        *kat_active = 0;
    }
}

static int derive_official_context(
    const CRYPTO_TEST_KAT_READER *reader, uint8_t *context,
    size_t *context_length) {
    uint8_t signature_randomness[32] = { 0 };
    uint8_t encoded_context_length = 0u;
    CryptoError error;

    error = crypto_pqc_random_bytes_internal(
        signature_randomness, sizeof(signature_randomness));
    if (error == CRYPTO_SUCCESS) {
        error = crypto_pqc_random_bytes_internal(
            &encoded_context_length, sizeof(encoded_context_length));
    }
    if (error == CRYPTO_SUCCESS && encoded_context_length != 0u) {
        error = crypto_pqc_random_bytes_internal(
            context, (size_t)encoded_context_length);
    }
    crypto_zeroize(signature_randomness, sizeof(signature_randomness));
    if (error != CRYPTO_SUCCESS) {
        return report_crypto_error(reader, "KAT context replay", error);
    }
    *context_length = (size_t)encoded_context_length;
    return 0;
}

static int rewind_to_signature_randomness(
    const CRYPTO_TEST_KAT_READER *reader,
    const uint8_t seed[CRYPTO_PQC_KAT_SEED_BYTES], int *kat_active) {
    uint8_t key_generation_seed[32] = { 0 };
    CryptoError error;

    finalize_kat(kat_active);
    if (initialize_kat(reader, seed, kat_active) != 0) return -1;
    error = crypto_pqc_random_bytes_internal(
        key_generation_seed, sizeof(key_generation_seed));
    crypto_zeroize(key_generation_seed, sizeof(key_generation_seed));
    if (error != CRYPTO_SUCCESS) {
        return report_crypto_error(reader, "KAT DRBG rewind", error);
    }
    return 0;
}

static int run_kat(
    const char *path, const CRYPTO_TEST_HAETAE_CASE *test_case) {
    CRYPTO_TEST_KAT_READER reader = { NULL, NULL, 0u };
    uint8_t seed[CRYPTO_PQC_KAT_SEED_BYTES] = { 0 };
    uint8_t context[CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES] = { 0 };
    uint8_t *message = NULL;
    uint8_t *expected_public_key = NULL;
    uint8_t *expected_private_key = NULL;
    uint8_t *expected_signature = NULL;
    uint8_t *actual_public_key = NULL;
    uint8_t *actual_private_key = NULL;
    uint8_t *actual_signature = NULL;
    const size_t public_key_length =
        CRYPTO_HAETAE_PUBLIC_KEY_SIZE(test_case->alg);
    const size_t private_key_length =
        CRYPTO_HAETAE_PRIVATE_KEY_SIZE(test_case->alg);
    const size_t signature_length =
        CRYPTO_HAETAE_SIGNATURE_SIZE(test_case->alg);
    size_t message_length = 0u;
    size_t message_capacity = 0u;
    size_t context_length = 0u;
    size_t index;
    int kat_active = 0;
    int status = 1;

    if (public_key_length == 0u || private_key_length == 0u ||
        signature_length == 0u) {
        fprintf(stderr, "%s: unsupported HAETAE algorithm\n", test_case->name);
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
        fprintf(stderr, "%s: allocation failed\n", test_case->name);
        goto cleanup;
    }
    if (crypto_test_kat_open(&reader, path) != 0) goto cleanup;

    for (index = 0u; index < 100u; ++index) {
        size_t count;
        size_t encoded_signature_length;
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
                &reader, "msg", message, message_length) != 0) {
            goto close_reader;
        }

        context_length = 0u;
        if (test_case->format == CRYPTO_TEST_HAETAE_KAT_LEGACY_CONTEXT) {
            if (crypto_test_kat_read_size(
                    &reader, "ctxlen", &context_length) != 0 ||
                context_length > sizeof(context) ||
                crypto_test_kat_read_hex(
                    &reader, "ctx", context, context_length) != 0) {
                goto close_reader;
            }
        }
        if (crypto_test_kat_read_hex(
                &reader, "pk", expected_public_key,
                public_key_length) != 0 ||
            crypto_test_kat_read_hex(
                &reader, "sk", expected_private_key,
                private_key_length) != 0) {
            goto close_reader;
        }
        if (test_case->format == CRYPTO_TEST_HAETAE_KAT_OFFICIAL_1_2) {
            if (crypto_test_kat_read_size(
                    &reader, "siglen", &encoded_signature_length) != 0 ||
                encoded_signature_length != signature_length) {
                fprintf(stderr,
                        "%s: record %zu: unexpected signature length\n",
                        path, index);
                goto close_reader;
            }
        }
        if (crypto_test_kat_read_hex(
                &reader, "sig", expected_signature,
                signature_length) != 0) {
            goto close_reader;
        }

        if (initialize_kat(&reader, seed, &kat_active) != 0)
            goto close_reader;
        error = CRYPTO_HAETAE_KEYGEN(
            actual_public_key, public_key_length,
            actual_private_key, private_key_length, test_case->alg);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "key generation", error);
            goto close_reader;
        }
        if (test_case->format == CRYPTO_TEST_HAETAE_KAT_OFFICIAL_1_2 &&
            derive_official_context(
                &reader, context, &context_length) != 0) {
            goto close_reader;
        }
        if (crypto_test_kat_compare(
                &reader, "public key", expected_public_key,
                actual_public_key, public_key_length) != 0 ||
            crypto_test_kat_compare(
                &reader, "private key", expected_private_key,
                actual_private_key, private_key_length) != 0) {
            goto close_reader;
        }

        if (test_case->format == CRYPTO_TEST_HAETAE_KAT_OFFICIAL_1_2) {
            if (rewind_to_signature_randomness(
                    &reader, seed, &kat_active) != 0) {
                goto close_reader;
            }
            error = CRYPTO_HAETAE_SIGN(
                actual_private_key, private_key_length,
                message, message_length, context, context_length,
                actual_signature, signature_length, test_case->alg);
            if (error != CRYPTO_SUCCESS) {
                report_crypto_error(&reader, "signature generation", error);
                goto close_reader;
            }
            if (crypto_test_kat_compare(
                    &reader, "signature", expected_signature,
                    actual_signature, signature_length) != 0) {
                goto close_reader;
            }
        }
        finalize_kat(&kat_active);

        error = CRYPTO_HAETAE_VERIFY(
            expected_public_key, public_key_length,
            message, message_length, context, context_length,
            expected_signature, signature_length, test_case->alg);
        if (error != CRYPTO_SUCCESS) {
            report_crypto_error(&reader, "signature verification", error);
            goto close_reader;
        }
    }

    if (crypto_test_kat_expect_eof(&reader) != 0) goto close_reader;
    printf("%s KAT passed: 100 records\n", test_case->name);
    status = 0;

close_reader:
    finalize_kat(&kat_active);
    if (crypto_test_kat_close(&reader) != 0) status = 1;
cleanup:
    crypto_zeroize(seed, sizeof(seed));
    crypto_zeroize(context, sizeof(context));
    if (message != NULL) crypto_zeroize(message, message_capacity);
    if (expected_public_key != NULL)
        crypto_zeroize(expected_public_key, public_key_length);
    if (expected_private_key != NULL)
        crypto_zeroize(expected_private_key, private_key_length);
    if (expected_signature != NULL)
        crypto_zeroize(expected_signature, signature_length);
    if (actual_public_key != NULL)
        crypto_zeroize(actual_public_key, public_key_length);
    if (actual_private_key != NULL)
        crypto_zeroize(actual_private_key, private_key_length);
    if (actual_signature != NULL)
        crypto_zeroize(actual_signature, signature_length);
    free(actual_signature);
    free(actual_private_key);
    free(actual_public_key);
    free(expected_signature);
    free(expected_private_key);
    free(expected_public_key);
    free(message);
    return status;
}

int main(int argc, char **argv) {
    size_t index;

    if (argc != 3) {
        fprintf(stderr, "usage: haetae_kat <vector.kat> <selector>\n");
        return 2;
    }
    for (index = 0u;
         index < sizeof(haetae_cases) / sizeof(haetae_cases[0]);
         ++index) {
        if (strcmp(argv[2], haetae_cases[index].name) == 0)
            return run_kat(argv[1], &haetae_cases[index]);
    }
    fprintf(stderr, "unsupported HAETAE KAT selector: %s\n", argv[2]);
    return 2;
}
