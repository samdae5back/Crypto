/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "HashFunction.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    LiberaCAlgID algorithm;
    size_t output_length;
} HashTestCase;

static const HashTestCase HASH_TEST_CASES[] = {
    {LIBERAC_ALG_HASH_SHA1, LIBERAC_SHA1_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_SHA2_224, LIBERAC_SHA2_224_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_SHA2_256, LIBERAC_SHA2_256_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_SHA2_384, LIBERAC_SHA2_384_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_SHA2_512, LIBERAC_SHA2_512_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_SHA2_512_224, LIBERAC_SHA2_512_224_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_SHA2_512_256, LIBERAC_SHA2_512_256_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_LSH_256_224, LIBERAC_LSH_256_224_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_LSH_256_256, LIBERAC_LSH_256_256_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_LSH_512_224, LIBERAC_LSH_512_224_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_LSH_512_256, LIBERAC_LSH_512_256_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_LSH_512_384, LIBERAC_LSH_512_384_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_LSH_512_512, LIBERAC_LSH_512_512_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_SHA3_224, LIBERAC_SHA3_224_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_SHA3_256, LIBERAC_SHA3_256_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_SHA3_384, LIBERAC_SHA3_384_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_SHA3_512, LIBERAC_SHA3_512_DIGEST_BYTES},
    {LIBERAC_ALG_HASH_SHAKE128, 337u},
    {LIBERAC_ALG_HASH_SHAKE256, 337u}
};

static int all_zero(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    size_t i;

    for (i = 0u; i < length; ++i) {
        if (bytes[i] != 0u) return 0;
    }
    return 1;
}

static int is_shake(LiberaCAlgID algorithm) {
    return algorithm == LIBERAC_ALG_HASH_SHAKE128 ||
           algorithm == LIBERAC_ALG_HASH_SHAKE256;
}

static int test_argument_validation(void) {
    uint8_t output[64];
    uint8_t snapshot[64];
    LiberaCError error;

    memset(output, 0x3c, sizeof(output));
    memcpy(snapshot, output, sizeof(output));
    error = LIBERAC_HASH(output, 31u, NULL, 0u, LIBERAC_ALG_HASH_SHA2_256);
    if (error != LIBERAC_ERROR_BUFFER_TOO_SMALL ||
        memcmp(output, snapshot, sizeof(output)) != 0) {
        fprintf(stderr, "short fixed-digest buffer validation failed\n");
        return 1;
    }
    if (LIBERAC_HASH(NULL, 0u, NULL, 0u, LIBERAC_ALG_HASH_SHA2_256) !=
        LIBERAC_ERROR_BUFFER_TOO_SMALL) {
        fprintf(stderr, "null fixed-digest buffer validation failed\n");
        return 1;
    }
    if (LIBERAC_HASH(NULL, 1u, NULL, 0u, LIBERAC_ALG_HASH_SHAKE128) !=
        LIBERAC_ERROR_INVALID_ARGUMENT) {
        fprintf(stderr, "null XOF output validation failed\n");
        return 1;
    }
    if (LIBERAC_HASH(NULL, 0u, NULL, 0u, LIBERAC_ALG_HASH_SHAKE128) !=
        LIBERAC_SUCCESS) {
        fprintf(stderr, "zero-length XOF validation failed\n");
        return 1;
    }
    if (LIBERAC_HASH(output, sizeof(output), NULL, 1u, LIBERAC_ALG_HASH_SHA3_512) !=
        LIBERAC_ERROR_INVALID_ARGUMENT) {
        fprintf(stderr, "null input validation failed\n");
        return 1;
    }
    if (LIBERAC_HASH(output, sizeof(output), NULL, 0u, (LiberaCAlgID)0x7fffffff) !=
        LIBERAC_ERROR_INVALID_ALG_ID) {
        fprintf(stderr, "invalid algorithm validation failed\n");
        return 1;
    }
    return 0;
}

static int test_incremental_equivalence(void) {
    uint8_t message[521];
    uint8_t expected[337];
    uint8_t actual[337];
    size_t case_index;
    size_t i;

    for (i = 0u; i < sizeof(message); ++i)
        message[i] = (uint8_t)(i * 29u + 7u);

    for (case_index = 0u;
         case_index < sizeof(HASH_TEST_CASES) / sizeof(HASH_TEST_CASES[0]);
         ++case_index) {
        const HashTestCase *test_case = &HASH_TEST_CASES[case_index];
        LiberaCHashContext context;

        memset(expected, 0xa5, sizeof(expected));
        memset(actual, 0x5a, sizeof(actual));
        if (LIBERAC_HASH(expected, test_case->output_length,
                        message, sizeof(message),
                        test_case->algorithm) != LIBERAC_SUCCESS ||
            LIBERAC_HASH_INIT(&context, test_case->algorithm) !=
                LIBERAC_SUCCESS ||
            LIBERAC_HASH_UPDATE(&context, NULL, 0u) != LIBERAC_SUCCESS) {
            return 1;
        }
        for (i = 0u; i < sizeof(message); ++i) {
            if (LIBERAC_HASH_UPDATE(&context, message + i, 1u) !=
                LIBERAC_SUCCESS) {
                LIBERAC_HASH_CLEAR(&context);
                return 1;
            }
        }
        if (LIBERAC_HASH_FINALIZE(&context) != LIBERAC_SUCCESS) {
            LIBERAC_HASH_CLEAR(&context);
            return 1;
        }

        if (is_shake(test_case->algorithm)) {
            const size_t rate = test_case->algorithm == LIBERAC_ALG_HASH_SHAKE128
                                    ? 168u : 136u;
            if (LIBERAC_HASH_SQUEEZE(
                    &context, actual, rate - 1u) != LIBERAC_SUCCESS ||
                LIBERAC_HASH_SQUEEZE(
                    &context, actual + rate - 1u, 2u) != LIBERAC_SUCCESS ||
                LIBERAC_HASH_SQUEEZE(
                    &context, actual + rate + 1u,
                    test_case->output_length - rate - 1u) !=
                    LIBERAC_SUCCESS) {
                LIBERAC_HASH_CLEAR(&context);
                return 1;
            }
        } else {
            if (LIBERAC_HASH_SQUEEZE(
                    &context, actual, test_case->output_length) !=
                    LIBERAC_SUCCESS ||
                LIBERAC_HASH_SQUEEZE(
                    &context, actual, test_case->output_length) !=
                    LIBERAC_ERROR_INVALID_ARGUMENT) {
                LIBERAC_HASH_CLEAR(&context);
                return 1;
            }
        }
        if (memcmp(actual, expected, test_case->output_length) != 0) {
            LIBERAC_HASH_CLEAR(&context);
            return 1;
        }
        LIBERAC_HASH_CLEAR(&context);
        if (!all_zero(&context, sizeof(context))) return 1;
    }
    return 0;
}

static int test_incremental_lifecycle(void) {
    static const uint8_t message[] = {'a', 'b', 'c'};
    LiberaCHashContext context;
    uint8_t output[64];
    uint8_t snapshot[64];
    uint8_t expected[64];

    memset(&context, 0xa5, sizeof(context));
    if (LIBERAC_HASH_INIT(NULL, LIBERAC_ALG_HASH_SHA2_256) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_INIT(&context, (LiberaCAlgID)0x7fffffff) !=
            LIBERAC_ERROR_INVALID_ALG_ID ||
        !all_zero(&context, sizeof(context))) {
        return 1;
    }
    if (LIBERAC_HASH_UPDATE(NULL, NULL, 0u) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_FINALIZE(NULL) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_SQUEEZE(NULL, output, sizeof(output)) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_UPDATE(&context, NULL, 0u) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_FINALIZE(&context) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_SQUEEZE(&context, output, sizeof(output)) !=
            LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 1;
    }

    if (LIBERAC_HASH_INIT(&context, LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_SUCCESS ||
        LIBERAC_HASH_SQUEEZE(&context, output, sizeof(output)) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_UPDATE(&context, NULL, 1u) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_UPDATE(&context, message, sizeof(message)) !=
            LIBERAC_SUCCESS ||
        LIBERAC_HASH_FINALIZE(&context) != LIBERAC_SUCCESS ||
        LIBERAC_HASH_UPDATE(&context, message, sizeof(message)) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_FINALIZE(&context) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        LIBERAC_HASH_CLEAR(&context);
        return 1;
    }

    memset(output, 0x3c, sizeof(output));
    memcpy(snapshot, output, sizeof(output));
    if (LIBERAC_HASH_SQUEEZE(
            &context, output, LIBERAC_SHA2_256_DIGEST_BYTES - 1u) !=
            LIBERAC_ERROR_BUFFER_TOO_SMALL ||
        memcmp(output, snapshot, sizeof(output)) != 0 ||
        LIBERAC_HASH_SQUEEZE(
            &context, output, LIBERAC_SHA2_256_DIGEST_BYTES) !=
            LIBERAC_SUCCESS ||
        LIBERAC_HASH(expected, LIBERAC_SHA2_256_DIGEST_BYTES,
                    message, sizeof(message), LIBERAC_ALG_HASH_SHA2_256) !=
            LIBERAC_SUCCESS ||
        memcmp(output, expected, LIBERAC_SHA2_256_DIGEST_BYTES) != 0 ||
        LIBERAC_HASH_SQUEEZE(
            &context, output, LIBERAC_SHA2_256_DIGEST_BYTES) !=
            LIBERAC_ERROR_INVALID_ARGUMENT) {
        LIBERAC_HASH_CLEAR(&context);
        return 1;
    }
    LIBERAC_HASH_CLEAR(&context);
    return !all_zero(&context, sizeof(context));
}

static int test_shake_lifecycle(void) {
    static const uint8_t message[] = {'x', 'o', 'f'};
    LiberaCHashContext context;
    uint8_t expected[200];
    uint8_t actual[200];

    if (LIBERAC_HASH(expected, sizeof(expected), message, sizeof(message),
                    LIBERAC_ALG_HASH_SHAKE256) != LIBERAC_SUCCESS ||
        LIBERAC_HASH_INIT(&context, LIBERAC_ALG_HASH_SHAKE256) != LIBERAC_SUCCESS ||
        LIBERAC_HASH_UPDATE(&context, message, sizeof(message)) !=
            LIBERAC_SUCCESS ||
        LIBERAC_HASH_FINALIZE(&context) != LIBERAC_SUCCESS ||
        LIBERAC_HASH_SQUEEZE(&context, NULL, 0u) != LIBERAC_SUCCESS ||
        LIBERAC_HASH_SQUEEZE(&context, actual, 135u) != LIBERAC_SUCCESS ||
        LIBERAC_HASH_SQUEEZE(&context, NULL, 1u) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_SQUEEZE(
            &context, actual + 135u, sizeof(actual) - 135u) !=
            LIBERAC_SUCCESS ||
        memcmp(actual, expected, sizeof(actual)) != 0 ||
        LIBERAC_HASH_UPDATE(&context, message, sizeof(message)) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_FINALIZE(&context) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        LIBERAC_HASH_CLEAR(&context);
        return 1;
    }
    LIBERAC_HASH_CLEAR(&context);
    return !all_zero(&context, sizeof(context));
}

int main(void) {
    if (test_argument_validation()) return 1;
    if (test_incremental_equivalence()) {
        fputs("incremental hash equivalence test failed\n", stderr);
        return 1;
    }
    if (test_incremental_lifecycle()) {
        fputs("incremental hash lifecycle test failed\n", stderr);
        return 1;
    }
    if (test_shake_lifecycle()) {
        fputs("SHAKE lifecycle test failed\n", stderr);
        return 1;
    }
    puts("hash unit tests passed");
    return 0;
}
