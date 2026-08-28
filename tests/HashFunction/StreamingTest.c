/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "HashFunction.h"

#include <stdio.h>
#include <string.h>

#define STREAM_MESSAGE_BYTES 521u
#define STREAM_XOF_BYTES 400u
#define STREAM_OUTPUT_BYTES (STREAM_XOF_BYTES + 8u)

typedef struct hash_stream_case {
    LiberaCAlgID algorithm;
    size_t output_length;
    size_t rate;
} hash_stream_case;

static const hash_stream_case HASH_STREAM_CASES[] = {
    {LIBERAC_ALG_HASH_SHA2_224, LIBERAC_SHA2_224_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_SHA2_256, LIBERAC_SHA2_256_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_SHA2_384, LIBERAC_SHA2_384_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_SHA2_512, LIBERAC_SHA2_512_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_SHA2_512_224, LIBERAC_SHA2_512_224_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_SHA2_512_256, LIBERAC_SHA2_512_256_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_SHA3_224, LIBERAC_SHA3_224_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_SHA3_256, LIBERAC_SHA3_256_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_SHA3_384, LIBERAC_SHA3_384_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_SHA3_512, LIBERAC_SHA3_512_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_SHAKE128, STREAM_XOF_BYTES, 168u},
    {LIBERAC_ALG_HASH_SHAKE256, STREAM_XOF_BYTES, 136u},
    {LIBERAC_ALG_HASH_LSH_256_224, LIBERAC_LSH_256_224_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_LSH_256_256, LIBERAC_LSH_256_256_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_LSH_512_224, LIBERAC_LSH_512_224_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_LSH_512_256, LIBERAC_LSH_512_256_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_LSH_512_384, LIBERAC_LSH_512_384_DIGEST_BYTES, 0u},
    {LIBERAC_ALG_HASH_LSH_512_512, LIBERAC_LSH_512_512_DIGEST_BYTES, 0u}
};

static int bytes_are(
    const uint8_t *buffer, size_t length, uint8_t expected) {
    size_t index;

    for (index = 0u; index < length; ++index) {
        if (buffer[index] != expected) {
            return 0;
        }
    }
    return 1;
}

static int context_is_clear(const LiberaCHashContext *context) {
    return bytes_are((const uint8_t *)context, sizeof(*context), 0u);
}

static int report_failure(
    LiberaCAlgID algorithm, unsigned int chunk_mode, const char *operation) {
    fprintf(stderr, "hash 0x%08lx mode %u: %s failed\n",
            (unsigned long)(uint32_t)algorithm, chunk_mode, operation);
    return 1;
}

static LiberaCError update_in_chunks(
    LiberaCHashContext *context,
    const uint8_t *message, size_t message_length,
    unsigned int chunk_mode) {
    static const size_t irregular_chunks[] = {
        17u, 47u, 1u, 63u, 2u, 70u, 33u, 128u, 5u, 155u
    };
    size_t offset = 0u;
    size_t index;
    LiberaCError error;

    if (chunk_mode == 0u) {
        return LIBERAC_HASH_UPDATE(context, message, message_length);
    }
    if (chunk_mode == 1u) {
        for (offset = 0u; offset < message_length; ++offset) {
            error = LIBERAC_HASH_UPDATE(context, message + offset, 1u);
            if (error != LIBERAC_SUCCESS) {
                return error;
            }
        }
        return LIBERAC_SUCCESS;
    }

    error = LIBERAC_HASH_UPDATE(context, NULL, 0u);
    if (error != LIBERAC_SUCCESS) {
        return error;
    }
    for (index = 0u;
         index < sizeof(irregular_chunks) / sizeof(irregular_chunks[0]);
         ++index) {
        const size_t chunk = irregular_chunks[index];

        if (chunk > message_length - offset) {
            return LIBERAC_ERROR_INTERNAL;
        }
        error = LIBERAC_HASH_UPDATE(context, message + offset, chunk);
        if (error != LIBERAC_SUCCESS) {
            return error;
        }
        offset += chunk;
    }
    return offset == message_length
               ? LIBERAC_SUCCESS : LIBERAC_ERROR_INTERNAL;
}

static int squeeze_fixed(
    LiberaCHashContext *context,
    const uint8_t *expected, size_t digest_length,
    LiberaCAlgID algorithm, unsigned int chunk_mode) {
    uint8_t output[STREAM_OUTPUT_BYTES];

    memset(output, 0xa5, sizeof(output));
    if (LIBERAC_HASH_SQUEEZE(context, output, digest_length - 1u) !=
            LIBERAC_ERROR_BUFFER_TOO_SMALL ||
        !bytes_are(output, sizeof(output), 0xa5u)) {
        return report_failure(algorithm, chunk_mode, "short-buffer retry");
    }
    if (LIBERAC_HASH_SQUEEZE(context, output, sizeof(output)) !=
            LIBERAC_SUCCESS ||
        memcmp(output, expected, digest_length) != 0 ||
        !bytes_are(output + digest_length,
                   sizeof(output) - digest_length, 0xa5u)) {
        return report_failure(algorithm, chunk_mode, "fixed squeeze/tail");
    }
    if (LIBERAC_HASH_SQUEEZE(context, output, sizeof(output)) !=
            LIBERAC_ERROR_INVALID_ARGUMENT) {
        return report_failure(algorithm, chunk_mode, "second fixed squeeze");
    }
    return 0;
}

static int squeeze_xof(
    LiberaCHashContext *context,
    const uint8_t *expected, size_t output_length, size_t rate,
    LiberaCAlgID algorithm, unsigned int chunk_mode) {
    uint8_t output[STREAM_OUTPUT_BYTES];
    size_t offset = 0u;
    size_t first;

    memset(output, 0xa5, sizeof(output));
    if (LIBERAC_HASH_SQUEEZE(context, NULL, 0u) != LIBERAC_SUCCESS ||
        LIBERAC_HASH_SQUEEZE(context, NULL, 1u) !=
            LIBERAC_ERROR_INVALID_ARGUMENT) {
        return report_failure(algorithm, chunk_mode, "zero/invalid XOF squeeze");
    }

    first = rate - 1u;
    if (LIBERAC_HASH_SQUEEZE(context, output + offset, first) !=
            LIBERAC_SUCCESS) {
        return report_failure(algorithm, chunk_mode, "first XOF segment");
    }
    offset += first;
    if (LIBERAC_HASH_SQUEEZE(context, output + offset, 2u) !=
            LIBERAC_SUCCESS) {
        return report_failure(algorithm, chunk_mode, "rate-boundary XOF segment");
    }
    offset += 2u;
    if (LIBERAC_HASH_SQUEEZE(
            context, output + offset, output_length - offset) !=
            LIBERAC_SUCCESS ||
        memcmp(output, expected, output_length) != 0 ||
        !bytes_are(output + output_length,
                   sizeof(output) - output_length, 0xa5u)) {
        return report_failure(algorithm, chunk_mode, "continued XOF stream");
    }
    return 0;
}

static int test_stream_case(
    const hash_stream_case *test_case,
    const uint8_t *message, size_t message_length,
    unsigned int chunk_mode) {
    LiberaCHashContext context;
    uint8_t expected[STREAM_XOF_BYTES];
    uint8_t scratch[LIBERAC_HASH_MAX_DIGEST_BYTES];
    int failed;

    if (LIBERAC_HASH(expected, test_case->output_length,
                    message, message_length, test_case->algorithm) !=
            LIBERAC_SUCCESS ||
        LIBERAC_HASH_INIT(&context, test_case->algorithm) != LIBERAC_SUCCESS) {
        return report_failure(test_case->algorithm, chunk_mode,
                              "one-shot/init");
    }
    if (LIBERAC_HASH_SQUEEZE(&context, scratch, sizeof(scratch)) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_UPDATE(&context, NULL, 1u) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        update_in_chunks(&context, message, message_length, chunk_mode) !=
            LIBERAC_SUCCESS ||
        LIBERAC_HASH_FINALIZE(&context) != LIBERAC_SUCCESS ||
        LIBERAC_HASH_UPDATE(&context, NULL, 0u) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_FINALIZE(&context) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        LIBERAC_HASH_CLEAR(&context);
        return report_failure(test_case->algorithm, chunk_mode, "lifecycle");
    }

    if (test_case->rate == 0u) {
        failed = squeeze_fixed(&context, expected, test_case->output_length,
                               test_case->algorithm, chunk_mode);
    } else {
        failed = squeeze_xof(&context, expected, test_case->output_length,
                             test_case->rate,
                             test_case->algorithm, chunk_mode);
    }
    LIBERAC_HASH_CLEAR(&context);
    if (failed != 0) {
        return failed;
    }
    if (!context_is_clear(&context) ||
        LIBERAC_HASH_UPDATE(&context, NULL, 0u) !=
            LIBERAC_ERROR_INVALID_ARGUMENT) {
        return report_failure(test_case->algorithm, chunk_mode, "clear");
    }
    return 0;
}

static int test_invalid_contexts(void) {
    LiberaCHashContext context;
    uint8_t output[LIBERAC_HASH_MAX_DIGEST_BYTES];

    memset(&context, 0xa5, sizeof(context));
    if (LIBERAC_HASH_INIT(NULL, LIBERAC_ALG_HASH_SHA2_256) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_INIT(&context, (LiberaCAlgID)0x7fffffff) !=
            LIBERAC_ERROR_INVALID_ALG_ID ||
        !context_is_clear(&context) ||
        LIBERAC_HASH_UPDATE(NULL, NULL, 0u) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_FINALIZE(NULL) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HASH_SQUEEZE(NULL, output, sizeof(output)) !=
            LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    LIBERAC_HASH_CLEAR(NULL);
    return 0;
}

int main(void) {
    uint8_t message[STREAM_MESSAGE_BYTES];
    size_t case_index;
    size_t index;
    unsigned int chunk_mode;
    int failures = 0;

    for (index = 0u; index < sizeof(message); ++index) {
        message[index] = (uint8_t)(index * 37u + 11u);
    }
    if (test_invalid_contexts() != 0) {
        fputs("invalid hash-context tests failed\n", stderr);
        ++failures;
    }
    for (case_index = 0u;
         case_index < sizeof(HASH_STREAM_CASES) /
                      sizeof(HASH_STREAM_CASES[0]);
         ++case_index) {
        for (chunk_mode = 0u; chunk_mode < 3u; ++chunk_mode) {
            failures += test_stream_case(
                &HASH_STREAM_CASES[case_index],
                message, sizeof(message), chunk_mode);
        }
    }
    if (failures != 0) {
        fprintf(stderr, "streaming hash tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("streaming hash tests passed for all 18 algorithms");
    return 0;
}
