/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Util.h"

#include <stdio.h>
#include <string.h>

static int test_bignum(void) {
    static const uint8_t input[] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    uint8_t output[sizeof(input)];
    uint8_t little_endian[sizeof(input)];
    LiberaCBignum value;
    size_t i;
    int failed;

    LIBERAC_BIGNUM_INIT(&value);
    failed = LIBERAC_BIGNUM_FROM_BYTES_BE(&value, input, sizeof(input)) != LIBERAC_SUCCESS ||
             LIBERAC_BIGNUM_TO_BYTES_BE(&value, output, sizeof(output)) != LIBERAC_SUCCESS ||
             memcmp(input, output, sizeof(input)) != 0 ||
             LIBERAC_BIGNUM_TO_BYTES_BE(&value, output, sizeof(output) - 1u) !=
                 LIBERAC_ERROR_BUFFER_TOO_SMALL ||
             LIBERAC_BIGNUM_FROM_BYTES_BE(&value, NULL, 1u) !=
                 LIBERAC_ERROR_INVALID_ARGUMENT ||
             LIBERAC_BIGNUM_FROM_BYTES_BE(&value, input, SIZE_MAX) !=
                 LIBERAC_ERROR_MESSAGE_TOO_LARGE ||
             LIBERAC_PRIME_GENERATE(&value, SIZE_MAX, 1u) !=
                 LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    if (!failed) {
        for (i = 0u; i < sizeof(input); ++i)
            little_endian[i] = input[sizeof(input) - 1u - i];
        failed = LIBERAC_BIGNUM_TO_BYTES_LE(
                     &value, output, sizeof(output)) != LIBERAC_SUCCESS ||
                 memcmp(little_endian, output, sizeof(output)) != 0 ||
                 LIBERAC_BIGNUM_FROM_BYTES_LE(
                     &value, little_endian, sizeof(little_endian)) !=
                     LIBERAC_SUCCESS ||
                 LIBERAC_BIGNUM_TO_BYTES_BE(
                     &value, output, sizeof(output)) != LIBERAC_SUCCESS ||
                 memcmp(input, output, sizeof(input)) != 0;
    }
    if (!failed) {
        memset(output, 0xa5, sizeof(output));
        failed = LIBERAC_PRIME_GENERATE_SAFE(&value, &value, 32u, 1u) !=
                     LIBERAC_ERROR_INVALID_ARGUMENT ||
                 LIBERAC_BIGNUM_FROM_BYTES_BE(&value, NULL, 0u) !=
                     LIBERAC_SUCCESS ||
                 LIBERAC_BIGNUM_TO_BYTES_BE(
                     &value, output, sizeof(output)) != LIBERAC_SUCCESS;
        for (i = 0u; !failed && i < sizeof(output); ++i)
            failed = output[i] != 0u;
    }
    LIBERAC_BIGNUM_FREE(&value);
    return failed;
}

int main(void) {
    if (test_bignum()) {
        fputs("bignum/prime unit test failed\n", stderr);
        return 1;
    }
    puts("utility unit tests passed");
    return 0;
}
