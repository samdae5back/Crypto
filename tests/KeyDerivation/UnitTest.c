/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "KeyDerivation.h"

#include <stdio.h>
#include <string.h>

static int api_validation_tests(void) {
    uint8_t buffer[64];
    uint8_t prk[64];
    uint8_t password[] = "password";
    uint8_t salt[] = "salt";

    memset(buffer, 0xa5, sizeof(buffer));
    memset(prk, 0x5a, sizeof(prk));

    if (LIBERAC_HKDF_PRK_SIZE(LIBERAC_ALG_HASH_SHA2_256) != 32u ||
        LIBERAC_HKDF_PRK_SIZE(LIBERAC_ALG_HASH_SHA3_512) != 64u ||
        LIBERAC_HKDF_PRK_SIZE(LIBERAC_ALG_HASH_SHAKE128) != 0u ||
        LIBERAC_HKDF_PRK_SIZE(LIBERAC_ALG_HASH_LSH_256_256) != 0u) {
        return 1;
    }

    if (LIBERAC_HKDF_EXTRACT(
            buffer, 31u, password, sizeof(password) - 1u,
            salt, sizeof(salt) - 1u,
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_BUFFER_TOO_SMALL) {
        return 1;
    }
    if (LIBERAC_HKDF_EXTRACT(
            buffer, sizeof(buffer), password, sizeof(password) - 1u,
            salt, sizeof(salt) - 1u,
            LIBERAC_ALG_HASH_SHAKE128) != LIBERAC_ERROR_INVALID_ALG_ID) {
        return 1;
    }
    if (LIBERAC_HKDF_EXPAND(
            buffer, sizeof(buffer), 32u, prk, 31u,
            NULL, 0u,
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    if (LIBERAC_HKDF_EXPAND(
            NULL, 0u, 0u, prk, 32u,
            NULL, 0u,
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_SUCCESS) {
        return 1;
    }
    if (LIBERAC_HKDF_EXPAND(
            buffer, sizeof(buffer), 256u * 32u, prk, 32u,
            NULL, 0u,
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_MESSAGE_TOO_LARGE) {
        return 1;
    }

    if (LIBERAC_PBKDF2_HMAC(
            buffer, sizeof(buffer), 32u,
            password, sizeof(password) - 1u,
            salt, sizeof(salt) - 1u,
            0u, LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    if (LIBERAC_PBKDF2_HMAC(
            buffer, sizeof(buffer), 0u,
            password, sizeof(password) - 1u,
            salt, sizeof(salt) - 1u,
            1u, LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    if (LIBERAC_PBKDF2_HMAC(
            buffer, 31u, 32u,
            password, sizeof(password) - 1u,
            salt, sizeof(salt) - 1u,
            1u, LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_BUFFER_TOO_SMALL) {
        return 1;
    }
    if (LIBERAC_PBKDF2_HMAC(
            salt, sizeof(salt), sizeof(salt),
            password, sizeof(password) - 1u,
            salt, sizeof(salt) - 1u,
            1u, LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    return 0;
}

static int sha3_runtime_selection_test(void) {
    static const uint8_t expected[] = {
        0x4c, 0x91, 0x5b, 0xae, 0xdd, 0x17, 0x73, 0x38,
        0x3e, 0x77, 0xfc, 0xfe, 0x38, 0x11, 0x4c, 0xa7,
        0x51, 0x40, 0x10, 0xad, 0xec, 0x24, 0xb4, 0x72,
        0x90, 0xec, 0x17, 0x02, 0x08, 0x42, 0x3f, 0x76
    };
    static const uint8_t password[] = "password";
    static const uint8_t salt[] = "salt";
    uint8_t output[sizeof(expected)];

    if (LIBERAC_PBKDF2_HMAC(
            output, sizeof(output), sizeof(output),
            password, sizeof(password) - 1u,
            salt, sizeof(salt) - 1u,
            2u, LIBERAC_ALG_HASH_SHA3_256) != LIBERAC_SUCCESS ||
        memcmp(output, expected, sizeof(expected)) != 0) {
        return 1;
    }
    return 0;
}

int main(void) {
    if (api_validation_tests() != 0) {
        fprintf(stderr, "Key-derivation API validation tests failed\n");
        return 1;
    }
    if (sha3_runtime_selection_test() != 0) {
        fprintf(stderr, "PBKDF2-HMAC-SHA3-256 runtime-selection test failed\n");
        return 1;
    }

    puts("Key-derivation unit tests passed.");
    return 0;
}
