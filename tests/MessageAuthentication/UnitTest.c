/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "MessageAuthentication.h"

#include <stdio.h>
#include <string.h>

static int dispatch_test(void) {
    static const struct {
        LiberaCAlgID ALGORITHM;
        size_t TAG_LENGTH;
    } hmac_algorithms[] = {
        {LIBERAC_ALG_HASH_SHA1, 20u},
        {LIBERAC_ALG_HASH_SHA2_224, 28u},
        {LIBERAC_ALG_HASH_SHA2_256, 32u},
        {LIBERAC_ALG_HASH_SHA2_384, 48u},
        {LIBERAC_ALG_HASH_SHA2_512, 64u},
        {LIBERAC_ALG_HASH_SHA2_512_224, 28u},
        {LIBERAC_ALG_HASH_SHA2_512_256, 32u},
        {LIBERAC_ALG_HASH_SHA3_224, 28u},
        {LIBERAC_ALG_HASH_SHA3_256, 32u},
        {LIBERAC_ALG_HASH_SHA3_384, 48u},
        {LIBERAC_ALG_HASH_SHA3_512, 64u}
    };
    size_t index;

    for (index = 0u;
         index < sizeof(hmac_algorithms) / sizeof(hmac_algorithms[0]);
         ++index) {
        if (LIBERAC_HMAC_TAG_SIZE(hmac_algorithms[index].ALGORITHM) !=
            hmac_algorithms[index].TAG_LENGTH) {
            return 1;
        }
    }
    if (LIBERAC_HMAC_TAG_SIZE(LIBERAC_ALG_HASH_SHAKE128) != 0u ||
        LIBERAC_HMAC_TAG_SIZE(LIBERAC_ALG_HASH_LSH_256_256) != 0u ||
        LIBERAC_HMAC_TAG_SIZE(LIBERAC_ALG_AES_128_ECB) != 0u) {
        return 1;
    }

    if (LIBERAC_CMAC_TAG_SIZE(LIBERAC_ALG_AES_128_ECB) != 16u ||
        LIBERAC_CMAC_TAG_SIZE(LIBERAC_ALG_AES_192_ECB) != 16u ||
        LIBERAC_CMAC_TAG_SIZE(LIBERAC_ALG_AES_256_ECB) != 16u ||
        LIBERAC_CMAC_TAG_SIZE(LIBERAC_ALG_TDES_EDE3_ECB) != 8u ||
        LIBERAC_CMAC_TAG_SIZE(LIBERAC_ALG_AES_128_CBC) != 0u ||
        LIBERAC_CMAC_TAG_SIZE(LIBERAC_ALG_TDES_EDE3_CBC) != 0u) {
        return 1;
    }
    return 0;
}

static int hmac_api_test(void) {
    static const uint8_t message[] = "runtime HMAC selection";
    uint8_t key[32];
    uint8_t tag[LIBERAC_HMAC_MAX_TAG_BYTES];
    uint8_t bad_tag[16];
    size_t index;

    for (index = 0u; index < sizeof(key); ++index) {
        key[index] = (uint8_t)(index * 5u + 1u);
    }
    memset(tag, 0xa5, sizeof(tag));
    if (LIBERAC_HMAC(
            tag, sizeof(tag), 16u, message, sizeof(message) - 1u,
            key, sizeof(key), LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_SUCCESS) {
        return 1;
    }
    for (index = 16u; index < sizeof(tag); ++index) {
        if (tag[index] != 0xa5u) return 1;
    }
    if (LIBERAC_HMAC_VERIFY(
            tag, 16u, message, sizeof(message) - 1u,
            key, sizeof(key), LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_SUCCESS) {
        return 1;
    }
    memcpy(bad_tag, tag, sizeof(bad_tag));
    bad_tag[7] ^= UINT8_C(0x80);
    if (LIBERAC_HMAC_VERIFY(
            bad_tag, sizeof(bad_tag), message, sizeof(message) - 1u,
            key, sizeof(key),
            LIBERAC_ALG_HASH_SHA2_256) !=
        LIBERAC_ERROR_AUTHENTICATION_FAILED) {
        return 1;
    }

    if (LIBERAC_HMAC(
            tag, 15u, 16u, message, sizeof(message) - 1u,
            key, sizeof(key),
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_BUFFER_TOO_SMALL ||
        LIBERAC_HMAC(
            tag, sizeof(tag), 0u, message, sizeof(message) - 1u,
            key, sizeof(key),
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HMAC(
            tag, sizeof(tag), 33u, message, sizeof(message) - 1u,
            key, sizeof(key),
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HMAC(
            tag, sizeof(tag), 16u, NULL, 1u,
            key, sizeof(key),
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HMAC(
            tag, sizeof(tag), 16u, message, sizeof(message) - 1u,
            NULL, 1u,
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_HMAC(
            tag, sizeof(tag), 16u, message, sizeof(message) - 1u,
            key, sizeof(key),
            LIBERAC_ALG_HASH_SHAKE128) != LIBERAC_ERROR_INVALID_ALG_ID ||
        LIBERAC_HMAC(
            tag, sizeof(tag), 16u, message, sizeof(message) - 1u,
            key, sizeof(key),
            LIBERAC_ALG_HASH_LSH_256_256) != LIBERAC_ERROR_INVALID_ALG_ID) {
        return 1;
    }
    return 0;
}

static int cmac_api_test(void) {
    static const uint8_t message[] = "runtime CMAC selection";
    uint8_t key[32];
    uint8_t tag[LIBERAC_CMAC_MAX_TAG_BYTES];
    uint8_t bad_tag[12];
    size_t index;

    for (index = 0u; index < sizeof(key); ++index) {
        key[index] = (uint8_t)(index * 7u + 3u);
    }
    memset(tag, 0xa5, sizeof(tag));
    if (LIBERAC_CMAC(
            tag, sizeof(tag), 12u, message, sizeof(message) - 1u,
            key, sizeof(key), LIBERAC_ALG_AES_256_ECB) != LIBERAC_SUCCESS) {
        return 1;
    }
    for (index = 12u; index < sizeof(tag); ++index) {
        if (tag[index] != 0xa5u) return 1;
    }
    if (LIBERAC_CMAC_VERIFY(
            tag, 12u, message, sizeof(message) - 1u,
            key, sizeof(key), LIBERAC_ALG_AES_256_ECB) != LIBERAC_SUCCESS) {
        return 1;
    }
    memcpy(bad_tag, tag, sizeof(bad_tag));
    bad_tag[0] ^= 1u;
    if (LIBERAC_CMAC_VERIFY(
            bad_tag, sizeof(bad_tag), message, sizeof(message) - 1u,
            key, sizeof(key),
            LIBERAC_ALG_AES_256_ECB) !=
        LIBERAC_ERROR_AUTHENTICATION_FAILED) {
        return 1;
    }

    if (LIBERAC_CMAC(
            tag, 11u, 12u, message, sizeof(message) - 1u,
            key, sizeof(key),
            LIBERAC_ALG_AES_256_ECB) != LIBERAC_ERROR_BUFFER_TOO_SMALL ||
        LIBERAC_CMAC(
            tag, sizeof(tag), 17u, message, sizeof(message) - 1u,
            key, sizeof(key),
            LIBERAC_ALG_AES_256_ECB) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_CMAC(
            tag, sizeof(tag), 12u, message, sizeof(message) - 1u,
            key, sizeof(key) - 1u,
            LIBERAC_ALG_AES_256_ECB) != LIBERAC_ERROR_INVALID_KEY ||
        LIBERAC_CMAC(
            tag, sizeof(tag), 12u, message, sizeof(message) - 1u,
            key, sizeof(key),
            LIBERAC_ALG_AES_256_CBC) != LIBERAC_ERROR_INVALID_ALG_ID ||
        LIBERAC_CMAC(
            tag, sizeof(tag), 8u, message, sizeof(message) - 1u,
            key, 24u,
            LIBERAC_ALG_TDES_EDE3_CBC) != LIBERAC_ERROR_INVALID_ALG_ID ||
        LIBERAC_CMAC(
            tag, sizeof(tag), 12u, NULL, 1u,
            key, sizeof(key),
            LIBERAC_ALG_AES_256_ECB) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    return 0;
}

static int gmac_api_test(void) {
    static const uint8_t message[] = "runtime GMAC selection";
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t tag[LIBERAC_GMAC_MAX_TAG_BYTES];
    uint8_t bad_tag[12];
    size_t index;

    for (index = 0u; index < sizeof(key); ++index) {
        key[index] = (uint8_t)(index * 11u + 1u);
    }
    for (index = 0u; index < sizeof(iv); ++index) {
        iv[index] = (uint8_t)(index * 3u + 9u);
    }
    memset(tag, 0xa5, sizeof(tag));
    if (LIBERAC_GMAC(
            tag, sizeof(tag), 12u, message, sizeof(message) - 1u,
            key, sizeof(key), iv, sizeof(iv),
            LIBERAC_ALG_AES_128_GCM) != LIBERAC_SUCCESS) {
        return 1;
    }
    for (index = 12u; index < sizeof(tag); ++index) {
        if (tag[index] != 0xa5u) return 1;
    }
    if (LIBERAC_GMAC_VERIFY(
            tag, 12u, message, sizeof(message) - 1u,
            key, sizeof(key), iv, sizeof(iv),
            LIBERAC_ALG_AES_128_GCM) != LIBERAC_SUCCESS) {
        return 1;
    }
    memcpy(bad_tag, tag, sizeof(bad_tag));
    bad_tag[11] ^= UINT8_C(0x40);
    if (LIBERAC_GMAC_VERIFY(
            bad_tag, sizeof(bad_tag), message, sizeof(message) - 1u,
            key, sizeof(key), iv, sizeof(iv),
            LIBERAC_ALG_AES_128_GCM) !=
        LIBERAC_ERROR_AUTHENTICATION_FAILED) {
        return 1;
    }

    if (LIBERAC_GMAC(
            tag, 11u, 12u, message, sizeof(message) - 1u,
            key, sizeof(key), iv, sizeof(iv),
            LIBERAC_ALG_AES_128_GCM) != LIBERAC_ERROR_BUFFER_TOO_SMALL ||
        LIBERAC_GMAC(
            tag, sizeof(tag), 5u, message, sizeof(message) - 1u,
            key, sizeof(key), iv, sizeof(iv),
            LIBERAC_ALG_AES_128_GCM) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_GMAC(
            tag, sizeof(tag), 12u, message, sizeof(message) - 1u,
            key, sizeof(key) - 1u, iv, sizeof(iv),
            LIBERAC_ALG_AES_128_GCM) != LIBERAC_ERROR_INVALID_KEY ||
        LIBERAC_GMAC(
            tag, sizeof(tag), 12u, message, sizeof(message) - 1u,
            key, sizeof(key), NULL, 0u,
            LIBERAC_ALG_AES_128_GCM) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_GMAC(
            tag, sizeof(tag), 12u, message, sizeof(message) - 1u,
            key, sizeof(key), iv, sizeof(iv),
            LIBERAC_ALG_AES_128_ECB) != LIBERAC_ERROR_INVALID_ALG_ID ||
        LIBERAC_GMAC(
            tag, sizeof(tag), 12u, NULL, 1u,
            key, sizeof(key), iv, sizeof(iv),
            LIBERAC_ALG_AES_128_GCM) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    return 0;
}

int main(void) {
    if (dispatch_test()) {
        fputs("message authentication dispatch test failed\n", stderr);
        return 1;
    }
    if (hmac_api_test()) {
        fputs("HMAC API test failed\n", stderr);
        return 1;
    }
    if (cmac_api_test()) {
        fputs("CMAC API test failed\n", stderr);
        return 1;
    }
    if (gmac_api_test()) {
        fputs("GMAC API test failed\n", stderr);
        return 1;
    }
    puts("message authentication unit tests passed");
    return 0;
}
