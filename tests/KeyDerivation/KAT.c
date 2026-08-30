/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "KeyDerivation.h"

#include <stdio.h>
#include <string.h>

static int hex_nibble(char value, uint8_t *nibble) {
    if (value >= '0' && value <= '9') {
        *nibble = (uint8_t)(value - '0');
        return 1;
    }
    if (value >= 'a' && value <= 'f') {
        *nibble = (uint8_t)(value - 'a' + 10);
        return 1;
    }
    if (value >= 'A' && value <= 'F') {
        *nibble = (uint8_t)(value - 'A' + 10);
        return 1;
    }
    return 0;
}

static int decode_hex(
    uint8_t *output, size_t output_capacity,
    const char *hex, size_t *output_length) {
    size_t hex_length;
    size_t index;

    if (output_length == NULL || hex == NULL) return 0;
    hex_length = strlen(hex);
    if ((hex_length & 1u) != 0u || output_capacity < hex_length / 2u) return 0;
    for (index = 0u; index < hex_length / 2u; ++index) {
        uint8_t high;
        uint8_t low;
        if (!hex_nibble(hex[2u * index], &high) ||
            !hex_nibble(hex[2u * index + 1u], &low)) {
            return 0;
        }
        output[index] = (uint8_t)((high << 4) | low);
    }
    *output_length = hex_length / 2u;
    return 1;
}

static int hkdf_rfc5869_case1(void) {
    static const char *ikm_hex =
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    static const char *salt_hex = "000102030405060708090a0b0c";
    static const char *info_hex = "f0f1f2f3f4f5f6f7f8f9";
    static const char *prk_hex =
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5";
    static const char *okm_hex =
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865";
    uint8_t ikm[22];
    uint8_t salt[13];
    uint8_t info[10];
    uint8_t prk[32];
    uint8_t expected_prk[32];
    uint8_t okm[42];
    uint8_t expected_okm[42];
    size_t length;

    if (!decode_hex(ikm, sizeof(ikm), ikm_hex, &length) ||
        length != sizeof(ikm) ||
        !decode_hex(salt, sizeof(salt), salt_hex, &length) ||
        length != sizeof(salt) ||
        !decode_hex(info, sizeof(info), info_hex, &length) ||
        length != sizeof(info) ||
        !decode_hex(expected_prk, sizeof(expected_prk), prk_hex, &length) ||
        length != sizeof(expected_prk) ||
        !decode_hex(expected_okm, sizeof(expected_okm), okm_hex, &length) ||
        length != sizeof(expected_okm)) {
        return 1;
    }

    if (LIBERAC_HKDF_PRK_SIZE(LIBERAC_ALG_HASH_SHA2_256) != sizeof(prk) ||
        LIBERAC_HKDF_EXTRACT(
            prk, sizeof(prk), ikm, sizeof(ikm), salt, sizeof(salt),
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_SUCCESS ||
        memcmp(prk, expected_prk, sizeof(prk)) != 0 ||
        LIBERAC_HKDF_EXPAND(
            okm, sizeof(okm), sizeof(okm), prk, sizeof(prk),
            info, sizeof(info), LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_SUCCESS ||
        memcmp(okm, expected_okm, sizeof(okm)) != 0 ||
        LIBERAC_HKDF(
            okm, sizeof(okm), sizeof(okm), ikm, sizeof(ikm),
            salt, sizeof(salt), info, sizeof(info),
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_SUCCESS ||
        memcmp(okm, expected_okm, sizeof(okm)) != 0) {
        return 1;
    }
    return 0;
}

static int hkdf_rfc5869_case3(void) {
    static const char *ikm_hex =
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    static const char *prk_hex =
        "19ef24a32c717b167f33a91d6f648bdf"
        "96596776afdb6377ac434c1c293ccb04";
    static const char *okm_hex =
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8";
    uint8_t ikm[22];
    uint8_t prk[32];
    uint8_t expected_prk[32];
    uint8_t okm[42];
    uint8_t expected_okm[42];
    size_t length;

    if (!decode_hex(ikm, sizeof(ikm), ikm_hex, &length) ||
        length != sizeof(ikm) ||
        !decode_hex(expected_prk, sizeof(expected_prk), prk_hex, &length) ||
        length != sizeof(expected_prk) ||
        !decode_hex(expected_okm, sizeof(expected_okm), okm_hex, &length) ||
        length != sizeof(expected_okm)) {
        return 1;
    }

    if (LIBERAC_HKDF_EXTRACT(
            prk, sizeof(prk), ikm, sizeof(ikm), NULL, 0u,
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_SUCCESS ||
        memcmp(prk, expected_prk, sizeof(prk)) != 0 ||
        LIBERAC_HKDF(
            okm, sizeof(okm), sizeof(okm), ikm, sizeof(ikm),
            NULL, 0u, NULL, 0u,
            LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_SUCCESS ||
        memcmp(okm, expected_okm, sizeof(okm)) != 0) {
        return 1;
    }
    return 0;
}

static int pbkdf2_rfc6070(void) {
    static const struct {
        uint64_t ITERATIONS;
        size_t LENGTH;
        const char *EXPECTED;
    } vectors[] = {
        {1u, 20u, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
        {2u, 20u, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
        {4096u, 20u, "4b007901b765489abead49d926f721d065a429c1"}
    };
    static const uint8_t password[] = "password";
    static const uint8_t salt[] = "salt";
    uint8_t output[20];
    uint8_t expected[20];
    size_t expected_length;
    size_t index;

    for (index = 0u; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        if (!decode_hex(
                expected, sizeof(expected), vectors[index].EXPECTED,
                &expected_length) ||
            expected_length != vectors[index].LENGTH ||
            LIBERAC_PBKDF2_HMAC(
                output, sizeof(output), vectors[index].LENGTH,
                password, sizeof(password) - 1u,
                salt, sizeof(salt) - 1u,
                vectors[index].ITERATIONS,
                LIBERAC_ALG_HASH_SHA1) != LIBERAC_SUCCESS ||
            memcmp(output, expected, expected_length) != 0) {
            return 1;
        }
    }
    return 0;
}

static int pbkdf2_rfc7914_sha256(void) {
    static const uint8_t password[] = "passwd";
    static const uint8_t salt[] = "salt";
    static const char *expected_hex =
        "55ac046e56e3089fec1691c22544b605"
        "f94185216dde0465e68b9d57c20dacbc"
        "49ca9cccf179b645991664b39d77ef31"
        "7c71b845b1e30bd509112041d3a19783";
    uint8_t output[64];
    uint8_t expected[64];
    size_t expected_length;

    if (!decode_hex(expected, sizeof(expected), expected_hex, &expected_length) ||
        expected_length != sizeof(expected) ||
        LIBERAC_PBKDF2_HMAC(
            output, sizeof(output), sizeof(output),
            password, sizeof(password) - 1u,
            salt, sizeof(salt) - 1u,
            1u, LIBERAC_ALG_HASH_SHA2_256) != LIBERAC_SUCCESS ||
        memcmp(output, expected, sizeof(output)) != 0) {
        return 1;
    }
    return 0;
}

int main(void) {
    if (hkdf_rfc5869_case1() != 0) {
        fprintf(stderr, "RFC 5869 HKDF test case 1 failed\n");
        return 1;
    }
    if (hkdf_rfc5869_case3() != 0) {
        fprintf(stderr, "RFC 5869 HKDF test case 3 failed\n");
        return 1;
    }
    if (pbkdf2_rfc6070() != 0) {
        fprintf(stderr, "RFC 6070 PBKDF2-HMAC-SHA1 tests failed\n");
        return 1;
    }
    if (pbkdf2_rfc7914_sha256() != 0) {
        fprintf(stderr, "RFC 7914 PBKDF2-HMAC-SHA256 test failed\n");
        return 1;
    }

    puts("Key-derivation known-answer tests passed.");
    return 0;
}
