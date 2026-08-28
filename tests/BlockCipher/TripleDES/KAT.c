/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "BlockCipher.h"

#include <stdio.h>
#include <string.h>

static const uint8_t KEY[24] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
    0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
};

static int ecb_kat(void) {
    static const uint8_t plaintext[8] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    };
    static const uint8_t expected[8] = {
        0x69,0x17,0x47,0xfd,0x88,0xb6,0xd2,0x28
    };
    uint8_t ciphertext[8];
    uint8_t recovered[8];

    return LIBERAC_BLOCK_CIPHER_ENCRYPT(
               ciphertext, sizeof(ciphertext), NULL, 0u,
               plaintext, sizeof(plaintext), KEY, sizeof(KEY),
               NULL, 0u, NULL, 0u,
               LIBERAC_ALG_TDES_EDE3_ECB) != LIBERAC_SUCCESS ||
           memcmp(ciphertext, expected, sizeof(expected)) != 0 ||
           LIBERAC_BLOCK_CIPHER_DECRYPT(
               recovered, sizeof(recovered), NULL, 0u,
               ciphertext, sizeof(ciphertext), KEY, sizeof(KEY),
               NULL, 0u, NULL, 0u,
               LIBERAC_ALG_TDES_EDE3_ECB) != LIBERAC_SUCCESS ||
           memcmp(recovered, plaintext, sizeof(plaintext)) != 0;
}

static int cbc_kat(void) {
    static const uint8_t iv[8] = {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef
    };
    static const uint8_t plaintext[16] = {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    static const uint8_t expected[16] = {
        0x20,0x40,0x11,0xf9,0x86,0xe3,0x56,0x47,
        0x19,0x9e,0x47,0xaf,0x39,0x16,0x20,0xc5
    };
    uint8_t ciphertext[16];
    uint8_t recovered[16];

    return LIBERAC_BLOCK_CIPHER_ENCRYPT(
               ciphertext, sizeof(ciphertext), NULL, 0u,
               plaintext, sizeof(plaintext), KEY, sizeof(KEY),
               iv, sizeof(iv), NULL, 0u,
               LIBERAC_ALG_TDES_EDE3_CBC) != LIBERAC_SUCCESS ||
           memcmp(ciphertext, expected, sizeof(expected)) != 0 ||
           LIBERAC_BLOCK_CIPHER_DECRYPT(
               recovered, sizeof(recovered), NULL, 0u,
               ciphertext, sizeof(ciphertext), KEY, sizeof(KEY),
               iv, sizeof(iv), NULL, 0u,
               LIBERAC_ALG_TDES_EDE3_CBC) != LIBERAC_SUCCESS ||
           memcmp(recovered, plaintext, sizeof(plaintext)) != 0;
}

static int in_place_test(void) {
    static const uint8_t iv[8] = {0,1,2,3,4,5,6,7};
    uint8_t data[24];
    uint8_t original[24];
    size_t index;

    for (index = 0u; index < sizeof(data); ++index) {
        data[index] = (uint8_t)(index * 13u + 9u);
    }
    memcpy(original, data, sizeof(data));
    return LIBERAC_BLOCK_CIPHER_ENCRYPT(
               data, sizeof(data), NULL, 0u, data, sizeof(data),
               KEY, sizeof(KEY), iv, sizeof(iv), NULL, 0u,
               LIBERAC_ALG_TDES_EDE3_CBC) != LIBERAC_SUCCESS ||
           LIBERAC_BLOCK_CIPHER_DECRYPT(
               data, sizeof(data), NULL, 0u, data, sizeof(data),
               KEY, sizeof(KEY), iv, sizeof(iv), NULL, 0u,
               LIBERAC_ALG_TDES_EDE3_CBC) != LIBERAC_SUCCESS ||
           memcmp(data, original, sizeof(data)) != 0;
}

static int validation_test(void) {
    uint8_t data[9] = {0};
    uint8_t ignored = 0u;

    return LIBERAC_BLOCK_CIPHER_KEY_SIZE(LIBERAC_ALG_TDES_EDE3_ECB) !=
               LIBERAC_TDES_EDE3_KEY_BYTES ||
           LIBERAC_BLOCK_CIPHER_ENCRYPT(
               data, sizeof(data), NULL, 0u, data, sizeof(data),
               KEY, sizeof(KEY), NULL, 0u, NULL, 0u,
               LIBERAC_ALG_TDES_EDE3_ECB) !=
               LIBERAC_ERROR_INVALID_ARGUMENT ||
           LIBERAC_BLOCK_CIPHER_ENCRYPT(
               data, 7u, NULL, 0u, data, 8u,
               KEY, sizeof(KEY), NULL, 0u, NULL, 0u,
               LIBERAC_ALG_TDES_EDE3_ECB) !=
               LIBERAC_ERROR_BUFFER_TOO_SMALL ||
           LIBERAC_BLOCK_CIPHER_ENCRYPT(
               data, 8u, NULL, 0u, data, 8u,
               KEY, sizeof(KEY) - 1u, NULL, 0u, NULL, 0u,
               LIBERAC_ALG_TDES_EDE3_ECB) != LIBERAC_ERROR_INVALID_KEY ||
           LIBERAC_BLOCK_CIPHER_ENCRYPT(
               data, 8u, &ignored, 1u, data, 8u,
               KEY, sizeof(KEY), NULL, 0u, NULL, 0u,
               LIBERAC_ALG_TDES_EDE3_ECB) !=
               LIBERAC_ERROR_INVALID_ARGUMENT ||
           LIBERAC_BLOCK_CIPHER_ENCRYPT(
               NULL, 0u, &ignored, 0u, NULL, 0u,
               KEY, sizeof(KEY), &ignored, 0u, &ignored, 0u,
               LIBERAC_ALG_TDES_EDE3_ECB) != LIBERAC_SUCCESS ||
           LIBERAC_BLOCK_CIPHER_ENCRYPT(
               NULL, 0u, NULL, 0u, NULL, 0u,
               NULL, 0u, NULL, 0u, NULL, 0u,
               LIBERAC_ALG_TDES_EDE3_ECB) !=
               LIBERAC_ERROR_INVALID_ARGUMENT;
}

int main(void) {
    if (ecb_kat() || cbc_kat() || in_place_test()) {
        fputs("Triple-DES KAT failed\n", stderr);
        return 1;
    }
    if (validation_test()) {
        fputs("Triple-DES validation failed\n", stderr);
        return 1;
    }
    puts("Triple-DES KAT passed");
    return 0;
}
