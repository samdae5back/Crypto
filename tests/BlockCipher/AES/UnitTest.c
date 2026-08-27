/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "BlockCipher.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    LiberaCAlgID ALG;
    LiberaCAlgID EXPECTED_ID;
    size_t KEY_LENGTH;
} AesParameterSet;

static const AesParameterSet AES_PARAMETER_SETS[] = {
    {LIBERAC_ALG_AES_128_ECB, 0x00500110, 16u},
    {LIBERAC_ALG_AES_192_ECB, 0x00500118, 24u},
    {LIBERAC_ALG_AES_256_ECB, 0x00500120, 32u},
    {LIBERAC_ALG_AES_128_CBC, 0x00500210, 16u},
    {LIBERAC_ALG_AES_192_CBC, 0x00500218, 24u},
    {LIBERAC_ALG_AES_256_CBC, 0x00500220, 32u},
    {LIBERAC_ALG_AES_128_CTR, 0x00500610, 16u},
    {LIBERAC_ALG_AES_192_CTR, 0x00500618, 24u},
    {LIBERAC_ALG_AES_256_CTR, 0x00500620, 32u},
    {LIBERAC_ALG_AES_128_CCM, 0x00580110, 16u},
    {LIBERAC_ALG_AES_192_CCM, 0x00580118, 24u},
    {LIBERAC_ALG_AES_256_CCM, 0x00580120, 32u},
    {LIBERAC_ALG_AES_128_GCM, 0x00580210, 16u},
    {LIBERAC_ALG_AES_192_GCM, 0x00580218, 24u},
    {LIBERAC_ALG_AES_256_GCM, 0x00580220, 32u}
};

static int all_zero(const uint8_t *data, size_t length) {
    size_t i;
    for (i = 0u; i < length; ++i) {
        if (data[i] != 0u) return 0;
    }
    return 1;
}

static int key_size_test(void) {
    size_t i;

    for (i = 0u;
         i < sizeof(AES_PARAMETER_SETS) / sizeof(AES_PARAMETER_SETS[0]);
         ++i) {
        if (AES_PARAMETER_SETS[i].ALG != AES_PARAMETER_SETS[i].EXPECTED_ID ||
            LIBERAC_BLOCK_CIPHER_KEY_SIZE(AES_PARAMETER_SETS[i].ALG) !=
            AES_PARAMETER_SETS[i].KEY_LENGTH) {
            return 1;
        }
    }
    return LIBERAC_BLOCK_CIPHER_KEY_SIZE(LIBERAC_ALG_NONE) != 0u ||
           LIBERAC_BLOCK_CIPHER_KEY_SIZE(LIBERAC_ALG_RSA_RAW) != 0u;
}

static int all_parameter_sets_roundtrip(void) {
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t aad[13];
    uint8_t plaintext[32];
    uint8_t ciphertext[32];
    uint8_t recovered[32];
    uint8_t tag[16];
    size_t i;
    size_t j;

    for (i = 0u; i < sizeof(key); ++i) key[i] = (uint8_t)(i * 3u + 1u);
    for (i = 0u; i < sizeof(iv); ++i) iv[i] = (uint8_t)(i + 0x40u);
    for (i = 0u; i < sizeof(aad); ++i) aad[i] = (uint8_t)(i + 0x70u);
    for (i = 0u; i < sizeof(plaintext); ++i)
        plaintext[i] = (uint8_t)(i * 7u + 5u);

    for (j = 0u;
         j < sizeof(AES_PARAMETER_SETS) / sizeof(AES_PARAMETER_SETS[0]);
         ++j) {
        LiberaCAlgID alg = AES_PARAMETER_SETS[j].ALG;
        size_t input_length = sizeof(plaintext);
        const uint8_t *mode_iv = NULL;
        size_t iv_length = 0u;
        const uint8_t *mode_aad = NULL;
        size_t aad_length = 0u;
        size_t tag_length = 0u;

        if (alg == LIBERAC_ALG_AES_128_CTR || alg == LIBERAC_ALG_AES_192_CTR ||
            alg == LIBERAC_ALG_AES_256_CTR) {
            input_length = 29u;
            mode_iv = iv;
            iv_length = 16u;
        } else if (alg == LIBERAC_ALG_AES_128_CBC || alg == LIBERAC_ALG_AES_192_CBC ||
                   alg == LIBERAC_ALG_AES_256_CBC) {
            mode_iv = iv;
            iv_length = 16u;
        } else if (alg == LIBERAC_ALG_AES_128_CCM || alg == LIBERAC_ALG_AES_192_CCM ||
                   alg == LIBERAC_ALG_AES_256_CCM) {
            input_length = 29u;
            mode_iv = iv;
            iv_length = 13u;
            mode_aad = aad;
            aad_length = sizeof(aad);
            tag_length = 8u;
        } else if (alg == LIBERAC_ALG_AES_128_GCM || alg == LIBERAC_ALG_AES_192_GCM ||
                   alg == LIBERAC_ALG_AES_256_GCM) {
            input_length = 29u;
            mode_iv = iv;
            iv_length = 12u;
            mode_aad = aad;
            aad_length = sizeof(aad);
            tag_length = 16u;
        }

        if (LIBERAC_BLOCK_CIPHER_ENCRYPT(
                ciphertext, sizeof(ciphertext),
                tag_length ? tag : NULL, tag_length,
                plaintext, input_length,
                key, AES_PARAMETER_SETS[j].KEY_LENGTH,
                mode_iv, iv_length, mode_aad, aad_length,
                alg) != LIBERAC_SUCCESS) {
            return 1;
        }
        if (LIBERAC_BLOCK_CIPHER_DECRYPT(
                recovered, sizeof(recovered),
                tag_length ? tag : NULL, tag_length,
                ciphertext, input_length,
                key, AES_PARAMETER_SETS[j].KEY_LENGTH,
                mode_iv, iv_length, mode_aad, aad_length,
                alg) != LIBERAC_SUCCESS) {
            return 1;
        }
        if (memcmp(recovered, plaintext, input_length) != 0) return 1;
    }
    return 0;
}

static int negative_test(void) {
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    uint8_t input[17] = {0};
    uint8_t output[17];
    uint8_t tag[16] = {0};
    uint8_t bad_tag[16];

    if (LIBERAC_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), NULL, 0u, input, 16u,
            key, sizeof(key), NULL, 0u, NULL, 0u,
            LIBERAC_ALG_NONE) != LIBERAC_ERROR_INVALID_ALG_ID) {
        return 1;
    }
    if (LIBERAC_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), NULL, 0u, input, 16u,
            key, sizeof(key), NULL, 0u, NULL, 0u,
            (LiberaCAlgID)0x00500010) != LIBERAC_ERROR_INVALID_ALG_ID ||
        LIBERAC_BLOCK_CIPHER_KEY_SIZE((LiberaCAlgID)0x00500310) != 0u) {
        return 1;
    }
    if (LIBERAC_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), NULL, 0u, input, 16u,
            key, sizeof(key) - 1u, NULL, 0u, NULL, 0u,
            LIBERAC_ALG_AES_128_ECB) != LIBERAC_ERROR_INVALID_KEY) {
        return 1;
    }
    if (LIBERAC_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), NULL, 0u, input, 17u,
            key, sizeof(key), iv, sizeof(iv), NULL, 0u,
            LIBERAC_ALG_AES_128_CBC) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    if (LIBERAC_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), tag, 5u, input, 16u,
            key, sizeof(key), iv, 12u, NULL, 0u,
            LIBERAC_ALG_AES_128_GCM) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    if (LIBERAC_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), tag, 5u, input, 16u,
            key, sizeof(key), iv, 13u, NULL, 0u,
            LIBERAC_ALG_AES_128_CCM) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    if (LIBERAC_BLOCK_CIPHER_ENCRYPT(
            output, 15u, NULL, 0u, input, 16u,
            key, sizeof(key), NULL, 0u, NULL, 0u,
            LIBERAC_ALG_AES_128_ECB) != LIBERAC_ERROR_BUFFER_TOO_SMALL) {
        return 1;
    }

    if (LIBERAC_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), tag, sizeof(tag), input, 16u,
            key, sizeof(key), iv, 12u, NULL, 0u,
            LIBERAC_ALG_AES_128_GCM) != LIBERAC_SUCCESS) {
        return 1;
    }
    memcpy(bad_tag, tag, sizeof(tag));
    bad_tag[0] ^= 1u;
    memset(input, 0xa5, 16u);
    if (LIBERAC_BLOCK_CIPHER_DECRYPT(
            input, sizeof(input), bad_tag, sizeof(bad_tag), output, 16u,
            key, sizeof(key), iv, 12u, NULL, 0u,
            LIBERAC_ALG_AES_128_GCM) != LIBERAC_ERROR_AUTHENTICATION_FAILED ||
        !all_zero(input, 16u)) {
        return 1;
    }
    return 0;
}

int main(void) {
    if (key_size_test()) {
        fputs("AES parameter-set dispatch test failed\n", stderr);
        return 1;
    }
    if (all_parameter_sets_roundtrip()) {
        fputs("AES complete parameter-set roundtrip failed\n", stderr);
        return 1;
    }
    if (negative_test()) {
        fputs("AES negative test failed\n", stderr);
        return 1;
    }
    puts("block cipher unit tests passed");
    return 0;
}
