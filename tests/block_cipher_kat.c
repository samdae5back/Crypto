/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "BlockCipher.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    AlgID ALG;
    size_t KEY_LENGTH;
} AesParameterSet;

static const AesParameterSet AES_PARAMETER_SETS[] = {
    {ALG_AES_128_ECB, 16u}, {ALG_AES_192_ECB, 24u},
    {ALG_AES_256_ECB, 32u}, {ALG_AES_128_CBC, 16u},
    {ALG_AES_192_CBC, 24u}, {ALG_AES_256_CBC, 32u},
    {ALG_AES_128_CTR, 16u}, {ALG_AES_192_CTR, 24u},
    {ALG_AES_256_CTR, 32u}, {ALG_AES_128_CCM, 16u},
    {ALG_AES_192_CCM, 24u}, {ALG_AES_256_CCM, 32u},
    {ALG_AES_128_GCM, 16u}, {ALG_AES_192_GCM, 24u},
    {ALG_AES_256_GCM, 32u}
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

    if (ALG_AES_128_ECB != 0x00500110 ||
        ALG_AES_192_ECB != 0x00500118 ||
        ALG_AES_256_ECB != 0x00500120 ||
        ALG_AES_128_CBC != 0x00500210 ||
        ALG_AES_192_CBC != 0x00500218 ||
        ALG_AES_256_CBC != 0x00500220 ||
        ALG_AES_128_CTR != 0x00500610 ||
        ALG_AES_192_CTR != 0x00500618 ||
        ALG_AES_256_CTR != 0x00500620 ||
        ALG_AES_128_CCM != 0x00580110 ||
        ALG_AES_192_CCM != 0x00580118 ||
        ALG_AES_256_CCM != 0x00580120 ||
        ALG_AES_128_GCM != 0x00580210 ||
        ALG_AES_192_GCM != 0x00580218 ||
        ALG_AES_256_GCM != 0x00580220) {
        return 1;
    }
    for (i = 0u;
         i < sizeof(AES_PARAMETER_SETS) / sizeof(AES_PARAMETER_SETS[0]);
         ++i) {
        if (CRYPTO_BLOCK_CIPHER_KEY_SIZE(AES_PARAMETER_SETS[i].ALG) !=
            AES_PARAMETER_SETS[i].KEY_LENGTH) {
            return 1;
        }
    }
    return CRYPTO_BLOCK_CIPHER_KEY_SIZE(ALG_NONE) != 0u;
}

static int ecb_kat(void) {
    static const uint8_t plaintext[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t keys[3][32] = {
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17},
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
         0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f}
    };
    static const uint8_t expected[3][16] = {
        {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
         0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a},
        {0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,
         0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91},
        {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
         0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89}
    };
    static const AlgID algorithms[3] = {
        ALG_AES_128_ECB, ALG_AES_192_ECB, ALG_AES_256_ECB
    };
    static const size_t key_lengths[3] = {16u, 24u, 32u};
    uint8_t ciphertext[16];
    uint8_t recovered[16];
    size_t i;

    for (i = 0u; i < 3u; ++i) {
        if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
                ciphertext, sizeof(ciphertext), NULL, 0u,
                plaintext, sizeof(plaintext), keys[i], key_lengths[i],
                NULL, 0u, NULL, 0u, algorithms[i]) != CRYPTO_SUCCESS) {
            return 1;
        }
        if (memcmp(ciphertext, expected[i], sizeof(ciphertext)) != 0)
            return 1;
        if (CRYPTO_BLOCK_CIPHER_DECRYPT(
                recovered, sizeof(recovered), NULL, 0u,
                ciphertext, sizeof(ciphertext), keys[i], key_lengths[i],
                NULL, 0u, NULL, 0u, algorithms[i]) != CRYPTO_SUCCESS) {
            return 1;
        }
        if (memcmp(recovered, plaintext, sizeof(recovered)) != 0) return 1;
    }
    return 0;
}

static int cbc_ctr_kat(void) {
    static const uint8_t plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t counter[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };
    static const uint8_t keys[3][32] = {
        {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
         0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c},
        {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
         0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
         0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b},
        {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
         0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
         0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
         0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
    };
    static const uint8_t cbc_expected[3][16] = {
        {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
         0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d},
        {0x4f,0x02,0x1d,0xb2,0x43,0xbc,0x63,0x3d,
         0x71,0x78,0x18,0x3a,0x9f,0xa0,0x71,0xe8},
        {0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
         0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6}
    };
    static const uint8_t ctr_expected[3][16] = {
        {0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
         0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce},
        {0x1a,0xbc,0x93,0x24,0x17,0x52,0x1c,0xa2,
         0x4f,0x2b,0x04,0x59,0xfe,0x7e,0x6e,0x0b},
        {0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,
         0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28}
    };
    static const AlgID cbc_algorithms[3] = {
        ALG_AES_128_CBC, ALG_AES_192_CBC, ALG_AES_256_CBC
    };
    static const AlgID ctr_algorithms[3] = {
        ALG_AES_128_CTR, ALG_AES_192_CTR, ALG_AES_256_CTR
    };
    static const size_t key_lengths[3] = {16u, 24u, 32u};
    uint8_t output[16];
    size_t i;

    for (i = 0u; i < 3u; ++i) {
        if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
                output, sizeof(output), NULL, 0u,
                plaintext, sizeof(plaintext), keys[i], key_lengths[i],
                iv, sizeof(iv), NULL, 0u,
                cbc_algorithms[i]) != CRYPTO_SUCCESS ||
            memcmp(output, cbc_expected[i], sizeof(output)) != 0) {
            return 1;
        }
        if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
                output, sizeof(output), NULL, 0u,
                plaintext, sizeof(plaintext), keys[i], key_lengths[i],
                counter, sizeof(counter), NULL, 0u,
                ctr_algorithms[i]) != CRYPTO_SUCCESS ||
            memcmp(output, ctr_expected[i], sizeof(output)) != 0) {
            return 1;
        }
    }
    return 0;
}

static int gcm_kat(void) {
    static const uint8_t keys[3][32] = {{0}, {0}, {0}};
    static const size_t key_lengths[3] = {16u, 24u, 32u};
    static const AlgID algorithms[3] = {
        ALG_AES_128_GCM, ALG_AES_192_GCM, ALG_AES_256_GCM
    };
    static const uint8_t expected_ciphertext[3][16] = {
        {0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
         0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78},
        {0x98,0xe7,0x24,0x7c,0x07,0xf0,0xfe,0x41,
         0x1c,0x26,0x7e,0x43,0x84,0xb0,0xf6,0x00},
        {0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,
         0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18}
    };
    static const uint8_t expected_tag[3][16] = {
        {0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
         0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf},
        {0x2f,0xf5,0x8d,0x80,0x03,0x39,0x27,0xab,
         0x8e,0xf4,0xd4,0x58,0x75,0x14,0xf0,0xfb},
        {0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,
         0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19}
    };
    static const uint8_t iv[12] = {0};
    static const uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];
    uint8_t tag[16];
    size_t i;

    for (i = 0u; i < 3u; ++i) {
        if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
                ciphertext, sizeof(ciphertext), tag, sizeof(tag),
                plaintext, sizeof(plaintext), keys[i], key_lengths[i],
                iv, sizeof(iv), NULL, 0u,
                algorithms[i]) != CRYPTO_SUCCESS) {
            return 1;
        }
        if (memcmp(ciphertext, expected_ciphertext[i], sizeof(ciphertext)) != 0 ||
            memcmp(tag, expected_tag[i], sizeof(tag)) != 0) {
            return 1;
        }
    }
    return 0;
}

static int ccm_kat(void) {
    static const uint8_t key[16] = {
        0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
        0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf
    };
    static const uint8_t nonce[13] = {
        0x00,0x00,0x00,0x03,0x02,0x01,0x00,
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5
    };
    static const uint8_t aad[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
    static const uint8_t plaintext[23] = {
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e
    };
    static const uint8_t expected_ciphertext[23] = {
        0x58,0x8c,0x97,0x9a,0x61,0xc6,0x63,0xd2,
        0xf0,0x66,0xd0,0xc2,0xc0,0xf9,0x89,0x80,
        0x6d,0x5f,0x6b,0x61,0xda,0xc3,0x84
    };
    static const uint8_t expected_tag[8] = {
        0x17,0xe8,0xd1,0x2c,0xfd,0xf9,0x26,0xe0
    };
    uint8_t ciphertext[23];
    uint8_t tag[8];

    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            ciphertext, sizeof(ciphertext), tag, sizeof(tag),
            plaintext, sizeof(plaintext), key, sizeof(key),
            nonce, sizeof(nonce), aad, sizeof(aad),
            ALG_AES_128_CCM) != CRYPTO_SUCCESS) {
        return 1;
    }
    return memcmp(ciphertext, expected_ciphertext, sizeof(ciphertext)) != 0 ||
           memcmp(tag, expected_tag, sizeof(tag)) != 0;
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
        AlgID alg = AES_PARAMETER_SETS[j].ALG;
        size_t input_length = sizeof(plaintext);
        const uint8_t *mode_iv = NULL;
        size_t iv_length = 0u;
        const uint8_t *mode_aad = NULL;
        size_t aad_length = 0u;
        size_t tag_length = 0u;

        if (alg == ALG_AES_128_CTR || alg == ALG_AES_192_CTR ||
            alg == ALG_AES_256_CTR) {
            input_length = 29u;
            mode_iv = iv;
            iv_length = 16u;
        } else if (alg == ALG_AES_128_CBC || alg == ALG_AES_192_CBC ||
                   alg == ALG_AES_256_CBC) {
            mode_iv = iv;
            iv_length = 16u;
        } else if (alg == ALG_AES_128_CCM || alg == ALG_AES_192_CCM ||
                   alg == ALG_AES_256_CCM) {
            input_length = 29u;
            mode_iv = iv;
            iv_length = 13u;
            mode_aad = aad;
            aad_length = sizeof(aad);
            tag_length = 8u;
        } else if (alg == ALG_AES_128_GCM || alg == ALG_AES_192_GCM ||
                   alg == ALG_AES_256_GCM) {
            input_length = 29u;
            mode_iv = iv;
            iv_length = 12u;
            mode_aad = aad;
            aad_length = sizeof(aad);
            tag_length = 16u;
        }

        if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
                ciphertext, sizeof(ciphertext),
                tag_length ? tag : NULL, tag_length,
                plaintext, input_length,
                key, AES_PARAMETER_SETS[j].KEY_LENGTH,
                mode_iv, iv_length, mode_aad, aad_length,
                alg) != CRYPTO_SUCCESS) {
            return 1;
        }
        if (CRYPTO_BLOCK_CIPHER_DECRYPT(
                recovered, sizeof(recovered),
                tag_length ? tag : NULL, tag_length,
                ciphertext, input_length,
                key, AES_PARAMETER_SETS[j].KEY_LENGTH,
                mode_iv, iv_length, mode_aad, aad_length,
                alg) != CRYPTO_SUCCESS) {
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

    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), NULL, 0u, input, 16u,
            key, sizeof(key), NULL, 0u, NULL, 0u,
            ALG_NONE) != CRYPTO_ERROR_INVALID_ALG_ID) {
        return 1;
    }
    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), NULL, 0u, input, 16u,
            key, sizeof(key), NULL, 0u, NULL, 0u,
            (AlgID)0x00500010) != CRYPTO_ERROR_INVALID_ALG_ID ||
        CRYPTO_BLOCK_CIPHER_KEY_SIZE((AlgID)0x00500310) != 0u) {
        return 1;
    }
    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), NULL, 0u, input, 16u,
            key, sizeof(key) - 1u, NULL, 0u, NULL, 0u,
            ALG_AES_128_ECB) != CRYPTO_ERROR_INVALID_KEY) {
        return 1;
    }
    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), NULL, 0u, input, 17u,
            key, sizeof(key), iv, sizeof(iv), NULL, 0u,
            ALG_AES_128_CBC) != CRYPTO_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), tag, 5u, input, 16u,
            key, sizeof(key), iv, 12u, NULL, 0u,
            ALG_AES_128_GCM) != CRYPTO_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), tag, 5u, input, 16u,
            key, sizeof(key), iv, 13u, NULL, 0u,
            ALG_AES_128_CCM) != CRYPTO_ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            output, 15u, NULL, 0u, input, 16u,
            key, sizeof(key), NULL, 0u, NULL, 0u,
            ALG_AES_128_ECB) != CRYPTO_ERROR_BUFFER_TOO_SMALL) {
        return 1;
    }

    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), tag, sizeof(tag), input, 16u,
            key, sizeof(key), iv, 12u, NULL, 0u,
            ALG_AES_128_GCM) != CRYPTO_SUCCESS) {
        return 1;
    }
    memcpy(bad_tag, tag, sizeof(tag));
    bad_tag[0] ^= 1u;
    memset(input, 0xa5, 16u);
    if (CRYPTO_BLOCK_CIPHER_DECRYPT(
            input, sizeof(input), bad_tag, sizeof(bad_tag), output, 16u,
            key, sizeof(key), iv, 12u, NULL, 0u,
            ALG_AES_128_GCM) != CRYPTO_ERROR_AUTHENTICATION_FAILED ||
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
    if (ecb_kat()) {
        fputs("AES ECB KAT failed\n", stderr);
        return 1;
    }
    if (cbc_ctr_kat()) {
        fputs("AES CBC/CTR KAT failed\n", stderr);
        return 1;
    }
    if (gcm_kat()) {
        fputs("AES GCM KAT failed\n", stderr);
        return 1;
    }
    if (ccm_kat()) {
        fputs("AES CCM KAT failed\n", stderr);
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
    puts("block cipher KAT passed");
    return 0;
}
