/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "MessageAuthentication.h"

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

static int hmac_kat(void) {
    static const struct {
        LiberaCAlgID ALGORITHM;
        const char *EXPECTED;
    } vectors[] = {
        {LIBERAC_ALG_HASH_SHA1,
         "b617318655057264e28bc0b6fb378c8ef146be00"},
        {LIBERAC_ALG_HASH_SHA2_224,
         "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"},
        {LIBERAC_ALG_HASH_SHA2_256,
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
        {LIBERAC_ALG_HASH_SHA2_384,
         "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59"
         "cfaea9ea9076ede7f4af152e8b2fa9cb6"},
        {LIBERAC_ALG_HASH_SHA2_512,
         "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
         "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"},
        {LIBERAC_ALG_HASH_SHA2_512_224,
         "b244ba01307c0e7a8ccaad13b1067a4cf6b961fe0c6a20bda3d92039"},
        {LIBERAC_ALG_HASH_SHA2_512_256,
         "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab"},
        {LIBERAC_ALG_HASH_SHA3_224,
         "3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7"},
        {LIBERAC_ALG_HASH_SHA3_256,
         "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb"},
        {LIBERAC_ALG_HASH_SHA3_384,
         "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723"
         "a20d370b47743130e26ac7e3d532886bd"},
        {LIBERAC_ALG_HASH_SHA3_512,
         "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba"
         "47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e"}
    };
    static const uint8_t message[] = "Hi There";
    uint8_t key[20];
    uint8_t tag[LIBERAC_HMAC_MAX_TAG_BYTES];
    uint8_t expected[LIBERAC_HMAC_MAX_TAG_BYTES];
    size_t expected_length;
    size_t index;

    memset(key, 0x0b, sizeof(key));
    for (index = 0u; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        if (!decode_hex(expected, sizeof(expected), vectors[index].EXPECTED,
                        &expected_length) ||
            LIBERAC_HMAC_TAG_SIZE(vectors[index].ALGORITHM) != expected_length ||
            LIBERAC_HMAC(
                tag, sizeof(tag), expected_length,
                message, sizeof(message) - 1u,
                key, sizeof(key), vectors[index].ALGORITHM) != LIBERAC_SUCCESS ||
            memcmp(tag, expected, expected_length) != 0 ||
            LIBERAC_HMAC_VERIFY(
                tag, expected_length,
                message, sizeof(message) - 1u,
                key, sizeof(key), vectors[index].ALGORITHM) != LIBERAC_SUCCESS) {
            return 1;
        }
    }
    return 0;
}

static int hmac_long_key_kat(void) {
    static const uint8_t message[] =
        "Test Using Larger Than Block-Size Key - Hash Key First";
    static const struct {
        LiberaCAlgID ALGORITHM;
        const char *EXPECTED;
    } vectors[] = {
        {LIBERAC_ALG_HASH_SHA2_256,
         "f84c159648a99f6ace4dc6e293ebc50e9ec6936ebd7022091d9ae0f5cd6693ba"},
        {LIBERAC_ALG_HASH_SHA2_512,
         "9dc6330f4c966b62b735d565343cb77413deccdf42a92d9ef5e4e2ae33f6c924"
         "bbc8e34c47111bc069482d4dbcfee148419a6547f2d01500e8160b39cc2e4ae8"},
        {LIBERAC_ALG_HASH_SHA3_256,
         "49ad92b02124fdac9627ae45e008a696182ab6bfb8470457777c744aeb9df06f"},
        {LIBERAC_ALG_HASH_SHA3_512,
         "fafc7b7fe3332ce153966b27f6586fa5b49ec5d8dff3d7fd26a011451ca4c9de"
         "437913879159d9c5181a9a6f377ef18b48399756decea695b04fe90a9d3b93d1"}
    };
    uint8_t key[200];
    uint8_t tag[LIBERAC_HMAC_MAX_TAG_BYTES];
    uint8_t expected[LIBERAC_HMAC_MAX_TAG_BYTES];
    size_t expected_length;
    size_t index;

    memset(key, 0xaa, sizeof(key));
    for (index = 0u; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        if (!decode_hex(expected, sizeof(expected), vectors[index].EXPECTED,
                        &expected_length) ||
            LIBERAC_HMAC(
                tag, sizeof(tag), expected_length,
                message, sizeof(message) - 1u,
                key, sizeof(key), vectors[index].ALGORITHM) != LIBERAC_SUCCESS ||
            memcmp(tag, expected, expected_length) != 0) {
            return 1;
        }
    }
    return 0;
}

static int aes_cmac_kat(void) {
    static const char *message_hex =
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710";
    static const size_t message_lengths[] = {0u, 16u, 40u, 64u};
    static const struct {
        LiberaCAlgID ALGORITHM;
        const char *KEY;
        const char *EXPECTED[4];
    } vectors[] = {
        {LIBERAC_ALG_AES_128_ECB,
         "2b7e151628aed2a6abf7158809cf4f3c",
         {"bb1d6929e95937287fa37d129b756746",
          "070a16b46b4d4144f79bdd9dd04a287c",
          "dfa66747de9ae63030ca32611497c827",
          "51f0bebf7e3b9d92fc49741779363cfe"}},
        {LIBERAC_ALG_AES_192_ECB,
         "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
         {"d17ddf46adaacde531cac483de7a9367",
          "9e99a7bf31e710900662f65e617c5184",
          "8a1de5be2eb31aad089a82e6ee908b0e",
          "a1d5df0eed790f794d77589659f39a11"}},
        {LIBERAC_ALG_AES_256_ECB,
         "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
         {"028962f61b7bf89efc6b551f4667d983",
          "28a7023f452e8f82bd4bf28d8c37c35c",
          "aaf3d8f1de5640c232f5b169b9c911e6",
          "e1992190549f6ed5696a2c056c315410"}}
    };
    uint8_t message[64];
    uint8_t key[32];
    uint8_t tag[LIBERAC_CMAC_MAX_TAG_BYTES];
    uint8_t expected[LIBERAC_CMAC_MAX_TAG_BYTES];
    size_t message_length;
    size_t key_length;
    size_t expected_length;
    size_t vector_index;
    size_t length_index;

    if (!decode_hex(message, sizeof(message), message_hex, &message_length) ||
        message_length != sizeof(message)) {
        return 1;
    }
    for (vector_index = 0u;
         vector_index < sizeof(vectors) / sizeof(vectors[0]);
         ++vector_index) {
        if (!decode_hex(key, sizeof(key), vectors[vector_index].KEY,
                        &key_length) ||
            LIBERAC_CMAC_TAG_SIZE(vectors[vector_index].ALGORITHM) != 16u) {
            return 1;
        }
        for (length_index = 0u;
             length_index < sizeof(message_lengths) / sizeof(message_lengths[0]);
             ++length_index) {
            const uint8_t *input =
                message_lengths[length_index] == 0u ? NULL : message;
            if (!decode_hex(
                    expected, sizeof(expected),
                    vectors[vector_index].EXPECTED[length_index],
                    &expected_length) ||
                expected_length != 16u ||
                LIBERAC_CMAC(
                    tag, sizeof(tag), sizeof(tag),
                    input, message_lengths[length_index],
                    key, key_length,
                    vectors[vector_index].ALGORITHM) != LIBERAC_SUCCESS ||
                memcmp(tag, expected, sizeof(tag)) != 0 ||
                LIBERAC_CMAC_VERIFY(
                    tag, sizeof(tag), input, message_lengths[length_index],
                    key, key_length,
                    vectors[vector_index].ALGORITHM) != LIBERAC_SUCCESS) {
                return 1;
            }
        }
    }
    return 0;
}

static int tdes_cmac_kat(void) {
    static const char *key_hex =
        "8aa83bf8cbda10620bc1bf19fbb6cd58bc313d4a371ca8b5";
    static const char *messages[] = {
        "",
        "6bc1bee22e409f96",
        "6bc1bee22e409f96e93d7e117393172aae2d8a57",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    };
    static const char *expected_hex[] = {
        "b7a688e122ffaf95",
        "8e8f293136283797",
        "743ddbe0ce2dc2ed",
        "33e6b1092400eae5"
    };
    uint8_t key[24];
    uint8_t message[32];
    uint8_t tag[8];
    uint8_t expected[8];
    size_t key_length;
    size_t message_length;
    size_t expected_length;
    size_t index;

    if (!decode_hex(key, sizeof(key), key_hex, &key_length) ||
        key_length != sizeof(key) ||
        LIBERAC_CMAC_TAG_SIZE(LIBERAC_ALG_TDES_EDE3_ECB) != sizeof(tag)) {
        return 1;
    }
    for (index = 0u; index < sizeof(messages) / sizeof(messages[0]); ++index) {
        const uint8_t *input;
        if (!decode_hex(message, sizeof(message), messages[index],
                        &message_length) ||
            !decode_hex(expected, sizeof(expected), expected_hex[index],
                        &expected_length) ||
            expected_length != sizeof(tag)) {
            return 1;
        }
        input = message_length == 0u ? NULL : message;
        if (LIBERAC_CMAC(
                tag, sizeof(tag), sizeof(tag), input, message_length,
                key, key_length,
                LIBERAC_ALG_TDES_EDE3_ECB) != LIBERAC_SUCCESS ||
            memcmp(tag, expected, sizeof(tag)) != 0 ||
            LIBERAC_CMAC_VERIFY(
                tag, sizeof(tag), input, message_length,
                key, key_length,
                LIBERAC_ALG_TDES_EDE3_ECB) != LIBERAC_SUCCESS) {
            return 1;
        }
    }
    return 0;
}

static int gmac_kat(void) {
    static const LiberaCAlgID algorithms[] = {
        LIBERAC_ALG_AES_128_GCM,
        LIBERAC_ALG_AES_192_GCM,
        LIBERAC_ALG_AES_256_GCM
    };
    static const size_t key_lengths[] = {16u, 24u, 32u};
    static const char *empty_expected[] = {
        "58e2fccefa7e3061367f1d57a4e7455a",
        "cd33b28ac773f74ba00ed1f312572435",
        "530f8afbc74536b9a963b4f1c4cb738b"
    };
    static const char *block_expected[] = {
        "21c2eb20cd2214dbdf34c9b82ecb7ed2",
        "7f0d6248b11f290f4067435fad0587dd",
        "2d45552d8575922b3ca3cc538442fa26"
    };
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t message[16] = {0};
    uint8_t tag[LIBERAC_GMAC_MAX_TAG_BYTES];
    uint8_t expected[LIBERAC_GMAC_MAX_TAG_BYTES];
    size_t expected_length;
    size_t index;

    for (index = 0u; index < sizeof(algorithms) / sizeof(algorithms[0]); ++index) {
        if (!decode_hex(expected, sizeof(expected), empty_expected[index],
                        &expected_length) ||
            expected_length != sizeof(tag) ||
            LIBERAC_GMAC(
                tag, sizeof(tag), sizeof(tag), NULL, 0u,
                key, key_lengths[index], iv, sizeof(iv),
                algorithms[index]) != LIBERAC_SUCCESS ||
            memcmp(tag, expected, sizeof(tag)) != 0 ||
            LIBERAC_GMAC_VERIFY(
                tag, sizeof(tag), NULL, 0u,
                key, key_lengths[index], iv, sizeof(iv),
                algorithms[index]) != LIBERAC_SUCCESS) {
            return 1;
        }
        if (!decode_hex(expected, sizeof(expected), block_expected[index],
                        &expected_length) ||
            LIBERAC_GMAC(
                tag, sizeof(tag), sizeof(tag), message, sizeof(message),
                key, key_lengths[index], iv, sizeof(iv),
                algorithms[index]) != LIBERAC_SUCCESS ||
            memcmp(tag, expected, sizeof(tag)) != 0 ||
            LIBERAC_GMAC_VERIFY(
                tag, sizeof(tag), message, sizeof(message),
                key, key_lengths[index], iv, sizeof(iv),
                algorithms[index]) != LIBERAC_SUCCESS) {
            return 1;
        }
    }
    return 0;
}

int main(void) {
    if (hmac_kat()) {
        fputs("HMAC known-answer test failed\n", stderr);
        return 1;
    }
    if (hmac_long_key_kat()) {
        fputs("HMAC long-key known-answer test failed\n", stderr);
        return 1;
    }
    if (aes_cmac_kat()) {
        fputs("AES-CMAC known-answer test failed\n", stderr);
        return 1;
    }
    if (tdes_cmac_kat()) {
        fputs("Triple-DES CMAC known-answer test failed\n", stderr);
        return 1;
    }
    if (gmac_kat()) {
        fputs("GMAC known-answer test failed\n", stderr);
        return 1;
    }
    puts("message authentication known-answer tests passed");
    return 0;
}
