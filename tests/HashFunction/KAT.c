/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "HashFunction.h"

#include <stdio.h>
#include <string.h>

typedef struct hash_vector {
    const char *name;
    const char *message_hex;
    const char *digest_hex;
    LiberaCAlgID algorithm;
} hash_vector;

/*
 * SHA-2/SHA-3 and LSH records are taken from the iotcc-new self-test corpus.
 * SHA-512/t and SHAKE records are the corresponding FIPS 180-4/FIPS 202 KATs.
 */
static const hash_vector vectors[] = {
    { "SHA-1 empty", "",
      "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      LIBERAC_ALG_HASH_SHA1 },
    { "SHA-1 abc", "616263",
      "a9993e364706816aba3e25717850c26c9cd0d89d",
      LIBERAC_ALG_HASH_SHA1 },
    { "SHA-224 empty", "",
      "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
      LIBERAC_ALG_HASH_SHA2_224 },
    { "SHA-256 empty", "",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      LIBERAC_ALG_HASH_SHA2_256 },
    { "SHA-384 empty", "",
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
      "274edebfe76f65fbd51ad2f14898b95b",
      LIBERAC_ALG_HASH_SHA2_384 },
    { "SHA-512 empty", "",
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
      LIBERAC_ALG_HASH_SHA2_512 },
    { "SHA-512/224 abc", "616263",
      "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
      LIBERAC_ALG_HASH_SHA2_512_224 },
    { "SHA-512/256 abc", "616263",
      "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
      LIBERAC_ALG_HASH_SHA2_512_256 },

    { "LSH-256-224 empty", "",
      "48a0d55b2b3d91f26e06f7110fe9ce8ea0e2656bbe344cb1c5930653",
      LIBERAC_ALG_HASH_LSH_256_224 },
    { "LSH-256-256 empty", "",
      "f3cd416a03818217726cb47f4e4d2881c9c29fd445c18b66fb19dea1a81007c1",
      LIBERAC_ALG_HASH_LSH_256_256 },
    { "LSH-512-224 empty", "",
      "3c124edfe149b45c067965dae681322cdf52aa2c9d738b8f271b9318",
      LIBERAC_ALG_HASH_LSH_512_224 },
    { "LSH-512-256 empty", "",
      "706df4ebf100f06d5cc9f6c79be5297c3f6f515801dd10fbc1b665a2d7bdb653",
      LIBERAC_ALG_HASH_LSH_512_256 },
    { "LSH-512-384 empty", "",
      "dbb259cf22459368ab2c52b3e1c977288b38670adcb91cae6b8b6a2d646e76f8"
      "bd53e5cab0e47c856f55249b895c1730",
      LIBERAC_ALG_HASH_LSH_512_384 },
    { "LSH-512-512 empty", "",
      "118a2ff2a99e3b2134125e2baf20ebe3bdd034d5a69b29c22fc4995063340b466"
      "97801d7f7fb0070568f78e8ed514215fc70af27d6f27b01aa8a1da72b14ce7c",
      LIBERAC_ALG_HASH_LSH_512_512 },
    { "LSH-256-224 one byte", "6e",
      "c3b9090274f7e89944107424e4939e4e25e8dec3981b72d51624c616",
      LIBERAC_ALG_HASH_LSH_256_224 },
    { "LSH-256-256 one byte", "75",
      "7456abb1c57b30e0cc0408321816fbbabe6f45828c7baec04c8bde0ac7d89810",
      LIBERAC_ALG_HASH_LSH_256_256 },
    { "LSH-512-224 one byte", "7b",
      "fc85d90052c59d25438694a83a0f778802612fbeef108b3ce72c14c5",
      LIBERAC_ALG_HASH_LSH_512_224 },
    { "LSH-512-256 one byte", "82",
      "9d5788121af3037a682812d066f8b95c771e1ae693a139880267fff172628e06",
      LIBERAC_ALG_HASH_LSH_512_256 },
    { "LSH-512-384 one byte", "8c",
      "cdf6699fc3c2f783616e20628a7ec52cbe87b728d2834b23dd0aae5566d60fd9"
      "70cec29d44f945f38f5a94e6f09716cb",
      LIBERAC_ALG_HASH_LSH_512_384 },
    { "LSH-512-512 one byte", "92",
      "782be1878403ac5f23ff8cf6b1583ac08ce2b6ae8fb9f4ac2889a123aa411d62"
      "fdcf60b2693be59321823d931cd8df89c82bb5e63f2f19a7376daf6d03f3ce99",
      LIBERAC_ALG_HASH_LSH_512_512 },

    { "SHA3-224 empty", "",
      "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
      LIBERAC_ALG_HASH_SHA3_224 },
    { "SHA3-256 empty", "",
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
      LIBERAC_ALG_HASH_SHA3_256 },
    { "SHA3-256 abc", "616263",
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
      LIBERAC_ALG_HASH_SHA3_256 },
    { "SHA3-384 empty", "",
      "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
      "c3713831264adb47fb6bd1e058d5f004",
      LIBERAC_ALG_HASH_SHA3_384 },
    { "SHA3-512 empty", "",
      "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
      "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
      LIBERAC_ALG_HASH_SHA3_512 },
    { "SHAKE128 empty (256 bits)", "",
      "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
      LIBERAC_ALG_HASH_SHAKE128 },
    { "SHAKE256 empty (512 bits)", "",
      "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
      "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
      LIBERAC_ALG_HASH_SHAKE256 }
};

static int hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static size_t decode_hex(uint8_t *output, size_t capacity, const char *hex) {
    const size_t hex_length = strlen(hex);
    const size_t output_length = hex_length / 2u;
    size_t index;

    if ((hex_length & 1u) != 0u || output_length > capacity) {
        return SIZE_MAX;
    }
    for (index = 0; index < output_length; ++index) {
        const int high = hex_nibble(hex[index * 2u]);
        const int low = hex_nibble(hex[(index * 2u) + 1u]);
        if (high < 0 || low < 0) {
            return SIZE_MAX;
        }
        output[index] = (uint8_t)((high << 4) | low);
    }
    return output_length;
}

static int run_vector(const hash_vector *vector) {
    uint8_t message[512];
    uint8_t expected[64];
    uint8_t actual[80];
    size_t message_length;
    size_t digest_length;
    size_t index;
    LiberaCError error;

    message_length = decode_hex(message, sizeof(message), vector->message_hex);
    digest_length = decode_hex(expected, sizeof(expected), vector->digest_hex);
    if (message_length == SIZE_MAX || digest_length == SIZE_MAX) {
        fprintf(stderr, "%s: malformed test vector\n", vector->name);
        return 1;
    }

    memset(actual, 0xa5, sizeof(actual));
    error = LIBERAC_HASH(
        actual, digest_length,
        message_length == 0u ? NULL : message, message_length,
        vector->algorithm);
    if (error != LIBERAC_SUCCESS) {
        fprintf(stderr, "%s: LIBERAC_HASH returned %d\n",
                vector->name, (int)error);
        return 1;
    }
    if (memcmp(actual, expected, digest_length) != 0) {
        fprintf(stderr, "%s: digest mismatch\n", vector->name);
        return 1;
    }
    for (index = digest_length; index < sizeof(actual); ++index) {
        if (actual[index] != 0xa5u) {
            fprintf(stderr, "%s: wrote past requested output length\n",
                    vector->name);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    size_t index;
    int failures = 0;

    for (index = 0; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        failures += run_vector(&vectors[index]);
    }
    if (failures != 0) {
        fprintf(stderr, "hash KAT: %d failure(s)\n", failures);
        return 1;
    }
    printf("hash KAT: %u vectors passed\n",
           (unsigned int)(sizeof(vectors) / sizeof(vectors[0])));
    return 0;
}
