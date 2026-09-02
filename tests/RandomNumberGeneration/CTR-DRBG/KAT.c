/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "RandomNumberGeneration.h"

#include <stdio.h>
#include <string.h>

static int hex_value(char character, uint8_t *value) {
    if (character >= '0' && character <= '9') {
        *value = (uint8_t)(character - '0');
        return 1;
    }
    if (character >= 'a' && character <= 'f') {
        *value = (uint8_t)(character - 'a' + 10);
        return 1;
    }
    if (character >= 'A' && character <= 'F') {
        *value = (uint8_t)(character - 'A' + 10);
        return 1;
    }
    return 0;
}

static int decode_hex(
    uint8_t *output, size_t output_length, const char *hex) {
    size_t index;

    if (strlen(hex) != 2u * output_length) {
        return 0;
    }
    for (index = 0u; index < output_length; ++index) {
        uint8_t high;
        uint8_t low;

        if (!hex_value(hex[2u * index], &high) ||
            !hex_value(hex[2u * index + 1u], &low)) {
            return 0;
        }
        output[index] = (uint8_t)((uint8_t)(high << 4) | low);
    }
    return 1;
}

static int test_nist_aes256_no_df(void) {
    static const uint8_t entropy[48] = {
        0xdf,0x5d,0x73,0xfa,0xa4,0x68,0x64,0x9e,0xdd,0xa3,0x3b,0x5c,0xca,0x79,0xb0,0xb0,
        0x56,0x00,0x41,0x9c,0xcb,0x7a,0x87,0x9d,0xdf,0xec,0x9d,0xb3,0x2e,0xe4,0x94,0xe5,
        0x53,0x1b,0x51,0xde,0x16,0xa3,0x0f,0x76,0x92,0x62,0x47,0x4c,0x73,0xbe,0xc0,0x10
    };
    static const uint8_t key_after_instantiate[32] = {
        0x8c,0x52,0xf9,0x01,0x63,0x2d,0x52,0x27,0x74,0xc0,0x8f,0xad,0x0e,0xb2,0xc3,0x3b,
        0x98,0xa7,0x01,0xa1,0x86,0x1a,0xec,0xf3,0xd8,0xa2,0x58,0x60,0x94,0x17,0x09,0xfd
    };
    static const uint8_t v_after_instantiate[16] = {
        0x21,0x7b,0x52,0x14,0x21,0x05,0x25,0x02,0x43,0xc0,0xb2,0xc2,0x06,0xb8,0xf5,0x9e
    };
    static const uint8_t returned_bits[64] = {
        0xd1,0xc0,0x7c,0xd9,0x5a,0xf8,0xa7,0xf1,0x10,0x12,0xc8,0x4c,0xe4,0x8b,0xb8,0xcb,
        0x87,0x18,0x9e,0x99,0xd4,0x0f,0xcc,0xb1,0x77,0x1c,0x61,0x9b,0xdf,0x82,0xab,0x22,
        0x80,0xb1,0xdc,0x2f,0x25,0x81,0xf3,0x91,0x64,0xf7,0xac,0x0c,0x51,0x04,0x94,0xb3,
        0xa4,0x3c,0x41,0xb7,0xdb,0x17,0x51,0x4c,0x87,0xb1,0x07,0xae,0x79,0x3e,0x01,0xc5
    };
    static const uint8_t final_key[32] = {
        0x1a,0x1c,0x6e,0x5f,0x1c,0xcc,0xc6,0x97,0x44,0x36,0xe5,0xfd,0x3f,0x01,0x5b,0xc8,
        0xe9,0xdc,0x0f,0x90,0x05,0x3b,0x73,0xe3,0xc1,0x9d,0x4d,0xfd,0x66,0xd1,0xb8,0x5a
    };
    static const uint8_t final_v[16] = {
        0x53,0xc7,0x8a,0xc6,0x1a,0x0b,0xac,0x9d,0x7d,0x2e,0x92,0xb1,0xe7,0x3e,0x33,0x92
    };
    LiberaCCtrDrbgContext ctx;
    uint8_t output[64];

    if (LIBERAC_CTR_DRBG_SEED_SIZE(LIBERAC_ALG_CTR_DRBG_AES_256_NO_DF) != 48u) return 1;
    if (LIBERAC_CTR_DRBG_INSTANTIATE(&ctx, entropy, sizeof(entropy), NULL, 0u,
                                     NULL, 0u, LIBERAC_ALG_CTR_DRBG_AES_256_NO_DF) != LIBERAC_SUCCESS) return 1;
    if (memcmp(ctx.KEY, key_after_instantiate, sizeof(key_after_instantiate)) != 0) return 1;
    if (memcmp(ctx.V, v_after_instantiate, sizeof(v_after_instantiate)) != 0) return 1;
    if (ctx.RESEED_COUNTER != 1u) return 1;

    if (LIBERAC_CTR_DRBG_GENERATE(&ctx, output, sizeof(output), NULL, 0u, 0) != LIBERAC_SUCCESS) return 1;
    if (LIBERAC_CTR_DRBG_GENERATE(&ctx, output, sizeof(output), NULL, 0u, 0) != LIBERAC_SUCCESS) return 1;
    if (memcmp(output, returned_bits, sizeof(returned_bits)) != 0) return 1;
    if (memcmp(ctx.KEY, final_key, sizeof(final_key)) != 0) return 1;
    if (memcmp(ctx.V, final_v, sizeof(final_v)) != 0) return 1;
    if (ctx.RESEED_COUNTER != 3u) return 1;

    LIBERAC_CTR_DRBG_CLEAR(&ctx);
    return 0;
}

static int test_nist_tdea_df(void) {
    uint8_t entropy[14];
    uint8_t nonce[7];
    uint8_t expected_key[LIBERAC_CTR_DRBG_TDEA_KEY_BYTES];
    uint8_t expected_v[LIBERAC_CTR_DRBG_TDEA_BLOCK_BYTES];
    uint8_t expected_output[32];
    uint8_t expected_final_key[LIBERAC_CTR_DRBG_TDEA_KEY_BYTES];
    uint8_t expected_final_v[LIBERAC_CTR_DRBG_TDEA_BLOCK_BYTES];
    uint8_t output[32];
    LiberaCCtrDrbgContext context;

    if (!decode_hex(entropy, sizeof(entropy),
                    "b54d0bbaa78adf0915d3dd83ed3f") ||
        !decode_hex(nonce, sizeof(nonce), "11d849d2de4b58") ||
        !decode_hex(expected_key, sizeof(expected_key),
                    "3a86fb933eec93771449f825a509aa89c7177ee4b7") ||
        !decode_hex(expected_v, sizeof(expected_v), "2f458a05e14989bb") ||
        !decode_hex(expected_output, sizeof(expected_output),
                    "88b166404866fd6b1168c4472163e3cb"
                    "3d5c9cca2e5abfa2faf929025f21fed1") ||
        !decode_hex(expected_final_key, sizeof(expected_final_key),
                    "53bc8bbbf507acf02f8b0794ffc435019cc6c747fc") ||
        !decode_hex(expected_final_v, sizeof(expected_final_v),
                    "e392c943cfd7e99e")) {
        return 1;
    }
    if (LIBERAC_CTR_DRBG_SEED_SIZE(LIBERAC_ALG_CTR_DRBG_TDEA_DF) !=
            LIBERAC_CTR_DRBG_TDEA_SEED_BYTES ||
        LIBERAC_CTR_DRBG_INSTANTIATE(
            &context, entropy, sizeof(entropy), nonce, sizeof(nonce),
            NULL, 0u, LIBERAC_ALG_CTR_DRBG_TDEA_DF) != LIBERAC_SUCCESS ||
        context.KEY_LENGTH != LIBERAC_CTR_DRBG_TDEA_KEY_BYTES ||
        context.USE_DF == 0u ||
        memcmp(context.KEY, expected_key, sizeof(expected_key)) != 0 ||
        memcmp(context.V, expected_v, sizeof(expected_v)) != 0) {
        LIBERAC_CTR_DRBG_CLEAR(&context);
        return 1;
    }
    if (LIBERAC_CTR_DRBG_GENERATE(
            &context, output, sizeof(output), NULL, 0u, 0) !=
            LIBERAC_SUCCESS ||
        LIBERAC_CTR_DRBG_GENERATE(
            &context, output, sizeof(output), NULL, 0u, 0) !=
            LIBERAC_SUCCESS ||
        memcmp(output, expected_output, sizeof(output)) != 0 ||
        memcmp(context.KEY, expected_final_key,
               sizeof(expected_final_key)) != 0 ||
        memcmp(context.V, expected_final_v, sizeof(expected_final_v)) != 0 ||
        context.RESEED_COUNTER != 3u) {
        LIBERAC_CTR_DRBG_CLEAR(&context);
        return 1;
    }
    LIBERAC_CTR_DRBG_CLEAR(&context);
    return 0;
}

static int run_nist_tdea_vector(
    LiberaCAlgID algorithm,
    const char *entropy_hex, const char *nonce_hex,
    const char *reseed_entropy_hex, const char *expected_hex) {
    uint8_t entropy[LIBERAC_CTR_DRBG_TDEA_SEED_BYTES];
    uint8_t nonce[7];
    uint8_t reseed_entropy[LIBERAC_CTR_DRBG_TDEA_SEED_BYTES];
    uint8_t expected[32];
    uint8_t output[32];
    size_t entropy_length = strlen(entropy_hex) / 2u;
    size_t nonce_length = strlen(nonce_hex) / 2u;
    size_t reseed_length = reseed_entropy_hex != NULL
                               ? strlen(reseed_entropy_hex) / 2u
                               : 0u;
    LiberaCCtrDrbgContext context;

    if (entropy_length > sizeof(entropy) || nonce_length > sizeof(nonce) ||
        reseed_length > sizeof(reseed_entropy) ||
        !decode_hex(entropy, entropy_length, entropy_hex) ||
        !decode_hex(nonce, nonce_length, nonce_hex) ||
        !decode_hex(expected, sizeof(expected), expected_hex) ||
        (reseed_entropy_hex != NULL &&
         !decode_hex(reseed_entropy, reseed_length, reseed_entropy_hex))) {
        return 1;
    }
    if (LIBERAC_CTR_DRBG_INSTANTIATE(
            &context, entropy, entropy_length,
            nonce_length != 0u ? nonce : NULL, nonce_length,
            NULL, 0u, algorithm) != LIBERAC_SUCCESS) {
        return 1;
    }
    if (reseed_entropy_hex != NULL &&
        LIBERAC_CTR_DRBG_RESEED(
            &context, reseed_entropy, reseed_length,
            NULL, 0u) != LIBERAC_SUCCESS) {
        LIBERAC_CTR_DRBG_CLEAR(&context);
        return 1;
    }
    if (LIBERAC_CTR_DRBG_GENERATE(
            &context, output, sizeof(output), NULL, 0u, 0) !=
            LIBERAC_SUCCESS ||
        LIBERAC_CTR_DRBG_GENERATE(
            &context, output, sizeof(output), NULL, 0u, 0) !=
            LIBERAC_SUCCESS ||
        memcmp(output, expected, sizeof(expected)) != 0) {
        LIBERAC_CTR_DRBG_CLEAR(&context);
        return 1;
    }
    LIBERAC_CTR_DRBG_CLEAR(&context);
    return 0;
}

static int test_nist_tdea_additional_configurations(void) {
    if (run_nist_tdea_vector(
            LIBERAC_ALG_CTR_DRBG_TDEA_NO_DF,
            "4cd97f1701716d1a22f90b55c569c8f2b91aa53322653dcae809abc5c6",
            "", NULL,
            "4353dd937ec55e6733cf7a5d2cea557c"
            "e8e3fcc6cdb18e44395e4b1c4669c9d1")) {
        return 1;
    }
    return run_nist_tdea_vector(
        LIBERAC_ALG_CTR_DRBG_TDEA_DF,
        "dedfcf34617ac04ff579b87ca18f", "40bce1b72deaea",
        "876beead5bdf5c206ace3bfa05d9",
        "f87cfa1529fdaf57ee1542844e556f00"
        "ff7fc70e3267372b56dce6141e124f85");
}

int main(void) {
    if (test_nist_aes256_no_df()) {
        fprintf(stderr, "CTR_DRBG NIST KAT failed\n");
        return 1;
    }
    if (test_nist_tdea_df() ||
        test_nist_tdea_additional_configurations()) {
        fprintf(stderr, "legacy TDEA CTR_DRBG NIST CAVP KAT failed\n");
        return 1;
    }
    puts("CTR_DRBG KAT passed");
    return 0;
}
