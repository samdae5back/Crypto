/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "RandomNumberGeneration.h"

#include <stdio.h>
#include <string.h>

static int all_zero(const void *ptr, size_t length) {
    const uint8_t *bytes = (const uint8_t *)ptr;
    size_t i;

    for (i = 0u; i < length; ++i) {
        if (bytes[i] != 0u) return 0;
    }
    return 1;
}

static int test_df_variants(void) {
    const LiberaCAlgID algorithms[] = {
        LIBERAC_ALG_CTR_DRBG_AES_128_DF,
        LIBERAC_ALG_CTR_DRBG_AES_192_DF,
        LIBERAC_ALG_CTR_DRBG_AES_256_DF
    };
    uint8_t entropy[32], nonce[16], additional[13];
    uint8_t first[64], second[64];
    size_t i, j, key_length, security_length, nonce_length;

    for (i = 0u; i < sizeof(entropy); ++i) entropy[i] = (uint8_t)i;
    for (i = 0u; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(0x80u + i);
    for (i = 0u; i < sizeof(additional); ++i)
        additional[i] = (uint8_t)(0x40u + i);

    for (j = 0u; j < sizeof(algorithms) / sizeof(algorithms[0]); ++j) {
        LiberaCCtrDrbgContext first_context, second_context;
        key_length = (j == 0u) ? 16u : (j == 1u ? 24u : 32u);
        security_length = key_length;
        nonce_length = (security_length + 1u) / 2u;
        if (LIBERAC_CTR_DRBG_SEED_SIZE(algorithms[j]) != key_length + 16u)
            return 1;
        if (LIBERAC_CTR_DRBG_INSTANTIATE(
                &first_context, entropy, security_length,
                nonce, nonce_length, (const uint8_t *)"crypto-test", 11u,
                algorithms[j]) != LIBERAC_SUCCESS) {
            return 1;
        }
        if (LIBERAC_CTR_DRBG_INSTANTIATE(
                &second_context, entropy, security_length,
                nonce, nonce_length, (const uint8_t *)"crypto-test", 11u,
                algorithms[j]) != LIBERAC_SUCCESS) {
            LIBERAC_CTR_DRBG_CLEAR(&first_context);
            return 1;
        }
        if (LIBERAC_CTR_DRBG_GENERATE(
                &first_context, first, sizeof(first), additional,
                sizeof(additional), 0) != LIBERAC_SUCCESS ||
            LIBERAC_CTR_DRBG_GENERATE(
                &second_context, second, sizeof(second), additional,
                sizeof(additional), 0) != LIBERAC_SUCCESS ||
            memcmp(first, second, sizeof(first)) != 0) {
            LIBERAC_CTR_DRBG_CLEAR(&first_context);
            LIBERAC_CTR_DRBG_CLEAR(&second_context);
            return 1;
        }
        LIBERAC_CTR_DRBG_CLEAR(&first_context);
        LIBERAC_CTR_DRBG_CLEAR(&second_context);
    }
    return 0;
}

static int test_reseed_limit_and_clear(void) {
    uint8_t entropy[48] = {0};
    uint8_t output[16];
    LiberaCCtrDrbgContext context;

    if (LIBERAC_CTR_DRBG_INSTANTIATE(
            &context, entropy, sizeof(entropy), NULL, 0u, NULL, 0u,
            LIBERAC_ALG_CTR_DRBG_AES_256_NO_DF) != LIBERAC_SUCCESS) {
        return 1;
    }
    context.RESEED_COUNTER = ((uint64_t)1u << 48) + 1u;
    if (LIBERAC_CTR_DRBG_GENERATE(
            &context, output, sizeof(output), NULL, 0u, 0) !=
        LIBERAC_ERROR_RESEED_REQUIRED) {
        LIBERAC_CTR_DRBG_CLEAR(&context);
        return 1;
    }
    LIBERAC_CTR_DRBG_CLEAR(&context);
    return !all_zero(&context, sizeof(context));
}

static int test_legacy_tdea_configuration(void) {
    uint8_t entropy[LIBERAC_CTR_DRBG_TDEA_SEED_BYTES];
    uint8_t df_entropy[14];
    uint8_t nonce[7];
    uint8_t additional[13];
    uint8_t first[257];
    uint8_t second[257];
    uint8_t oversized[LIBERAC_CTR_DRBG_TDEA_MAX_REQUEST_BYTES + 1u];
    LiberaCCtrDrbgContext first_context;
    LiberaCCtrDrbgContext second_context;
    size_t index;

    for (index = 0u; index < sizeof(entropy); ++index) {
        entropy[index] = (uint8_t)(3u * index + 1u);
    }
    for (index = 0u; index < sizeof(df_entropy); ++index) {
        df_entropy[index] = (uint8_t)(0x80u + index);
    }
    for (index = 0u; index < sizeof(nonce); ++index) {
        nonce[index] = (uint8_t)(0x30u + index);
    }
    for (index = 0u; index < sizeof(additional); ++index) {
        additional[index] = (uint8_t)(0x50u + index);
    }

    if (LIBERAC_CTR_DRBG_SEED_SIZE(LIBERAC_ALG_CTR_DRBG_TDEA_DF) !=
            LIBERAC_CTR_DRBG_TDEA_SEED_BYTES ||
        LIBERAC_CTR_DRBG_SEED_SIZE(LIBERAC_ALG_CTR_DRBG_TDEA_NO_DF) !=
            LIBERAC_CTR_DRBG_TDEA_SEED_BYTES ||
        LIBERAC_CTR_DRBG_INSTANTIATE(
            &first_context, df_entropy, sizeof(df_entropy),
            nonce, sizeof(nonce), (const uint8_t *)"legacy", 6u,
            LIBERAC_ALG_CTR_DRBG_TDEA_DF) != LIBERAC_SUCCESS ||
        LIBERAC_CTR_DRBG_INSTANTIATE(
            &second_context, df_entropy, sizeof(df_entropy),
            nonce, sizeof(nonce), (const uint8_t *)"legacy", 6u,
            LIBERAC_ALG_CTR_DRBG_TDEA_DF) != LIBERAC_SUCCESS ||
        LIBERAC_CTR_DRBG_GENERATE(
            &first_context, first, sizeof(first),
            additional, sizeof(additional), 0) != LIBERAC_SUCCESS ||
        LIBERAC_CTR_DRBG_GENERATE(
            &second_context, second, sizeof(second),
            additional, sizeof(additional), 0) != LIBERAC_SUCCESS ||
        memcmp(first, second, sizeof(first)) != 0) {
        LIBERAC_CTR_DRBG_CLEAR(&first_context);
        LIBERAC_CTR_DRBG_CLEAR(&second_context);
        return 1;
    }
    LIBERAC_CTR_DRBG_CLEAR(&first_context);
    LIBERAC_CTR_DRBG_CLEAR(&second_context);

    if (LIBERAC_CTR_DRBG_INSTANTIATE(
            &first_context, df_entropy, sizeof(df_entropy) - 1u,
            nonce, sizeof(nonce), NULL, 0u,
            LIBERAC_ALG_CTR_DRBG_TDEA_DF) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_CTR_DRBG_INSTANTIATE(
            &first_context, df_entropy, sizeof(df_entropy),
            nonce, sizeof(nonce) - 1u, NULL, 0u,
            LIBERAC_ALG_CTR_DRBG_TDEA_DF) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_CTR_DRBG_INSTANTIATE(
            &first_context, entropy, sizeof(entropy) - 1u,
            NULL, 0u, NULL, 0u,
            LIBERAC_ALG_CTR_DRBG_TDEA_NO_DF) !=
            LIBERAC_ERROR_INVALID_ARGUMENT) {
        LIBERAC_CTR_DRBG_CLEAR(&first_context);
        return 1;
    }

    if (LIBERAC_CTR_DRBG_INSTANTIATE(
            &first_context, entropy, sizeof(entropy),
            NULL, 0u, NULL, 0u,
            LIBERAC_ALG_CTR_DRBG_TDEA_NO_DF) != LIBERAC_SUCCESS) {
        return 1;
    }
    memset(oversized, 0xa5, sizeof(oversized));
    if (LIBERAC_CTR_DRBG_GENERATE(
            &first_context, oversized,
            LIBERAC_CTR_DRBG_TDEA_MAX_REQUEST_BYTES,
            NULL, 0u, 0) != LIBERAC_SUCCESS) {
        LIBERAC_CTR_DRBG_CLEAR(&first_context);
        return 1;
    }
    memset(oversized, 0xa5, sizeof(oversized));
    if (LIBERAC_CTR_DRBG_GENERATE(
            &first_context, oversized, sizeof(oversized),
            NULL, 0u, 0) != LIBERAC_ERROR_MESSAGE_TOO_LARGE ||
        oversized[0] != 0xa5u ||
        LIBERAC_CTR_DRBG_GENERATE(
            &first_context, first, sizeof(first),
            entropy, sizeof(entropy) + 1u, 0) !=
            LIBERAC_ERROR_INVALID_ARGUMENT) {
        LIBERAC_CTR_DRBG_CLEAR(&first_context);
        return 1;
    }
    first_context.RESEED_COUNTER = (UINT64_C(1) << 32) + 1u;
    if (LIBERAC_CTR_DRBG_GENERATE(
            &first_context, first, sizeof(first),
            NULL, 0u, 0) != LIBERAC_ERROR_RESEED_REQUIRED) {
        LIBERAC_CTR_DRBG_CLEAR(&first_context);
        return 1;
    }
    LIBERAC_CTR_DRBG_CLEAR(&first_context);
    return !all_zero(&first_context, sizeof(first_context));
}

int main(void) {
    if (test_df_variants()) {
        fputs("CTR_DRBG derivation-function test failed\n", stderr);
        return 1;
    }
    if (test_reseed_limit_and_clear()) {
        fputs("CTR_DRBG lifecycle test failed\n", stderr);
        return 1;
    }
    if (test_legacy_tdea_configuration()) {
        fputs("legacy TDEA CTR_DRBG configuration test failed\n", stderr);
        return 1;
    }
    puts("CTR_DRBG unit tests passed");
    return 0;
}
