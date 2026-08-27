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
    const AlgID algorithms[] = {
        ALG_CTR_DRBG_AES_128_DF,
        ALG_CTR_DRBG_AES_192_DF,
        ALG_CTR_DRBG_AES_256_DF
    };
    uint8_t entropy[32], nonce[16], additional[13];
    uint8_t first[64], second[64];
    size_t i, j, key_length, security_length, nonce_length;

    for (i = 0u; i < sizeof(entropy); ++i) entropy[i] = (uint8_t)i;
    for (i = 0u; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(0x80u + i);
    for (i = 0u; i < sizeof(additional); ++i)
        additional[i] = (uint8_t)(0x40u + i);

    for (j = 0u; j < sizeof(algorithms) / sizeof(algorithms[0]); ++j) {
        CRYPTO_CTR_DRBG_CONTEXT first_context, second_context;
        key_length = (j == 0u) ? 16u : (j == 1u ? 24u : 32u);
        security_length = key_length;
        nonce_length = (security_length + 1u) / 2u;
        if (CRYPTO_CTR_DRBG_SEED_SIZE(algorithms[j]) != key_length + 16u)
            return 1;
        if (CRYPTO_CTR_DRBG_INSTANTIATE(
                &first_context, entropy, security_length,
                nonce, nonce_length, (const uint8_t *)"crypto-test", 11u,
                algorithms[j]) != CRYPTO_SUCCESS) {
            return 1;
        }
        if (CRYPTO_CTR_DRBG_INSTANTIATE(
                &second_context, entropy, security_length,
                nonce, nonce_length, (const uint8_t *)"crypto-test", 11u,
                algorithms[j]) != CRYPTO_SUCCESS) {
            CRYPTO_CTR_DRBG_CLEAR(&first_context);
            return 1;
        }
        if (CRYPTO_CTR_DRBG_GENERATE(
                &first_context, first, sizeof(first), additional,
                sizeof(additional), 0) != CRYPTO_SUCCESS ||
            CRYPTO_CTR_DRBG_GENERATE(
                &second_context, second, sizeof(second), additional,
                sizeof(additional), 0) != CRYPTO_SUCCESS ||
            memcmp(first, second, sizeof(first)) != 0) {
            CRYPTO_CTR_DRBG_CLEAR(&first_context);
            CRYPTO_CTR_DRBG_CLEAR(&second_context);
            return 1;
        }
        CRYPTO_CTR_DRBG_CLEAR(&first_context);
        CRYPTO_CTR_DRBG_CLEAR(&second_context);
    }
    return 0;
}

static int test_reseed_limit_and_clear(void) {
    uint8_t entropy[48] = {0};
    uint8_t output[16];
    CRYPTO_CTR_DRBG_CONTEXT context;

    if (CRYPTO_CTR_DRBG_INSTANTIATE(
            &context, entropy, sizeof(entropy), NULL, 0u, NULL, 0u,
            ALG_CTR_DRBG_AES_256_NO_DF) != CRYPTO_SUCCESS) {
        return 1;
    }
    context.RESEED_COUNTER = ((uint64_t)1u << 48) + 1u;
    if (CRYPTO_CTR_DRBG_GENERATE(
            &context, output, sizeof(output), NULL, 0u, 0) !=
        CRYPTO_ERROR_RESEED_REQUIRED) {
        CRYPTO_CTR_DRBG_CLEAR(&context);
        return 1;
    }
    CRYPTO_CTR_DRBG_CLEAR(&context);
    return !all_zero(&context, sizeof(context));
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
    puts("CTR_DRBG unit tests passed");
    return 0;
}
