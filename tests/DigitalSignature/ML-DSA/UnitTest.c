/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "DigitalSignature.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_variant(AlgID algorithm) {
    static const uint8_t message[] = {'p','q','-','s','i','g'};
    static const uint8_t context[] = {'t','e','s','t'};
    size_t public_key_length = CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(algorithm);
    size_t private_key_length = CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(algorithm);
    size_t signature_length = CRYPTO_ML_DSA_SIGNATURE_SIZE(algorithm);
    uint8_t *public_key = NULL;
    uint8_t *private_key = NULL;
    uint8_t *signature = NULL;
    int failed = 1;

    if (!public_key_length || !private_key_length || !signature_length)
        return 1;
    public_key = (uint8_t *)malloc(public_key_length);
    private_key = (uint8_t *)malloc(private_key_length);
    signature = (uint8_t *)malloc(signature_length);
    if (!public_key || !private_key || !signature) goto done;

    if (CRYPTO_ML_DSA_KEYGEN(
            public_key, public_key_length, private_key, private_key_length,
            algorithm) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_ML_DSA_SIGN(
            private_key, private_key_length, message, sizeof(message),
            context, sizeof(context), signature, signature_length,
            algorithm) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_ML_DSA_VERIFY(
            public_key, public_key_length, message, sizeof(message),
            context, sizeof(context), signature, signature_length,
            algorithm) != CRYPTO_SUCCESS)
        goto done;

    signature[0] ^= 1u;
    if (CRYPTO_ML_DSA_VERIFY(
            public_key, public_key_length, message, sizeof(message),
            context, sizeof(context), signature, signature_length,
            algorithm) != CRYPTO_ERROR_SIGNATURE_INVALID)
        goto done;
    signature[0] ^= 1u;
    failed = 0;

done:
    if (private_key) memset(private_key, 0, private_key_length);
    if (signature) memset(signature, 0, signature_length);
    free(public_key);
    free(private_key);
    free(signature);
    return failed;
}

static int test_sizes(void) {
    if (CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(ALG_ML_DSA_44) !=
            CRYPTO_ML_DSA_44_PUBLIC_KEY_BYTES ||
        CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(ALG_ML_DSA_44) !=
            CRYPTO_ML_DSA_44_PRIVATE_KEY_BYTES ||
        CRYPTO_ML_DSA_SIGNATURE_SIZE(ALG_ML_DSA_44) !=
            CRYPTO_ML_DSA_44_SIGNATURE_BYTES)
        return 1;
    if (CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(ALG_ML_DSA_65) !=
            CRYPTO_ML_DSA_65_PUBLIC_KEY_BYTES ||
        CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(ALG_ML_DSA_65) !=
            CRYPTO_ML_DSA_65_PRIVATE_KEY_BYTES ||
        CRYPTO_ML_DSA_SIGNATURE_SIZE(ALG_ML_DSA_65) !=
            CRYPTO_ML_DSA_65_SIGNATURE_BYTES)
        return 1;
    if (CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(ALG_ML_DSA_87) !=
            CRYPTO_ML_DSA_87_PUBLIC_KEY_BYTES ||
        CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(ALG_ML_DSA_87) !=
            CRYPTO_ML_DSA_87_PRIVATE_KEY_BYTES ||
        CRYPTO_ML_DSA_SIGNATURE_SIZE(ALG_ML_DSA_87) !=
            CRYPTO_ML_DSA_87_SIGNATURE_BYTES)
        return 1;
    return CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(ALG_RSA_RAW) != 0u;
}

int main(void) {
    static const AlgID algorithms[] = {
        ALG_ML_DSA_44, ALG_ML_DSA_65, ALG_ML_DSA_87
    };
    size_t i;

    if (test_sizes()) {
        fputs("ML-DSA size table test failed\n", stderr);
        return 1;
    }
    for (i = 0u; i < sizeof(algorithms) / sizeof(algorithms[0]); ++i) {
        if (test_variant(algorithms[i])) {
            fprintf(stderr, "ML-DSA algorithm %d roundtrip failed\n",
                    (int)algorithms[i]);
            return 1;
        }
    }
    puts("all ML-DSA variants passed");
    return 0;
}
