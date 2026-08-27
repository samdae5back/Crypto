/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "DigitalSignature.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const LiberaCAlgID algorithms[] = {
    LIBERAC_ALG_AIMER_128F, LIBERAC_ALG_AIMER_128S,
    LIBERAC_ALG_AIMER_192F, LIBERAC_ALG_AIMER_192S,
    LIBERAC_ALG_AIMER_256F, LIBERAC_ALG_AIMER_256S
};

static int buffer_is_zero(const uint8_t *buffer, size_t length) {
    size_t index;

    for (index = 0u; index < length; ++index) {
        if (buffer[index] != 0u) return 0;
    }
    return 1;
}

static int run_case(LiberaCAlgID alg) {
    static const uint8_t message[] = "AIMer runtime dispatch";
    static const uint8_t context[] = "Crypto unit test";
    const size_t public_key_length = LIBERAC_AIMER_PUBLIC_KEY_SIZE(alg);
    const size_t private_key_length = LIBERAC_AIMER_PRIVATE_KEY_SIZE(alg);
    const size_t signature_length = LIBERAC_AIMER_SIGNATURE_SIZE(alg);
    uint8_t *public_key = (uint8_t *)malloc(public_key_length);
    uint8_t *private_key = (uint8_t *)malloc(private_key_length);
    uint8_t *signature = (uint8_t *)malloc(signature_length);
    LiberaCError error;
    int result = 1;

    if (public_key == NULL || private_key == NULL || signature == NULL)
        goto cleanup;
    error = LIBERAC_AIMER_KEYGEN(
        public_key, public_key_length, private_key, private_key_length, alg);
    if (error != LIBERAC_SUCCESS) {
        fprintf(stderr, "AIMer 0x%04x key generation failed: %d\n",
                (unsigned int)alg, (int)error);
        goto cleanup;
    }
    error = LIBERAC_AIMER_KEYGEN(
        private_key, public_key_length,
        private_key, private_key_length, alg);
    if (error != LIBERAC_ERROR_INVALID_ARGUMENT) {
        fprintf(stderr, "AIMer 0x%04x accepted overlapping key outputs: %d\n",
                (unsigned int)alg, (int)error);
        goto cleanup;
    }
    error = LIBERAC_AIMER_SIGN(
        private_key, private_key_length,
        message, sizeof(message) - 1u,
        context, sizeof(context) - 1u,
        signature, signature_length, alg);
    if (error != LIBERAC_SUCCESS) {
        fprintf(stderr, "AIMer 0x%04x signing failed: %d\n",
                (unsigned int)alg, (int)error);
        goto cleanup;
    }
    error = LIBERAC_AIMER_VERIFY(
        public_key, public_key_length,
        message, sizeof(message) - 1u,
        context, sizeof(context) - 1u,
        signature, signature_length, alg);
    if (error != LIBERAC_SUCCESS) {
        fprintf(stderr, "AIMer 0x%04x verification failed: %d\n",
                (unsigned int)alg, (int)error);
        goto cleanup;
    }
    error = LIBERAC_AIMER_SIGN(
        private_key, private_key_length,
        signature, 1u,
        context, sizeof(context) - 1u,
        signature, signature_length, alg);
    if (error != LIBERAC_ERROR_INVALID_ARGUMENT) {
        fprintf(stderr, "AIMer 0x%04x accepted overlapping sign buffers: %d\n",
                (unsigned int)alg, (int)error);
        goto cleanup;
    }
    signature[public_key_length / 2u] ^= 1u;
    error = LIBERAC_AIMER_VERIFY(
        public_key, public_key_length,
        message, sizeof(message) - 1u,
        context, sizeof(context) - 1u,
        signature, signature_length, alg);
    if (error != LIBERAC_ERROR_SIGNATURE_INVALID) {
        fprintf(stderr, "AIMer 0x%04x accepted a modified signature: %d\n",
                (unsigned int)alg, (int)error);
        goto cleanup;
    }
    signature[public_key_length / 2u] ^= 1u;

    private_key[private_key_length - 1u] ^= 1u;
    memset(signature, 0xa5, signature_length);
    error = LIBERAC_AIMER_SIGN(
        private_key, private_key_length,
        message, sizeof(message) - 1u,
        context, sizeof(context) - 1u,
        signature, signature_length, alg);
    private_key[private_key_length - 1u] ^= 1u;
    if (error != LIBERAC_ERROR_INVALID_KEY ||
        !buffer_is_zero(signature, signature_length)) {
        fprintf(stderr,
                "AIMer 0x%04x invalid-key handling failed: %d\n",
                (unsigned int)alg, (int)error);
        goto cleanup;
    }
    result = 0;

cleanup:
    free(signature);
    free(private_key);
    free(public_key);
    return result;
}

int main(void) {
    size_t index;

    if (LIBERAC_AIMER_PUBLIC_KEY_SIZE(LIBERAC_ALG_NONE) != 0u ||
        LIBERAC_AIMER_PRIVATE_KEY_SIZE(LIBERAC_ALG_NONE) != 0u ||
        LIBERAC_AIMER_SIGNATURE_SIZE(LIBERAC_ALG_NONE) != 0u) {
        return 1;
    }
    for (index = 0u; index < sizeof(algorithms) / sizeof(algorithms[0]);
         ++index) {
        if (run_case(algorithms[index]) != 0) return 1;
    }
    puts("AIMer unit tests passed");
    return 0;
}
