/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "DigitalSignature.h"

#include <stdio.h>
#include <stdlib.h>

static const LiberaCAlgID algorithms[] = {
    LIBERAC_ALG_HAETAE_120, LIBERAC_ALG_HAETAE_180, LIBERAC_ALG_HAETAE_260
};

static int run_case(LiberaCAlgID alg) {
    static const uint8_t message[] = "HAETAE runtime dispatch";
    static const uint8_t context[] = "Crypto unit test";
    const size_t public_key_length = LIBERAC_HAETAE_PUBLIC_KEY_SIZE(alg);
    const size_t private_key_length = LIBERAC_HAETAE_PRIVATE_KEY_SIZE(alg);
    const size_t signature_length = LIBERAC_HAETAE_SIGNATURE_SIZE(alg);
    uint8_t *public_key = (uint8_t *)malloc(public_key_length);
    uint8_t *private_key = (uint8_t *)malloc(private_key_length);
    uint8_t *signature = (uint8_t *)malloc(signature_length);
    LiberaCError error;
    int result = 1;

    if (public_key == NULL || private_key == NULL || signature == NULL)
        goto cleanup;
    error = LIBERAC_HAETAE_KEYGEN(
        public_key, public_key_length, private_key, private_key_length, alg);
    if (error != LIBERAC_SUCCESS) goto cleanup;
    error = LIBERAC_HAETAE_SIGN(
        private_key, private_key_length,
        message, sizeof(message) - 1u,
        context, sizeof(context) - 1u,
        signature, signature_length, alg);
    if (error != LIBERAC_SUCCESS) goto cleanup;
    error = LIBERAC_HAETAE_VERIFY(
        public_key, public_key_length,
        message, sizeof(message) - 1u,
        context, sizeof(context) - 1u,
        signature, signature_length, alg);
    if (error != LIBERAC_SUCCESS) goto cleanup;
    signature[0] ^= 1u;
    error = LIBERAC_HAETAE_VERIFY(
        public_key, public_key_length,
        message, sizeof(message) - 1u,
        context, sizeof(context) - 1u,
        signature, signature_length, alg);
    if (error != LIBERAC_ERROR_SIGNATURE_INVALID) goto cleanup;
    result = 0;

cleanup:
    free(signature);
    free(private_key);
    free(public_key);
    return result;
}

int main(void) {
    size_t index;

    if (LIBERAC_HAETAE_PUBLIC_KEY_SIZE(LIBERAC_ALG_NONE) != 0u ||
        LIBERAC_HAETAE_PRIVATE_KEY_SIZE(LIBERAC_ALG_NONE) != 0u ||
        LIBERAC_HAETAE_SIGNATURE_SIZE(LIBERAC_ALG_NONE) != 0u) {
        return 1;
    }
    for (index = 0u; index < sizeof(algorithms) / sizeof(algorithms[0]);
         ++index) {
        if (run_case(algorithms[index]) != 0) return 1;
    }
    puts("HAETAE unit tests passed");
    return 0;
}
