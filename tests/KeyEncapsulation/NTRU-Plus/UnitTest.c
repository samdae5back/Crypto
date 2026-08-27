/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "KeyEncapsulation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const LiberaCAlgID algorithms[] = {
    LIBERAC_ALG_NTRU_PLUS_768, LIBERAC_ALG_NTRU_PLUS_864, LIBERAC_ALG_NTRU_PLUS_1152
};

static int run_case(LiberaCAlgID alg) {
    static const uint8_t zero_secret[LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES] = {0};
    const size_t public_key_length = LIBERAC_NTRU_PLUS_PUBLIC_KEY_SIZE(alg);
    const size_t private_key_length = LIBERAC_NTRU_PLUS_PRIVATE_KEY_SIZE(alg);
    const size_t ciphertext_length = LIBERAC_NTRU_PLUS_CIPHERTEXT_SIZE(alg);
    uint8_t *public_key = (uint8_t *)malloc(public_key_length);
    uint8_t *private_key = (uint8_t *)malloc(private_key_length);
    uint8_t *ciphertext = (uint8_t *)malloc(ciphertext_length);
    uint8_t encapsulated[LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES];
    uint8_t decapsulated[LIBERAC_NTRU_PLUS_SHARED_SECRET_BYTES];
    LiberaCError error;
    int result = 1;

    if (public_key == NULL || private_key == NULL || ciphertext == NULL)
        goto cleanup;
    error = LIBERAC_NTRU_PLUS_KEYGEN(
        public_key, public_key_length, private_key, private_key_length, alg);
    if (error != LIBERAC_SUCCESS) goto cleanup;
    error = LIBERAC_NTRU_PLUS_ENCAPS(
        public_key, public_key_length, encapsulated,
        ciphertext, ciphertext_length, alg);
    if (error != LIBERAC_SUCCESS) goto cleanup;
    error = LIBERAC_NTRU_PLUS_DECAPS(
        private_key, private_key_length, ciphertext, ciphertext_length,
        decapsulated, alg);
    if (error != LIBERAC_SUCCESS ||
        memcmp(encapsulated, decapsulated, sizeof(encapsulated)) != 0) {
        goto cleanup;
    }

    memset(decapsulated, 0xa5, sizeof(decapsulated));
    ciphertext[0] = 0xffu;
    ciphertext[1] = 0xffu;
    ciphertext[2] = 0xffu;
    error = LIBERAC_NTRU_PLUS_DECAPS(
        private_key, private_key_length, ciphertext, ciphertext_length,
        decapsulated, alg);
    if (error != LIBERAC_ERROR_AUTHENTICATION_FAILED ||
        memcmp(decapsulated, zero_secret, sizeof(decapsulated)) != 0) {
        goto cleanup;
    }
    error = LIBERAC_NTRU_PLUS_ENCAPS(
        public_key, public_key_length, encapsulated,
        ciphertext, ciphertext_length, alg);
    if (error != LIBERAC_SUCCESS) goto cleanup;

    private_key[0] = 0xffu;
    private_key[1] = 0xffu;
    private_key[2] = 0xffu;
    memset(decapsulated, 0xa5, sizeof(decapsulated));
    error = LIBERAC_NTRU_PLUS_DECAPS(
        private_key, private_key_length, ciphertext, ciphertext_length,
        decapsulated, alg);
    if (error != LIBERAC_ERROR_INVALID_KEY ||
        memcmp(decapsulated, zero_secret, sizeof(decapsulated)) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    free(ciphertext);
    free(private_key);
    free(public_key);
    return result;
}

int main(void) {
    size_t index;

    if (LIBERAC_NTRU_PLUS_PUBLIC_KEY_SIZE(LIBERAC_ALG_NONE) != 0u ||
        LIBERAC_NTRU_PLUS_PRIVATE_KEY_SIZE(LIBERAC_ALG_NONE) != 0u ||
        LIBERAC_NTRU_PLUS_CIPHERTEXT_SIZE(LIBERAC_ALG_NONE) != 0u) {
        return 1;
    }
    for (index = 0u; index < sizeof(algorithms) / sizeof(algorithms[0]);
         ++index) {
        if (run_case(algorithms[index]) != 0) return 1;
    }
    puts("NTRU+ unit tests passed");
    return 0;
}
