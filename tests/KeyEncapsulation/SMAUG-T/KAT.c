/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Internal/KemKat.h"

#include <stdio.h>
#include <string.h>

typedef struct crypto_test_smaug_t_case {
    const char *name;
    LiberaCAlgID alg;
} CRYPTO_TEST_SMAUG_T_CASE;

static const CRYPTO_TEST_SMAUG_T_CASE smaug_t_cases[] = {
    { "SMAUG-T-128", LIBERAC_ALG_SMAUG_T_128 },
    { "SMAUG-T-192", LIBERAC_ALG_SMAUG_T_192 },
    { "SMAUG-T-256", LIBERAC_ALG_SMAUG_T_256 }
};

int main(int argc, char **argv) {
    static const CRYPTO_TEST_KEM_API api = {
        LIBERAC_SMAUG_T_SHARED_SECRET_BYTES,
        LIBERAC_SMAUG_T_PUBLIC_KEY_SIZE,
        LIBERAC_SMAUG_T_PRIVATE_KEY_SIZE,
        LIBERAC_SMAUG_T_CIPHERTEXT_SIZE,
        LIBERAC_SMAUG_T_KEYGEN,
        LIBERAC_SMAUG_T_ENCAPS,
        LIBERAC_SMAUG_T_DECAPS
    };
    size_t index;

    if (argc != 3) {
        fprintf(stderr, "usage: smaug_t_kat <vector.kat> <algorithm-name>\n");
        return 2;
    }
    for (index = 0u;
         index < sizeof(smaug_t_cases) / sizeof(smaug_t_cases[0]);
         ++index) {
        if (strcmp(argv[2], smaug_t_cases[index].name) == 0) {
            return crypto_test_run_kem_kat(
                argv[1], argv[2], smaug_t_cases[index].alg, &api, 100u);
        }
    }
    fprintf(stderr, "unsupported SMAUG-T KAT selector: %s\n", argv[2]);
    return 2;
}
