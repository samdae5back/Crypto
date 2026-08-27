/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Internal/SignatureKat.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    LiberaCAlgID alg;
} ML_DSA_KAT_CASE;

static const ML_DSA_KAT_CASE ml_dsa_cases[] = {
    { "ML-DSA-44", LIBERAC_ALG_ML_DSA_44 },
    { "ML-DSA-65", LIBERAC_ALG_ML_DSA_65 },
    { "ML-DSA-87", LIBERAC_ALG_ML_DSA_87 }
};

int main(int argc, char **argv) {
    static const CRYPTO_TEST_SIGNATURE_API api = {
        LIBERAC_ML_DSA_PUBLIC_KEY_SIZE,
        LIBERAC_ML_DSA_PRIVATE_KEY_SIZE,
        LIBERAC_ML_DSA_SIGNATURE_SIZE,
        LIBERAC_ML_DSA_KEYGEN,
        LIBERAC_ML_DSA_SIGN,
        LIBERAC_ML_DSA_VERIFY
    };
    size_t index;

    if (argc != 3) {
        fprintf(stderr, "usage: ml_dsa_kat <vector.kat> <algorithm-name>\n");
        return 2;
    }
    for (index = 0u; index < sizeof(ml_dsa_cases) / sizeof(ml_dsa_cases[0]);
         ++index) {
        if (strcmp(argv[2], ml_dsa_cases[index].name) == 0) {
            return crypto_test_run_signature_kat(
                argv[1], argv[2], ml_dsa_cases[index].alg, &api, 100u);
        }
    }
    fprintf(stderr, "unsupported ML-DSA KAT selector: %s\n", argv[2]);
    return 2;
}
