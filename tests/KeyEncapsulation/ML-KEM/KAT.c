/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Internal/KemKat.h"

#include <stdio.h>
#include <string.h>

typedef struct crypto_test_ml_kem_case {
    const char *name;
    AlgID alg;
} CRYPTO_TEST_ML_KEM_CASE;

static const CRYPTO_TEST_ML_KEM_CASE ml_kem_cases[] = {
    { "ML-KEM-512", ALG_ML_KEM_512 },
    { "ML-KEM-768", ALG_ML_KEM_768 },
    { "ML-KEM-1024", ALG_ML_KEM_1024 }
};

int main(int argc, char **argv) {
    static const CRYPTO_TEST_KEM_API api = {
        CRYPTO_ML_KEM_SHARED_SECRET_BYTES,
        CRYPTO_ML_KEM_PUBLIC_KEY_SIZE,
        CRYPTO_ML_KEM_PRIVATE_KEY_SIZE,
        CRYPTO_ML_KEM_CIPHERTEXT_SIZE,
        CRYPTO_ML_KEM_KEYGEN,
        CRYPTO_ML_KEM_ENCAPS,
        CRYPTO_ML_KEM_DECAPS
    };
    size_t index;

    if (argc != 3) {
        fprintf(stderr, "usage: ml_kem_kat <vector.kat> <algorithm-name>\n");
        return 2;
    }
    for (index = 0u; index < sizeof(ml_kem_cases) / sizeof(ml_kem_cases[0]);
         ++index) {
        if (strcmp(argv[2], ml_kem_cases[index].name) == 0) {
            return crypto_test_run_kem_kat(
                argv[1], argv[2], ml_kem_cases[index].alg, &api, 100u);
        }
    }
    fprintf(stderr, "unsupported ML-KEM KAT selector: %s\n", argv[2]);
    return 2;
}
