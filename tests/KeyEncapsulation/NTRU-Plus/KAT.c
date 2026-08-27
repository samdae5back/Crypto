/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Internal/KemKat.h"

#include <stdio.h>
#include <string.h>

typedef struct crypto_test_ntru_plus_case {
    const char *name;
    AlgID alg;
} CRYPTO_TEST_NTRU_PLUS_CASE;

static const CRYPTO_TEST_NTRU_PLUS_CASE ntru_plus_cases[] = {
    { "NTRU+768", ALG_NTRU_PLUS_768 },
    { "NTRU+864", ALG_NTRU_PLUS_864 },
    { "NTRU+1152", ALG_NTRU_PLUS_1152 }
};

int main(int argc, char **argv) {
    static const CRYPTO_TEST_KEM_API api = {
        CRYPTO_NTRU_PLUS_SHARED_SECRET_BYTES,
        CRYPTO_NTRU_PLUS_PUBLIC_KEY_SIZE,
        CRYPTO_NTRU_PLUS_PRIVATE_KEY_SIZE,
        CRYPTO_NTRU_PLUS_CIPHERTEXT_SIZE,
        CRYPTO_NTRU_PLUS_KEYGEN,
        CRYPTO_NTRU_PLUS_ENCAPS,
        CRYPTO_NTRU_PLUS_DECAPS
    };
    size_t index;

    if (argc != 3) {
        fprintf(stderr, "usage: ntru_plus_kat <vector.kat> <algorithm-name>\n");
        return 2;
    }
    for (index = 0u;
         index < sizeof(ntru_plus_cases) / sizeof(ntru_plus_cases[0]);
         ++index) {
        if (strcmp(argv[2], ntru_plus_cases[index].name) == 0) {
            return crypto_test_run_kem_kat(
                argv[1], argv[2], ntru_plus_cases[index].alg, &api, 100u);
        }
    }
    fprintf(stderr, "unsupported NTRU+ KAT selector: %s\n", argv[2]);
    return 2;
}
