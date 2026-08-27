/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Internal/SignatureKat.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    AlgID alg;
} SLH_DSA_KAT_CASE;

static const SLH_DSA_KAT_CASE slh_dsa_cases[] = {
    { "SLH-DSA-SHA2-128s", ALG_SLH_DSA_SHA2_128S },
    { "SLH-DSA-SHA2-128f", ALG_SLH_DSA_SHA2_128F },
    { "SLH-DSA-SHA2-192s", ALG_SLH_DSA_SHA2_192S },
    { "SLH-DSA-SHA2-192f", ALG_SLH_DSA_SHA2_192F },
    { "SLH-DSA-SHA2-256s", ALG_SLH_DSA_SHA2_256S },
    { "SLH-DSA-SHA2-256f", ALG_SLH_DSA_SHA2_256F },
    { "SLH-DSA-SHAKE-128s", ALG_SLH_DSA_SHAKE_128S },
    { "SLH-DSA-SHAKE-128f", ALG_SLH_DSA_SHAKE_128F },
    { "SLH-DSA-SHAKE-192s", ALG_SLH_DSA_SHAKE_192S },
    { "SLH-DSA-SHAKE-192f", ALG_SLH_DSA_SHAKE_192F },
    { "SLH-DSA-SHAKE-256s", ALG_SLH_DSA_SHAKE_256S },
    { "SLH-DSA-SHAKE-256f", ALG_SLH_DSA_SHAKE_256F }
};

int main(int argc, char **argv) {
    static const CRYPTO_TEST_SIGNATURE_API api = {
        CRYPTO_SLH_DSA_PUBLIC_KEY_SIZE,
        CRYPTO_SLH_DSA_PRIVATE_KEY_SIZE,
        CRYPTO_SLH_DSA_SIGNATURE_SIZE,
        CRYPTO_SLH_DSA_KEYGEN,
        CRYPTO_SLH_DSA_SIGN,
        CRYPTO_SLH_DSA_VERIFY
    };
    size_t index;

    if (argc != 3) {
        fprintf(stderr, "usage: slh_dsa_kat <vector.kat> <algorithm-name>\n");
        return 2;
    }
    for (index = 0u; index < sizeof(slh_dsa_cases) / sizeof(slh_dsa_cases[0]);
         ++index) {
        if (strcmp(argv[2], slh_dsa_cases[index].name) == 0) {
            return crypto_test_run_signature_kat(
                argv[1], argv[2], slh_dsa_cases[index].alg, &api, 100u);
        }
    }
    fprintf(stderr, "unsupported SLH-DSA KAT selector: %s\n", argv[2]);
    return 2;
}
