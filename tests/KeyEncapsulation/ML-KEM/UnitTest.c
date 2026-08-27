/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "HashFunction.h"
#include "KeyEncapsulation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int bytes_are(const uint8_t *buffer, size_t length, uint8_t value) {
    size_t i;
    for (i = 0u; i < length; ++i)
        if (buffer[i] != value) return 0;
    return 1;
}

static int test_ml_kem(AlgID alg) {
    size_t public_key_length = CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(alg);
    size_t private_key_length = CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(alg);
    size_t ciphertext_length = CRYPTO_ML_KEM_CIPHERTEXT_SIZE(alg);
    uint8_t *public_key = NULL, *private_key = NULL, *ciphertext = NULL;
    uint8_t shared_a[CRYPTO_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t shared_b[CRYPTO_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t rejected[CRYPTO_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t rejection_expected[CRYPTO_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t rejection_input[CRYPTO_ML_KEM_1024_CIPHERTEXT_BYTES + 32u];
    uint8_t overlap_snapshot[CRYPTO_ML_KEM_1024_PRIVATE_KEY_BYTES];
    size_t embedded_public_key_offset;
    uint8_t saved_first;
    uint8_t saved_second;
    int failed = 1;

    public_key = (uint8_t *)malloc(public_key_length);
    private_key = (uint8_t *)malloc(private_key_length);
    ciphertext = (uint8_t *)malloc(ciphertext_length);
    if (!public_key || !private_key || !ciphertext) goto done;
    if (CRYPTO_ML_KEM_KEYGEN(public_key, public_key_length,
                             private_key, private_key_length, alg) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_ML_KEM_ENCAPS(public_key, public_key_length, shared_a,
                             ciphertext, ciphertext_length, alg) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_ML_KEM_DECAPS(private_key, private_key_length,
                             ciphertext, ciphertext_length, shared_b,
                             alg) != CRYPTO_SUCCESS)
        goto done;
    if (memcmp(shared_a, shared_b, sizeof(shared_a)) != 0)
        goto done;

    ciphertext[0] ^= 1u;
    memcpy(rejection_input, private_key + private_key_length - 32u, 32u);
    memcpy(rejection_input + 32u, ciphertext, ciphertext_length);
    if (CRYPTO_HASH(rejection_expected, sizeof(rejection_expected),
                    rejection_input, ciphertext_length + 32u,
                    ALG_HASH_SHAKE256) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_ML_KEM_DECAPS(private_key, private_key_length,
                             ciphertext, ciphertext_length, rejected,
                             alg) != CRYPTO_SUCCESS)
        goto done;
    if (memcmp(rejected, rejection_expected, sizeof(rejected)) != 0)
        goto done;

    /* Encapsulation rejects non-canonical 12-bit public-key coefficients. */
    saved_first = public_key[0];
    saved_second = public_key[1];
    public_key[0] = 0x01u;
    public_key[1] = (uint8_t)((public_key[1] & 0xf0u) | 0x0du); /* 3329 */
    memset(shared_a, 0xa5, sizeof(shared_a));
    memset(ciphertext, 0xa5, ciphertext_length);
    if (CRYPTO_ML_KEM_ENCAPS(public_key, public_key_length, shared_a,
                             ciphertext, ciphertext_length, alg) !=
            CRYPTO_ERROR_INVALID_KEY ||
        !bytes_are(shared_a, sizeof(shared_a), 0u) ||
        !bytes_are(ciphertext, ciphertext_length, 0u))
        goto done;
    public_key[0] = saved_first;
    public_key[1] = saved_second;

    /* Decapsulation validates H(embedded public key) before PKE work. */
    embedded_public_key_offset =
        private_key_length - public_key_length - 64u;
    private_key[embedded_public_key_offset] ^= 1u;
    memset(shared_b, 0xa5, sizeof(shared_b));
    if (CRYPTO_ML_KEM_DECAPS(private_key, private_key_length,
                             ciphertext, ciphertext_length, shared_b,
                             alg) != CRYPTO_ERROR_INVALID_KEY ||
        !bytes_are(shared_b, sizeof(shared_b), 0u))
        goto done;
    private_key[embedded_public_key_offset] ^= 1u;

    private_key[private_key_length - 64u] ^= 1u;
    memset(shared_b, 0xa5, sizeof(shared_b));
    if (CRYPTO_ML_KEM_DECAPS(private_key, private_key_length,
                             ciphertext, ciphertext_length, shared_b,
                             alg) != CRYPTO_ERROR_INVALID_KEY ||
        !bytes_are(shared_b, sizeof(shared_b), 0u))
        goto done;
    private_key[private_key_length - 64u] ^= 1u;

    /* Actual input/output regions must not overlap; rejection is non-mutating. */
    memcpy(overlap_snapshot, public_key, public_key_length);
    if (CRYPTO_ML_KEM_ENCAPS(public_key, public_key_length, public_key,
                             ciphertext, ciphertext_length, alg) !=
            CRYPTO_ERROR_INVALID_ARGUMENT ||
        memcmp(public_key, overlap_snapshot, public_key_length) != 0)
        goto done;

    memcpy(overlap_snapshot, public_key, public_key_length);
    memset(shared_a, 0xa5, sizeof(shared_a));
    if (CRYPTO_ML_KEM_ENCAPS(public_key, public_key_length, shared_a,
                             public_key, ciphertext_length, alg) !=
            CRYPTO_ERROR_INVALID_ARGUMENT ||
        memcmp(public_key, overlap_snapshot, public_key_length) != 0 ||
        !bytes_are(shared_a, sizeof(shared_a), 0xa5u))
        goto done;

    memset(ciphertext, 0xa5, ciphertext_length);
    memcpy(overlap_snapshot, ciphertext, ciphertext_length);
    if (CRYPTO_ML_KEM_ENCAPS(public_key, public_key_length, ciphertext,
                             ciphertext, ciphertext_length, alg) !=
            CRYPTO_ERROR_INVALID_ARGUMENT ||
        memcmp(ciphertext, overlap_snapshot, ciphertext_length) != 0)
        goto done;

    memcpy(overlap_snapshot, private_key, private_key_length);
    if (CRYPTO_ML_KEM_DECAPS(private_key, private_key_length,
                             ciphertext, ciphertext_length, private_key,
                             alg) != CRYPTO_ERROR_INVALID_ARGUMENT ||
        memcmp(private_key, overlap_snapshot, private_key_length) != 0)
        goto done;

    memcpy(overlap_snapshot, ciphertext, ciphertext_length);
    if (CRYPTO_ML_KEM_DECAPS(private_key, private_key_length,
                             ciphertext, ciphertext_length, ciphertext,
                             alg) != CRYPTO_ERROR_INVALID_ARGUMENT ||
        memcmp(ciphertext, overlap_snapshot, ciphertext_length) != 0)
        goto done;

    memset(private_key, 0xa5, private_key_length);
    if (CRYPTO_ML_KEM_KEYGEN(private_key, public_key_length,
                             private_key, private_key_length, alg) !=
            CRYPTO_ERROR_INVALID_ARGUMENT ||
        !bytes_are(private_key, private_key_length, 0xa5u))
        goto done;

    failed = 0;

done:
    free(public_key);
    free(private_key);
    free(ciphertext);
    return failed;
}

int main(void) {
    static const AlgID ml_kem_algorithms[] = {
        ALG_ML_KEM_512, ALG_ML_KEM_768, ALG_ML_KEM_1024
    };
    size_t i;

    for (i = 0u; i < sizeof(ml_kem_algorithms) / sizeof(ml_kem_algorithms[0]); ++i) {
        if (test_ml_kem(ml_kem_algorithms[i])) {
            fprintf(stderr, "ML-KEM algorithm %d unit test failed\n",
                    (int)ml_kem_algorithms[i]);
            return 1;
        }
    }
    puts("ML-KEM unit tests passed");
    return 0;
}
