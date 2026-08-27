/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_TEST_KEM_KAT_H
#define CRYPTO_TEST_KEM_KAT_H

#include "KeyEncapsulation.h"

typedef struct crypto_test_kem_api {
    size_t shared_secret_size;
    size_t (*public_key_size)(AlgID alg);
    size_t (*private_key_size)(AlgID alg);
    size_t (*ciphertext_size)(AlgID alg);
    CryptoError (*keygen)(
        uint8_t *public_key, size_t public_key_length,
        uint8_t *private_key, size_t private_key_length,
        AlgID alg);
    CryptoError (*encaps)(
        const uint8_t *public_key, size_t public_key_length,
        uint8_t *shared_secret,
        uint8_t *ciphertext, size_t ciphertext_length,
        AlgID alg);
    CryptoError (*decaps)(
        const uint8_t *private_key, size_t private_key_length,
        const uint8_t *ciphertext, size_t ciphertext_length,
        uint8_t *shared_secret,
        AlgID alg);
} CRYPTO_TEST_KEM_API;

int crypto_test_run_kem_kat(
    const char *path, const char *algorithm_name, AlgID alg,
    const CRYPTO_TEST_KEM_API *api, size_t record_count);

#endif
