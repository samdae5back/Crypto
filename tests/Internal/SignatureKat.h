/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_TEST_SIGNATURE_KAT_H
#define CRYPTO_TEST_SIGNATURE_KAT_H

#include "DigitalSignature.h"

typedef struct {
    size_t (*public_key_size)(LiberaCAlgID alg);
    size_t (*private_key_size)(LiberaCAlgID alg);
    size_t (*signature_size)(LiberaCAlgID alg);
    LiberaCError (*keygen)(
        uint8_t *public_key, size_t public_key_length,
        uint8_t *private_key, size_t private_key_length,
        LiberaCAlgID alg);
    LiberaCError (*sign)(
        const uint8_t *private_key, size_t private_key_length,
        const uint8_t *message, size_t message_length,
        const uint8_t *context, size_t context_length,
        uint8_t *signature, size_t signature_length,
        LiberaCAlgID alg);
    LiberaCError (*verify)(
        const uint8_t *public_key, size_t public_key_length,
        const uint8_t *message, size_t message_length,
        const uint8_t *context, size_t context_length,
        const uint8_t *signature, size_t signature_length,
        LiberaCAlgID alg);
} CRYPTO_TEST_SIGNATURE_API;

int crypto_test_run_signature_kat(
    const char *path, const char *algorithm_name, LiberaCAlgID alg,
    const CRYPTO_TEST_SIGNATURE_API *api, size_t record_count);

#endif
