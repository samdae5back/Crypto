/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "AuthenticatedEncryption.h"
#include "AuthenticatedEncryption/ChaCha20Poly1305/chacha20_poly1305_internal.h"
#include "Util/Core/memory_internal.h"

static int aead_algorithm_valid(LiberaCAlgID alg) {
    return alg == LIBERAC_ALG_CHACHA20_POLY1305;
}

size_t LIBERAC_AEAD_KEY_SIZE(LiberaCAlgID ALG) {
    return aead_algorithm_valid(ALG)
               ? LIBERAC_CHACHA20_POLY1305_KEY_BYTES
               : 0u;
}

size_t LIBERAC_AEAD_NONCE_SIZE(LiberaCAlgID ALG) {
    return aead_algorithm_valid(ALG)
               ? LIBERAC_CHACHA20_POLY1305_NONCE_BYTES
               : 0u;
}

size_t LIBERAC_AEAD_TAG_SIZE(LiberaCAlgID ALG) {
    return aead_algorithm_valid(ALG)
               ? LIBERAC_CHACHA20_POLY1305_TAG_BYTES
               : 0u;
}

static LiberaCError aead_validate_request(
    const uint8_t *output, size_t output_capacity,
    const uint8_t *tag, size_t tag_length,
    const uint8_t *input, size_t input_length,
    const uint8_t *key, size_t key_length,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *aad, size_t aad_length) {
    LiberaCError err;

    if (!tag || !key || !nonce || (!input && input_length != 0u) ||
        (!output && input_length != 0u) || (!aad && aad_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (key_length != LIBERAC_CHACHA20_POLY1305_KEY_BYTES)
        return LIBERAC_ERROR_INVALID_KEY;
    if (nonce_length != LIBERAC_CHACHA20_POLY1305_NONCE_BYTES ||
        tag_length != LIBERAC_CHACHA20_POLY1305_TAG_BYTES) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (output_capacity < input_length)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;

    err = crypto_chacha20_poly1305_validate_lengths(
        input_length, aad_length);
    if (err != LIBERAC_SUCCESS) return err;

    if (output != input &&
        crypto_ranges_overlap(output, input_length, input, input_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (crypto_ranges_overlap(output, input_length,
                              key, LIBERAC_CHACHA20_POLY1305_KEY_BYTES) ||
        crypto_ranges_overlap(output, input_length,
                              nonce, LIBERAC_CHACHA20_POLY1305_NONCE_BYTES) ||
        crypto_ranges_overlap(output, input_length, aad, aad_length) ||
        crypto_ranges_overlap(output, input_length,
                              tag, LIBERAC_CHACHA20_POLY1305_TAG_BYTES) ||
        crypto_ranges_overlap(tag, LIBERAC_CHACHA20_POLY1305_TAG_BYTES,
                              input, input_length) ||
        crypto_ranges_overlap(tag, LIBERAC_CHACHA20_POLY1305_TAG_BYTES,
                              key, LIBERAC_CHACHA20_POLY1305_KEY_BYTES) ||
        crypto_ranges_overlap(tag, LIBERAC_CHACHA20_POLY1305_TAG_BYTES,
                              nonce, LIBERAC_CHACHA20_POLY1305_NONCE_BYTES) ||
        crypto_ranges_overlap(tag, LIBERAC_CHACHA20_POLY1305_TAG_BYTES,
                              aad, aad_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    return LIBERAC_SUCCESS;
}

LiberaCError LIBERAC_AEAD_ENCRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    uint8_t *TAG, size_t TAG_CAPACITY,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    LiberaCAlgID ALG) {
    LiberaCError err;

    if (!aead_algorithm_valid(ALG))
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!TAG) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (TAG_CAPACITY < LIBERAC_CHACHA20_POLY1305_TAG_BYTES)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    err = aead_validate_request(
        OUTPUT, OUTPUT_CAPACITY, TAG, LIBERAC_CHACHA20_POLY1305_TAG_BYTES,
        INPUT, INPUT_LENGTH, KEY, KEY_LENGTH, NONCE, NONCE_LENGTH,
        AAD, AAD_LENGTH);
    if (err != LIBERAC_SUCCESS) return err;

    return crypto_chacha20_poly1305_encrypt_internal(
        OUTPUT, TAG, INPUT, INPUT_LENGTH, KEY, NONCE, AAD, AAD_LENGTH);
}

LiberaCError LIBERAC_AEAD_DECRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    LiberaCAlgID ALG) {
    LiberaCError err;

    if (!aead_algorithm_valid(ALG))
        return LIBERAC_ERROR_INVALID_ALG_ID;
    err = aead_validate_request(
        OUTPUT, OUTPUT_CAPACITY, TAG, TAG_LENGTH,
        INPUT, INPUT_LENGTH, KEY, KEY_LENGTH, NONCE, NONCE_LENGTH,
        AAD, AAD_LENGTH);
    if (err != LIBERAC_SUCCESS) return err;

    return crypto_chacha20_poly1305_decrypt_internal(
        OUTPUT, TAG, INPUT, INPUT_LENGTH, KEY, NONCE, AAD, AAD_LENGTH);
}
