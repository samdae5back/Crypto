/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "StreamCipher.h"
#include "StreamCipher/ChaCha20/chacha20_internal.h"
#include "Util/Core/memory_internal.h"

static int stream_cipher_algorithm_valid(LiberaCAlgID alg) {
    return alg == LIBERAC_ALG_CHACHA20;
}

size_t LIBERAC_STREAM_CIPHER_KEY_SIZE(LiberaCAlgID ALG) {
    return stream_cipher_algorithm_valid(ALG) ? LIBERAC_CHACHA20_KEY_BYTES : 0u;
}

size_t LIBERAC_STREAM_CIPHER_NONCE_SIZE(LiberaCAlgID ALG) {
    return stream_cipher_algorithm_valid(ALG) ? LIBERAC_CHACHA20_NONCE_BYTES : 0u;
}

LiberaCError LIBERAC_STREAM_CIPHER_XOR(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    uint32_t INITIAL_COUNTER,
    LiberaCAlgID ALG) {
    LiberaCError err;

    if (!stream_cipher_algorithm_valid(ALG))
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!KEY || !NONCE || (!INPUT && INPUT_LENGTH != 0u) ||
        (!OUTPUT && INPUT_LENGTH != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (KEY_LENGTH != LIBERAC_CHACHA20_KEY_BYTES)
        return LIBERAC_ERROR_INVALID_KEY;
    if (NONCE_LENGTH != LIBERAC_CHACHA20_NONCE_BYTES)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (OUTPUT_CAPACITY < INPUT_LENGTH)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (OUTPUT != INPUT &&
        crypto_ranges_overlap(OUTPUT, INPUT_LENGTH, INPUT, INPUT_LENGTH)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (crypto_ranges_overlap(OUTPUT, INPUT_LENGTH,
                              KEY, LIBERAC_CHACHA20_KEY_BYTES) ||
        crypto_ranges_overlap(OUTPUT, INPUT_LENGTH,
                              NONCE, LIBERAC_CHACHA20_NONCE_BYTES)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    err = crypto_chacha20_validate_length(INPUT_LENGTH, INITIAL_COUNTER);
    if (err != LIBERAC_SUCCESS) return err;
    return crypto_chacha20_xor_internal(
        OUTPUT, INPUT, INPUT_LENGTH, KEY, NONCE, INITIAL_COUNTER);
}
