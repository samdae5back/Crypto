/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "AuthenticatedEncryption/ChaCha20Poly1305/chacha20_poly1305_internal.h"
#include "MessageAuthentication/Poly1305/poly1305_internal.h"
#include "StreamCipher/ChaCha20/chacha20_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/Endian/endian_internal.h"

#include <string.h>

LiberaCError crypto_chacha20_poly1305_validate_lengths(
    size_t message_length, size_t aad_length) {
    if (message_length > (size_t)UINT64_MAX ||
        aad_length > (size_t)UINT64_MAX) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }
    return crypto_chacha20_validate_length(message_length, UINT32_C(1));
}

static void poly1305_pad16(
    CryptoPoly1305Context *context, size_t unpadded_length) {
    static const uint8_t zeroes[16] = {0};
    size_t remainder = unpadded_length & 15u;

    if (remainder != 0u)
        crypto_poly1305_update_internal(context, zeroes, 16u - remainder);
}

static void chacha20_poly1305_tag(
    uint8_t tag[LIBERAC_CHACHA20_POLY1305_TAG_BYTES],
    const uint8_t key[LIBERAC_CHACHA20_POLY1305_KEY_BYTES],
    const uint8_t nonce[LIBERAC_CHACHA20_POLY1305_NONCE_BYTES],
    const uint8_t *aad, size_t aad_length,
    const uint8_t *ciphertext, size_t ciphertext_length) {
    CryptoPoly1305Context context;
    uint8_t block_zero[LIBERAC_CHACHA20_BLOCK_BYTES];
    uint8_t lengths[16];

    crypto_chacha20_block_internal(block_zero, key, nonce, 0u);
    crypto_poly1305_init_internal(&context, block_zero);
    crypto_zeroize(block_zero, sizeof(block_zero));

    crypto_poly1305_update_internal(&context, aad, aad_length);
    poly1305_pad16(&context, aad_length);
    crypto_poly1305_update_internal(
        &context, ciphertext, ciphertext_length);
    poly1305_pad16(&context, ciphertext_length);
    crypto_store64_le(lengths, (uint64_t)aad_length);
    crypto_store64_le(lengths + 8u, (uint64_t)ciphertext_length);
    crypto_poly1305_update_internal(&context, lengths, sizeof(lengths));
    crypto_poly1305_final_internal(&context, tag);
    crypto_zeroize(lengths, sizeof(lengths));
}

LiberaCError crypto_chacha20_poly1305_encrypt_internal(
    uint8_t *output,
    uint8_t tag[LIBERAC_CHACHA20_POLY1305_TAG_BYTES],
    const uint8_t *input, size_t input_length,
    const uint8_t key[LIBERAC_CHACHA20_POLY1305_KEY_BYTES],
    const uint8_t nonce[LIBERAC_CHACHA20_POLY1305_NONCE_BYTES],
    const uint8_t *aad, size_t aad_length) {
    LiberaCError err = crypto_chacha20_poly1305_validate_lengths(
        input_length, aad_length);

    if (err != LIBERAC_SUCCESS) return err;
    err = crypto_chacha20_xor_internal(
        output, input, input_length, key, nonce, UINT32_C(1));
    if (err == LIBERAC_SUCCESS)
        chacha20_poly1305_tag(
            tag, key, nonce, aad, aad_length, output, input_length);
    if (err != LIBERAC_SUCCESS && output && input_length != 0u)
        crypto_zeroize(output, input_length);
    return err;
}

LiberaCError crypto_chacha20_poly1305_decrypt_internal(
    uint8_t *output,
    const uint8_t tag[LIBERAC_CHACHA20_POLY1305_TAG_BYTES],
    const uint8_t *input, size_t input_length,
    const uint8_t key[LIBERAC_CHACHA20_POLY1305_KEY_BYTES],
    const uint8_t nonce[LIBERAC_CHACHA20_POLY1305_NONCE_BYTES],
    const uint8_t *aad, size_t aad_length) {
    uint8_t expected[LIBERAC_CHACHA20_POLY1305_TAG_BYTES];
    LiberaCError err = crypto_chacha20_poly1305_validate_lengths(
        input_length, aad_length);

    if (err != LIBERAC_SUCCESS) return err;
    chacha20_poly1305_tag(
        expected, key, nonce, aad, aad_length, input, input_length);
    if (!crypto_constant_time_equal(expected, tag, sizeof(expected)))
        err = LIBERAC_ERROR_AUTHENTICATION_FAILED;
    else
        err = crypto_chacha20_xor_internal(
            output, input, input_length, key, nonce, UINT32_C(1));

    if (err != LIBERAC_SUCCESS && output && input_length != 0u)
        crypto_zeroize(output, input_length);
    crypto_zeroize(expected, sizeof(expected));
    return err;
}
