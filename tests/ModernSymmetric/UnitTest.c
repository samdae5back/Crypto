/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "LiberaCrypt.h"

#include <stdio.h>
#include <string.h>

static int all_zero(const uint8_t *data, size_t length) {
    size_t i;
    uint8_t combined = 0u;
    for (i = 0u; i < length; ++i) combined |= data[i];
    return combined == 0u;
}

static void fill_inputs(uint8_t *key, uint8_t *nonce) {
    size_t i;
    for (i = 0u; i < LIBERAC_CHACHA20_KEY_BYTES; ++i)
        key[i] = (uint8_t)(3u * i + 1u);
    for (i = 0u; i < LIBERAC_CHACHA20_NONCE_BYTES; ++i)
        nonce[i] = (uint8_t)(0xa0u + i);
}

static int test_size_queries(void) {
    if (LIBERAC_STREAM_CIPHER_KEY_SIZE(LIBERAC_ALG_CHACHA20) != 32u ||
        LIBERAC_STREAM_CIPHER_NONCE_SIZE(LIBERAC_ALG_CHACHA20) != 12u ||
        LIBERAC_STREAM_CIPHER_KEY_SIZE(LIBERAC_ALG_AES_128_CTR) != 0u ||
        LIBERAC_STREAM_CIPHER_NONCE_SIZE(LIBERAC_ALG_NONE) != 0u) {
        return 1;
    }
    if (LIBERAC_POLY1305_TAG_SIZE(LIBERAC_ALG_POLY1305) != 16u ||
        LIBERAC_POLY1305_TAG_SIZE(LIBERAC_ALG_NONE) != 0u) {
        return 1;
    }
    return LIBERAC_AEAD_KEY_SIZE(LIBERAC_ALG_CHACHA20_POLY1305) != 32u ||
           LIBERAC_AEAD_NONCE_SIZE(LIBERAC_ALG_CHACHA20_POLY1305) != 12u ||
           LIBERAC_AEAD_TAG_SIZE(LIBERAC_ALG_CHACHA20_POLY1305) != 16u ||
           LIBERAC_AEAD_KEY_SIZE(LIBERAC_ALG_NONE) != 0u;
}

static int test_chacha20_round_trip(void) {
    uint8_t key[LIBERAC_CHACHA20_KEY_BYTES];
    uint8_t nonce[LIBERAC_CHACHA20_NONCE_BYTES];
    uint8_t message[257];
    uint8_t ciphertext[257];
    uint8_t recovered[257];
    uint8_t overlap[80];
    uint8_t limit_input[65] = {0};
    uint8_t limit_output[65];
    size_t i;

    fill_inputs(key, nonce);
    for (i = 0u; i < sizeof(message); ++i)
        message[i] = (uint8_t)(i ^ (i >> 3));
    if (LIBERAC_STREAM_CIPHER_XOR(
            ciphertext, sizeof(ciphertext), message, sizeof(message),
            key, sizeof(key), nonce, sizeof(nonce), 7u,
            LIBERAC_ALG_CHACHA20) != LIBERAC_SUCCESS ||
        LIBERAC_STREAM_CIPHER_XOR(
            recovered, sizeof(recovered), ciphertext, sizeof(ciphertext),
            key, sizeof(key), nonce, sizeof(nonce), 7u,
            LIBERAC_ALG_CHACHA20) != LIBERAC_SUCCESS ||
        memcmp(recovered, message, sizeof(message)) != 0) {
        return 1;
    }

    memcpy(recovered, message, sizeof(message));
    if (LIBERAC_STREAM_CIPHER_XOR(
            recovered, sizeof(recovered), recovered, sizeof(recovered),
            key, sizeof(key), nonce, sizeof(nonce), 9u,
            LIBERAC_ALG_CHACHA20) != LIBERAC_SUCCESS ||
        LIBERAC_STREAM_CIPHER_XOR(
            recovered, sizeof(recovered), recovered, sizeof(recovered),
            key, sizeof(key), nonce, sizeof(nonce), 9u,
            LIBERAC_ALG_CHACHA20) != LIBERAC_SUCCESS ||
        memcmp(recovered, message, sizeof(message)) != 0) {
        return 1;
    }

    memset(limit_output, 0xa5, sizeof(limit_output));
    if (LIBERAC_STREAM_CIPHER_XOR(
            limit_output, sizeof(limit_output), limit_input, sizeof(limit_input),
            key, sizeof(key), nonce, sizeof(nonce), UINT32_MAX,
            LIBERAC_ALG_CHACHA20) != LIBERAC_ERROR_MESSAGE_TOO_LARGE ||
        limit_output[0] != 0xa5u ||
        LIBERAC_STREAM_CIPHER_XOR(
            limit_output, 64u, limit_input, 64u,
            key, sizeof(key), nonce, sizeof(nonce), UINT32_MAX,
            LIBERAC_ALG_CHACHA20) != LIBERAC_SUCCESS) {
        return 1;
    }

    memset(overlap, 0, sizeof(overlap));
    if (LIBERAC_STREAM_CIPHER_XOR(
            overlap + 1u, sizeof(overlap) - 1u, overlap, 64u,
            key, sizeof(key), nonce, sizeof(nonce), 0u,
            LIBERAC_ALG_CHACHA20) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_STREAM_CIPHER_XOR(
            ciphertext, sizeof(ciphertext), message, sizeof(message),
            key, sizeof(key) - 1u, nonce, sizeof(nonce), 0u,
            LIBERAC_ALG_CHACHA20) != LIBERAC_ERROR_INVALID_KEY ||
        LIBERAC_STREAM_CIPHER_XOR(
            ciphertext, sizeof(ciphertext), message, sizeof(message),
            key, sizeof(key), nonce, sizeof(nonce) - 1u, 0u,
            LIBERAC_ALG_CHACHA20) != LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_STREAM_CIPHER_XOR(
            ciphertext, sizeof(message) - 1u, message, sizeof(message),
            key, sizeof(key), nonce, sizeof(nonce), 0u,
            LIBERAC_ALG_CHACHA20) != LIBERAC_ERROR_BUFFER_TOO_SMALL ||
        LIBERAC_STREAM_CIPHER_XOR(
            ciphertext, sizeof(ciphertext), message, sizeof(message),
            key, sizeof(key), nonce, sizeof(nonce), 0u,
            LIBERAC_ALG_NONE) != LIBERAC_ERROR_INVALID_ALG_ID) {
        return 1;
    }
    return 0;
}

static int test_poly1305_api(void) {
    uint8_t key[LIBERAC_POLY1305_KEY_BYTES];
    uint8_t tag[LIBERAC_POLY1305_TAG_BYTES];
    uint8_t message[33];
    size_t i;

    for (i = 0u; i < sizeof(key); ++i) key[i] = (uint8_t)(i + 11u);
    for (i = 0u; i < sizeof(message); ++i) message[i] = (uint8_t)(i * 7u);
    if (LIBERAC_POLY1305(
            tag, sizeof(tag), message, sizeof(message),
            key, sizeof(key), LIBERAC_ALG_POLY1305) != LIBERAC_SUCCESS ||
        LIBERAC_POLY1305_VERIFY(
            tag, sizeof(tag), message, sizeof(message),
            key, sizeof(key), LIBERAC_ALG_POLY1305) != LIBERAC_SUCCESS) {
        return 1;
    }
    tag[3] ^= 1u;
    if (LIBERAC_POLY1305_VERIFY(
            tag, sizeof(tag), message, sizeof(message),
            key, sizeof(key), LIBERAC_ALG_POLY1305) !=
            LIBERAC_ERROR_AUTHENTICATION_FAILED ||
        LIBERAC_POLY1305_VERIFY(
            tag, sizeof(tag) - 1u, message, sizeof(message),
            key, sizeof(key), LIBERAC_ALG_POLY1305) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_POLY1305(
            tag, sizeof(tag) - 1u, message, sizeof(message),
            key, sizeof(key), LIBERAC_ALG_POLY1305) !=
            LIBERAC_ERROR_BUFFER_TOO_SMALL ||
        LIBERAC_POLY1305(
            tag, sizeof(tag), message, sizeof(message),
            key, sizeof(key) - 1u, LIBERAC_ALG_POLY1305) !=
            LIBERAC_ERROR_INVALID_KEY ||
        LIBERAC_POLY1305(
            tag, sizeof(tag), message, sizeof(message),
            key, sizeof(key), LIBERAC_ALG_NONE) !=
            LIBERAC_ERROR_INVALID_ALG_ID) {
        return 1;
    }
    return LIBERAC_POLY1305(
               tag, sizeof(tag), NULL, 0u, key, sizeof(key),
               LIBERAC_ALG_POLY1305) != LIBERAC_SUCCESS;
}

static int test_aead_round_trip_and_failure(void) {
    uint8_t key[LIBERAC_CHACHA20_POLY1305_KEY_BYTES];
    uint8_t nonce[LIBERAC_CHACHA20_POLY1305_NONCE_BYTES];
    uint8_t aad[19];
    uint8_t message[73];
    uint8_t ciphertext[73];
    uint8_t recovered[73];
    uint8_t tag[LIBERAC_CHACHA20_POLY1305_TAG_BYTES];
    uint8_t bad_tag[LIBERAC_CHACHA20_POLY1305_TAG_BYTES];
    uint8_t overlap[96];
    size_t i;

    fill_inputs(key, nonce);
    for (i = 0u; i < sizeof(aad); ++i) aad[i] = (uint8_t)(0x30u + i);
    for (i = 0u; i < sizeof(message); ++i) message[i] = (uint8_t)(i * 5u + 9u);

    if (LIBERAC_AEAD_ENCRYPT(
            ciphertext, sizeof(ciphertext), tag, sizeof(tag),
            message, sizeof(message), key, sizeof(key), nonce, sizeof(nonce),
            aad, sizeof(aad), LIBERAC_ALG_CHACHA20_POLY1305) !=
            LIBERAC_SUCCESS ||
        LIBERAC_AEAD_DECRYPT(
            recovered, sizeof(recovered), tag, sizeof(tag),
            ciphertext, sizeof(ciphertext), key, sizeof(key),
            nonce, sizeof(nonce), aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) != LIBERAC_SUCCESS ||
        memcmp(recovered, message, sizeof(message)) != 0) {
        return 1;
    }

    memcpy(recovered, message, sizeof(message));
    if (LIBERAC_AEAD_ENCRYPT(
            recovered, sizeof(recovered), tag, sizeof(tag),
            recovered, sizeof(recovered), key, sizeof(key),
            nonce, sizeof(nonce), aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) != LIBERAC_SUCCESS ||
        LIBERAC_AEAD_DECRYPT(
            recovered, sizeof(recovered), tag, sizeof(tag),
            recovered, sizeof(recovered), key, sizeof(key),
            nonce, sizeof(nonce), aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) != LIBERAC_SUCCESS ||
        memcmp(recovered, message, sizeof(message)) != 0) {
        return 1;
    }

    memcpy(bad_tag, tag, sizeof(tag));
    bad_tag[7] ^= 0x80u;
    memset(recovered, 0xa5, sizeof(recovered));
    if (LIBERAC_AEAD_DECRYPT(
            recovered, sizeof(recovered), bad_tag, sizeof(bad_tag),
            ciphertext, sizeof(ciphertext), key, sizeof(key),
            nonce, sizeof(nonce), aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) !=
            LIBERAC_ERROR_AUTHENTICATION_FAILED ||
        !all_zero(recovered, sizeof(recovered))) {
        return 1;
    }

    ciphertext[4] ^= 1u;
    memset(recovered, 0xa5, sizeof(recovered));
    if (LIBERAC_AEAD_DECRYPT(
            recovered, sizeof(recovered), tag, sizeof(tag),
            ciphertext, sizeof(ciphertext), key, sizeof(key),
            nonce, sizeof(nonce), aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) !=
            LIBERAC_ERROR_AUTHENTICATION_FAILED ||
        !all_zero(recovered, sizeof(recovered))) {
        return 1;
    }
    ciphertext[4] ^= 1u;

    memset(overlap, 0, sizeof(overlap));
    if (LIBERAC_AEAD_ENCRYPT(
            overlap + 1u, 73u, tag, sizeof(tag), overlap, 73u,
            key, sizeof(key), nonce, sizeof(nonce), aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_AEAD_ENCRYPT(
            overlap, 73u, overlap + 16u, sizeof(tag), message, 73u,
            key, sizeof(key), nonce, sizeof(nonce), aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_AEAD_ENCRYPT(
            ciphertext, sizeof(ciphertext), tag, sizeof(tag) - 1u,
            message, sizeof(message), key, sizeof(key), nonce, sizeof(nonce),
            aad, sizeof(aad), LIBERAC_ALG_CHACHA20_POLY1305) !=
            LIBERAC_ERROR_BUFFER_TOO_SMALL ||
        LIBERAC_AEAD_DECRYPT(
            recovered, sizeof(recovered), tag, sizeof(tag) - 1u,
            ciphertext, sizeof(ciphertext), key, sizeof(key),
            nonce, sizeof(nonce), aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_AEAD_ENCRYPT(
            ciphertext, sizeof(ciphertext), tag, sizeof(tag),
            message, sizeof(message), key, sizeof(key) - 1u,
            nonce, sizeof(nonce), aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) != LIBERAC_ERROR_INVALID_KEY ||
        LIBERAC_AEAD_ENCRYPT(
            ciphertext, sizeof(ciphertext), tag, sizeof(tag),
            message, sizeof(message), key, sizeof(key),
            nonce, sizeof(nonce) - 1u, aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) !=
            LIBERAC_ERROR_INVALID_ARGUMENT ||
        LIBERAC_AEAD_ENCRYPT(
            ciphertext, sizeof(ciphertext), tag, sizeof(tag),
            message, sizeof(message), key, sizeof(key), nonce, sizeof(nonce),
            aad, sizeof(aad), LIBERAC_ALG_NONE) !=
            LIBERAC_ERROR_INVALID_ALG_ID) {
        return 1;
    }

    if (LIBERAC_AEAD_ENCRYPT(
            NULL, 0u, tag, sizeof(tag), NULL, 0u,
            key, sizeof(key), nonce, sizeof(nonce), NULL, 0u,
            LIBERAC_ALG_CHACHA20_POLY1305) != LIBERAC_SUCCESS ||
        LIBERAC_AEAD_DECRYPT(
            NULL, 0u, tag, sizeof(tag), NULL, 0u,
            key, sizeof(key), nonce, sizeof(nonce), NULL, 0u,
            LIBERAC_ALG_CHACHA20_POLY1305) != LIBERAC_SUCCESS) {
        return 1;
    }
    return 0;
}

int main(void) {
    if (test_size_queries()) {
        fputs("modern symmetric size-query test failed\n", stderr);
        return 1;
    }
    if (test_chacha20_round_trip()) {
        fputs("ChaCha20 unit test failed\n", stderr);
        return 1;
    }
    if (test_poly1305_api()) {
        fputs("Poly1305 API test failed\n", stderr);
        return 1;
    }
    if (test_aead_round_trip_and_failure()) {
        fputs("ChaCha20-Poly1305 unit test failed\n", stderr);
        return 1;
    }
    puts("modern symmetric unit tests passed");
    return 0;
}
