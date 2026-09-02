/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "LiberaCrypt.h"

#include <stdio.h>
#include <string.h>

static int hex_value(char character, uint8_t *value) {
    if (character >= '0' && character <= '9') {
        *value = (uint8_t)(character - '0');
        return 1;
    }
    if (character >= 'a' && character <= 'f') {
        *value = (uint8_t)(character - 'a' + 10);
        return 1;
    }
    if (character >= 'A' && character <= 'F') {
        *value = (uint8_t)(character - 'A' + 10);
        return 1;
    }
    return 0;
}

static int decode_hex(uint8_t *output, size_t output_length,
                      const char *hex) {
    size_t i;

    if (strlen(hex) != output_length * 2u) return 0;
    for (i = 0u; i < output_length; ++i) {
        uint8_t high;
        uint8_t low;
        if (!hex_value(hex[2u * i], &high) ||
            !hex_value(hex[2u * i + 1u], &low)) {
            return 0;
        }
        output[i] = (uint8_t)((uint8_t)(high << 4) | low);
    }
    return 1;
}

static int test_chacha20_block(void) {
    uint8_t key[LIBERAC_CHACHA20_KEY_BYTES];
    uint8_t nonce[LIBERAC_CHACHA20_NONCE_BYTES];
    uint8_t zero[LIBERAC_CHACHA20_BLOCK_BYTES] = {0};
    uint8_t output[LIBERAC_CHACHA20_BLOCK_BYTES];
    uint8_t expected[LIBERAC_CHACHA20_BLOCK_BYTES];
    size_t i;

    for (i = 0u; i < sizeof(key); ++i) key[i] = (uint8_t)i;
    if (!decode_hex(nonce, sizeof(nonce),
                    "000000090000004a00000000") ||
        !decode_hex(expected, sizeof(expected),
                    "10f1e7e4d13b5915500fdd1fa32071c4"
                    "c7d1f4c733c068030422aa9ac3d46c4e"
                    "d2826446079faa0914c2d705d98b02a2"
                    "b5129cd1de164eb9cbd083e8a2503c4e")) {
        return 1;
    }
    if (LIBERAC_STREAM_CIPHER_XOR(
            output, sizeof(output), zero, sizeof(zero),
            key, sizeof(key), nonce, sizeof(nonce), 1u,
            LIBERAC_ALG_CHACHA20) != LIBERAC_SUCCESS) {
        return 1;
    }
    return memcmp(output, expected, sizeof(expected)) != 0;
}

static int test_chacha20_cipher(void) {
    static const uint8_t plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    uint8_t key[LIBERAC_CHACHA20_KEY_BYTES];
    uint8_t nonce[LIBERAC_CHACHA20_NONCE_BYTES];
    uint8_t output[sizeof(plaintext) - 1u];
    uint8_t recovered[sizeof(plaintext) - 1u];
    uint8_t expected[sizeof(plaintext) - 1u];
    size_t i;

    for (i = 0u; i < sizeof(key); ++i) key[i] = (uint8_t)i;
    if (!decode_hex(nonce, sizeof(nonce),
                    "000000000000004a00000000") ||
        !decode_hex(expected, sizeof(expected),
                    "6e2e359a2568f98041ba0728dd0d6981"
                    "e97e7aec1d4360c20a27afccfd9fae0b"
                    "f91b65c5524733ab8f593dabcd62b357"
                    "1639d624e65152ab8f530c359f0861d8"
                    "07ca0dbf500d6a6156a38e088a22b65e"
                    "52bc514d16ccf806818ce91ab7793736"
                    "5af90bbf74a35be6b40b8eedf2785e42"
                    "874d")) {
        return 1;
    }
    if (LIBERAC_STREAM_CIPHER_XOR(
            output, sizeof(output), plaintext, sizeof(plaintext) - 1u,
            key, sizeof(key), nonce, sizeof(nonce), 1u,
            LIBERAC_ALG_CHACHA20) != LIBERAC_SUCCESS ||
        memcmp(output, expected, sizeof(expected)) != 0) {
        return 1;
    }
    if (LIBERAC_STREAM_CIPHER_XOR(
            recovered, sizeof(recovered), output, sizeof(output),
            key, sizeof(key), nonce, sizeof(nonce), 1u,
            LIBERAC_ALG_CHACHA20) != LIBERAC_SUCCESS) {
        return 1;
    }
    return memcmp(recovered, plaintext, sizeof(recovered)) != 0;
}

static int poly1305_vector(const char *key_hex, const char *message_hex,
                           const char *tag_hex) {
    uint8_t key[LIBERAC_POLY1305_KEY_BYTES];
    uint8_t message[128];
    uint8_t expected[LIBERAC_POLY1305_TAG_BYTES];
    uint8_t tag[LIBERAC_POLY1305_TAG_BYTES];
    size_t message_length = strlen(message_hex) / 2u;

    if (message_length > sizeof(message) ||
        !decode_hex(key, sizeof(key), key_hex) ||
        !decode_hex(message, message_length, message_hex) ||
        !decode_hex(expected, sizeof(expected), tag_hex)) {
        return 1;
    }
    if (LIBERAC_POLY1305(
            tag, sizeof(tag), message, message_length,
            key, sizeof(key), LIBERAC_ALG_POLY1305) != LIBERAC_SUCCESS) {
        return 1;
    }
    return memcmp(tag, expected, sizeof(tag)) != 0;
}

static int test_poly1305(void) {
    static const uint8_t message[] = "Cryptographic Forum Research Group";
    uint8_t key[LIBERAC_POLY1305_KEY_BYTES];
    uint8_t expected[LIBERAC_POLY1305_TAG_BYTES];
    uint8_t tag[LIBERAC_POLY1305_TAG_BYTES];

    if (!decode_hex(key, sizeof(key),
                    "85d6be7857556d337f4452fe42d506a8"
                    "0103808afb0db2fd4abff6af4149f51b") ||
        !decode_hex(expected, sizeof(expected),
                    "a8061dc1305136c6c22b8baf0c0127a9")) {
        return 1;
    }
    if (LIBERAC_POLY1305(
            tag, sizeof(tag), message, sizeof(message) - 1u,
            key, sizeof(key), LIBERAC_ALG_POLY1305) != LIBERAC_SUCCESS ||
        memcmp(tag, expected, sizeof(tag)) != 0) {
        return 1;
    }

    /* RFC 8439 Appendix A.3 vectors exercise final reduction and carries. */
    if (poly1305_vector(
            "02000000000000000000000000000000"
            "00000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff",
            "03000000000000000000000000000000") ||
        poly1305_vector(
            "02000000000000000000000000000000"
            "ffffffffffffffffffffffffffffffff",
            "02000000000000000000000000000000",
            "03000000000000000000000000000000") ||
        poly1305_vector(
            "01000000000000000000000000000000"
            "00000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff"
            "f0ffffffffffffffffffffffffffffff"
            "11000000000000000000000000000000",
            "05000000000000000000000000000000") ||
        poly1305_vector(
            "01000000000000000000000000000000"
            "00000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff"
            "fbfefefefefefefefefefefefefefefe"
            "01010101010101010101010101010101",
            "00000000000000000000000000000000") ||
        poly1305_vector(
            "02000000000000000000000000000000"
            "00000000000000000000000000000000",
            "fdffffffffffffffffffffffffffffff",
            "faffffffffffffffffffffffffffffff")) {
        return 1;
    }
    return 0;
}

static int test_chacha20_poly1305(void) {
    static const uint8_t plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    uint8_t key[LIBERAC_CHACHA20_POLY1305_KEY_BYTES];
    uint8_t nonce[LIBERAC_CHACHA20_POLY1305_NONCE_BYTES];
    uint8_t aad[12];
    uint8_t expected_ciphertext[sizeof(plaintext) - 1u];
    uint8_t expected_tag[LIBERAC_CHACHA20_POLY1305_TAG_BYTES];
    uint8_t ciphertext[sizeof(plaintext) - 1u];
    uint8_t recovered[sizeof(plaintext) - 1u];
    uint8_t tag[LIBERAC_CHACHA20_POLY1305_TAG_BYTES];
    size_t i;

    for (i = 0u; i < sizeof(key); ++i) key[i] = (uint8_t)(0x80u + i);
    if (!decode_hex(nonce, sizeof(nonce),
                    "070000004041424344454647") ||
        !decode_hex(aad, sizeof(aad),
                    "50515253c0c1c2c3c4c5c6c7") ||
        !decode_hex(expected_ciphertext, sizeof(expected_ciphertext),
                    "d31a8d34648e60db7b86afbc53ef7ec2"
                    "a4aded51296e08fea9e2b5a736ee62d6"
                    "3dbea45e8ca9671282fafb69da92728b"
                    "1a71de0a9e060b2905d6a5b67ecd3b36"
                    "92ddbd7f2d778b8c9803aee328091b58"
                    "fab324e4fad675945585808b4831d7bc"
                    "3ff4def08e4b7a9de576d26586cec64b"
                    "6116") ||
        !decode_hex(expected_tag, sizeof(expected_tag),
                    "1ae10b594f09e26a7e902ecbd0600691")) {
        return 1;
    }

    if (LIBERAC_AEAD_ENCRYPT(
            ciphertext, sizeof(ciphertext), tag, sizeof(tag),
            plaintext, sizeof(plaintext) - 1u, key, sizeof(key),
            nonce, sizeof(nonce), aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) != LIBERAC_SUCCESS ||
        memcmp(ciphertext, expected_ciphertext, sizeof(ciphertext)) != 0 ||
        memcmp(tag, expected_tag, sizeof(tag)) != 0) {
        return 1;
    }
    if (LIBERAC_AEAD_DECRYPT(
            recovered, sizeof(recovered), tag, sizeof(tag),
            ciphertext, sizeof(ciphertext), key, sizeof(key),
            nonce, sizeof(nonce), aad, sizeof(aad),
            LIBERAC_ALG_CHACHA20_POLY1305) != LIBERAC_SUCCESS) {
        return 1;
    }
    return memcmp(recovered, plaintext, sizeof(recovered)) != 0;
}

int main(void) {
    if (test_chacha20_block()) {
        fputs("RFC 8439 ChaCha20 block KAT failed\n", stderr);
        return 1;
    }
    if (test_chacha20_cipher()) {
        fputs("RFC 8439 ChaCha20 cipher KAT failed\n", stderr);
        return 1;
    }
    if (test_poly1305()) {
        fputs("RFC 8439 Poly1305 KAT failed\n", stderr);
        return 1;
    }
    if (test_chacha20_poly1305()) {
        fputs("RFC 8439 ChaCha20-Poly1305 KAT failed\n", stderr);
        return 1;
    }
    puts("RFC 8439 modern symmetric KATs passed");
    return 0;
}
