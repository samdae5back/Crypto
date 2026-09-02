/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "DigitalSignature.h"

#include <stdio.h>
#include <string.h>

typedef struct Ed25519Kat {
    const char *seed;
    const char *public_key;
    const char *message;
    const char *signature;
} Ed25519Kat;

static int hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static int decode_hex(uint8_t *output, size_t output_length,
                      const char *hex) {
    size_t i;
    if (hex == NULL || strlen(hex) != 2u * output_length) {
        return 0;
    }
    for (i = 0u; i < output_length; ++i) {
        const int high = hex_nibble(hex[2u * i]);
        const int low = hex_nibble(hex[2u * i + 1u]);
        if (high < 0 || low < 0) {
            return 0;
        }
        output[i] = (uint8_t)(((unsigned)high << 4) | (unsigned)low);
    }
    return 1;
}

static int run_vector(const Ed25519Kat *vector, size_t index) {
    uint8_t seed[LIBERAC_ED25519_PRIVATE_KEY_BYTES];
    uint8_t expected_public[LIBERAC_ED25519_PUBLIC_KEY_BYTES];
    uint8_t derived_public[LIBERAC_ED25519_PUBLIC_KEY_BYTES];
    uint8_t message[2];
    uint8_t expected_signature[LIBERAC_ED25519_SIGNATURE_BYTES];
    uint8_t signature[LIBERAC_ED25519_SIGNATURE_BYTES];
    const size_t message_length = strlen(vector->message) / 2u;
    LiberaCError error;

    if (message_length > sizeof(message) ||
        !decode_hex(seed, sizeof(seed), vector->seed) ||
        !decode_hex(expected_public, sizeof(expected_public),
                    vector->public_key) ||
        !decode_hex(message, message_length, vector->message) ||
        !decode_hex(expected_signature, sizeof(expected_signature),
                    vector->signature)) {
        fprintf(stderr, "Ed25519 vector %zu has invalid test data\n", index);
        return 0;
    }

    error = LIBERAC_ED25519_PUBLIC_FROM_PRIVATE(
        derived_public, sizeof(derived_public), seed, sizeof(seed),
        LIBERAC_ALG_ED25519);
    if (error != LIBERAC_SUCCESS ||
        memcmp(derived_public, expected_public, sizeof(derived_public)) != 0) {
        fprintf(stderr, "Ed25519 vector %zu public key mismatch (%d)\n",
                index, (int)error);
        return 0;
    }
    error = LIBERAC_ED25519_SIGN(
        seed, sizeof(seed), message_length != 0u ? message : NULL,
        message_length, signature, sizeof(signature), LIBERAC_ALG_ED25519);
    if (error != LIBERAC_SUCCESS ||
        memcmp(signature, expected_signature, sizeof(signature)) != 0) {
        fprintf(stderr, "Ed25519 vector %zu signature mismatch (%d)\n",
                index, (int)error);
        return 0;
    }
    error = LIBERAC_ED25519_VERIFY(
        expected_public, sizeof(expected_public),
        message_length != 0u ? message : NULL, message_length,
        expected_signature, sizeof(expected_signature),
        LIBERAC_ALG_ED25519);
    if (error != LIBERAC_SUCCESS) {
        fprintf(stderr, "Ed25519 vector %zu verification failed (%d)\n",
                index, (int)error);
        return 0;
    }
    return 1;
}

int main(void) {
    static const Ed25519Kat vectors[] = {
        {
            "9d61b19deffd5a60ba844af492ec2cc4"
            "4449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073"
            "a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"
        },
        {
            "4ccd089b28ff96da9db6c346ec114e0f"
            "5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc"
            "9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540"
            "a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8"
            "c387b2eaeb4302aeeb00d291612bb0c00"
        },
        {
            "c5aa8df43f9f837bedb7442f31dcb7b1"
            "66d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f058"
            "0816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a3"
            "0ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc659"
            "4a7c15e9716ed28dc027beceea1ec40a"
        }
    };
    size_t i;

    for (i = 0u; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        if (!run_vector(&vectors[i], i + 1u)) {
            return 1;
        }
    }
    puts("Ed25519 RFC 8032 known-answer tests passed");
    return 0;
}
