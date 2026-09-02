/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "DigitalSignature.h"

#include <stdio.h>
#include <string.h>

static int require_error(LiberaCError actual, LiberaCError expected,
                         const char *label) {
    if (actual != expected) {
        fprintf(stderr, "%s: expected %d, got %d\n",
                label, (int)expected, (int)actual);
        return 0;
    }
    return 1;
}

int main(void) {
    static const uint8_t scalar_l[LIBERAC_ED25519_PRIVATE_KEY_BYTES] = {
        0xedu, 0xd3u, 0xf5u, 0x5cu, 0x1au, 0x63u, 0x12u, 0x58u,
        0xd6u, 0x9cu, 0xf7u, 0xa2u, 0xdeu, 0xf9u, 0xdeu, 0x14u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x10u
    };
    uint8_t public_key[LIBERAC_ED25519_PUBLIC_KEY_BYTES];
    uint8_t derived_public[LIBERAC_ED25519_PUBLIC_KEY_BYTES];
    uint8_t private_key[LIBERAC_ED25519_PRIVATE_KEY_BYTES];
    uint8_t signature[LIBERAC_ED25519_SIGNATURE_BYTES];
    uint8_t second_signature[LIBERAC_ED25519_SIGNATURE_BYTES];
    uint8_t malformed[LIBERAC_ED25519_SIGNATURE_BYTES];
    uint8_t identity[LIBERAC_ED25519_PUBLIC_KEY_BYTES] = { 1u };
    uint8_t noncanonical[LIBERAC_ED25519_PUBLIC_KEY_BYTES];
    uint8_t overlap[96];
    uint8_t message[] = { 0x00u, 0x01u, 0x7fu, 0x80u, 0xffu };
    LiberaCError error;
    size_t i;

    if (LIBERAC_ED25519_PRIVATE_KEY_SIZE(LIBERAC_ALG_ED25519) !=
            LIBERAC_ED25519_PRIVATE_KEY_BYTES ||
        LIBERAC_ED25519_PUBLIC_KEY_SIZE(LIBERAC_ALG_ED25519) !=
            LIBERAC_ED25519_PUBLIC_KEY_BYTES ||
        LIBERAC_ED25519_SIGNATURE_SIZE(LIBERAC_ALG_ED25519) !=
            LIBERAC_ED25519_SIGNATURE_BYTES ||
        LIBERAC_ED25519_PRIVATE_KEY_SIZE(LIBERAC_ALG_ECDSA_P256) != 0u ||
        LIBERAC_ED25519_PUBLIC_KEY_SIZE(LIBERAC_ALG_ECDSA_P256) != 0u ||
        LIBERAC_ED25519_SIGNATURE_SIZE(LIBERAC_ALG_ECDSA_P256) != 0u) {
        fputs("Ed25519 size queries failed\n", stderr);
        return 1;
    }

    error = LIBERAC_ED25519_KEYGEN(
        public_key, sizeof(public_key), private_key, sizeof(private_key),
        LIBERAC_ALG_ED25519);
    if (!require_error(error, LIBERAC_SUCCESS, "keygen")) {
        return 1;
    }
    error = LIBERAC_ED25519_PUBLIC_FROM_PRIVATE(
        derived_public, sizeof(derived_public), private_key,
        sizeof(private_key), LIBERAC_ALG_ED25519);
    if (!require_error(error, LIBERAC_SUCCESS, "public derivation") ||
        memcmp(public_key, derived_public, sizeof(public_key)) != 0) {
        fputs("Ed25519 derived public key mismatch\n", stderr);
        return 1;
    }
    error = LIBERAC_ED25519_SIGN(
        private_key, sizeof(private_key), message, sizeof(message),
        signature, sizeof(signature), LIBERAC_ALG_ED25519);
    if (!require_error(error, LIBERAC_SUCCESS, "sign")) {
        return 1;
    }
    error = LIBERAC_ED25519_SIGN(
        private_key, sizeof(private_key), message, sizeof(message),
        second_signature, sizeof(second_signature), LIBERAC_ALG_ED25519);
    if (!require_error(error, LIBERAC_SUCCESS, "repeat sign") ||
        memcmp(signature, second_signature, sizeof(signature)) != 0) {
        fputs("Ed25519 signing is not deterministic\n", stderr);
        return 1;
    }
    error = LIBERAC_ED25519_VERIFY(
        public_key, sizeof(public_key), message, sizeof(message),
        signature, sizeof(signature), LIBERAC_ALG_ED25519);
    if (!require_error(error, LIBERAC_SUCCESS, "verify")) {
        return 1;
    }
    error = LIBERAC_ED25519_SIGN(
        private_key, sizeof(private_key), NULL, 0u,
        second_signature, sizeof(second_signature), LIBERAC_ALG_ED25519);
    if (!require_error(error, LIBERAC_SUCCESS, "empty-message sign")) {
        return 1;
    }
    error = LIBERAC_ED25519_VERIFY(
        public_key, sizeof(public_key), NULL, 0u,
        second_signature, sizeof(second_signature), LIBERAC_ALG_ED25519);
    if (!require_error(error, LIBERAC_SUCCESS, "empty-message verify")) {
        return 1;
    }

    memcpy(malformed, signature, sizeof(malformed));
    malformed[0] ^= UINT8_C(1);
    if (!require_error(LIBERAC_ED25519_VERIFY(
            public_key, sizeof(public_key), message, sizeof(message),
            malformed, sizeof(malformed), LIBERAC_ALG_ED25519),
            LIBERAC_ERROR_SIGNATURE_INVALID, "tampered R")) {
        return 1;
    }
    memcpy(malformed, signature, sizeof(malformed));
    memcpy(malformed + LIBERAC_ED25519_PRIVATE_KEY_BYTES,
           scalar_l, sizeof(scalar_l));
    if (!require_error(LIBERAC_ED25519_VERIFY(
            public_key, sizeof(public_key), message, sizeof(message),
            malformed, sizeof(malformed), LIBERAC_ALG_ED25519),
            LIBERAC_ERROR_SIGNATURE_INVALID, "non-canonical S")) {
        return 1;
    }
    if (!require_error(LIBERAC_ED25519_VERIFY(
            identity, sizeof(identity), message, sizeof(message),
            signature, sizeof(signature), LIBERAC_ALG_ED25519),
            LIBERAC_ERROR_INVALID_KEY, "identity public key")) {
        return 1;
    }
    noncanonical[0] = UINT8_C(0xed);
    for (i = 1u; i + 1u < sizeof(noncanonical); ++i) {
        noncanonical[i] = UINT8_C(0xff);
    }
    noncanonical[31] = UINT8_C(0x7f);
    if (!require_error(LIBERAC_ED25519_VERIFY(
            noncanonical, sizeof(noncanonical), message, sizeof(message),
            signature, sizeof(signature), LIBERAC_ALG_ED25519),
            LIBERAC_ERROR_INVALID_KEY, "non-canonical public key")) {
        return 1;
    }
    memcpy(malformed, signature, sizeof(malformed));
    memcpy(malformed, noncanonical, sizeof(noncanonical));
    if (!require_error(LIBERAC_ED25519_VERIFY(
            public_key, sizeof(public_key), message, sizeof(message),
            malformed, sizeof(malformed), LIBERAC_ALG_ED25519),
            LIBERAC_ERROR_SIGNATURE_INVALID, "non-canonical R")) {
        return 1;
    }

    memset(overlap, 0x5a, sizeof(overlap));
    if (!require_error(LIBERAC_ED25519_KEYGEN(
            overlap, LIBERAC_ED25519_PUBLIC_KEY_BYTES,
            overlap + 16u, LIBERAC_ED25519_PRIVATE_KEY_BYTES,
            LIBERAC_ALG_ED25519), LIBERAC_ERROR_INVALID_ARGUMENT,
            "overlapping keygen outputs") ||
        !require_error(LIBERAC_ED25519_PUBLIC_FROM_PRIVATE(
            overlap + 16u, LIBERAC_ED25519_PUBLIC_KEY_BYTES,
            overlap, LIBERAC_ED25519_PRIVATE_KEY_BYTES,
            LIBERAC_ALG_ED25519), LIBERAC_ERROR_INVALID_ARGUMENT,
            "overlapping public derivation") ||
        !require_error(LIBERAC_ED25519_SIGN(
            overlap, LIBERAC_ED25519_PRIVATE_KEY_BYTES, message,
            sizeof(message), overlap + 16u,
            LIBERAC_ED25519_SIGNATURE_BYTES, LIBERAC_ALG_ED25519),
            LIBERAC_ERROR_INVALID_ARGUMENT, "overlapping signature")) {
        return 1;
    }

    if (!require_error(LIBERAC_ED25519_KEYGEN(
            public_key, sizeof(public_key), private_key, sizeof(private_key),
            LIBERAC_ALG_ECDSA_P256), LIBERAC_ERROR_INVALID_ALG_ID,
            "invalid keygen algorithm") ||
        !require_error(LIBERAC_ED25519_PUBLIC_FROM_PRIVATE(
            derived_public, sizeof(derived_public), private_key,
            sizeof(private_key) - 1u, LIBERAC_ALG_ED25519),
            LIBERAC_ERROR_INVALID_KEY, "short private seed") ||
        !require_error(LIBERAC_ED25519_SIGN(
            private_key, sizeof(private_key), NULL, 1u,
            signature, sizeof(signature), LIBERAC_ALG_ED25519),
            LIBERAC_ERROR_INVALID_ARGUMENT, "null message") ||
        !require_error(LIBERAC_ED25519_SIGN(
            private_key, sizeof(private_key), message, sizeof(message),
            signature, sizeof(signature) - 1u, LIBERAC_ALG_ED25519),
            LIBERAC_ERROR_BUFFER_TOO_SMALL, "short signature output") ||
        !require_error(LIBERAC_ED25519_VERIFY(
            public_key, sizeof(public_key) - 1u, message, sizeof(message),
            signature, sizeof(signature), LIBERAC_ALG_ED25519),
            LIBERAC_ERROR_INVALID_KEY, "short public key") ||
        !require_error(LIBERAC_ED25519_VERIFY(
            public_key, sizeof(public_key), message, sizeof(message),
            signature, sizeof(signature) - 1u, LIBERAC_ALG_ED25519),
            LIBERAC_ERROR_SIGNATURE_INVALID, "short signature input")) {
        return 1;
    }

    puts("Ed25519 unit tests passed");
    return 0;
}
