/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdio.h>
#include <string.h>

#include "DigitalSignature.h"
#include "HashFunction.h"

#define ECDSA_MAX_PRIVATE_BYTES 66u
#define ECDSA_MAX_PUBLIC_BYTES 133u
#define ECDSA_MAX_SIGNATURE_BYTES 132u

typedef struct {
    const char *name;
    LiberaCAlgID algorithm;
    LiberaCAlgID hash_algorithm;
    size_t private_bytes;
    size_t public_bytes;
    size_t signature_bytes;
} EcdsaCase;

static const EcdsaCase CASES[] = {
    {
        "P-256/SHA3-256", LIBERAC_ALG_ECDSA_P256,
        LIBERAC_ALG_HASH_SHA3_256,
        LIBERAC_ECDSA_P256_PRIVATE_KEY_BYTES,
        LIBERAC_ECDSA_P256_PUBLIC_KEY_BYTES,
        LIBERAC_ECDSA_P256_SIGNATURE_BYTES
    },
    {
        "P-384/SHA3-384", LIBERAC_ALG_ECDSA_P384,
        LIBERAC_ALG_HASH_SHA3_384,
        LIBERAC_ECDSA_P384_PRIVATE_KEY_BYTES,
        LIBERAC_ECDSA_P384_PUBLIC_KEY_BYTES,
        LIBERAC_ECDSA_P384_SIGNATURE_BYTES
    },
    {
        "P-521/SHA3-512", LIBERAC_ALG_ECDSA_P521,
        LIBERAC_ALG_HASH_SHA3_512,
        LIBERAC_ECDSA_P521_PRIVATE_KEY_BYTES,
        LIBERAC_ECDSA_P521_PUBLIC_KEY_BYTES,
        LIBERAC_ECDSA_P521_SIGNATURE_BYTES
    }
};

static int fail(const EcdsaCase *test_case, const char *stage) {
    fprintf(stderr, "ECDSA unit failure: %s stage=%s\n",
            test_case->name, stage);
    return 0;
}

static int test_case(const EcdsaCase *test_case) {
    static const uint8_t message[] = "LiberaCrypt deterministic ECDSA";
    uint8_t private_key[ECDSA_MAX_PRIVATE_BYTES];
    uint8_t public_key[ECDSA_MAX_PUBLIC_BYTES];
    uint8_t derived_public[ECDSA_MAX_PUBLIC_BYTES];
    uint8_t signature[ECDSA_MAX_SIGNATURE_BYTES];
    uint8_t second_signature[ECDSA_MAX_SIGNATURE_BYTES];
    uint8_t tampered_message[sizeof(message)];
    uint8_t tampered_public[ECDSA_MAX_PUBLIC_BYTES];
    uint8_t tampered_signature[ECDSA_MAX_SIGNATURE_BYTES];
    LiberaCError error;

    memset(private_key, 0, sizeof(private_key));
    memset(public_key, 0, sizeof(public_key));
    memset(derived_public, 0, sizeof(derived_public));
    memset(signature, 0, sizeof(signature));
    memset(second_signature, 0, sizeof(second_signature));

    if (LIBERAC_ECDSA_PRIVATE_KEY_SIZE(test_case->algorithm) !=
            test_case->private_bytes ||
        LIBERAC_ECDSA_PUBLIC_KEY_SIZE(test_case->algorithm) !=
            test_case->public_bytes ||
        LIBERAC_ECDSA_SIGNATURE_SIZE(test_case->algorithm) !=
            test_case->signature_bytes) {
        return fail(test_case, "size constants");
    }
    if (LIBERAC_ECDSA_KEYGEN(
            public_key, test_case->public_bytes,
            private_key, test_case->private_bytes,
            test_case->algorithm) != LIBERAC_SUCCESS) {
        return fail(test_case, "key generation");
    }
    if (LIBERAC_ECDSA_PUBLIC_FROM_PRIVATE(
            derived_public, test_case->public_bytes,
            private_key, test_case->private_bytes,
            test_case->algorithm) != LIBERAC_SUCCESS ||
        memcmp(public_key, derived_public, test_case->public_bytes) != 0) {
        return fail(test_case, "public derivation");
    }
    if (LIBERAC_ECDSA_SIGN(
            private_key, test_case->private_bytes,
            message, sizeof(message) - 1u,
            signature, test_case->signature_bytes,
            test_case->hash_algorithm,
            test_case->algorithm) != LIBERAC_SUCCESS ||
        LIBERAC_ECDSA_SIGN(
            private_key, test_case->private_bytes,
            message, sizeof(message) - 1u,
            second_signature, test_case->signature_bytes,
            test_case->hash_algorithm,
            test_case->algorithm) != LIBERAC_SUCCESS ||
        memcmp(signature, second_signature,
               test_case->signature_bytes) != 0) {
        return fail(test_case, "deterministic signing");
    }
    if (LIBERAC_ECDSA_VERIFY(
            public_key, test_case->public_bytes,
            message, sizeof(message) - 1u,
            signature, test_case->signature_bytes,
            test_case->hash_algorithm,
            test_case->algorithm) != LIBERAC_SUCCESS) {
        return fail(test_case, "verification");
    }

    memcpy(tampered_message, message, sizeof(message));
    tampered_message[0] ^= UINT8_C(0x01);
    if (LIBERAC_ECDSA_VERIFY(
            public_key, test_case->public_bytes,
            tampered_message, sizeof(message) - 1u,
            signature, test_case->signature_bytes,
            test_case->hash_algorithm,
            test_case->algorithm) != LIBERAC_ERROR_SIGNATURE_INVALID) {
        return fail(test_case, "tampered message rejection");
    }

    memcpy(tampered_signature, signature, test_case->signature_bytes);
    tampered_signature[test_case->signature_bytes - 1u] ^= UINT8_C(0x01);
    if (LIBERAC_ECDSA_VERIFY(
            public_key, test_case->public_bytes,
            message, sizeof(message) - 1u,
            tampered_signature, test_case->signature_bytes,
            test_case->hash_algorithm,
            test_case->algorithm) != LIBERAC_ERROR_SIGNATURE_INVALID) {
        return fail(test_case, "tampered signature rejection");
    }
    memset(tampered_signature, 0, test_case->signature_bytes);
    if (LIBERAC_ECDSA_VERIFY(
            public_key, test_case->public_bytes,
            message, sizeof(message) - 1u,
            tampered_signature, test_case->signature_bytes,
            test_case->hash_algorithm,
            test_case->algorithm) != LIBERAC_ERROR_SIGNATURE_INVALID) {
        return fail(test_case, "zero signature rejection");
    }

    memcpy(tampered_public, public_key, test_case->public_bytes);
    tampered_public[0] = UINT8_C(0x05);
    if (LIBERAC_ECDSA_VERIFY(
            tampered_public, test_case->public_bytes,
            message, sizeof(message) - 1u,
            signature, test_case->signature_bytes,
            test_case->hash_algorithm,
            test_case->algorithm) != LIBERAC_ERROR_INVALID_KEY) {
        return fail(test_case, "malformed public key rejection");
    }

    error = LIBERAC_ECDSA_SIGN(
        private_key, test_case->private_bytes,
        message, sizeof(message) - 1u,
        second_signature, test_case->signature_bytes - 1u,
        test_case->hash_algorithm, test_case->algorithm);
    if (error != LIBERAC_ERROR_BUFFER_TOO_SMALL) {
        return fail(test_case, "small signature buffer");
    }
    error = LIBERAC_ECDSA_VERIFY(
        public_key, test_case->public_bytes,
        message, sizeof(message) - 1u,
        signature, test_case->signature_bytes - 1u,
        test_case->hash_algorithm, test_case->algorithm);
    if (error != LIBERAC_ERROR_SIGNATURE_INVALID) {
        return fail(test_case, "truncated signature rejection");
    }

    memset(second_signature, UINT8_C(0xa5), test_case->signature_bytes);
    memset(derived_public, 0, test_case->private_bytes);
    error = LIBERAC_ECDSA_SIGN(
        derived_public, test_case->private_bytes,
        message, sizeof(message) - 1u,
        second_signature, test_case->signature_bytes,
        test_case->hash_algorithm, test_case->algorithm);
    if (error != LIBERAC_ERROR_INVALID_KEY) {
        return fail(test_case, "zero private key rejection");
    }
    {
        size_t index;
        for (index = 0u; index < test_case->signature_bytes; ++index) {
            if (second_signature[index] != 0u) {
                return fail(test_case, "failed signature clearing");
            }
        }
    }

    return 1;
}

static int test_invalid_api_inputs(void) {
    uint8_t buffer[ECDSA_MAX_PUBLIC_BYTES + ECDSA_MAX_PRIVATE_BYTES];
    uint8_t signature[ECDSA_MAX_SIGNATURE_BYTES];
    uint8_t message = UINT8_C(0x42);

    memset(buffer, 0, sizeof(buffer));
    memset(signature, 0, sizeof(signature));
    if (LIBERAC_ECDSA_PRIVATE_KEY_SIZE(LIBERAC_ALG_NONE) != 0u ||
        LIBERAC_ECDSA_PUBLIC_KEY_SIZE(LIBERAC_ALG_NONE) != 0u ||
        LIBERAC_ECDSA_SIGNATURE_SIZE(LIBERAC_ALG_NONE) != 0u) {
        return 0;
    }
    if (LIBERAC_ECDSA_KEYGEN(
            buffer, LIBERAC_ECDSA_P256_PUBLIC_KEY_BYTES,
            buffer + 1u, LIBERAC_ECDSA_P256_PRIVATE_KEY_BYTES,
            LIBERAC_ALG_ECDSA_P256) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 0;
    }
    if (LIBERAC_ECDSA_SIGN(
            buffer, LIBERAC_ECDSA_P384_PRIVATE_KEY_BYTES,
            &message, 1u, signature, LIBERAC_ECDSA_P384_SIGNATURE_BYTES,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_ECDSA_P384) != LIBERAC_ERROR_INVALID_ALG_ID) {
        return 0;
    }
    if (LIBERAC_ECDSA_SIGN(
            buffer, LIBERAC_ECDSA_P521_PRIVATE_KEY_BYTES,
            &message, 1u, signature, LIBERAC_ECDSA_P521_SIGNATURE_BYTES,
            LIBERAC_ALG_HASH_SHA2_384,
            LIBERAC_ALG_ECDSA_P521) != LIBERAC_ERROR_INVALID_ALG_ID) {
        return 0;
    }
    if (LIBERAC_ECDSA_SIGN(
            buffer, LIBERAC_ECDSA_P256_PRIVATE_KEY_BYTES,
            NULL, 1u, signature, LIBERAC_ECDSA_P256_SIGNATURE_BYTES,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_ECDSA_P256) != LIBERAC_ERROR_INVALID_ARGUMENT) {
        return 0;
    }
    return 1;
}

int main(void) {
    size_t index;

    for (index = 0u; index < sizeof(CASES) / sizeof(CASES[0]); ++index) {
        if (!test_case(&CASES[index])) {
            return 1;
        }
    }
    if (!test_invalid_api_inputs()) {
        fputs("ECDSA unit failure: invalid API input handling\n", stderr);
        return 1;
    }
    puts("ECDSA unit test passed");
    return 0;
}
