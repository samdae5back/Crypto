/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "LiberaCrypt.h"

#include <stdio.h>
#include <string.h>

#define RSA_TEST_BYTES 256u
#define RSA_TEST_OAEP_MAX 190u

static const char RSA_N_HEX[] =
    "a4dc4da8dbbe597d03ccbf6aa2eabf41f7734452d1b7e42aaa17db6f75d811a6"
    "5a3b655b1483b91720be7f79b580af11c922245aa5dcde296f5ac7b4f36d2672"
    "39efedb923c4a9f05649c395b1bd926c232f9cbc8d697bea191dfa3c4edf9e2c"
    "65a28eeed41026e2693708981fa35377098ab505b01f2cb15b7598e16d367860"
    "bc80be40a6de42a2bc7d0eeb56eaec13af4ac87ffb2fff11b95ccf1e1c8b5b39"
    "9a422907dafb5c37dbf96d7b86d330dae2edcb1d1d0c8051cd305d5d7d8abe42"
    "a7cb1ac794854b7909605ff11ed13ca4d79d6c90a2f734f0c1c14ab5ad1750f0"
    "edc22b602b91cd7b061fb13b9900ec212fb36c2659e30b7abe49355436d5eb75";

static const char RSA_D_HEX[] =
    "1f416933cf5d7a47da559220dc7c570061b2a7cc6fd84658d460ab88a935eaba"
    "b836b4939d03102f5354ea841fa6230ae33026e64cb5e024c8e8d41df95cc342"
    "3abbc33d2b8bd890293bd8e9e385c661dc15e5c855a31f0c15f0fa053f0ae449"
    "1487ca437b4f08a03a4465cbb98bd48227fbf52ffbe11d2f0ee0efb825658352"
    "bdd604949446679f2b75ab303cb9421a321e94bc010733b579cfafbd73cac184"
    "e4d11ac19f4fa4dc04946f02d2d03b55576c3a087dfec1e3d6f1b5b31ddbed39"
    "4b9792b3f1682f24c8a49698a7253808b5609d523dd6ae7fe5bac2d33cea6c46"
    "f404440e8b3601f8c7ae7a3af52db5b55489d8598ec8336c5bbaa0b04d579821";

static const char OAEP_CIPHERTEXT_HEX[] =
    "523b65f569e7ff65adcbda256081b079ed5c431e3000ee865923042b0bd3f9d4"
    "f394a565354b5950f951fd0f588c0cb8b0569f2ad5117a577c24cc75327e86c2"
    "6c5c3cff83b625382dd8f77cfbf6551221ebf120cc89ea2167c8bfd08c722430"
    "c5196967b6448991eb25df519524fa9c36deb23eccf7c4d7ab482d5cefd7b1ac"
    "39effbfeb9ddcf1bbbf9d667fe4afbc9809aafc28a5a8022946f3e30464abff3"
    "55838ca73df37b1f820627513aa820a9ce242d270cd205f3f1447279a40eb13c"
    "a44fa73af5d2f10c9fc3cc7cc6dddb6cd0f988c33909862258b59ac03c1231d7"
    "5bc93abacb3e28bfc18ef5e5e3ab848477a7bf92421bcaf28624fbee977ace65";

static const char PSS_SIGNATURE_HEX[] =
    "745d4f5e2216343739c05ecbd8959ab68cd024781009f5508e3164cf7741c608"
    "d327f3a0cc5552d4a7e404e04e1f8dc424b9e6b5fc705f991fd3b5e2f8403a81"
    "454967ac3b4e94a0d3adc12e18c305fcb4e85f7cdb12d197cb0686f46a13d754"
    "8971aac6790b4c711eb950a0849807fbc87ce9f1a4ccca970d57b941c5452bd3"
    "8ec6485f79c571d337bc6d688c9544aa2b63e793b67a03a77da0f12e58710534"
    "0b88101c6b4cf0553681560e9799ec50bd628afabdb4536771a31c016b97bc71"
    "24d5a1b94165bc65d5517473c37182358e65d59c1fa2860bed2fbcbcf2448ed5"
    "d56de625008233d2050a4a2b96286b23590419207fce274953886cfc3164d588";

static const uint8_t OAEP_MESSAGE[] =
    "LiberaCrypt RSA-OAEP interoperability";
static const uint8_t PSS_MESSAGE[] =
    "LiberaCrypt RSA-PSS interoperability";
static const uint8_t ROUND_TRIP_MESSAGE[] =
    "OAEP round trip with a non-empty label";
static const uint8_t ROUND_TRIP_LABEL[] =
    "liberacrypt-test-label";

static int hex_nibble(char value) {
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

static int decode_hex(uint8_t *output, size_t output_length,
                      const char *hex) {
    size_t i;
    if (!output || !hex || strlen(hex) != 2u * output_length)
        return 0;
    for (i = 0u; i < output_length; ++i) {
        int high = hex_nibble(hex[2u * i]);
        int low = hex_nibble(hex[2u * i + 1u]);
        if (high < 0 || low < 0)
            return 0;
        output[i] = (uint8_t)(((unsigned)high << 4) | (unsigned)low);
    }
    return 1;
}

static int load_test_key(LiberaCRsaPublicKey *public_key,
                         LiberaCRsaPrivateKey *private_key) {
    static const uint8_t exponent[] = {1u, 0u, 1u};
    uint8_t bytes[RSA_TEST_BYTES];
    LiberaCError error;

    if (!decode_hex(bytes, sizeof(bytes), RSA_N_HEX))
        return 0;
    error = LIBERAC_BIGNUM_FROM_BYTES_BE(
        &public_key->N, bytes, sizeof(bytes));
    if (error == LIBERAC_SUCCESS)
        error = LIBERAC_BIGNUM_FROM_BYTES_BE(
            &private_key->N, bytes, sizeof(bytes));
    if (error == LIBERAC_SUCCESS)
        error = LIBERAC_BIGNUM_FROM_BYTES_BE(
            &public_key->E, exponent, sizeof(exponent));
    if (!decode_hex(bytes, sizeof(bytes), RSA_D_HEX))
        error = LIBERAC_ERROR_INTERNAL;
    if (error == LIBERAC_SUCCESS)
        error = LIBERAC_BIGNUM_FROM_BYTES_BE(
            &private_key->D, bytes, sizeof(bytes));
    memset(bytes, 0, sizeof(bytes));
    return error == LIBERAC_SUCCESS;
}

static int all_zero(const uint8_t *bytes, size_t length) {
    size_t i;
    uint8_t aggregate = 0u;
    for (i = 0u; i < length; ++i)
        aggregate |= bytes[i];
    return aggregate == 0u;
}

static int test_interoperability_vectors(
    const LiberaCRsaPublicKey *public_key,
    const LiberaCRsaPrivateKey *private_key) {
    uint8_t ciphertext[RSA_TEST_BYTES];
    uint8_t signature[RSA_TEST_BYTES];
    uint8_t recovered[RSA_TEST_OAEP_MAX];
    size_t recovered_length = 0u;

    if (!decode_hex(
            ciphertext, sizeof(ciphertext), OAEP_CIPHERTEXT_HEX) ||
        !decode_hex(signature, sizeof(signature), PSS_SIGNATURE_HEX))
        return 0;
    if (LIBERAC_RSA_OAEP_DECRYPT(
            recovered, sizeof(recovered), &recovered_length,
            ciphertext, sizeof(ciphertext), NULL, 0u, private_key,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_OAEP) != LIBERAC_SUCCESS)
        return 0;
    if (recovered_length != sizeof(OAEP_MESSAGE) - 1u ||
        memcmp(recovered, OAEP_MESSAGE, recovered_length) != 0)
        return 0;
    if (LIBERAC_RSA_PSS_VERIFY(
            public_key, PSS_MESSAGE, sizeof(PSS_MESSAGE) - 1u,
            signature, sizeof(signature), 32u,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_PSS) != LIBERAC_SUCCESS)
        return 0;
    return 1;
}

static int test_oaep(
    const LiberaCRsaPublicKey *public_key,
    const LiberaCRsaPrivateKey *private_key) {
    static const uint8_t wrong_label[] = "wrong-label";
    uint8_t ciphertext[RSA_TEST_BYTES];
    uint8_t second_ciphertext[RSA_TEST_BYTES];
    uint8_t recovered[RSA_TEST_OAEP_MAX];
    uint8_t overlap[RSA_TEST_BYTES];
    size_t recovered_length = 0u;
    LiberaCError error;

    if (LIBERAC_RSA_PUBLIC_MODULUS_SIZE(public_key) != RSA_TEST_BYTES ||
        LIBERAC_RSA_PRIVATE_MODULUS_SIZE(private_key) != RSA_TEST_BYTES ||
        LIBERAC_RSA_OAEP_MAX_MESSAGE_SIZE(
            RSA_TEST_BYTES, LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_OAEP) != RSA_TEST_OAEP_MAX ||
        LIBERAC_RSA_OAEP_MAX_MESSAGE_SIZE(
            RSA_TEST_BYTES, LIBERAC_ALG_HASH_SHA3_256,
            LIBERAC_ALG_RSA_OAEP) != 0u)
        return 0;

    if (LIBERAC_RSA_OAEP_ENCRYPT(
            ciphertext, sizeof(ciphertext),
            ROUND_TRIP_MESSAGE, sizeof(ROUND_TRIP_MESSAGE) - 1u,
            ROUND_TRIP_LABEL, sizeof(ROUND_TRIP_LABEL) - 1u,
            public_key, LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_OAEP) != LIBERAC_SUCCESS)
        return 0;
    if (LIBERAC_RSA_OAEP_ENCRYPT(
            second_ciphertext, sizeof(second_ciphertext),
            ROUND_TRIP_MESSAGE, sizeof(ROUND_TRIP_MESSAGE) - 1u,
            ROUND_TRIP_LABEL, sizeof(ROUND_TRIP_LABEL) - 1u,
            public_key, LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_OAEP) != LIBERAC_SUCCESS)
        return 0;
    if (memcmp(ciphertext, second_ciphertext, sizeof(ciphertext)) == 0)
        return 0;
    if (LIBERAC_RSA_OAEP_DECRYPT(
            recovered, sizeof(recovered), &recovered_length,
            ciphertext, sizeof(ciphertext),
            ROUND_TRIP_LABEL, sizeof(ROUND_TRIP_LABEL) - 1u,
            private_key, LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_OAEP) != LIBERAC_SUCCESS)
        return 0;
    if (recovered_length != sizeof(ROUND_TRIP_MESSAGE) - 1u ||
        memcmp(recovered, ROUND_TRIP_MESSAGE, recovered_length) != 0)
        return 0;

    memset(recovered, 0xa5, sizeof(recovered));
    recovered_length = sizeof(recovered);
    error = LIBERAC_RSA_OAEP_DECRYPT(
        recovered, sizeof(recovered), &recovered_length,
        ciphertext, sizeof(ciphertext),
        wrong_label, sizeof(wrong_label) - 1u,
        private_key, LIBERAC_ALG_HASH_SHA2_256,
        LIBERAC_ALG_RSA_OAEP);
    if (error != LIBERAC_ERROR_AUTHENTICATION_FAILED ||
        recovered_length != 0u || !all_zero(recovered, sizeof(recovered)))
        return 0;

    ciphertext[17] ^= 1u;
    memset(recovered, 0xa5, sizeof(recovered));
    recovered_length = sizeof(recovered);
    error = LIBERAC_RSA_OAEP_DECRYPT(
        recovered, sizeof(recovered), &recovered_length,
        ciphertext, sizeof(ciphertext), NULL, 0u, private_key,
        LIBERAC_ALG_HASH_SHA2_256, LIBERAC_ALG_RSA_OAEP);
    if (error != LIBERAC_ERROR_AUTHENTICATION_FAILED ||
        recovered_length != 0u || !all_zero(recovered, sizeof(recovered)))
        return 0;

    if (LIBERAC_RSA_OAEP_DECRYPT(
            recovered, sizeof(recovered), &recovered_length,
            ciphertext, sizeof(ciphertext) - 1u, NULL, 0u, private_key,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_OAEP) !=
        LIBERAC_ERROR_AUTHENTICATION_FAILED)
        return 0;
    if (LIBERAC_RSA_OAEP_DECRYPT(
            recovered, sizeof(recovered) - 1u, &recovered_length,
            ciphertext, sizeof(ciphertext), NULL, 0u, private_key,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_OAEP) != LIBERAC_ERROR_BUFFER_TOO_SMALL)
        return 0;
    if (LIBERAC_RSA_OAEP_ENCRYPT(
            ciphertext, sizeof(ciphertext) - 1u,
            ROUND_TRIP_MESSAGE, sizeof(ROUND_TRIP_MESSAGE) - 1u,
            NULL, 0u, public_key, LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_OAEP) != LIBERAC_ERROR_BUFFER_TOO_SMALL)
        return 0;
    memcpy(overlap, ROUND_TRIP_MESSAGE, sizeof(ROUND_TRIP_MESSAGE));
    if (LIBERAC_RSA_OAEP_ENCRYPT(
            overlap, sizeof(overlap), overlap,
            sizeof(ROUND_TRIP_MESSAGE) - 1u, NULL, 0u, public_key,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_OAEP) != LIBERAC_ERROR_INVALID_ARGUMENT)
        return 0;
    if (LIBERAC_RSA_OAEP_ENCRYPT(
            ciphertext, sizeof(ciphertext),
            ROUND_TRIP_MESSAGE, sizeof(ROUND_TRIP_MESSAGE) - 1u,
            NULL, 0u, public_key, LIBERAC_ALG_HASH_SHA3_256,
            LIBERAC_ALG_RSA_OAEP) != LIBERAC_ERROR_INVALID_ALG_ID)
        return 0;
    return 1;
}

static int test_pss(
    const LiberaCRsaPublicKey *public_key,
    const LiberaCRsaPrivateKey *private_key) {
    static const uint8_t different_message[] = "different message";
    uint8_t signature[RSA_TEST_BYTES];
    uint8_t overlap[RSA_TEST_BYTES];

    if (LIBERAC_RSA_PSS_SIGN(
            private_key, ROUND_TRIP_MESSAGE,
            sizeof(ROUND_TRIP_MESSAGE) - 1u,
            signature, sizeof(signature),
            LIBERAC_RSA_PSS_SALT_LENGTH_DIGEST,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_PSS) != LIBERAC_SUCCESS)
        return 0;
    if (LIBERAC_RSA_PSS_VERIFY(
            public_key, ROUND_TRIP_MESSAGE,
            sizeof(ROUND_TRIP_MESSAGE) - 1u,
            signature, sizeof(signature),
            LIBERAC_RSA_PSS_SALT_LENGTH_DIGEST,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_PSS) != LIBERAC_SUCCESS)
        return 0;
    if (LIBERAC_RSA_PSS_VERIFY(
            public_key, different_message,
            sizeof(different_message) - 1u,
            signature, sizeof(signature), 32u,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_PSS) != LIBERAC_ERROR_SIGNATURE_INVALID)
        return 0;
    if (LIBERAC_RSA_PSS_VERIFY(
            public_key, ROUND_TRIP_MESSAGE,
            sizeof(ROUND_TRIP_MESSAGE) - 1u,
            signature, sizeof(signature), 31u,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_PSS) != LIBERAC_ERROR_SIGNATURE_INVALID)
        return 0;
    signature[0] ^= 1u;
    if (LIBERAC_RSA_PSS_VERIFY(
            public_key, ROUND_TRIP_MESSAGE,
            sizeof(ROUND_TRIP_MESSAGE) - 1u,
            signature, sizeof(signature), 32u,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_PSS) != LIBERAC_ERROR_SIGNATURE_INVALID)
        return 0;
    if (LIBERAC_RSA_PSS_VERIFY(
            public_key, ROUND_TRIP_MESSAGE,
            sizeof(ROUND_TRIP_MESSAGE) - 1u,
            signature, sizeof(signature) - 1u, 32u,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_PSS) != LIBERAC_ERROR_SIGNATURE_INVALID)
        return 0;

    memcpy(overlap, ROUND_TRIP_MESSAGE, sizeof(ROUND_TRIP_MESSAGE));
    if (LIBERAC_RSA_PSS_SIGN(
            private_key, overlap, sizeof(ROUND_TRIP_MESSAGE) - 1u,
            overlap, sizeof(overlap), 32u,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_PSS) != LIBERAC_ERROR_INVALID_ARGUMENT)
        return 0;
    if (LIBERAC_RSA_PSS_SIGN(
            private_key, ROUND_TRIP_MESSAGE,
            sizeof(ROUND_TRIP_MESSAGE) - 1u,
            signature, sizeof(signature), 32u,
            LIBERAC_ALG_HASH_SHA3_256,
            LIBERAC_ALG_RSA_PSS) != LIBERAC_ERROR_INVALID_ALG_ID)
        return 0;
    return 1;
}

int main(void) {
    LiberaCRsaPublicKey public_key;
    LiberaCRsaPrivateKey private_key;
    int ok;

    LIBERAC_RSA_PUBLIC_KEY_INIT(&public_key);
    LIBERAC_RSA_PRIVATE_KEY_INIT(&private_key);
    ok = load_test_key(&public_key, &private_key);
    if (ok)
        ok = test_interoperability_vectors(&public_key, &private_key);
    if (ok)
        ok = test_oaep(&public_key, &private_key);
    if (ok)
        ok = test_pss(&public_key, &private_key);
    LIBERAC_RSA_PUBLIC_KEY_FREE(&public_key);
    LIBERAC_RSA_PRIVATE_KEY_FREE(&private_key);

    if (!ok) {
        fputs("RSA OAEP/PSS test failed\n", stderr);
        return 1;
    }
    puts("RSA OAEP/PSS tests passed");
    return 0;
}
