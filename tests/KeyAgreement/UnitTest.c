/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "KeyAgreement.h"

#include <stdio.h>
#include <string.h>

#define TEST_MAX_PRIVATE 66u
#define TEST_MAX_PUBLIC 133u
#define TEST_MAX_SHARED 66u
#define TEST_MAX_COMPRESSED 67u

static int test_expect(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        return 0;
    }
    return 1;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *hex, uint8_t *output, size_t output_length) {
    size_t i;
    for (i = 0u; i < output_length; ++i) {
        const int high = hex_value(hex[2u * i]);
        const int low = hex_value(hex[2u * i + 1u]);
        if (high < 0 || low < 0) return 0;
        output[i] = (uint8_t)((high << 4) | low);
    }
    return hex[2u * output_length] == '\0';
}

static int bytes_are_zero(const uint8_t *value, size_t length) {
    uint32_t accumulator = 0u;
    size_t i;
    for (i = 0u; i < length; ++i) accumulator |= value[i];
    return accumulator == 0u;
}

static int test_sizes(void) {
    int ok = 1;
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PRIVATE_KEY_SIZE(LIBERAC_ALG_ECDH_P256) == 32u,
        "P-256 private size");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PUBLIC_KEY_SIZE(LIBERAC_ALG_ECDH_P256) == 65u,
        "P-256 public size");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET_SIZE(LIBERAC_ALG_ECDH_P256) == 32u,
        "P-256 shared size");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PRIVATE_KEY_SIZE(LIBERAC_ALG_ECDH_P384) == 48u,
        "P-384 private size");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PUBLIC_KEY_SIZE(LIBERAC_ALG_ECDH_P384) == 97u,
        "P-384 public size");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET_SIZE(LIBERAC_ALG_ECDH_P384) == 48u,
        "P-384 shared size");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PRIVATE_KEY_SIZE(LIBERAC_ALG_ECDH_P521) == 66u,
        "P-521 private size");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PUBLIC_KEY_SIZE(LIBERAC_ALG_ECDH_P521) == 133u,
        "P-521 public size");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET_SIZE(LIBERAC_ALG_ECDH_P521) == 66u,
        "P-521 shared size");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PRIVATE_KEY_SIZE(LIBERAC_ALG_X25519) == 32u &&
        LIBERAC_KEY_AGREEMENT_PUBLIC_KEY_SIZE(LIBERAC_ALG_X25519) == 32u &&
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET_SIZE(LIBERAC_ALG_X25519) == 32u,
        "X25519 sizes");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PRIVATE_KEY_SIZE(LIBERAC_ALG_NONE) == 0u &&
        LIBERAC_KEY_AGREEMENT_PUBLIC_KEY_SIZE(LIBERAC_ALG_NONE) == 0u &&
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET_SIZE(LIBERAC_ALG_NONE) == 0u,
        "invalid algorithm sizes");
    return ok;
}

static int test_x25519_rfc7748(void) {
    static const char alice_private_hex[] =
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a";
    static const char alice_public_hex[] =
        "8520f0098930a754748b7ddcb43ef75a0"
        "dbf3a0d26381af4eba4a98eaa9b4e6a";
    static const char bob_private_hex[] =
        "5dab087e624a8a4b79e17f8b83800ee6"
        "6f3bb1292618b6fd1c2f8b27ff88e0eb";
    static const char bob_public_hex[] =
        "de9edb7d7b7dc1b4d35b61c2ece43537"
        "3f8343c85b78674dadfc7e146f882b4f";
    static const char shared_hex[] =
        "4a5d9d5ba4ce2de1728e3bf480350f25"
        "e07e21c947d19e3376f09b3c1e161742";
    uint8_t alice_private[32];
    uint8_t alice_public[32];
    uint8_t expected_alice_public[32];
    uint8_t bob_private[32];
    uint8_t bob_public[32];
    uint8_t expected_bob_public[32];
    uint8_t shared_ab[32];
    uint8_t shared_ba[32];
    uint8_t expected_shared[32];
    uint8_t zero_peer[32] = { 0u };
    uint8_t rejected[32];
    int ok = 1;

    ok &= test_expect(parse_hex(alice_private_hex, alice_private, sizeof(alice_private)),
                      "parse Alice private");
    ok &= test_expect(parse_hex(alice_public_hex, expected_alice_public,
                                sizeof(expected_alice_public)),
                      "parse Alice public");
    ok &= test_expect(parse_hex(bob_private_hex, bob_private, sizeof(bob_private)),
                      "parse Bob private");
    ok &= test_expect(parse_hex(bob_public_hex, expected_bob_public,
                                sizeof(expected_bob_public)),
                      "parse Bob public");
    ok &= test_expect(parse_hex(shared_hex, expected_shared, sizeof(expected_shared)),
                      "parse shared secret");
    if (!ok) return 0;

    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PUBLIC_FROM_PRIVATE(
            alice_public, sizeof(alice_public),
            alice_private, sizeof(alice_private),
            LIBERAC_ALG_X25519) == LIBERAC_SUCCESS,
        "derive Alice X25519 public key");
    ok &= test_expect(memcmp(alice_public, expected_alice_public, 32u) == 0,
                      "Alice RFC 7748 public key");

    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PUBLIC_FROM_PRIVATE(
            bob_public, sizeof(bob_public),
            bob_private, sizeof(bob_private),
            LIBERAC_ALG_X25519) == LIBERAC_SUCCESS,
        "derive Bob X25519 public key");
    ok &= test_expect(memcmp(bob_public, expected_bob_public, 32u) == 0,
                      "Bob RFC 7748 public key");

    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET(
            shared_ab, sizeof(shared_ab),
            alice_private, sizeof(alice_private),
            bob_public, sizeof(bob_public),
            LIBERAC_ALG_X25519) == LIBERAC_SUCCESS,
        "Alice to Bob X25519");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET(
            shared_ba, sizeof(shared_ba),
            bob_private, sizeof(bob_private),
            alice_public, sizeof(alice_public),
            LIBERAC_ALG_X25519) == LIBERAC_SUCCESS,
        "Bob to Alice X25519");
    ok &= test_expect(memcmp(shared_ab, expected_shared, 32u) == 0,
                      "RFC 7748 shared secret");
    ok &= test_expect(memcmp(shared_ab, shared_ba, 32u) == 0,
                      "X25519 bilateral agreement");

    memset(rejected, 0xa5, sizeof(rejected));
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET(
            rejected, sizeof(rejected),
            alice_private, sizeof(alice_private),
            zero_peer, sizeof(zero_peer),
            LIBERAC_ALG_X25519) == LIBERAC_ERROR_INVALID_KEY,
        "reject all-zero X25519 agreement");
    ok &= test_expect(bytes_are_zero(rejected, sizeof(rejected)),
                      "clear rejected X25519 secret");
    return ok;
}

static int test_ecdh_curve(LiberaCAlgID alg, const char *name) {
    uint8_t private_one[TEST_MAX_PRIVATE] = { 0u };
    uint8_t private_two[TEST_MAX_PRIVATE] = { 0u };
    uint8_t public_one[TEST_MAX_PUBLIC];
    uint8_t public_two[TEST_MAX_PUBLIC];
    uint8_t shared_one[TEST_MAX_SHARED];
    uint8_t shared_two[TEST_MAX_SHARED];
    uint8_t shared_compressed[TEST_MAX_SHARED];
    uint8_t compressed[TEST_MAX_COMPRESSED];
    uint8_t invalid_output[TEST_MAX_SHARED];
    size_t private_size = LIBERAC_KEY_AGREEMENT_PRIVATE_KEY_SIZE(alg);
    size_t public_size = LIBERAC_KEY_AGREEMENT_PUBLIC_KEY_SIZE(alg);
    size_t shared_size = LIBERAC_KEY_AGREEMENT_SHARED_SECRET_SIZE(alg);
    size_t compressed_size = 1u + shared_size;
    int ok = 1;

    private_one[private_size - 1u] = 1u;
    private_two[private_size - 1u] = 2u;

    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PUBLIC_FROM_PRIVATE(
            public_one, public_size, private_one, private_size, alg) ==
            LIBERAC_SUCCESS,
        name);
    ok &= test_expect(public_one[0] == 4u, "ECDH uncompressed public encoding");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PUBLIC_FROM_PRIVATE(
            public_two, public_size, private_two, private_size, alg) ==
            LIBERAC_SUCCESS,
        "derive second ECDH public key");

    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET(
            shared_one, shared_size,
            private_one, private_size,
            public_two, public_size, alg) == LIBERAC_SUCCESS,
        "ECDH forward agreement");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET(
            shared_two, shared_size,
            private_two, private_size,
            public_one, public_size, alg) == LIBERAC_SUCCESS,
        "ECDH reverse agreement");
    ok &= test_expect(memcmp(shared_one, shared_two, shared_size) == 0,
                      "ECDH bilateral agreement");
    ok &= test_expect(!bytes_are_zero(shared_one, shared_size),
                      "ECDH shared secret nonzero");

    compressed[0] = (uint8_t)(2u | (public_two[public_size - 1u] & 1u));
    memcpy(compressed + 1u, public_two + 1u, shared_size);
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET(
            shared_compressed, shared_size,
            private_one, private_size,
            compressed, compressed_size, alg) == LIBERAC_SUCCESS,
        "ECDH compressed peer key");
    ok &= test_expect(memcmp(shared_one, shared_compressed, shared_size) == 0,
                      "ECDH compressed/uncompressed agreement");

    memset(private_one, 0, private_size);
    memset(invalid_output, 0xa5, shared_size);
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET(
            invalid_output, shared_size,
            private_one, private_size,
            public_two, public_size, alg) == LIBERAC_ERROR_INVALID_KEY,
        "reject zero ECDH private scalar");
    ok &= test_expect(bytes_are_zero(invalid_output, shared_size),
                      "clear invalid ECDH shared secret");
    return ok;
}

static int test_keygen_roundtrip(LiberaCAlgID alg, const char *name) {
    uint8_t private_a[TEST_MAX_PRIVATE];
    uint8_t private_b[TEST_MAX_PRIVATE];
    uint8_t public_a[TEST_MAX_PUBLIC];
    uint8_t public_b[TEST_MAX_PUBLIC];
    uint8_t recomputed[TEST_MAX_PUBLIC];
    uint8_t shared_a[TEST_MAX_SHARED];
    uint8_t shared_b[TEST_MAX_SHARED];
    size_t private_size = LIBERAC_KEY_AGREEMENT_PRIVATE_KEY_SIZE(alg);
    size_t public_size = LIBERAC_KEY_AGREEMENT_PUBLIC_KEY_SIZE(alg);
    size_t shared_size = LIBERAC_KEY_AGREEMENT_SHARED_SECRET_SIZE(alg);
    int ok = 1;

    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_KEYGEN(
            public_a, public_size, private_a, private_size, alg) == LIBERAC_SUCCESS,
        name);
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_KEYGEN(
            public_b, public_size, private_b, private_size, alg) == LIBERAC_SUCCESS,
        "generate second key-agreement keypair");
    if (!ok) return 0;

    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_PUBLIC_FROM_PRIVATE(
            recomputed, public_size, private_a, private_size, alg) == LIBERAC_SUCCESS,
        "recompute generated public key");
    ok &= test_expect(memcmp(recomputed, public_a, public_size) == 0,
                      "generated public key matches private key");

    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET(
            shared_a, shared_size,
            private_a, private_size,
            public_b, public_size, alg) == LIBERAC_SUCCESS,
        "generated keypair agreement A");
    ok &= test_expect(
        LIBERAC_KEY_AGREEMENT_SHARED_SECRET(
            shared_b, shared_size,
            private_b, private_size,
            public_a, public_size, alg) == LIBERAC_SUCCESS,
        "generated keypair agreement B");
    ok &= test_expect(memcmp(shared_a, shared_b, shared_size) == 0,
                      "generated keypair shared secret agreement");
    return ok;
}

int main(void) {
    int ok = 1;
    ok &= test_sizes();
    ok &= test_x25519_rfc7748();
    ok &= test_ecdh_curve(LIBERAC_ALG_ECDH_P256, "derive P-256 public key");
    ok &= test_ecdh_curve(LIBERAC_ALG_ECDH_P384, "derive P-384 public key");
    ok &= test_ecdh_curve(LIBERAC_ALG_ECDH_P521, "derive P-521 public key");
    ok &= test_keygen_roundtrip(LIBERAC_ALG_ECDH_P256, "generate P-256 keypair");
    ok &= test_keygen_roundtrip(LIBERAC_ALG_ECDH_P384, "generate P-384 keypair");
    ok &= test_keygen_roundtrip(LIBERAC_ALG_ECDH_P521, "generate P-521 keypair");
    ok &= test_keygen_roundtrip(LIBERAC_ALG_X25519, "generate X25519 keypair");
    if (!ok) return 1;
    puts("KeyAgreement tests passed");
    return 0;
}
