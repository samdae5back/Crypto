/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Crypto.h"

#include <stdio.h>
#include <string.h>

/* First AES ECB KAT records copied from iotcc-new selftest_vectors.h. */
static int aes_kat(void) {
    static const struct {
        AlgID alg;
        size_t key_length;
        uint8_t expected[16];
    } vectors[] = {
        { ALG_AES_128_ECB, 16u, {0x3a,0xd7,0x8e,0x72,0x6c,0x1e,0xc0,0x2b,0x7e,0xbf,0xe9,0x2b,0x23,0xd9,0xec,0x34} },
        { ALG_AES_192_ECB, 24u, {0x6c,0xd0,0x25,0x13,0xe8,0xd4,0xdc,0x98,0x6b,0x4a,0xfe,0x08,0x7a,0x60,0xbd,0x0c} },
        { ALG_AES_256_ECB, 32u, {0xdd,0xc6,0xbf,0x79,0x0c,0x15,0x76,0x0d,0x8d,0x9a,0xeb,0x6f,0x9a,0x75,0xfd,0x4e} }
    };
    uint8_t key[32] = {0};
    uint8_t plaintext[16] = {0x80};
    uint8_t ciphertext[16];
    size_t i;
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
                ciphertext, sizeof(ciphertext), NULL, 0u,
                plaintext, sizeof(plaintext), key, vectors[i].key_length,
                NULL, 0u, NULL, 0u, vectors[i].alg) != CRYPTO_SUCCESS)
            return 1;
        if (memcmp(ciphertext, vectors[i].expected, sizeof(ciphertext)) != 0)
            return 1;
    }
    return 0;
}

/* SHA3-256 empty-message SMT record copied from the same iotcc vector table. */
static int sha3_kat(void) {
    static const uint8_t expected[32] = {
        0xa7,0xff,0xc6,0xf8,0xbf,0x1e,0xd7,0x66,0x51,0xc1,0x47,0x56,0xa0,0x61,0xd6,0x62,
        0xf5,0x80,0xff,0x4d,0xe4,0x3b,0x49,0xfa,0x82,0xd8,0x0a,0x4b,0x80,0xf8,0x43,0x4a
    };
    uint8_t digest[32];
    if (CRYPTO_HASH(digest, sizeof(digest), NULL, 0u,
                    ALG_HASH_SHA3_256) != CRYPTO_SUCCESS)
        return 1;
    return memcmp(digest, expected, sizeof(digest)) != 0;
}

int main(void) {
    if (aes_kat()) { fputs("AES KAT failed\n", stderr); return 1; }
    if (sha3_kat()) { fputs("SHA3 KAT failed\n", stderr); return 1; }
    puts("iotcc known-answer tests passed");
    return 0;
}
