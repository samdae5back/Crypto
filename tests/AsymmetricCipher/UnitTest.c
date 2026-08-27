/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "AsymmetricCipher.h"

#include <stdio.h>
#include <string.h>

static int test_elgamal(void) {
    static const uint8_t encoded[] = {42u};
    uint8_t decoded[sizeof(encoded)];
    CRYPTO_ELGAMAL_PUBLIC_KEY public_key;
    CRYPTO_ELGAMAL_PRIVATE_KEY private_key;
    CRYPTO_ELGAMAL_CIPHERTEXT ciphertext;
    CRYPTO_BIGNUM message, recovered;
    int failed = 1;

    CRYPTO_ELGAMAL_PUBLIC_KEY_INIT(&public_key);
    CRYPTO_ELGAMAL_PRIVATE_KEY_INIT(&private_key);
    CRYPTO_ELGAMAL_CIPHERTEXT_INIT(&ciphertext);
    CRYPTO_BIGNUM_INIT(&message);
    CRYPTO_BIGNUM_INIT(&recovered);
    if (CRYPTO_ELGAMAL_KEYGEN(&public_key, &private_key, 32u, 8u,
                              ALG_ELGAMAL_SAFE_PRIME) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_BIGNUM_FROM_BYTES_BE(
            &message, encoded, sizeof(encoded)) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_ELGAMAL_ENCRYPT(&ciphertext, &message, &public_key,
                               ALG_ELGAMAL_SAFE_PRIME) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_ELGAMAL_DECRYPT(&recovered, &ciphertext, &public_key,
                               &private_key,
                               ALG_ELGAMAL_SAFE_PRIME) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_BIGNUM_TO_BYTES_BE(
            &recovered, decoded, sizeof(decoded)) != CRYPTO_SUCCESS ||
        memcmp(encoded, decoded, sizeof(encoded)) != 0)
        goto done;
    failed = 0;

done:
    CRYPTO_BIGNUM_FREE(&message);
    CRYPTO_BIGNUM_FREE(&recovered);
    CRYPTO_ELGAMAL_CIPHERTEXT_FREE(&ciphertext);
    CRYPTO_ELGAMAL_PRIVATE_KEY_FREE(&private_key);
    CRYPTO_ELGAMAL_PUBLIC_KEY_FREE(&public_key);
    return failed;
}

static int test_rsa(void) {
    static const uint8_t encoded[] = {42u};
    uint8_t decoded[sizeof(encoded)];
    CRYPTO_RSA_PUBLIC_KEY public_key;
    CRYPTO_RSA_PRIVATE_KEY private_key;
    CRYPTO_BIGNUM message, ciphertext, recovered;
    int failed = 1;

    CRYPTO_RSA_PUBLIC_KEY_INIT(&public_key);
    CRYPTO_RSA_PRIVATE_KEY_INIT(&private_key);
    CRYPTO_BIGNUM_INIT(&message);
    CRYPTO_BIGNUM_INIT(&ciphertext);
    CRYPTO_BIGNUM_INIT(&recovered);
    if (CRYPTO_RSA_KEYGEN(&public_key, &private_key, 256u, 12u,
                          ALG_RSA_RAW) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_BIGNUM_FROM_BYTES_BE(
            &message, encoded, sizeof(encoded)) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_RSA_ENCRYPT(&ciphertext, &message, &public_key,
                           ALG_RSA_RAW) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_RSA_DECRYPT(&recovered, &ciphertext, &private_key,
                           ALG_RSA_RAW) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_BIGNUM_TO_BYTES_BE(
            &recovered, decoded, sizeof(decoded)) != CRYPTO_SUCCESS ||
        memcmp(encoded, decoded, sizeof(encoded)) != 0)
        goto done;
    failed = 0;

done:
    CRYPTO_BIGNUM_FREE(&message);
    CRYPTO_BIGNUM_FREE(&ciphertext);
    CRYPTO_BIGNUM_FREE(&recovered);
    CRYPTO_RSA_PUBLIC_KEY_FREE(&public_key);
    CRYPTO_RSA_PRIVATE_KEY_FREE(&private_key);
    return failed;
}

int main(void) {
    if (test_rsa()) {
        fputs("RSA unit test failed\n", stderr);
        return 1;
    }
    if (test_elgamal()) {
        fputs("ElGamal unit test failed\n", stderr);
        return 1;
    }
    puts("asymmetric-cipher unit tests passed");
    return 0;
}
