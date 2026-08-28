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
    LiberaCElgamalPublicKey public_key;
    LiberaCElgamalPrivateKey private_key;
    LiberaCElgamalCiphertext ciphertext;
    LiberaCBignum message, recovered;
    int failed = 1;

    LIBERAC_ELGAMAL_PUBLIC_KEY_INIT(&public_key);
    LIBERAC_ELGAMAL_PRIVATE_KEY_INIT(&private_key);
    LIBERAC_ELGAMAL_CIPHERTEXT_INIT(&ciphertext);
    LIBERAC_BIGNUM_INIT(&message);
    LIBERAC_BIGNUM_INIT(&recovered);
    if (LIBERAC_ELGAMAL_KEYGEN(&public_key, &private_key, 32u, 8u,
                              LIBERAC_ALG_ELGAMAL_SAFE_PRIME) != LIBERAC_SUCCESS)
        goto done;
    if (LIBERAC_BIGNUM_FROM_BYTES_BE(
            &message, encoded, sizeof(encoded)) != LIBERAC_SUCCESS)
        goto done;
    if (LIBERAC_ELGAMAL_ENCRYPT(&ciphertext, &message, &public_key,
                               LIBERAC_ALG_ELGAMAL_SAFE_PRIME) != LIBERAC_SUCCESS)
        goto done;
    if (LIBERAC_ELGAMAL_DECRYPT(&recovered, &ciphertext, &public_key,
                               &private_key,
                               LIBERAC_ALG_ELGAMAL_SAFE_PRIME) != LIBERAC_SUCCESS)
        goto done;
    if (LIBERAC_BIGNUM_TO_BYTES_BE(
            &recovered, decoded, sizeof(decoded)) != LIBERAC_SUCCESS ||
        memcmp(encoded, decoded, sizeof(encoded)) != 0)
        goto done;
    failed = 0;

done:
    LIBERAC_BIGNUM_FREE(&message);
    LIBERAC_BIGNUM_FREE(&recovered);
    LIBERAC_ELGAMAL_CIPHERTEXT_FREE(&ciphertext);
    LIBERAC_ELGAMAL_PRIVATE_KEY_FREE(&private_key);
    LIBERAC_ELGAMAL_PUBLIC_KEY_FREE(&public_key);
    return failed;
}

static int test_rsa(void) {
    static const uint8_t encoded[] = {42u};
    uint8_t decoded[sizeof(encoded)];
    LiberaCRsaPublicKey public_key;
    LiberaCRsaPrivateKey private_key;
    LiberaCBignum message, ciphertext, recovered;
    int failed = 1;

    LIBERAC_RSA_PUBLIC_KEY_INIT(&public_key);
    LIBERAC_RSA_PRIVATE_KEY_INIT(&private_key);
    LIBERAC_BIGNUM_INIT(&message);
    LIBERAC_BIGNUM_INIT(&ciphertext);
    LIBERAC_BIGNUM_INIT(&recovered);
    if (LIBERAC_RSA_KEYGEN(&public_key, &private_key, 256u, 12u,
                          LIBERAC_ALG_RSA_RAW) != LIBERAC_SUCCESS)
        goto done;
    if (LIBERAC_BIGNUM_FROM_BYTES_BE(
            &message, encoded, sizeof(encoded)) != LIBERAC_SUCCESS)
        goto done;
    if (LIBERAC_RSA_ENCRYPT(&ciphertext, &message, &public_key,
                           LIBERAC_ALG_RSA_RAW) != LIBERAC_SUCCESS)
        goto done;
    if (LIBERAC_RSA_DECRYPT(&recovered, &ciphertext, &private_key,
                           LIBERAC_ALG_RSA_RAW) != LIBERAC_SUCCESS)
        goto done;
    if (LIBERAC_BIGNUM_TO_BYTES_BE(
            &recovered, decoded, sizeof(decoded)) != LIBERAC_SUCCESS ||
        memcmp(encoded, decoded, sizeof(encoded)) != 0)
        goto done;
    failed = 0;

done:
    LIBERAC_BIGNUM_FREE(&message);
    LIBERAC_BIGNUM_FREE(&ciphertext);
    LIBERAC_BIGNUM_FREE(&recovered);
    LIBERAC_RSA_PUBLIC_KEY_FREE(&public_key);
    LIBERAC_RSA_PRIVATE_KEY_FREE(&private_key);
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
