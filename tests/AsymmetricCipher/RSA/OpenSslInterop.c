/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "LiberaCrypt.h"

#include <stdio.h>
#include <string.h>

#define RSA_INTEROP_BYTES 256u
#define RSA_INTEROP_OAEP_MAX 190u

static const uint8_t OAEP_MESSAGE[] =
    "LiberaCrypt dynamic OpenSSL OAEP interop";
static const uint8_t PSS_MESSAGE[] =
    "LiberaCrypt dynamic OpenSSL PSS interop";

static int hex_nibble(char value) {
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

static int decode_hex_fixed(
    uint8_t *output, size_t output_length, const char *hex) {
    size_t hex_length;
    size_t byte_length;
    size_t offset;
    size_t i;

    if (!output || !hex)
        return 0;
    hex_length = strlen(hex);
    while (hex_length > 2u * output_length &&
           hex[0] == '0' && hex[1] == '0') {
        hex += 2;
        hex_length -= 2u;
    }
    if ((hex_length & 1u) != 0u || hex_length > 2u * output_length)
        return 0;

    byte_length = hex_length / 2u;
    offset = output_length - byte_length;
    memset(output, 0, output_length);
    for (i = 0u; i < byte_length; ++i) {
        int high = hex_nibble(hex[2u * i]);
        int low = hex_nibble(hex[2u * i + 1u]);
        if (high < 0 || low < 0)
            return 0;
        output[offset + i] =
            (uint8_t)(((unsigned)high << 4) | (unsigned)low);
    }
    return 1;
}

static int read_exact(
    const char *path, uint8_t *output, size_t output_length) {
    FILE *file;
    size_t read_length;
    int extra;
    int ok;

    file = fopen(path, "rb");
    if (!file)
        return 0;
    read_length = fread(output, 1u, output_length, file);
    extra = fgetc(file);
    ok = read_length == output_length && extra == EOF && !ferror(file);
    if (fclose(file) != 0)
        ok = 0;
    return ok;
}

static int write_exact(
    const char *path, const uint8_t *input, size_t input_length) {
    FILE *file;
    size_t written;
    int ok;

    file = fopen(path, "wb");
    if (!file)
        return 0;
    written = fwrite(input, 1u, input_length, file);
    ok = written == input_length && !ferror(file);
    if (fclose(file) != 0)
        ok = 0;
    return ok;
}

static int load_key(
    LiberaCRsaPublicKey *public_key,
    LiberaCRsaPrivateKey *private_key,
    const char *modulus_hex, const char *private_exponent_hex) {
    static const uint8_t exponent[] = {1u, 0u, 1u};
    uint8_t bytes[RSA_INTEROP_BYTES];
    LiberaCError error;

    if (!decode_hex_fixed(
            bytes, sizeof(bytes), modulus_hex))
        return 0;
    error = LIBERAC_BIGNUM_FROM_BYTES_BE(
        &public_key->N, bytes, sizeof(bytes));
    if (error == LIBERAC_SUCCESS)
        error = LIBERAC_BIGNUM_FROM_BYTES_BE(
            &private_key->N, bytes, sizeof(bytes));
    if (error == LIBERAC_SUCCESS)
        error = LIBERAC_BIGNUM_FROM_BYTES_BE(
            &public_key->E, exponent, sizeof(exponent));
    if (!decode_hex_fixed(
            bytes, sizeof(bytes), private_exponent_hex))
        error = LIBERAC_ERROR_INTERNAL;
    if (error == LIBERAC_SUCCESS)
        error = LIBERAC_BIGNUM_FROM_BYTES_BE(
            &private_key->D, bytes, sizeof(bytes));
    memset(bytes, 0, sizeof(bytes));
    return error == LIBERAC_SUCCESS;
}

int main(int argc, char **argv) {
    LiberaCRsaPublicKey public_key;
    LiberaCRsaPrivateKey private_key;
    uint8_t openssl_ciphertext[RSA_INTEROP_BYTES];
    uint8_t openssl_signature[RSA_INTEROP_BYTES];
    uint8_t library_ciphertext[RSA_INTEROP_BYTES];
    uint8_t library_signature[RSA_INTEROP_BYTES];
    uint8_t recovered[RSA_INTEROP_OAEP_MAX];
    size_t recovered_length = 0u;
    int ok = 0;

    if (argc != 7) {
        fputs("usage: interop N_HEX D_HEX OPENSSL_CT OPENSSL_SIG "
              "LIBERAC_CT LIBERAC_SIG\n", stderr);
        return 2;
    }

    LIBERAC_RSA_PUBLIC_KEY_INIT(&public_key);
    LIBERAC_RSA_PRIVATE_KEY_INIT(&private_key);
    if (!load_key(&public_key, &private_key, argv[1], argv[2]))
        goto cleanup;
    if (!read_exact(
            argv[3], openssl_ciphertext, sizeof(openssl_ciphertext)) ||
        !read_exact(
            argv[4], openssl_signature, sizeof(openssl_signature)))
        goto cleanup;

    if (LIBERAC_RSA_OAEP_DECRYPT(
            recovered, sizeof(recovered), &recovered_length,
            openssl_ciphertext, sizeof(openssl_ciphertext),
            NULL, 0u, &private_key,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_OAEP) != LIBERAC_SUCCESS)
        goto cleanup;
    if (recovered_length != sizeof(OAEP_MESSAGE) - 1u ||
        memcmp(recovered, OAEP_MESSAGE, recovered_length) != 0)
        goto cleanup;
    if (LIBERAC_RSA_PSS_VERIFY(
            &public_key, PSS_MESSAGE, sizeof(PSS_MESSAGE) - 1u,
            openssl_signature, sizeof(openssl_signature), 32u,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_PSS) != LIBERAC_SUCCESS)
        goto cleanup;

    if (LIBERAC_RSA_OAEP_ENCRYPT(
            library_ciphertext, sizeof(library_ciphertext),
            OAEP_MESSAGE, sizeof(OAEP_MESSAGE) - 1u,
            NULL, 0u, &public_key,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_OAEP) != LIBERAC_SUCCESS)
        goto cleanup;
    if (LIBERAC_RSA_PSS_SIGN(
            &private_key, PSS_MESSAGE, sizeof(PSS_MESSAGE) - 1u,
            library_signature, sizeof(library_signature), 32u,
            LIBERAC_ALG_HASH_SHA2_256,
            LIBERAC_ALG_RSA_PSS) != LIBERAC_SUCCESS)
        goto cleanup;
    if (!write_exact(
            argv[5], library_ciphertext, sizeof(library_ciphertext)) ||
        !write_exact(
            argv[6], library_signature, sizeof(library_signature)))
        goto cleanup;
    ok = 1;

cleanup:
    LIBERAC_RSA_PUBLIC_KEY_FREE(&public_key);
    LIBERAC_RSA_PRIVATE_KEY_FREE(&private_key);
    memset(openssl_ciphertext, 0, sizeof(openssl_ciphertext));
    memset(openssl_signature, 0, sizeof(openssl_signature));
    memset(library_ciphertext, 0, sizeof(library_ciphertext));
    memset(library_signature, 0, sizeof(library_signature));
    memset(recovered, 0, sizeof(recovered));
    if (!ok) {
        fputs("OpenSSL RSA interoperability test failed\n", stderr);
        return 1;
    }
    puts("OpenSSL RSA interoperability test passed");
    return 0;
}
