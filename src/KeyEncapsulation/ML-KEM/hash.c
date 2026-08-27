/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "hash.h"
#include "RandomNumberGeneration/KAT/pqc_kat_rng_internal.h"
#include "Util/Core/secure_zero.h"

CryptoError RBG(unsigned char *seed, size_t length) {
    CryptoError result = crypto_pqc_random_bytes_internal(seed, length);
    if (result != CRYPTO_SUCCESS) crypto_zeroize(seed, length);
    return result;
}

int PRF(size_t eta, const unsigned char *seed, unsigned char nonce,
        unsigned char *output) {
    unsigned char input[33];

    if ((eta != 2u && eta != 3u) || !seed || !output) return -1;
    memcpy(input, seed, 32u);
    input[32] = nonce;
    crypto_shake256(output, 64u * eta, input, sizeof(input));
    crypto_zeroize(input, sizeof(input));
    return 0;
}

void H(const unsigned char *input, size_t input_length,
       unsigned char *output) {
    crypto_sha3_256(output, input, input_length);
}

void J(const unsigned char *input, size_t input_length,
       unsigned char *output) {
    crypto_shake256(output, 32u, input, input_length);
}

void G(const unsigned char *input, size_t input_length,
       unsigned char *output_first, unsigned char *output_second) {
    unsigned char output[64];

    crypto_sha3_512(output, input, input_length);
    memcpy(output_first, output, 32u);
    memcpy(output_second, output + 32u, 32u);
    crypto_zeroize(output, sizeof(output));
}

void XOF_init(crypto_sha3_ctx *context) {
    crypto_shake128_init(context);
}

void XOF_absorb(crypto_sha3_ctx *context, const unsigned char *input,
                size_t input_length) {
    crypto_sha3_update(context, input, input_length);
}

int XOF_squeeze(crypto_sha3_ctx *context, unsigned char *output,
                size_t output_length) {
    if (!context || (!output && output_length != 0u)) return -1;
    crypto_sha3_squeeze(context, output, output_length);
    return 0;
}

void XOF_clear(crypto_sha3_ctx *context) {
    crypto_sha3_clear(context);
}
