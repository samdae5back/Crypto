#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "../common/random.h"

void RBG(unsigned char *seed, size_t len) {
    if (crypto_random_bytes(seed, len) != 0) {
        fprintf(stderr, "RBG failed: operating-system CSPRNG unavailable\n");
        exit(EXIT_FAILURE);
    }
}

void sha3_256_hash(const unsigned char *input, size_t input_len, unsigned char *output) {
    crypto_sha3_256(output, input, input_len);
}

void sha3_512_hash(const unsigned char *input, size_t input_len, unsigned char *output) {
    crypto_sha3_512(output, input, input_len);
}

void shake_256_hash(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len) {
    crypto_shake256(output, output_len, input, input_len);
}

void PRF(size_t n_, unsigned char *s, unsigned char b, unsigned char *output) {
    unsigned char t[33];

    if (n_ != 2 && n_ != 3) {
        fprintf(stderr, "PRF: n must be 2 or 3\n");
        exit(EXIT_FAILURE);
    }

    memcpy(t, s, 32);
    t[32] = b;
    crypto_shake256(output, 64 * n_, t, sizeof(t));
}

void H(unsigned char *input, size_t input_length, unsigned char *output) {
    crypto_sha3_256(output, input, input_length);
}

void J(unsigned char *input, size_t input_length, unsigned char *output) {
    crypto_shake256(output, 32, input, input_length);
}

void G(unsigned char *input, size_t input_length, unsigned char *output_1, unsigned char *output_2) {
    unsigned char output[64];

    crypto_sha3_512(output, input, input_length);
    memcpy(output_1, output, 32);
    memcpy(output_2, output + 32, 32);
    memset(output, 0, sizeof(output));
}

void XOF_init(crypto_sha3_ctx *ctx) {
    crypto_shake128_init(ctx);
}

void XOF_absorb(crypto_sha3_ctx *ctx, const unsigned char *input, size_t input_length) {
    crypto_sha3_update(ctx, input, input_length);
}

int XOF_squeeze(crypto_sha3_ctx *ctx, unsigned char *output, size_t length) {
    if (!ctx || (!output && length)) {
        return -1;
    }
    crypto_sha3_squeeze(ctx, output, length);
    return 0;
}

void XOF_clear(crypto_sha3_ctx *ctx) {
    crypto_sha3_clear(ctx);
}
