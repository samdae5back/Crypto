#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include "../common/sha3.h"

void RBG(unsigned char *seed, size_t len);
void sha3_256_hash(const unsigned char *input, size_t input_len, unsigned char *output);
void sha3_512_hash(const unsigned char *input, size_t input_len, unsigned char *output);
void shake_256_hash(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len);
void PRF(size_t n_, unsigned char *s, unsigned char b, unsigned char *output);
void H(unsigned char *input, size_t input_length, unsigned char *output);
void J(unsigned char *input, size_t input_length, unsigned char *output);
void G(unsigned char *input, size_t input_length, unsigned char *output_1, unsigned char *output_2);

void XOF_init(crypto_sha3_ctx *ctx);
void XOF_absorb(crypto_sha3_ctx *ctx, const unsigned char *input, size_t input_length);
int XOF_squeeze(crypto_sha3_ctx *ctx, unsigned char *output, size_t length);
void XOF_clear(crypto_sha3_ctx *ctx);

#endif
