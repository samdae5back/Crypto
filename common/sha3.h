#ifndef CRYPTO_SHA3_H
#define CRYPTO_SHA3_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_SHA3_256_DIGEST_SIZE 32u
#define CRYPTO_SHA3_512_DIGEST_SIZE 64u

typedef struct {
    uint64_t state[25];
    size_t rate;
    size_t pos;
    uint8_t domain;
    int finalized;
} crypto_sha3_ctx;

void crypto_sha3_256(uint8_t out[CRYPTO_SHA3_256_DIGEST_SIZE], const uint8_t *in, size_t in_len);
void crypto_sha3_512(uint8_t out[CRYPTO_SHA3_512_DIGEST_SIZE], const uint8_t *in, size_t in_len);
void crypto_shake128(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);
void crypto_shake256(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);

void crypto_shake128_init(crypto_sha3_ctx *ctx);
void crypto_shake256_init(crypto_sha3_ctx *ctx);
void crypto_sha3_update(crypto_sha3_ctx *ctx, const uint8_t *in, size_t in_len);
void crypto_sha3_finalize(crypto_sha3_ctx *ctx);
void crypto_sha3_squeeze(crypto_sha3_ctx *ctx, uint8_t *out, size_t out_len);
void crypto_sha3_clear(crypto_sha3_ctx *ctx);

#endif
