#include "sha3.h"
#include <string.h>

static uint64_t rol64(uint64_t x, unsigned n) {
    return n ? ((x << n) | (x >> (64u - n))) : x;
}

static void keccak_f1600(uint64_t s[25]) {
    static const uint64_t rc[24] = {
        0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
        0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
        0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
        0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
        0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
        0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
    };
    static const unsigned rho[25] = {
        0,1,62,28,27,
        36,44,6,55,20,
        3,10,43,25,39,
        41,45,15,21,8,
        18,2,61,56,14
    };
    uint64_t a[25], b[25], c[5], d[5];
    unsigned round, x, y;

    for (round = 0; round < 24; ++round) {
        for (x = 0; x < 5; ++x) {
            c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        }
        for (x = 0; x < 5; ++x) {
            d[x] = c[(x + 4) % 5] ^ rol64(c[(x + 1) % 5], 1);
        }
        for (y = 0; y < 5; ++y) {
            for (x = 0; x < 5; ++x) {
                a[x + 5 * y] = s[x + 5 * y] ^ d[x];
            }
        }
        for (y = 0; y < 5; ++y) {
            for (x = 0; x < 5; ++x) {
                unsigned nx = y;
                unsigned ny = (2 * x + 3 * y) % 5;
                b[nx + 5 * ny] = rol64(a[x + 5 * y], rho[x + 5 * y]);
            }
        }
        for (y = 0; y < 5; ++y) {
            for (x = 0; x < 5; ++x) {
                s[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        s[0] ^= rc[round];
    }

    memset(a, 0, sizeof(a));
    memset(b, 0, sizeof(b));
    memset(c, 0, sizeof(c));
    memset(d, 0, sizeof(d));
}

static void sponge_init(crypto_sha3_ctx *ctx, size_t rate, uint8_t domain) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = rate;
    ctx->domain = domain;
}

void crypto_shake128_init(crypto_sha3_ctx *ctx) {
    sponge_init(ctx, 168u, 0x1fu);
}

void crypto_shake256_init(crypto_sha3_ctx *ctx) {
    sponge_init(ctx, 136u, 0x1fu);
}

void crypto_sha3_update(crypto_sha3_ctx *ctx, const uint8_t *in, size_t in_len) {
    if (!ctx || ctx->finalized || (!in && in_len)) {
        return;
    }

    while (in_len) {
        size_t take = ctx->rate - ctx->pos;
        size_t i;
        if (take > in_len) {
            take = in_len;
        }

        for (i = 0; i < take; ++i) {
            size_t p = ctx->pos + i;
            ctx->state[p >> 3] ^= (uint64_t)in[i] << (8u * (p & 7u));
        }

        ctx->pos += take;
        in += take;
        in_len -= take;
        if (ctx->pos == ctx->rate) {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }
    }
}

void crypto_sha3_finalize(crypto_sha3_ctx *ctx) {
    size_t last;

    if (!ctx || ctx->finalized) {
        return;
    }

    ctx->state[ctx->pos >> 3] ^= (uint64_t)ctx->domain << (8u * (ctx->pos & 7u));
    last = ctx->rate - 1u;
    ctx->state[last >> 3] ^= (uint64_t)0x80u << (8u * (last & 7u));
    keccak_f1600(ctx->state);
    ctx->pos = 0;
    ctx->finalized = 1;
}

void crypto_sha3_squeeze(crypto_sha3_ctx *ctx, uint8_t *out, size_t out_len) {
    if (!ctx || (!out && out_len)) {
        return;
    }
    if (!ctx->finalized) {
        crypto_sha3_finalize(ctx);
    }

    while (out_len) {
        size_t take, i;
        if (ctx->pos == ctx->rate) {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }
        take = ctx->rate - ctx->pos;
        if (take > out_len) {
            take = out_len;
        }
        for (i = 0; i < take; ++i) {
            size_t p = ctx->pos + i;
            out[i] = (uint8_t)(ctx->state[p >> 3] >> (8u * (p & 7u)));
        }
        ctx->pos += take;
        out += take;
        out_len -= take;
    }
}

void crypto_sha3_clear(crypto_sha3_ctx *ctx) {
    volatile uint8_t *p;
    size_t i;

    if (!ctx) {
        return;
    }
    p = (volatile uint8_t *)ctx;
    for (i = 0; i < sizeof(*ctx); ++i) {
        p[i] = 0;
    }
}

static void sha3_fixed(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len, size_t rate) {
    crypto_sha3_ctx ctx;
    sponge_init(&ctx, rate, 0x06u);
    crypto_sha3_update(&ctx, in, in_len);
    crypto_sha3_finalize(&ctx);
    crypto_sha3_squeeze(&ctx, out, out_len);
    crypto_sha3_clear(&ctx);
}

void crypto_sha3_256(uint8_t out[32], const uint8_t *in, size_t in_len) {
    sha3_fixed(out, 32, in, in_len, 136u);
}

void crypto_sha3_512(uint8_t out[64], const uint8_t *in, size_t in_len) {
    sha3_fixed(out, 64, in, in_len, 72u);
}

void crypto_shake128(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len) {
    crypto_sha3_ctx ctx;
    crypto_shake128_init(&ctx);
    crypto_sha3_update(&ctx, in, in_len);
    crypto_sha3_finalize(&ctx);
    crypto_sha3_squeeze(&ctx, out, out_len);
    crypto_sha3_clear(&ctx);
}

void crypto_shake256(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len) {
    crypto_sha3_ctx ctx;
    crypto_shake256_init(&ctx);
    crypto_sha3_update(&ctx, in, in_len);
    crypto_sha3_finalize(&ctx);
    crypto_sha3_squeeze(&ctx, out, out_len);
    crypto_sha3_clear(&ctx);
}
