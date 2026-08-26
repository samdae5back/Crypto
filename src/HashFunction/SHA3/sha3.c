#include "SHA3.h"
#include "sha3_internal.h"
#include "Util/Core/secure_zero.h"
#include <string.h>

static uint64_t rol64(uint64_t x, unsigned n) { return n ? ((x << n) | (x >> (64u - n))) : x; }

void sha3_keccak_f1600(uint64_t s[25]) {
    static const uint64_t rc[24] = {
        0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
        0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
        0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
        0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
        0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
        0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
    };
    static const unsigned r[25] = {
        0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14
    };
    unsigned round, x, y;
    for (round = 0; round < 24; ++round) {
        uint64_t c[5], d[5], b[25];
        for (x = 0; x < 5; ++x) c[x] = s[x]^s[x+5]^s[x+10]^s[x+15]^s[x+20];
        for (x = 0; x < 5; ++x) d[x] = c[(x+4)%5] ^ rol64(c[(x+1)%5],1);
        for (y = 0; y < 5; ++y) for (x = 0; x < 5; ++x) s[x+5*y] ^= d[x];
        for (y = 0; y < 5; ++y) for (x = 0; x < 5; ++x) {
            unsigned nx = y;
            unsigned ny = (2*x + 3*y) % 5;
            b[nx + 5*ny] = rol64(s[x+5*y], r[x+5*y]);
        }
        for (y = 0; y < 5; ++y) for (x = 0; x < 5; ++x)
            s[x+5*y] = b[x+5*y] ^ ((~b[(x+1)%5+5*y]) & b[(x+2)%5+5*y]);
        s[0] ^= rc[round];
        crypto_zeroize(c, sizeof(c));
        crypto_zeroize(d, sizeof(d));
        crypto_zeroize(b, sizeof(b));
    }
}

static void ctx_init(SHA3_CONTEXT *ctx, size_t rate, uint8_t domain) {
    crypto_zeroize(ctx, sizeof(*ctx));
    ctx->RATE = rate;
    ctx->DOMAIN = domain;
}

static void xor_byte(SHA3_CONTEXT *ctx, size_t pos, uint8_t v) {
    size_t lane = pos / 8u;
    unsigned shift = (unsigned)(8u * (pos % 8u));
    ctx->STATE[lane] ^= (uint64_t)v << shift;
}

static uint8_t get_byte(const SHA3_CONTEXT *ctx, size_t pos) {
    size_t lane = pos / 8u;
    unsigned shift = (unsigned)(8u * (pos % 8u));
    return (uint8_t)(ctx->STATE[lane] >> shift);
}

void CRYPTO_SHAKE128_INIT(SHA3_CONTEXT *CONTEXT) { if (CONTEXT) ctx_init(CONTEXT, 168u, 0x1fu); }
void CRYPTO_SHAKE256_INIT(SHA3_CONTEXT *CONTEXT) { if (CONTEXT) ctx_init(CONTEXT, 136u, 0x1fu); }

void CRYPTO_SHA3_UPDATE(SHA3_CONTEXT *CONTEXT, const uint8_t *IN, size_t IN_LENGTH) {
    size_t i;
    if (!CONTEXT || (!IN && IN_LENGTH) || CONTEXT->FINALIZED) return;
    for (i = 0; i < IN_LENGTH; ++i) {
        xor_byte(CONTEXT, CONTEXT->POS, IN[i]);
        if (++CONTEXT->POS == CONTEXT->RATE) {
            sha3_keccak_f1600(CONTEXT->STATE);
            CONTEXT->POS = 0;
        }
    }
}

void CRYPTO_SHA3_FINALIZE(SHA3_CONTEXT *CONTEXT) {
    if (!CONTEXT || CONTEXT->FINALIZED) return;
    xor_byte(CONTEXT, CONTEXT->POS, CONTEXT->DOMAIN);
    xor_byte(CONTEXT, CONTEXT->RATE - 1u, 0x80u);
    sha3_keccak_f1600(CONTEXT->STATE);
    CONTEXT->POS = 0;
    CONTEXT->FINALIZED = 1;
}

void CRYPTO_SHA3_SQUEEZE(SHA3_CONTEXT *CONTEXT, uint8_t *OUT, size_t OUT_LENGTH) {
    size_t i;
    if (!CONTEXT || (!OUT && OUT_LENGTH)) return;
    if (!CONTEXT->FINALIZED) CRYPTO_SHA3_FINALIZE(CONTEXT);
    for (i = 0; i < OUT_LENGTH; ++i) {
        if (CONTEXT->POS == CONTEXT->RATE) {
            sha3_keccak_f1600(CONTEXT->STATE);
            CONTEXT->POS = 0;
        }
        OUT[i] = get_byte(CONTEXT, CONTEXT->POS++);
    }
}

void CRYPTO_SHA3_CLEAR(SHA3_CONTEXT *CONTEXT) {
    if (CONTEXT) crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
}

static void hash_fixed(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len, size_t rate) {
    SHA3_CONTEXT ctx;
    ctx_init(&ctx, rate, 0x06u);
    CRYPTO_SHA3_UPDATE(&ctx, in, in_len);
    CRYPTO_SHA3_SQUEEZE(&ctx, out, out_len);
    CRYPTO_SHA3_CLEAR(&ctx);
}

void CRYPTO_SHA3_256(uint8_t OUT[SHA3_256_DIGEST_SIZE], const uint8_t *IN, size_t IN_LENGTH) { hash_fixed(OUT, 32u, IN, IN_LENGTH, 136u); }
void CRYPTO_SHA3_512(uint8_t OUT[SHA3_512_DIGEST_SIZE], const uint8_t *IN, size_t IN_LENGTH) { hash_fixed(OUT, 64u, IN, IN_LENGTH, 72u); }
void CRYPTO_SHAKE128(uint8_t *OUT, size_t OUT_LENGTH, const uint8_t *IN, size_t IN_LENGTH) { SHA3_CONTEXT c; CRYPTO_SHAKE128_INIT(&c); CRYPTO_SHA3_UPDATE(&c,IN,IN_LENGTH); CRYPTO_SHA3_SQUEEZE(&c,OUT,OUT_LENGTH); CRYPTO_SHA3_CLEAR(&c); }
void CRYPTO_SHAKE256(uint8_t *OUT, size_t OUT_LENGTH, const uint8_t *IN, size_t IN_LENGTH) { SHA3_CONTEXT c; CRYPTO_SHAKE256_INIT(&c); CRYPTO_SHA3_UPDATE(&c,IN,IN_LENGTH); CRYPTO_SHA3_SQUEEZE(&c,OUT,OUT_LENGTH); CRYPTO_SHA3_CLEAR(&c); }
