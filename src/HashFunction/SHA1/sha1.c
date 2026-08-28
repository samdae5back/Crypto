/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "HashFunction/SHA1/sha1_internal.h"

#include <string.h>

static uint32_t rol32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32u - n));
}

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24); p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);  p[3] = (uint8_t)x;
}

static void sha1_compress(crypto_sha1_context *ctx, const uint8_t block[64]) {
    uint32_t w[80], a, b, c, d, e, f, k, t;
    size_t i;
    for (i = 0; i < 16; ++i) w[i] = load_be32(block + 4u * i);
    for (; i < 80; ++i)
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    a = ctx->STATE[0]; b = ctx->STATE[1]; c = ctx->STATE[2];
    d = ctx->STATE[3]; e = ctx->STATE[4];
    for (i = 0; i < 80; ++i) {
        if (i < 20) { f = (b & c) | (~b & d); k = UINT32_C(0x5a827999); }
        else if (i < 40) { f = b ^ c ^ d; k = UINT32_C(0x6ed9eba1); }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = UINT32_C(0x8f1bbcdc); }
        else { f = b ^ c ^ d; k = UINT32_C(0xca62c1d6); }
        t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    ctx->STATE[0] += a; ctx->STATE[1] += b; ctx->STATE[2] += c;
    ctx->STATE[3] += d; ctx->STATE[4] += e;
    memset(w, 0, sizeof(w));
}

void crypto_sha1_init(crypto_sha1_context *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->STATE[0] = UINT32_C(0x67452301); ctx->STATE[1] = UINT32_C(0xefcdab89);
    ctx->STATE[2] = UINT32_C(0x98badcfe); ctx->STATE[3] = UINT32_C(0x10325476);
    ctx->STATE[4] = UINT32_C(0xc3d2e1f0);
}

LiberaCError crypto_sha1_update(crypto_sha1_context *ctx,
                                const uint8_t *input, size_t length) {
    size_t take;
    if (length > (UINT64_MAX - ctx->LENGTH) / 8u)
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    ctx->LENGTH += (uint64_t)length * 8u;
    while (length != 0u) {
        take = 64u - ctx->BUFFER_LENGTH;
        if (take > length) take = length;
        memcpy(ctx->BLOCK + ctx->BUFFER_LENGTH, input, take);
        ctx->BUFFER_LENGTH += take; input += take; length -= take;
        if (ctx->BUFFER_LENGTH == 64u) {
            sha1_compress(ctx, ctx->BLOCK); ctx->BUFFER_LENGTH = 0u;
        }
    }
    return LIBERAC_SUCCESS;
}

void crypto_sha1_finalize(crypto_sha1_context *ctx) {
    size_t i = ctx->BUFFER_LENGTH;
    uint64_t bits = ctx->LENGTH;
    ctx->BLOCK[i++] = 0x80u;
    if (i > 56u) { memset(ctx->BLOCK + i, 0, 64u - i); sha1_compress(ctx, ctx->BLOCK); i = 0u; }
    memset(ctx->BLOCK + i, 0, 56u - i);
    for (i = 0; i < 8; ++i) ctx->BLOCK[63u - i] = (uint8_t)(bits >> (8u * i));
    sha1_compress(ctx, ctx->BLOCK);
    ctx->BUFFER_LENGTH = 0u;
}

void crypto_sha1_squeeze(const crypto_sha1_context *ctx, uint8_t *output) {
    size_t i;
    for (i = 0; i < 5; ++i) store_be32(output + 4u * i, ctx->STATE[i]);
}
