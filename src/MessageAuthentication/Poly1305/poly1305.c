/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "MessageAuthentication/Poly1305/poly1305_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/Endian/endian_internal.h"

#include <string.h>

#define POLY1305_LIMB_MASK UINT32_C(0x03ffffff)
#define POLY1305_FULL_BLOCK_BIT UINT32_C(0x01000000)

void crypto_poly1305_init_internal(
    CryptoPoly1305Context *context,
    const uint8_t key[LIBERAC_POLY1305_KEY_BYTES]) {
    uint32_t t0 = crypto_load32_le(key);
    uint32_t t1 = crypto_load32_le(key + 4u);
    uint32_t t2 = crypto_load32_le(key + 8u);
    uint32_t t3 = crypto_load32_le(key + 12u);

    crypto_zeroize(context, sizeof(*context));

    /* Clamp r while decoding it into five 26-bit little-endian limbs. */
    context->R[0] = t0 & UINT32_C(0x03ffffff);
    context->R[1] = ((t0 >> 26) | (t1 << 6)) & UINT32_C(0x03ffff03);
    context->R[2] = ((t1 >> 20) | (t2 << 12)) & UINT32_C(0x03ffc0ff);
    context->R[3] = ((t2 >> 14) | (t3 << 18)) & UINT32_C(0x03f03fff);
    context->R[4] = (t3 >> 8) & UINT32_C(0x000fffff);

    context->PAD[0] = crypto_load32_le(key + 16u);
    context->PAD[1] = crypto_load32_le(key + 20u);
    context->PAD[2] = crypto_load32_le(key + 24u);
    context->PAD[3] = crypto_load32_le(key + 28u);

    crypto_zeroize(&t0, sizeof(t0));
    crypto_zeroize(&t1, sizeof(t1));
    crypto_zeroize(&t2, sizeof(t2));
    crypto_zeroize(&t3, sizeof(t3));
}

static void poly1305_blocks(
    CryptoPoly1305Context *context,
    const uint8_t *message, size_t message_length, uint32_t high_bit) {
    uint32_t r0 = context->R[0];
    uint32_t r1 = context->R[1];
    uint32_t r2 = context->R[2];
    uint32_t r3 = context->R[3];
    uint32_t r4 = context->R[4];
    uint32_t s1 = r1 * 5u;
    uint32_t s2 = r2 * 5u;
    uint32_t s3 = r3 * 5u;
    uint32_t s4 = r4 * 5u;
    uint32_t h0 = context->H[0];
    uint32_t h1 = context->H[1];
    uint32_t h2 = context->H[2];
    uint32_t h3 = context->H[3];
    uint32_t h4 = context->H[4];
    uint32_t t0 = 0u;
    uint32_t t1 = 0u;
    uint32_t t2 = 0u;
    uint32_t t3 = 0u;
    uint32_t carry = 0u;
    uint64_t d0 = 0u;
    uint64_t d1 = 0u;
    uint64_t d2 = 0u;
    uint64_t d3 = 0u;
    uint64_t d4 = 0u;

    while (message_length >= 16u) {
        t0 = crypto_load32_le(message);
        t1 = crypto_load32_le(message + 4u);
        t2 = crypto_load32_le(message + 8u);
        t3 = crypto_load32_le(message + 12u);

        h0 += t0 & POLY1305_LIMB_MASK;
        h1 += ((t0 >> 26) | (t1 << 6)) & POLY1305_LIMB_MASK;
        h2 += ((t1 >> 20) | (t2 << 12)) & POLY1305_LIMB_MASK;
        h3 += ((t2 >> 14) | (t3 << 18)) & POLY1305_LIMB_MASK;
        h4 += (t3 >> 8) | high_bit;

        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 +
             (uint64_t)h2 * s3 + (uint64_t)h3 * s2 +
             (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 +
             (uint64_t)h2 * s4 + (uint64_t)h3 * s3 +
             (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 +
             (uint64_t)h2 * r0 + (uint64_t)h3 * s4 +
             (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 +
             (uint64_t)h2 * r1 + (uint64_t)h3 * r0 +
             (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 +
             (uint64_t)h2 * r2 + (uint64_t)h3 * r1 +
             (uint64_t)h4 * r0;

        carry = (uint32_t)(d0 >> 26);
        h0 = (uint32_t)d0 & POLY1305_LIMB_MASK;
        d1 += carry;
        carry = (uint32_t)(d1 >> 26);
        h1 = (uint32_t)d1 & POLY1305_LIMB_MASK;
        d2 += carry;
        carry = (uint32_t)(d2 >> 26);
        h2 = (uint32_t)d2 & POLY1305_LIMB_MASK;
        d3 += carry;
        carry = (uint32_t)(d3 >> 26);
        h3 = (uint32_t)d3 & POLY1305_LIMB_MASK;
        d4 += carry;
        carry = (uint32_t)(d4 >> 26);
        h4 = (uint32_t)d4 & POLY1305_LIMB_MASK;
        h0 += carry * 5u;
        carry = h0 >> 26;
        h0 &= POLY1305_LIMB_MASK;
        h1 += carry;

        message += 16u;
        message_length -= 16u;
    }

    context->H[0] = h0;
    context->H[1] = h1;
    context->H[2] = h2;
    context->H[3] = h3;
    context->H[4] = h4;

    crypto_zeroize(&r0, sizeof(r0));
    crypto_zeroize(&r1, sizeof(r1));
    crypto_zeroize(&r2, sizeof(r2));
    crypto_zeroize(&r3, sizeof(r3));
    crypto_zeroize(&r4, sizeof(r4));
    crypto_zeroize(&s1, sizeof(s1));
    crypto_zeroize(&s2, sizeof(s2));
    crypto_zeroize(&s3, sizeof(s3));
    crypto_zeroize(&s4, sizeof(s4));
    crypto_zeroize(&h0, sizeof(h0));
    crypto_zeroize(&h1, sizeof(h1));
    crypto_zeroize(&h2, sizeof(h2));
    crypto_zeroize(&h3, sizeof(h3));
    crypto_zeroize(&h4, sizeof(h4));
    crypto_zeroize(&t0, sizeof(t0));
    crypto_zeroize(&t1, sizeof(t1));
    crypto_zeroize(&t2, sizeof(t2));
    crypto_zeroize(&t3, sizeof(t3));
    crypto_zeroize(&carry, sizeof(carry));
    crypto_zeroize(&d0, sizeof(d0));
    crypto_zeroize(&d1, sizeof(d1));
    crypto_zeroize(&d2, sizeof(d2));
    crypto_zeroize(&d3, sizeof(d3));
    crypto_zeroize(&d4, sizeof(d4));
}

void crypto_poly1305_update_internal(
    CryptoPoly1305Context *context,
    const uint8_t *message, size_t message_length) {
    if (context->LEFTOVER != 0u) {
        size_t wanted = 16u - context->LEFTOVER;
        if (wanted > message_length) wanted = message_length;
        if (wanted != 0u) {
            memcpy(context->BUFFER + context->LEFTOVER, message, wanted);
            message += wanted;
            message_length -= wanted;
            context->LEFTOVER += wanted;
        }
        if (context->LEFTOVER < 16u) return;
        poly1305_blocks(context, context->BUFFER, 16u,
                        POLY1305_FULL_BLOCK_BIT);
        context->LEFTOVER = 0u;
    }

    if (message_length >= 16u) {
        size_t complete = message_length & ~(size_t)15u;
        poly1305_blocks(context, message, complete,
                        POLY1305_FULL_BLOCK_BIT);
        message += complete;
        message_length -= complete;
    }

    if (message_length != 0u) {
        memcpy(context->BUFFER, message, message_length);
        context->LEFTOVER = message_length;
    }
}

void crypto_poly1305_final_internal(
    CryptoPoly1305Context *context,
    uint8_t tag[LIBERAC_POLY1305_TAG_BYTES]) {
    uint32_t h0;
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t h4;
    uint32_t g0;
    uint32_t g1;
    uint32_t g2;
    uint32_t g3;
    uint32_t g4;
    uint32_t mask;
    uint32_t carry;
    uint32_t word0;
    uint32_t word1;
    uint32_t word2;
    uint32_t word3;
    uint64_t sum;

    if (context->LEFTOVER != 0u) {
        context->BUFFER[context->LEFTOVER] = 1u;
        memset(context->BUFFER + context->LEFTOVER + 1u, 0,
               15u - context->LEFTOVER);
        poly1305_blocks(context, context->BUFFER, 16u, 0u);
    }

    h0 = context->H[0];
    h1 = context->H[1];
    h2 = context->H[2];
    h3 = context->H[3];
    h4 = context->H[4];

    carry = h1 >> 26;
    h1 &= POLY1305_LIMB_MASK;
    h2 += carry;
    carry = h2 >> 26;
    h2 &= POLY1305_LIMB_MASK;
    h3 += carry;
    carry = h3 >> 26;
    h3 &= POLY1305_LIMB_MASK;
    h4 += carry;
    carry = h4 >> 26;
    h4 &= POLY1305_LIMB_MASK;
    h0 += carry * 5u;
    carry = h0 >> 26;
    h0 &= POLY1305_LIMB_MASK;
    h1 += carry;

    /* Compute h - (2^130 - 5), then select it without a branch if h >= p. */
    g0 = h0 + 5u;
    carry = g0 >> 26;
    g0 &= POLY1305_LIMB_MASK;
    g1 = h1 + carry;
    carry = g1 >> 26;
    g1 &= POLY1305_LIMB_MASK;
    g2 = h2 + carry;
    carry = g2 >> 26;
    g2 &= POLY1305_LIMB_MASK;
    g3 = h3 + carry;
    carry = g3 >> 26;
    g3 &= POLY1305_LIMB_MASK;
    g4 = h4 + carry - (UINT32_C(1) << 26);

    mask = (g4 >> 31) - 1u;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* Form four low-endian words. Explicit truncation avoids double-counting
       limb bits when propagating only the addition carry between words. */
    word0 = h0 | (h1 << 26);
    word1 = (h1 >> 6) | (h2 << 20);
    word2 = (h2 >> 12) | (h3 << 14);
    word3 = (h3 >> 18) | (h4 << 8);

    sum = (uint64_t)word0 + context->PAD[0];
    crypto_store32_le(tag, (uint32_t)sum);
    sum = (uint64_t)word1 + context->PAD[1] + (sum >> 32);
    crypto_store32_le(tag + 4u, (uint32_t)sum);
    sum = (uint64_t)word2 + context->PAD[2] + (sum >> 32);
    crypto_store32_le(tag + 8u, (uint32_t)sum);
    sum = (uint64_t)word3 + context->PAD[3] + (sum >> 32);
    crypto_store32_le(tag + 12u, (uint32_t)sum);

    crypto_zeroize(context, sizeof(*context));
    crypto_zeroize(&h0, sizeof(h0));
    crypto_zeroize(&h1, sizeof(h1));
    crypto_zeroize(&h2, sizeof(h2));
    crypto_zeroize(&h3, sizeof(h3));
    crypto_zeroize(&h4, sizeof(h4));
    crypto_zeroize(&g0, sizeof(g0));
    crypto_zeroize(&g1, sizeof(g1));
    crypto_zeroize(&g2, sizeof(g2));
    crypto_zeroize(&g3, sizeof(g3));
    crypto_zeroize(&g4, sizeof(g4));
    crypto_zeroize(&mask, sizeof(mask));
    crypto_zeroize(&carry, sizeof(carry));
    crypto_zeroize(&word0, sizeof(word0));
    crypto_zeroize(&word1, sizeof(word1));
    crypto_zeroize(&word2, sizeof(word2));
    crypto_zeroize(&word3, sizeof(word3));
    crypto_zeroize(&sum, sizeof(sum));
}

void crypto_poly1305_internal(
    uint8_t tag[LIBERAC_POLY1305_TAG_BYTES],
    const uint8_t *message, size_t message_length,
    const uint8_t key[LIBERAC_POLY1305_KEY_BYTES]) {
    CryptoPoly1305Context context;

    crypto_poly1305_init_internal(&context, key);
    crypto_poly1305_update_internal(&context, message, message_length);
    crypto_poly1305_final_internal(&context, tag);
}

#undef POLY1305_LIMB_MASK
#undef POLY1305_FULL_BLOCK_BIT
