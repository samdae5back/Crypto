/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "bignum_internal.h"
#include "Util/Core/secure_zero.h"

#include <stdlib.h>
#include <string.h>

LiberaCError crypto_bignum_copy_secret_fixed(LiberaCBignum *out,
                                             const LiberaCBignum *in,
                                             size_t fixed_limbs) {
    LiberaCBignum tmp;
    if (!out || !in || in->LENGTH > fixed_limbs)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    crypto_bignum_init(&tmp);
    if (fixed_limbs != 0u && bignum_reserve(&tmp, fixed_limbs) != 0)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    if (fixed_limbs != 0u)
        memset(tmp.LIMBS, 0, fixed_limbs * sizeof(uint32_t));
    if (in->LENGTH != 0u)
        memcpy(tmp.LIMBS, in->LIMBS, in->LENGTH * sizeof(uint32_t));
    tmp.LENGTH = in->LENGTH;
    crypto_bignum_free(out);
    *out = tmp;
    return LIBERAC_SUCCESS;
}

static int bignum_square_add_product(uint32_t *limbs, size_t limb_count,
                                     size_t offset, uint64_t product) {
    uint64_t sum, carry;
    if (!limbs || offset >= limb_count) return -1;

    sum = (uint64_t)limbs[offset] + (uint32_t)product;
    limbs[offset] = (uint32_t)sum;
    carry = (product >> 32) + (sum >> 32);
    ++offset;

    while (carry != 0u && offset < limb_count) {
        sum = (uint64_t)limbs[offset] + (uint32_t)carry;
        limbs[offset] = (uint32_t)sum;
        carry = (carry >> 32) + (sum >> 32);
        ++offset;
    }
    return carry == 0u ? 0 : -1;
}

LiberaCError crypto_bignum_square(LiberaCBignum *out,
                                  const LiberaCBignum *a) {
    LiberaCBignum tmp;
    size_t n, i, j, limbs;
    if (!out || !a) return LIBERAC_ERROR_INVALID_ARGUMENT;

    crypto_bignum_init(&tmp);
    n = a->LENGTH;
    if (n == 0u) {
        crypto_bignum_free(out);
        *out = tmp;
        return LIBERAC_SUCCESS;
    }
    if (n > (SIZE_MAX - 1u) / 2u)
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    limbs = 2u * n + 1u;
    if (bignum_reserve(&tmp, limbs) != 0)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    memset(tmp.LIMBS, 0, limbs * sizeof(uint32_t));

    /* Variable-time fast path: exploit symmetry so each a[i]*a[j] cross
     * product is computed once and accumulated twice.  This roughly halves
     * wide limb multiplications compared with generic schoolbook a*a. */
    for (i = 0u; i < n; ++i) {
        uint64_t diagonal = (uint64_t)a->LIMBS[i] * a->LIMBS[i];
        if (bignum_square_add_product(tmp.LIMBS, limbs, 2u * i,
                                      diagonal) != 0)
            goto fail;
        for (j = i + 1u; j < n; ++j) {
            uint64_t cross = (uint64_t)a->LIMBS[i] * a->LIMBS[j];
            if (bignum_square_add_product(tmp.LIMBS, limbs, i + j,
                                          cross) != 0 ||
                bignum_square_add_product(tmp.LIMBS, limbs, i + j,
                                          cross) != 0)
                goto fail;
        }
    }

    tmp.LENGTH = limbs;
    bignum_normalize(&tmp);
    crypto_bignum_free(out);
    *out = tmp;
    return LIBERAC_SUCCESS;

fail:
    crypto_bignum_free(&tmp);
    return LIBERAC_ERROR_ARITHMETIC;
}

LiberaCError crypto_bignum_mod_square(LiberaCBignum *out,
                                      const LiberaCBignum *a,
                                      const LiberaCBignum *modulus) {
    LiberaCBignum square;
    LiberaCError err;
    if (!out || !a || !modulus || modulus->LENGTH == 0u)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    crypto_bignum_init(&square);
    err = crypto_bignum_square(&square, a);
    if (err == LIBERAC_SUCCESS)
        err = crypto_bignum_mod(out, &square, modulus);
    crypto_bignum_free(&square);
    return err;
}

typedef struct {
    size_t n;
    uint32_t n0inv;
    uint32_t *storage;
    uint32_t *mod;
    uint32_t *r2;
    uint32_t *work;
} BignumCtMontCtx;

typedef struct {
    uint32_t *base_m;
    uint32_t *acc;
    uint32_t *square;
    uint32_t *product;
} BignumCtExpState;

static uint32_t bignum_ct_n0inv(uint32_t n0) {
    uint32_t x = 1u;
    unsigned i;
    for (i = 0u; i < 5u; ++i) x *= 2u - n0 * x;
    return (uint32_t)(0u - x);
}

static void bignum_ct_mont_clear(BignumCtMontCtx *ctx) {
    size_t words;
    if (!ctx) return;
    if (ctx->storage) {
        words = 3u * ctx->n + 2u;
        crypto_zeroize(ctx->storage, words * sizeof(uint32_t));
        free(ctx->storage);
    }
    memset(ctx, 0, sizeof(*ctx));
}

static int bignum_ct_mont_init(BignumCtMontCtx *ctx,
                               const LiberaCBignum *modulus) {
    LiberaCBignum x, reduced;
    size_t i, rounds, words;
    if (!ctx || !modulus || modulus->LENGTH == 0u ||
        !(modulus->LIMBS[0] & 1u))
        return -1;
    if (modulus->LENGTH > (SIZE_MAX - 2u) / 3u ||
        modulus->LENGTH > SIZE_MAX / 64u)
        return -1;

    memset(ctx, 0, sizeof(*ctx));
    ctx->n = modulus->LENGTH;
    ctx->n0inv = bignum_ct_n0inv(modulus->LIMBS[0]);
    words = 3u * ctx->n + 2u;
    ctx->storage = (uint32_t *)calloc(words, sizeof(uint32_t));
    if (!ctx->storage) return -1;
    ctx->mod = ctx->storage;
    ctx->r2 = ctx->mod + ctx->n;
    ctx->work = ctx->r2 + ctx->n;
    memcpy(ctx->mod, modulus->LIMBS, ctx->n * sizeof(uint32_t));

    /* R^2 setup depends only on the public modulus and is performed once per
     * exponentiation context. */
    crypto_bignum_init(&x);
    crypto_bignum_init(&reduced);
    if (crypto_bignum_set_u64(&x, 1u) != LIBERAC_SUCCESS) goto fail;
    rounds = 64u * ctx->n;
    for (i = 0u; i < rounds; ++i) {
        if (bignum_shift_left_one(&x) != 0) goto fail;
        if (crypto_bignum_compare(&x, modulus) >= 0) {
            if (crypto_bignum_sub(&reduced, &x, modulus) != LIBERAC_SUCCESS)
                goto fail;
            crypto_bignum_free(&x);
            x = reduced;
            crypto_bignum_init(&reduced);
        }
    }
    if (x.LENGTH > ctx->n) goto fail;
    memcpy(ctx->r2, x.LIMBS, x.LENGTH * sizeof(uint32_t));
    crypto_bignum_free(&x);
    crypto_bignum_free(&reduced);
    return 0;

fail:
    crypto_bignum_free(&x);
    crypto_bignum_free(&reduced);
    bignum_ct_mont_clear(ctx);
    return -1;
}

static void bignum_ct_select(uint32_t *out, const uint32_t *zero_choice,
                             const uint32_t *one_choice, size_t n,
                             uint32_t bit) {
    uint32_t mask = 0u - (bit & 1u);
    size_t i;
    for (i = 0u; i < n; ++i)
        out[i] = (zero_choice[i] & ~mask) | (one_choice[i] & mask);
}

static int bignum_ct_mont_mul(uint32_t *out, const uint32_t *a,
                              const uint32_t *b, BignumCtMontCtx *ctx) {
    uint32_t *t;
    uint32_t borrow, use_subtracted, mask;
    size_t n, i, j;
    if (!out || !a || !b || !ctx || !ctx->work) return -1;
    n = ctx->n;
    t = ctx->work;
    memset(t, 0, (n + 2u) * sizeof(uint32_t));

    /* Coarsely integrated operand scanning Montgomery multiplication.  Loops
     * and memory indices depend only on the public modulus width. */
    for (i = 0u; i < n; ++i) {
        uint64_t carry = 0u;
        for (j = 0u; j < n; ++j) {
            uint64_t z = (uint64_t)a[j] * b[i] + t[j] + carry;
            t[j] = (uint32_t)z;
            carry = z >> 32;
        }
        {
            uint64_t z = (uint64_t)t[n] + carry;
            t[n] = (uint32_t)z;
            t[n + 1u] += (uint32_t)(z >> 32);
        }

        {
            uint32_t m = t[0] * ctx->n0inv;
            carry = 0u;
            for (j = 0u; j < n; ++j) {
                uint64_t z = (uint64_t)m * ctx->mod[j] + t[j] + carry;
                t[j] = (uint32_t)z;
                carry = z >> 32;
            }
            {
                uint64_t z = (uint64_t)t[n] + carry;
                t[n] = (uint32_t)z;
                t[n + 1u] += (uint32_t)(z >> 32);
            }
        }

        for (j = 0u; j <= n; ++j) t[j] = t[j + 1u];
        t[n + 1u] = 0u;
    }

    /* Compute candidate-modulus, then mask-select it iff candidate >= modulus.
     * This replaces the data-dependent final subtraction branch. */
    borrow = 0u;
    for (i = 0u; i < n; ++i) {
        uint64_t subtrahend = (uint64_t)ctx->mod[i] + borrow;
        uint64_t minuend = t[i];
        out[i] = (uint32_t)(minuend - subtrahend);
        borrow = (uint32_t)(minuend < subtrahend);
    }
    {
        uint64_t high = t[n];
        uint64_t subtrahend = borrow;
        borrow = (uint32_t)(high < subtrahend);
    }
    use_subtracted = borrow ^ 1u;
    mask = 0u - use_subtracted;
    for (i = 0u; i < n; ++i)
        out[i] = (out[i] & mask) | (t[i] & ~mask);
    return 0;
}

static LiberaCError bignum_ct_store_fixed(LiberaCBignum *out,
                                          const uint32_t *words, size_t n) {
    LiberaCBignum tmp;
    size_t i, length = 0u;
    if (!out || (!words && n != 0u)) return LIBERAC_ERROR_INVALID_ARGUMENT;
    crypto_bignum_init(&tmp);
    if (n != 0u && bignum_reserve(&tmp, n) != 0)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    if (n != 0u) memcpy(tmp.LIMBS, words, n * sizeof(uint32_t));

    /* Fixed-count normalization: no early exit based on the result value. */
    for (i = 0u; i < n; ++i) {
        uint32_t x = words[i];
        uint32_t nonzero = (x | (uint32_t)(0u - x)) >> 31;
        size_t mask = (size_t)0 - (size_t)nonzero;
        length = (length & ~mask) | ((i + 1u) & mask);
    }
    tmp.LENGTH = length;
    crypto_bignum_free(out);
    *out = tmp;
    return LIBERAC_SUCCESS;
}

static LiberaCError bignum_mod_exp_ct_core(
    LiberaCBignum *out1, const LiberaCBignum *base1,
    LiberaCBignum *out2, const LiberaCBignum *base2,
    const LiberaCBignum *exponent, const LiberaCBignum *modulus) {
    BignumCtMontCtx ctx;
    BignumCtExpState states[2];
    uint32_t *buffer = NULL, *one, *one_m, *cursor;
    size_t count, n, bits, bit_index, s, buffer_words;
    LiberaCError err = LIBERAC_ERROR_ARITHMETIC;

    if (!out1 || !base1 || !exponent || !modulus || modulus->LENGTH == 0u)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if ((out2 == NULL) != (base2 == NULL))
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (!(modulus->LIMBS[0] & 1u))
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (crypto_bignum_compare(base1, modulus) >= 0 ||
        (base2 && crypto_bignum_compare(base2, modulus) >= 0))
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    count = base2 ? 2u : 1u;
    n = modulus->LENGTH;
    if (exponent->CAPACITY < n)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (n > SIZE_MAX / 32u || n > SIZE_MAX / (2u + 4u * count))
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;

    memset(&ctx, 0, sizeof(ctx));
    memset(states, 0, sizeof(states));
    if (bignum_ct_mont_init(&ctx, modulus) != 0)
        return LIBERAC_ERROR_ALLOCATION_FAILED;

    buffer_words = (2u + 4u * count) * n;
    buffer = (uint32_t *)calloc(buffer_words, sizeof(uint32_t));
    if (!buffer) {
        bignum_ct_mont_clear(&ctx);
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    }
    one = buffer;
    one_m = one + n;
    cursor = one_m + n;
    one[0] = 1u;
    if (bignum_ct_mont_mul(one_m, one, ctx.r2, &ctx) != 0) goto done;

    for (s = 0u; s < count; ++s) {
        const LiberaCBignum *base = s == 0u ? base1 : base2;
        size_t i;
        states[s].base_m = cursor; cursor += n;
        states[s].acc = cursor; cursor += n;
        states[s].square = cursor; cursor += n;
        states[s].product = cursor; cursor += n;

        memset(states[s].square, 0, n * sizeof(uint32_t));
        for (i = 0u; i < base->LENGTH; ++i)
            states[s].square[i] = base->LIMBS[i];
        if (bignum_ct_mont_mul(states[s].base_m, states[s].square,
                              ctx.r2, &ctx) != 0)
            goto done;
        memcpy(states[s].acc, one_m, n * sizeof(uint32_t));
    }

    /* Scan the full modulus storage width, not the exponent bit length.  Every
     * exponent bit performs both candidate operations and then mask-selects. */
    bits = 32u * n;
    for (bit_index = bits; bit_index > 0u; --bit_index) {
        size_t bit = bit_index - 1u;
        uint32_t exponent_bit =
            (exponent->LIMBS[bit / 32u] >> (bit % 32u)) & 1u;
        for (s = 0u; s < count; ++s) {
            if (bignum_ct_mont_mul(states[s].square, states[s].acc,
                                   states[s].acc, &ctx) != 0 ||
                bignum_ct_mont_mul(states[s].product, states[s].square,
                                   states[s].base_m, &ctx) != 0)
                goto done;
            bignum_ct_select(states[s].acc, states[s].square,
                             states[s].product, n, exponent_bit);
        }
    }

    if (bignum_ct_mont_mul(states[0].square, states[0].acc, one, &ctx) != 0)
        goto done;
    err = bignum_ct_store_fixed(out1, states[0].square, n);
    if (err != LIBERAC_SUCCESS) goto done;

    if (count == 2u) {
        if (bignum_ct_mont_mul(states[1].square, states[1].acc, one,
                               &ctx) != 0) {
            err = LIBERAC_ERROR_ARITHMETIC;
            goto done;
        }
        err = bignum_ct_store_fixed(out2, states[1].square, n);
        if (err != LIBERAC_SUCCESS) goto done;
    }
    err = LIBERAC_SUCCESS;

done:
    if (buffer) {
        crypto_zeroize(buffer, buffer_words * sizeof(uint32_t));
        free(buffer);
    }
    bignum_ct_mont_clear(&ctx);
    return err;
}

LiberaCError crypto_bignum_mod_exp_ct(LiberaCBignum *out,
                                      const LiberaCBignum *base,
                                      const LiberaCBignum *exponent,
                                      const LiberaCBignum *modulus) {
    return bignum_mod_exp_ct_core(out, base, NULL, NULL, exponent, modulus);
}

LiberaCError crypto_bignum_mod_exp2_ct(LiberaCBignum *out1,
                                       const LiberaCBignum *base1,
                                       LiberaCBignum *out2,
                                       const LiberaCBignum *base2,
                                       const LiberaCBignum *exponent,
                                       const LiberaCBignum *modulus) {
    if (!out2 || !base2 || out1 == out2)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    return bignum_mod_exp_ct_core(out1, base1, out2, base2,
                                  exponent, modulus);
}
