/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "bignum_internal.h"
#include "Util/Core/secure_zero.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t n;
    uint32_t n0inv;
    uint32_t *storage;
    uint32_t *mod;
    uint32_t *r2;
    uint32_t *work;
} BignumVtMontCtx;

static uint32_t bignum_vt_n0inv(uint32_t n0) {
    uint32_t x = 1u;
    unsigned i;
    for (i = 0u; i < 5u; ++i) x *= 2u - n0 * x;
    return (uint32_t)(0u - x);
}

static void bignum_vt_mont_clear(BignumVtMontCtx *ctx) {
    size_t words;
    if (!ctx) return;
    if (ctx->storage) {
        words = 3u * ctx->n + 2u;
        crypto_zeroize(ctx->storage, words * sizeof(uint32_t));
        free(ctx->storage);
    }
    memset(ctx, 0, sizeof(*ctx));
}

static int bignum_vt_mont_init(BignumVtMontCtx *ctx,
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
    ctx->n0inv = bignum_vt_n0inv(modulus->LIMBS[0]);
    words = 3u * ctx->n + 2u;
    ctx->storage = (uint32_t *)calloc(words, sizeof(uint32_t));
    if (!ctx->storage) return -1;
    ctx->mod = ctx->storage;
    ctx->r2 = ctx->mod + ctx->n;
    ctx->work = ctx->r2 + ctx->n;
    memcpy(ctx->mod, modulus->LIMBS, ctx->n * sizeof(uint32_t));

    /* R^2 depends only on the public modulus.  Build it once and reuse it for
     * every Montgomery conversion and table entry in this exponentiation. */
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
    if (x.LENGTH)
        memcpy(ctx->r2, x.LIMBS, x.LENGTH * sizeof(uint32_t));
    crypto_bignum_free(&x);
    crypto_bignum_free(&reduced);
    return 0;

fail:
    crypto_bignum_free(&x);
    crypto_bignum_free(&reduced);
    bignum_vt_mont_clear(ctx);
    return -1;
}

static int bignum_vt_ge_mod(const uint32_t *candidate,
                            const BignumVtMontCtx *ctx) {
    size_t i;
    if (candidate[ctx->n] != 0u) return 1;
    /* Public-data early exit: stop at the first differing high limb. */
    for (i = ctx->n; i > 0u; --i) {
        uint32_t a = candidate[i - 1u];
        uint32_t b = ctx->mod[i - 1u];
        if (a > b) return 1;
        if (a < b) return 0;
    }
    return 1;
}

static int bignum_vt_mont_mul(uint32_t *out, const uint32_t *a,
                              const uint32_t *b, BignumVtMontCtx *ctx) {
    uint32_t *t;
    size_t n, i, j;
    if (!out || !a || !b || !ctx || !ctx->work) return -1;
    n = ctx->n;
    t = ctx->work;
    memset(t, 0, (n + 2u) * sizeof(uint32_t));

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

    if (bignum_vt_ge_mod(t, ctx)) {
        uint32_t borrow = 0u;
        for (i = 0u; i < n; ++i) {
            uint64_t subtrahend = (uint64_t)ctx->mod[i] + borrow;
            uint64_t minuend = t[i];
            out[i] = (uint32_t)(minuend - subtrahend);
            borrow = (uint32_t)(minuend < subtrahend);
        }
    } else {
        memcpy(out, t, n * sizeof(uint32_t));
    }
    return 0;
}

static unsigned bignum_vt_window_bits(size_t exponent_bits) {
    /* Small tables keep setup cheap for Miller-Rabin while larger public
     * exponents benefit from fewer multiply steps. */
    if (exponent_bits < 24u) return 1u;
    if (exponent_bits < 80u) return 2u;
    if (exponent_bits < 240u) return 3u;
    if (exponent_bits < 672u) return 4u;
    return 5u;
}

static int bignum_vt_is_u32(const LiberaCBignum *value, uint32_t expected) {
    if (!value) return 0;
    if (expected == 0u) return value->LENGTH == 0u;
    return value->LENGTH == 1u && value->LIMBS[0] == expected;
}

static LiberaCError bignum_vt_store(LiberaCBignum *out,
                                    const uint32_t *words, size_t n) {
    LiberaCBignum tmp;
    size_t length = n;
    if (!out || (!words && n)) return LIBERAC_ERROR_INVALID_ARGUMENT;
    /* Public-data early exit: normalization stops at the first nonzero limb. */
    while (length != 0u && words[length - 1u] == 0u) --length;
    crypto_bignum_init(&tmp);
    if (length != 0u && bignum_reserve(&tmp, length) != 0)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    if (length != 0u)
        memcpy(tmp.LIMBS, words, length * sizeof(uint32_t));
    tmp.LENGTH = length;
    crypto_bignum_free(out);
    *out = tmp;
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_bignum_mod_exp_vartime(
    LiberaCBignum *out, const LiberaCBignum *base,
    const LiberaCBignum *exponent, const LiberaCBignum *modulus) {
    BignumVtMontCtx ctx;
    LiberaCBignum reduced;
    uint32_t *buffer = NULL;
    uint32_t *one, *one_m, *base_words, *base_m, *base2, *acc, *tmp, *result;
    uint32_t *table;
    size_t n, bits, table_count, buffer_words, i, k;
    unsigned window_bits;
    LiberaCError err = LIBERAC_ERROR_ARITHMETIC;

    if (!out || !base || !exponent || !modulus || modulus->LENGTH == 0u)
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    /* This path intentionally exploits public values.  Cheap identities avoid
     * Montgomery/table setup altogether. */
    if (bignum_vt_is_u32(modulus, 1u)) {
        LiberaCBignum zero;
        crypto_bignum_init(&zero);
        crypto_bignum_free(out);
        *out = zero;
        return LIBERAC_SUCCESS;
    }
    if (exponent->LENGTH == 0u)
        return crypto_bignum_set_u64(out, 1u);
    if (bignum_vt_is_u32(exponent, 1u))
        return crypto_bignum_mod(out, base, modulus);
    if (bignum_vt_is_u32(exponent, 2u))
        return crypto_bignum_mod_square(out, base, modulus);

    /* The optimized Montgomery engine requires an odd modulus.  The legacy
     * variable-time path remains the compatibility fallback for even moduli. */
    if (!(modulus->LIMBS[0] & 1u))
        return crypto_bignum_mod_exp(out, base, exponent, modulus);

    crypto_bignum_init(&reduced);
    if (crypto_bignum_compare(base, modulus) < 0) {
        if (crypto_bignum_copy(&reduced, base) != LIBERAC_SUCCESS)
            return LIBERAC_ERROR_ALLOCATION_FAILED;
    } else if (crypto_bignum_mod(&reduced, base, modulus) != LIBERAC_SUCCESS) {
        return LIBERAC_ERROR_ARITHMETIC;
    }
    if (reduced.LENGTH == 0u) {
        crypto_bignum_free(out);
        *out = reduced;
        return LIBERAC_SUCCESS;
    }
    if (bignum_vt_is_u32(&reduced, 1u)) {
        crypto_bignum_free(&reduced);
        return crypto_bignum_set_u64(out, 1u);
    }

    bits = crypto_bignum_bit_length(exponent);
    window_bits = bignum_vt_window_bits(bits);
    table_count = (size_t)1u << (window_bits - 1u);
    n = modulus->LENGTH;
    if (n > SIZE_MAX / (8u + table_count)) {
        crypto_bignum_free(&reduced);
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }

    memset(&ctx, 0, sizeof(ctx));
    if (bignum_vt_mont_init(&ctx, modulus) != 0) {
        crypto_bignum_free(&reduced);
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    }

    buffer_words = (8u + table_count) * n;
    buffer = (uint32_t *)calloc(buffer_words, sizeof(uint32_t));
    if (!buffer) {
        bignum_vt_mont_clear(&ctx);
        crypto_bignum_free(&reduced);
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    }
    one = buffer;
    one_m = one + n;
    base_words = one_m + n;
    base_m = base_words + n;
    base2 = base_m + n;
    acc = base2 + n;
    tmp = acc + n;
    result = tmp + n;
    table = result + n;

    one[0] = 1u;
    memcpy(base_words, reduced.LIMBS,
           reduced.LENGTH * sizeof(uint32_t));
    if (bignum_vt_mont_mul(one_m, one, ctx.r2, &ctx) != 0 ||
        bignum_vt_mont_mul(base_m, base_words, ctx.r2, &ctx) != 0)
        goto done;

    memcpy(table, base_m, n * sizeof(uint32_t));
    if (table_count > 1u) {
        if (bignum_vt_mont_mul(base2, base_m, base_m, &ctx) != 0)
            goto done;
        for (k = 1u; k < table_count; ++k) {
            if (bignum_vt_mont_mul(table + k * n,
                                  table + (k - 1u) * n,
                                  base2, &ctx) != 0)
                goto done;
        }
    }

    memcpy(acc, one_m, n * sizeof(uint32_t));
    i = bits;
    while (i != 0u) {
        size_t low, j, squarings;
        unsigned value = 0u;

        /* Public-data early skip: a zero exponent bit only needs one square. */
        if (!bignum_get_bit(exponent, i - 1u)) {
            if (bignum_vt_mont_mul(tmp, acc, acc, &ctx) != 0) goto done;
            { uint32_t *swap = acc; acc = tmp; tmp = swap; }
            --i;
            continue;
        }

        low = i > window_bits ? i - window_bits : 0u;
        /* Sliding-window early trim: exclude low zero bits so the selected
         * window is odd and maps directly to the odd-power lookup table. */
        while (low < i - 1u && !bignum_get_bit(exponent, low)) ++low;
        for (j = i; j > low; --j)
            value = (value << 1) |
                    (unsigned)bignum_get_bit(exponent, j - 1u);

        squarings = i - low;
        for (j = 0u; j < squarings; ++j) {
            if (bignum_vt_mont_mul(tmp, acc, acc, &ctx) != 0) goto done;
            { uint32_t *swap = acc; acc = tmp; tmp = swap; }
        }

        /* The table index is derived from a public exponent.  This direct
         * lookup is intentionally confined to the variable-time path. */
        k = ((size_t)value - 1u) >> 1;
        if (k >= table_count ||
            bignum_vt_mont_mul(tmp, acc, table + k * n, &ctx) != 0)
            goto done;
        { uint32_t *swap = acc; acc = tmp; tmp = swap; }
        i = low;
    }

    if (bignum_vt_mont_mul(result, acc, one, &ctx) != 0) goto done;
    err = bignum_vt_store(out, result, n);

done:
    crypto_bignum_free(&reduced);
    if (buffer) {
        /* Public values do not require this wipe for confidentiality, but keep
         * allocation lifetime behavior consistent with the rest of bignum. */
        crypto_zeroize(buffer, buffer_words * sizeof(uint32_t));
        free(buffer);
    }
    bignum_vt_mont_clear(&ctx);
    return err;
}
