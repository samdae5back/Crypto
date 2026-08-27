#include "bignum_internal.h"
#include "RandomNumberGeneration/Noise/random_internal.h"

#include <stdlib.h>
#include <string.h>

void crypto_bignum_init(CRYPTO_BIGNUM *VALUE) {
    if (!VALUE) return;
    VALUE->LIMBS = NULL;
    VALUE->LENGTH = 0;
    VALUE->CAPACITY = 0;
}

void crypto_bignum_free(CRYPTO_BIGNUM *VALUE) {
    if (!VALUE) return;
    if (VALUE->LIMBS) {
        volatile uint32_t *p = (volatile uint32_t *)VALUE->LIMBS;
        size_t i;
        for (i = 0; i < VALUE->CAPACITY; ++i) p[i] = 0;
        free(VALUE->LIMBS);
    }
    crypto_bignum_init(VALUE);
}

int bignum_reserve(CRYPTO_BIGNUM *a, size_t capacity) {
    uint32_t *p;
    size_t old;
    if (!a) return -1;
    if (capacity <= a->CAPACITY) return 0;
    old = a->CAPACITY;
    p = (uint32_t *)realloc(a->LIMBS, capacity * sizeof(uint32_t));
    if (!p) return -1;
    memset(p + old, 0, (capacity - old) * sizeof(uint32_t));
    a->LIMBS = p;
    a->CAPACITY = capacity;
    return 0;
}

void bignum_normalize(CRYPTO_BIGNUM *a) {
    if (!a) return;
    while (a->LENGTH && a->LIMBS[a->LENGTH - 1] == 0) --a->LENGTH;
}

int crypto_bignum_copy(CRYPTO_BIGNUM *OUT, const CRYPTO_BIGNUM *IN) {
    if (!OUT || !IN) return -1;
    if (OUT == IN) return 0;
    if (bignum_reserve(OUT, IN->LENGTH) != 0) return -1;
    if (IN->LENGTH) memcpy(OUT->LIMBS, IN->LIMBS, IN->LENGTH * sizeof(uint32_t));
    if (OUT->LENGTH > IN->LENGTH) memset(OUT->LIMBS + IN->LENGTH, 0, (OUT->LENGTH - IN->LENGTH) * sizeof(uint32_t));
    OUT->LENGTH = IN->LENGTH;
    return 0;
}

int crypto_bignum_set_u64(CRYPTO_BIGNUM *OUT, uint64_t VALUE) {
    if (!OUT) return -1;
    if (VALUE == 0) {
        OUT->LENGTH = 0;
        return 0;
    }
    if (bignum_reserve(OUT, VALUE >> 32 ? 2 : 1) != 0) return -1;
    OUT->LIMBS[0] = (uint32_t)VALUE;
    if (VALUE >> 32) {
        OUT->LIMBS[1] = (uint32_t)(VALUE >> 32);
        OUT->LENGTH = 2;
    } else {
        OUT->LENGTH = 1;
    }
    return 0;
}

int crypto_bignum_from_bytes_le(CRYPTO_BIGNUM *OUT, const uint8_t *BYTES, size_t LENGTH) {
    size_t limbs, i;
    if (!OUT || (!BYTES && LENGTH)) return -1;
    limbs = (LENGTH + 3u) / 4u;
    if (bignum_reserve(OUT, limbs) != 0) return -1;
    if (limbs) memset(OUT->LIMBS, 0, limbs * sizeof(uint32_t));
    for (i = 0; i < LENGTH; ++i) OUT->LIMBS[i / 4u] |= (uint32_t)BYTES[i] << (8u * (i % 4u));
    OUT->LENGTH = limbs;
    bignum_normalize(OUT);
    return 0;
}

int crypto_bignum_from_bytes_be(CRYPTO_BIGNUM *OUT, const uint8_t *BYTES, size_t LENGTH) {
    size_t limbs, i;
    if (!OUT || (!BYTES && LENGTH)) return -1;
    limbs = (LENGTH + 3u) / 4u;
    if (bignum_reserve(OUT, limbs) != 0) return -1;
    if (limbs) memset(OUT->LIMBS, 0, limbs * sizeof(uint32_t));
    for (i = 0; i < LENGTH; ++i) {
        size_t ri = LENGTH - 1u - i;
        OUT->LIMBS[i / 4u] |= (uint32_t)BYTES[ri] << (8u * (i % 4u));
    }
    OUT->LENGTH = limbs;
    bignum_normalize(OUT);
    return 0;
}

size_t crypto_bignum_bit_length(const CRYPTO_BIGNUM *VALUE) {
    uint32_t top;
    size_t bits;
    if (!VALUE || VALUE->LENGTH == 0) return 0;
    top = VALUE->LIMBS[VALUE->LENGTH - 1];
    bits = 32u * (VALUE->LENGTH - 1u);
    while (top) { ++bits; top >>= 1; }
    return bits;
}

size_t crypto_bignum_byte_length(const CRYPTO_BIGNUM *VALUE) {
    size_t bits = crypto_bignum_bit_length(VALUE);
    return (bits + 7u) / 8u;
}

int crypto_bignum_to_bytes_le(const CRYPTO_BIGNUM *IN, uint8_t *OUT, size_t OUT_LENGTH) {
    size_t need, i;
    if (!IN || (!OUT && OUT_LENGTH)) return -1;
    need = crypto_bignum_byte_length(IN);
    if (OUT_LENGTH < need) return -1;
    if (OUT_LENGTH) memset(OUT, 0, OUT_LENGTH);
    for (i = 0; i < need; ++i) OUT[i] = (uint8_t)(IN->LIMBS[i / 4u] >> (8u * (i % 4u)));
    return 0;
}

int crypto_bignum_to_bytes_be(const CRYPTO_BIGNUM *IN, uint8_t *OUT, size_t OUT_LENGTH) {
    size_t need, i;
    if (!IN || (!OUT && OUT_LENGTH)) return -1;
    need = crypto_bignum_byte_length(IN);
    if (OUT_LENGTH < need) return -1;
    if (OUT_LENGTH) memset(OUT, 0, OUT_LENGTH);
    for (i = 0; i < need; ++i) OUT[OUT_LENGTH - 1u - i] = (uint8_t)(IN->LIMBS[i / 4u] >> (8u * (i % 4u)));
    return 0;
}

int crypto_bignum_compare(const CRYPTO_BIGNUM *A, const CRYPTO_BIGNUM *B) {
    size_t i;
    if (!A || !B) return 0;
    if (A->LENGTH < B->LENGTH) return -1;
    if (A->LENGTH > B->LENGTH) return 1;
    for (i = A->LENGTH; i > 0; --i) {
        uint32_t x = A->LIMBS[i - 1], y = B->LIMBS[i - 1];
        if (x < y) return -1;
        if (x > y) return 1;
    }
    return 0;
}

int crypto_bignum_is_zero(const CRYPTO_BIGNUM *VALUE) {
    return !VALUE || VALUE->LENGTH == 0;
}

int crypto_bignum_add(CRYPTO_BIGNUM *OUT, const CRYPTO_BIGNUM *A, const CRYPTO_BIGNUM *B) {
    CRYPTO_BIGNUM t;
    size_t n, i;
    uint64_t carry = 0;
    if (!OUT || !A || !B) return -1;
    crypto_bignum_init(&t);
    n = A->LENGTH > B->LENGTH ? A->LENGTH : B->LENGTH;
    if (bignum_reserve(&t, n + 1u) != 0) goto fail;
    for (i = 0; i < n; ++i) {
        uint64_t av = i < A->LENGTH ? A->LIMBS[i] : 0;
        uint64_t bv = i < B->LENGTH ? B->LIMBS[i] : 0;
        uint64_t s = av + bv + carry;
        t.LIMBS[i] = (uint32_t)s;
        carry = s >> 32;
    }
    if (carry) t.LIMBS[n++] = (uint32_t)carry;
    t.LENGTH = n;
    crypto_bignum_free(OUT);
    *OUT = t;
    return 0;
fail:
    crypto_bignum_free(&t);
    return -1;
}

int crypto_bignum_sub(CRYPTO_BIGNUM *OUT, const CRYPTO_BIGNUM *A, const CRYPTO_BIGNUM *B) {
    CRYPTO_BIGNUM t;
    size_t i;
    uint64_t borrow = 0;
    if (!OUT || !A || !B || crypto_bignum_compare(A, B) < 0) return -1;
    crypto_bignum_init(&t);
    if (bignum_reserve(&t, A->LENGTH) != 0) goto fail;
    for (i = 0; i < A->LENGTH; ++i) {
        uint64_t av = A->LIMBS[i];
        uint64_t bv = (i < B->LENGTH ? B->LIMBS[i] : 0) + borrow;
        t.LIMBS[i] = (uint32_t)(av - bv);
        borrow = av < bv;
    }
    t.LENGTH = A->LENGTH;
    bignum_normalize(&t);
    crypto_bignum_free(OUT);
    *OUT = t;
    return 0;
fail:
    crypto_bignum_free(&t);
    return -1;
}

int crypto_bignum_mul(CRYPTO_BIGNUM *OUT, const CRYPTO_BIGNUM *A, const CRYPTO_BIGNUM *B) {
    CRYPTO_BIGNUM t;
    size_t i, j, n;
    if (!OUT || !A || !B) return -1;
    crypto_bignum_init(&t);
    if (A->LENGTH == 0 || B->LENGTH == 0) {
        crypto_bignum_free(OUT);
        *OUT = t;
        return 0;
    }
    n = A->LENGTH + B->LENGTH + 1u;
    if (bignum_reserve(&t, n) != 0) goto fail;
    memset(t.LIMBS, 0, n * sizeof(uint32_t));
    for (i = 0; i < A->LENGTH; ++i) {
        uint64_t carry = 0;
        for (j = 0; j < B->LENGTH; ++j) {
            size_t k = i + j;
            uint64_t cur = (uint64_t)A->LIMBS[i] * B->LIMBS[j] + t.LIMBS[k] + carry;
            t.LIMBS[k] = (uint32_t)cur;
            carry = cur >> 32;
        }
        j = i + B->LENGTH;
        while (carry) {
            uint64_t cur = (uint64_t)t.LIMBS[j] + carry;
            t.LIMBS[j] = (uint32_t)cur;
            carry = cur >> 32;
            ++j;
        }
    }
    t.LENGTH = n;
    bignum_normalize(&t);
    crypto_bignum_free(OUT);
    *OUT = t;
    return 0;
fail:
    crypto_bignum_free(&t);
    return -1;
}

int bignum_get_bit(const CRYPTO_BIGNUM *a, size_t bit) {
    size_t limb = bit / 32u;
    if (!a || limb >= a->LENGTH) return 0;
    return (int)((a->LIMBS[limb] >> (bit % 32u)) & 1u);
}

int bignum_shift_left_one(CRYPTO_BIGNUM *a) {
    size_t i;
    uint64_t carry = 0;
    if (!a) return -1;
    if (a->LENGTH == 0) return 0;
    if (bignum_reserve(a, a->LENGTH + 1u) != 0) return -1;
    for (i = 0; i < a->LENGTH; ++i) {
        uint64_t v = ((uint64_t)a->LIMBS[i] << 1) | carry;
        a->LIMBS[i] = (uint32_t)v;
        carry = v >> 32;
    }
    if (carry) a->LIMBS[a->LENGTH++] = (uint32_t)carry;
    return 0;
}

int bignum_add_u32(CRYPTO_BIGNUM *a, uint32_t v) {
    size_t i = 0;
    uint64_t carry = v;
    if (!a) return -1;
    if (!carry) return 0;
    if (a->LENGTH == 0) {
        if (bignum_reserve(a, 1) != 0) return -1;
        a->LIMBS[0] = v;
        a->LENGTH = 1;
        return 0;
    }
    while (carry && i < a->LENGTH) {
        uint64_t s = (uint64_t)a->LIMBS[i] + carry;
        a->LIMBS[i] = (uint32_t)s;
        carry = s >> 32;
        ++i;
    }
    if (carry) {
        if (bignum_reserve(a, a->LENGTH + 1u) != 0) return -1;
        a->LIMBS[a->LENGTH++] = (uint32_t)carry;
    }
    return 0;
}

int crypto_bignum_mod(CRYPTO_BIGNUM *OUT, const CRYPTO_BIGNUM *A, const CRYPTO_BIGNUM *MODULUS) {
    CRYPTO_BIGNUM r, tmp;
    size_t bits, i;
    if (!OUT || !A || !MODULUS || MODULUS->LENGTH == 0) return -1;
    if (crypto_bignum_compare(A, MODULUS) < 0) return crypto_bignum_copy(OUT, A);
    crypto_bignum_init(&r);
    crypto_bignum_init(&tmp);
    bits = crypto_bignum_bit_length(A);
    for (i = bits; i > 0; --i) {
        if (bignum_shift_left_one(&r) != 0) goto fail;
        if (bignum_get_bit(A, i - 1u) && bignum_add_u32(&r, 1) != 0) goto fail;
        if (crypto_bignum_compare(&r, MODULUS) >= 0) {
            if (crypto_bignum_sub(&tmp, &r, MODULUS) != 0) goto fail;
            crypto_bignum_free(&r);
            r = tmp;
            crypto_bignum_init(&tmp);
        }
    }
    crypto_bignum_free(OUT);
    *OUT = r;
    crypto_bignum_free(&tmp);
    return 0;
fail:
    crypto_bignum_free(&r);
    crypto_bignum_free(&tmp);
    return -1;
}

int bignum_mul_u32(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, uint32_t v) {
    CRYPTO_BIGNUM t;
    size_t i;
    uint64_t carry = 0;
    if (!out || !a) return -1;
    crypto_bignum_init(&t);
    if (v == 0 || a->LENGTH == 0) {
        crypto_bignum_free(out);
        *out = t;
        return 0;
    }
    if (bignum_reserve(&t, a->LENGTH + 1u) != 0) goto fail;
    for (i = 0; i < a->LENGTH; ++i) {
        uint64_t z = (uint64_t)a->LIMBS[i] * v + carry;
        t.LIMBS[i] = (uint32_t)z;
        carry = z >> 32;
    }
    t.LENGTH = a->LENGTH;
    if (carry) t.LIMBS[t.LENGTH++] = (uint32_t)carry;
    crypto_bignum_free(out);
    *out = t;
    return 0;
fail:
    crypto_bignum_free(&t);
    return -1;
}

uint32_t bignum_mod_u32(const CRYPTO_BIGNUM *a, uint32_t v) {
    uint64_t r = 0;
    size_t i;
    if (!a || v == 0) return 0;
    for (i = a->LENGTH; i > 0; --i) r = ((r << 32) | a->LIMBS[i - 1u]) % v;
    return (uint32_t)r;
}

int bignum_div_u32(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, uint32_t v, uint32_t *remainder) {
    CRYPTO_BIGNUM t;
    uint64_t rem = 0;
    size_t i;
    if (!out || !a || v == 0) return -1;
    crypto_bignum_init(&t);
    if (bignum_reserve(&t, a->LENGTH) != 0) goto fail;
    for (i = a->LENGTH; i > 0; --i) {
        uint64_t cur = (rem << 32) | a->LIMBS[i - 1u];
        t.LIMBS[i - 1u] = (uint32_t)(cur / v);
        rem = cur % v;
    }
    t.LENGTH = a->LENGTH;
    bignum_normalize(&t);
    if (remainder) *remainder = (uint32_t)rem;
    crypto_bignum_free(out);
    *out = t;
    return 0;
fail:
    crypto_bignum_free(&t);
    return -1;
}

int bignum_sub_u32(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, uint32_t v) {
    CRYPTO_BIGNUM b;
    int rc;
    crypto_bignum_init(&b);
    if (crypto_bignum_set_u64(&b, v) != 0) return -1;
    rc = crypto_bignum_sub(out, a, &b);
    crypto_bignum_free(&b);
    return rc;
}

int bignum_add_u32_copy(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, uint32_t v) {
    if (crypto_bignum_copy(out, a) != 0) return -1;
    return bignum_add_u32(out, v);
}

typedef struct {
    size_t n;
    uint32_t n0inv;
    CRYPTO_BIGNUM mod;
    CRYPTO_BIGNUM r2;
} MONT_CTX;

static uint32_t mont_n0inv(uint32_t n0) {
    uint32_t x = 1u;
    int i;
    for (i = 0; i < 5; ++i) x *= 2u - n0 * x;
    return (uint32_t)(0u - x);
}

static void mont_clear(MONT_CTX *ctx) {
    if (!ctx) return;
    crypto_bignum_free(&ctx->mod);
    crypto_bignum_free(&ctx->r2);
    ctx->n = 0;
    ctx->n0inv = 0;
}

static int mont_init(MONT_CTX *ctx, const CRYPTO_BIGNUM *mod) {
    CRYPTO_BIGNUM x, tmp;
    size_t i, rounds;
    if (!ctx || !mod || mod->LENGTH == 0 || !(mod->LIMBS[0] & 1u)) return -1;
    ctx->n = mod->LENGTH;
    ctx->n0inv = mont_n0inv(mod->LIMBS[0]);
    crypto_bignum_init(&ctx->mod);
    crypto_bignum_init(&ctx->r2);
    crypto_bignum_init(&x);
    crypto_bignum_init(&tmp);
    if (crypto_bignum_copy(&ctx->mod, mod) != 0 || crypto_bignum_set_u64(&x, 1) != 0) goto fail;
    rounds = 64u * ctx->n;
    for (i = 0; i < rounds; ++i) {
        if (bignum_shift_left_one(&x) != 0) goto fail;
        if (crypto_bignum_compare(&x, mod) >= 0) {
            if (crypto_bignum_sub(&tmp, &x, mod) != 0) goto fail;
            crypto_bignum_free(&x);
            x = tmp;
            crypto_bignum_init(&tmp);
        }
    }
    ctx->r2 = x;
    crypto_bignum_init(&x);
    crypto_bignum_free(&tmp);
    return 0;
fail:
    crypto_bignum_free(&x);
    crypto_bignum_free(&tmp);
    mont_clear(ctx);
    return -1;
}

static int mont_mul(CRYPTO_BIGNUM *out, const CRYPTO_BIGNUM *a, const CRYPTO_BIGNUM *b, const MONT_CTX *ctx) {
    uint32_t *t;
    size_t n, i, j;
    CRYPTO_BIGNUM r, tmp;
    if (!out || !a || !b || !ctx) return -1;
    n = ctx->n;
    t = (uint32_t *)calloc(n + 2u, sizeof(uint32_t));
    if (!t) return -1;

    for (i = 0; i < n; ++i) {
        uint64_t carry = 0;
        uint32_t bi = i < b->LENGTH ? b->LIMBS[i] : 0;
        for (j = 0; j < n; ++j) {
            uint32_t aj = j < a->LENGTH ? a->LIMBS[j] : 0;
            uint64_t z = (uint64_t)aj * bi + t[j] + carry;
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
            carry = 0;
            for (j = 0; j < n; ++j) {
                uint64_t z = (uint64_t)m * ctx->mod.LIMBS[j] + t[j] + carry;
                t[j] = (uint32_t)z;
                carry = z >> 32;
            }
            {
                uint64_t z = (uint64_t)t[n] + carry;
                t[n] = (uint32_t)z;
                t[n + 1u] += (uint32_t)(z >> 32);
            }
        }

        for (j = 0; j <= n; ++j) t[j] = t[j + 1u];
        t[n + 1u] = 0;
    }

    crypto_bignum_init(&r);
    crypto_bignum_init(&tmp);
    if (bignum_reserve(&r, n + 1u) != 0) goto fail;
    memcpy(r.LIMBS, t, (n + 1u) * sizeof(uint32_t));
    r.LENGTH = n + 1u;
    bignum_normalize(&r);
    if (crypto_bignum_compare(&r, &ctx->mod) >= 0) {
        if (crypto_bignum_sub(&tmp, &r, &ctx->mod) != 0) goto fail2;
        crypto_bignum_free(&r);
        r = tmp;
        crypto_bignum_init(&tmp);
    }
    free(t);
    crypto_bignum_free(out);
    *out = r;
    crypto_bignum_free(&tmp);
    return 0;
fail:
    crypto_bignum_free(&r);
    crypto_bignum_free(&tmp);
    free(t);
    return -1;
fail2:
    crypto_bignum_free(&r);
    crypto_bignum_free(&tmp);
    free(t);
    return -1;
}

int crypto_bignum_mod_mul(CRYPTO_BIGNUM *OUT, const CRYPTO_BIGNUM *A, const CRYPTO_BIGNUM *B, const CRYPTO_BIGNUM *MODULUS) {
    CRYPTO_BIGNUM product;
    int rc;
    if (!OUT || !A || !B || !MODULUS || MODULUS->LENGTH == 0) return -1;
    crypto_bignum_init(&product);
    if (crypto_bignum_mul(&product, A, B) != 0) return -1;
    rc = crypto_bignum_mod(OUT, &product, MODULUS);
    crypto_bignum_free(&product);
    return rc;
}

int crypto_bignum_mod_exp(CRYPTO_BIGNUM *OUT, const CRYPTO_BIGNUM *BASE, const CRYPTO_BIGNUM *EXPONENT, const CRYPTO_BIGNUM *MODULUS) {
    MONT_CTX ctx;
    CRYPTO_BIGNUM base, base_m, acc, one, tmp;
    size_t bits, i;
    int rc = -1;
    if (!OUT || !BASE || !EXPONENT || !MODULUS || MODULUS->LENGTH == 0) return -1;
    if (!(MODULUS->LIMBS[0] & 1u)) {
        CRYPTO_BIGNUM result, b, prod;
        crypto_bignum_init(&result); crypto_bignum_init(&b); crypto_bignum_init(&prod);
        if (crypto_bignum_set_u64(&result, 1) != 0 || crypto_bignum_mod(&b, BASE, MODULUS) != 0) goto even_fail;
        bits = crypto_bignum_bit_length(EXPONENT);
        for (i = 0; i < bits; ++i) {
            if (bignum_get_bit(EXPONENT, i)) {
                if (crypto_bignum_mul(&prod, &result, &b) != 0 || crypto_bignum_mod(&result, &prod, MODULUS) != 0) goto even_fail;
                crypto_bignum_free(&prod); crypto_bignum_init(&prod);
            }
            if (i + 1u < bits) {
                if (crypto_bignum_mul(&prod, &b, &b) != 0 || crypto_bignum_mod(&b, &prod, MODULUS) != 0) goto even_fail;
                crypto_bignum_free(&prod); crypto_bignum_init(&prod);
            }
        }
        if (crypto_bignum_mod(&result, &result, MODULUS) != 0) goto even_fail;
        crypto_bignum_free(OUT); *OUT = result; crypto_bignum_init(&result); rc = 0;
even_fail:
        crypto_bignum_free(&result); crypto_bignum_free(&b); crypto_bignum_free(&prod);
        return rc;
    }

    memset(&ctx, 0, sizeof(ctx));
    crypto_bignum_init(&base); crypto_bignum_init(&base_m); crypto_bignum_init(&acc); crypto_bignum_init(&one); crypto_bignum_init(&tmp);
    if (mont_init(&ctx, MODULUS) != 0) goto done;
    if (crypto_bignum_mod(&base, BASE, MODULUS) != 0 || crypto_bignum_set_u64(&one, 1) != 0) goto done;
    if (mont_mul(&base_m, &base, &ctx.r2, &ctx) != 0) goto done;
    if (mont_mul(&acc, &one, &ctx.r2, &ctx) != 0) goto done;
    bits = crypto_bignum_bit_length(EXPONENT);
    for (i = bits; i > 0; --i) {
        if (mont_mul(&tmp, &acc, &acc, &ctx) != 0) goto done;
        crypto_bignum_free(&acc); acc = tmp; crypto_bignum_init(&tmp);
        if (bignum_get_bit(EXPONENT, i - 1u)) {
            if (mont_mul(&tmp, &acc, &base_m, &ctx) != 0) goto done;
            crypto_bignum_free(&acc); acc = tmp; crypto_bignum_init(&tmp);
        }
    }
    if (mont_mul(&tmp, &acc, &one, &ctx) != 0) goto done;
    crypto_bignum_free(OUT); *OUT = tmp; crypto_bignum_init(&tmp);
    rc = 0;
done:
    mont_clear(&ctx);
    crypto_bignum_free(&base); crypto_bignum_free(&base_m); crypto_bignum_free(&acc); crypto_bignum_free(&one); crypto_bignum_free(&tmp);
    return rc;
}

int crypto_bignum_random_bits(CRYPTO_BIGNUM *OUT, size_t BITS, int SET_TOP_BIT, int SET_ODD) {
    uint8_t *buf;
    size_t bytes;
    unsigned unused;
    int rc;
    if (!OUT || BITS == 0) return -1;
    bytes = (BITS + 7u) / 8u;
    buf = (uint8_t *)malloc(bytes);
    if (!buf) return -1;
    if (crypto_random_bytes_internal(buf, bytes) != 0) { free(buf); return -1; }
    unused = (unsigned)(bytes * 8u - BITS);
    if (unused) buf[0] &= (uint8_t)(0xffu >> unused);
    if (SET_TOP_BIT) buf[0] |= (uint8_t)(1u << (7u - unused));
    if (SET_ODD) buf[bytes - 1u] |= 1u;
    rc = crypto_bignum_from_bytes_be(OUT, buf, bytes);
    memset(buf, 0, bytes);
    free(buf);
    return rc;
}

int crypto_bignum_random_range(CRYPTO_BIGNUM *OUT, const CRYPTO_BIGNUM *UPPER_EXCLUSIVE) {
    CRYPTO_BIGNUM x;
    size_t bits;
    int tries;
    if (!OUT || !UPPER_EXCLUSIVE || UPPER_EXCLUSIVE->LENGTH == 0) return -1;
    bits = crypto_bignum_bit_length(UPPER_EXCLUSIVE);
    crypto_bignum_init(&x);
    for (tries = 0; tries < 128; ++tries) {
        if (crypto_bignum_random_bits(&x, bits, 0, 0) != 0) goto fail;
        if (crypto_bignum_compare(&x, UPPER_EXCLUSIVE) < 0) {
            crypto_bignum_free(OUT); *OUT = x; return 0;
        }
        crypto_bignum_free(&x); crypto_bignum_init(&x);
    }
fail:
    crypto_bignum_free(&x);
    return -1;
}
