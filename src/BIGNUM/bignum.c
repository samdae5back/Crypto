#include "BIGNUM.h"
#include "bignum_internal.h"
#include "RANDOM.h"

#include <stdlib.h>
#include <string.h>

void BIGNUM_INIT(BIGNUM *VALUE) {
    if (!VALUE) return;
    VALUE->LIMBS = NULL;
    VALUE->LENGTH = 0;
    VALUE->CAPACITY = 0;
}

void BIGNUM_FREE(BIGNUM *VALUE) {
    if (!VALUE) return;
    if (VALUE->LIMBS) {
        volatile uint32_t *p = (volatile uint32_t *)VALUE->LIMBS;
        size_t i;
        for (i = 0; i < VALUE->CAPACITY; ++i) p[i] = 0;
        free(VALUE->LIMBS);
    }
    BIGNUM_INIT(VALUE);
}

int bignum_reserve(BIGNUM *a, size_t capacity) {
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

void bignum_normalize(BIGNUM *a) {
    if (!a) return;
    while (a->LENGTH && a->LIMBS[a->LENGTH - 1] == 0) --a->LENGTH;
}

int BIGNUM_COPY(BIGNUM *OUT, const BIGNUM *IN) {
    if (!OUT || !IN) return -1;
    if (OUT == IN) return 0;
    if (bignum_reserve(OUT, IN->LENGTH) != 0) return -1;
    if (IN->LENGTH) memcpy(OUT->LIMBS, IN->LIMBS, IN->LENGTH * sizeof(uint32_t));
    if (OUT->LENGTH > IN->LENGTH) memset(OUT->LIMBS + IN->LENGTH, 0, (OUT->LENGTH - IN->LENGTH) * sizeof(uint32_t));
    OUT->LENGTH = IN->LENGTH;
    return 0;
}

int BIGNUM_SET_U64(BIGNUM *OUT, uint64_t VALUE) {
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

int BIGNUM_FROM_BYTES_LE(BIGNUM *OUT, const uint8_t *BYTES, size_t LENGTH) {
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

int BIGNUM_FROM_BYTES_BE(BIGNUM *OUT, const uint8_t *BYTES, size_t LENGTH) {
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

size_t BIGNUM_BIT_LENGTH(const BIGNUM *VALUE) {
    uint32_t top;
    size_t bits;
    if (!VALUE || VALUE->LENGTH == 0) return 0;
    top = VALUE->LIMBS[VALUE->LENGTH - 1];
    bits = 32u * (VALUE->LENGTH - 1u);
    while (top) { ++bits; top >>= 1; }
    return bits;
}

size_t BIGNUM_BYTE_LENGTH(const BIGNUM *VALUE) {
    size_t bits = BIGNUM_BIT_LENGTH(VALUE);
    return (bits + 7u) / 8u;
}

int BIGNUM_TO_BYTES_LE(const BIGNUM *IN, uint8_t *OUT, size_t OUT_LENGTH) {
    size_t need, i;
    if (!IN || (!OUT && OUT_LENGTH)) return -1;
    need = BIGNUM_BYTE_LENGTH(IN);
    if (OUT_LENGTH < need) return -1;
    if (OUT_LENGTH) memset(OUT, 0, OUT_LENGTH);
    for (i = 0; i < need; ++i) OUT[i] = (uint8_t)(IN->LIMBS[i / 4u] >> (8u * (i % 4u)));
    return 0;
}

int BIGNUM_TO_BYTES_BE(const BIGNUM *IN, uint8_t *OUT, size_t OUT_LENGTH) {
    size_t need, i;
    if (!IN || (!OUT && OUT_LENGTH)) return -1;
    need = BIGNUM_BYTE_LENGTH(IN);
    if (OUT_LENGTH < need) return -1;
    if (OUT_LENGTH) memset(OUT, 0, OUT_LENGTH);
    for (i = 0; i < need; ++i) OUT[OUT_LENGTH - 1u - i] = (uint8_t)(IN->LIMBS[i / 4u] >> (8u * (i % 4u)));
    return 0;
}

int BIGNUM_COMPARE(const BIGNUM *A, const BIGNUM *B) {
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

int BIGNUM_IS_ZERO(const BIGNUM *VALUE) {
    return !VALUE || VALUE->LENGTH == 0;
}

int BIGNUM_ADD(BIGNUM *OUT, const BIGNUM *A, const BIGNUM *B) {
    BIGNUM t;
    size_t n, i;
    uint64_t carry = 0;
    if (!OUT || !A || !B) return -1;
    BIGNUM_INIT(&t);
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
    BIGNUM_FREE(OUT);
    *OUT = t;
    return 0;
fail:
    BIGNUM_FREE(&t);
    return -1;
}

int BIGNUM_SUB(BIGNUM *OUT, const BIGNUM *A, const BIGNUM *B) {
    BIGNUM t;
    size_t i;
    uint64_t borrow = 0;
    if (!OUT || !A || !B || BIGNUM_COMPARE(A, B) < 0) return -1;
    BIGNUM_INIT(&t);
    if (bignum_reserve(&t, A->LENGTH) != 0) goto fail;
    for (i = 0; i < A->LENGTH; ++i) {
        uint64_t av = A->LIMBS[i];
        uint64_t bv = (i < B->LENGTH ? B->LIMBS[i] : 0) + borrow;
        t.LIMBS[i] = (uint32_t)(av - bv);
        borrow = av < bv;
    }
    t.LENGTH = A->LENGTH;
    bignum_normalize(&t);
    BIGNUM_FREE(OUT);
    *OUT = t;
    return 0;
fail:
    BIGNUM_FREE(&t);
    return -1;
}

int BIGNUM_MUL(BIGNUM *OUT, const BIGNUM *A, const BIGNUM *B) {
    BIGNUM t;
    size_t i, j, n;
    if (!OUT || !A || !B) return -1;
    BIGNUM_INIT(&t);
    if (A->LENGTH == 0 || B->LENGTH == 0) {
        BIGNUM_FREE(OUT);
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
    BIGNUM_FREE(OUT);
    *OUT = t;
    return 0;
fail:
    BIGNUM_FREE(&t);
    return -1;
}

int bignum_get_bit(const BIGNUM *a, size_t bit) {
    size_t limb = bit / 32u;
    if (!a || limb >= a->LENGTH) return 0;
    return (int)((a->LIMBS[limb] >> (bit % 32u)) & 1u);
}

int bignum_shift_left_one(BIGNUM *a) {
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

int bignum_add_u32(BIGNUM *a, uint32_t v) {
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

int BIGNUM_MOD(BIGNUM *OUT, const BIGNUM *A, const BIGNUM *MODULUS) {
    BIGNUM r, tmp;
    size_t bits, i;
    if (!OUT || !A || !MODULUS || MODULUS->LENGTH == 0) return -1;
    if (BIGNUM_COMPARE(A, MODULUS) < 0) return BIGNUM_COPY(OUT, A);
    BIGNUM_INIT(&r);
    BIGNUM_INIT(&tmp);
    bits = BIGNUM_BIT_LENGTH(A);
    for (i = bits; i > 0; --i) {
        if (bignum_shift_left_one(&r) != 0) goto fail;
        if (bignum_get_bit(A, i - 1u) && bignum_add_u32(&r, 1) != 0) goto fail;
        if (BIGNUM_COMPARE(&r, MODULUS) >= 0) {
            if (BIGNUM_SUB(&tmp, &r, MODULUS) != 0) goto fail;
            BIGNUM_FREE(&r);
            r = tmp;
            BIGNUM_INIT(&tmp);
        }
    }
    BIGNUM_FREE(OUT);
    *OUT = r;
    BIGNUM_FREE(&tmp);
    return 0;
fail:
    BIGNUM_FREE(&r);
    BIGNUM_FREE(&tmp);
    return -1;
}

int bignum_mul_u32(BIGNUM *out, const BIGNUM *a, uint32_t v) {
    BIGNUM t;
    size_t i;
    uint64_t carry = 0;
    if (!out || !a) return -1;
    BIGNUM_INIT(&t);
    if (v == 0 || a->LENGTH == 0) {
        BIGNUM_FREE(out);
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
    BIGNUM_FREE(out);
    *out = t;
    return 0;
fail:
    BIGNUM_FREE(&t);
    return -1;
}

uint32_t bignum_mod_u32(const BIGNUM *a, uint32_t v) {
    uint64_t r = 0;
    size_t i;
    if (!a || v == 0) return 0;
    for (i = a->LENGTH; i > 0; --i) r = ((r << 32) | a->LIMBS[i - 1u]) % v;
    return (uint32_t)r;
}

int bignum_div_u32(BIGNUM *out, const BIGNUM *a, uint32_t v, uint32_t *remainder) {
    BIGNUM t;
    uint64_t rem = 0;
    size_t i;
    if (!out || !a || v == 0) return -1;
    BIGNUM_INIT(&t);
    if (bignum_reserve(&t, a->LENGTH) != 0) goto fail;
    for (i = a->LENGTH; i > 0; --i) {
        uint64_t cur = (rem << 32) | a->LIMBS[i - 1u];
        t.LIMBS[i - 1u] = (uint32_t)(cur / v);
        rem = cur % v;
    }
    t.LENGTH = a->LENGTH;
    bignum_normalize(&t);
    if (remainder) *remainder = (uint32_t)rem;
    BIGNUM_FREE(out);
    *out = t;
    return 0;
fail:
    BIGNUM_FREE(&t);
    return -1;
}

int bignum_sub_u32(BIGNUM *out, const BIGNUM *a, uint32_t v) {
    BIGNUM b;
    int rc;
    BIGNUM_INIT(&b);
    if (BIGNUM_SET_U64(&b, v) != 0) return -1;
    rc = BIGNUM_SUB(out, a, &b);
    BIGNUM_FREE(&b);
    return rc;
}

int bignum_add_u32_copy(BIGNUM *out, const BIGNUM *a, uint32_t v) {
    if (BIGNUM_COPY(out, a) != 0) return -1;
    return bignum_add_u32(out, v);
}

typedef struct {
    size_t n;
    uint32_t n0inv;
    BIGNUM mod;
    BIGNUM r2;
} MONT_CTX;

static uint32_t mont_n0inv(uint32_t n0) {
    uint32_t x = 1u;
    int i;
    for (i = 0; i < 5; ++i) x *= 2u - n0 * x;
    return (uint32_t)(0u - x);
}

static void mont_clear(MONT_CTX *ctx) {
    if (!ctx) return;
    BIGNUM_FREE(&ctx->mod);
    BIGNUM_FREE(&ctx->r2);
    ctx->n = 0;
    ctx->n0inv = 0;
}

static int mont_init(MONT_CTX *ctx, const BIGNUM *mod) {
    BIGNUM x, tmp;
    size_t i, rounds;
    if (!ctx || !mod || mod->LENGTH == 0 || !(mod->LIMBS[0] & 1u)) return -1;
    ctx->n = mod->LENGTH;
    ctx->n0inv = mont_n0inv(mod->LIMBS[0]);
    BIGNUM_INIT(&ctx->mod);
    BIGNUM_INIT(&ctx->r2);
    BIGNUM_INIT(&x);
    BIGNUM_INIT(&tmp);
    if (BIGNUM_COPY(&ctx->mod, mod) != 0 || BIGNUM_SET_U64(&x, 1) != 0) goto fail;
    rounds = 64u * ctx->n;
    for (i = 0; i < rounds; ++i) {
        if (bignum_shift_left_one(&x) != 0) goto fail;
        if (BIGNUM_COMPARE(&x, mod) >= 0) {
            if (BIGNUM_SUB(&tmp, &x, mod) != 0) goto fail;
            BIGNUM_FREE(&x);
            x = tmp;
            BIGNUM_INIT(&tmp);
        }
    }
    ctx->r2 = x;
    BIGNUM_INIT(&x);
    BIGNUM_FREE(&tmp);
    return 0;
fail:
    BIGNUM_FREE(&x);
    BIGNUM_FREE(&tmp);
    mont_clear(ctx);
    return -1;
}

static int mont_mul(BIGNUM *out, const BIGNUM *a, const BIGNUM *b, const MONT_CTX *ctx) {
    uint32_t *t;
    size_t n, i, j;
    BIGNUM r, tmp;
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

    BIGNUM_INIT(&r);
    BIGNUM_INIT(&tmp);
    if (bignum_reserve(&r, n + 1u) != 0) goto fail;
    memcpy(r.LIMBS, t, (n + 1u) * sizeof(uint32_t));
    r.LENGTH = n + 1u;
    bignum_normalize(&r);
    if (BIGNUM_COMPARE(&r, &ctx->mod) >= 0) {
        if (BIGNUM_SUB(&tmp, &r, &ctx->mod) != 0) goto fail2;
        BIGNUM_FREE(&r);
        r = tmp;
        BIGNUM_INIT(&tmp);
    }
    free(t);
    BIGNUM_FREE(out);
    *out = r;
    BIGNUM_FREE(&tmp);
    return 0;
fail:
    BIGNUM_FREE(&r);
    BIGNUM_FREE(&tmp);
    free(t);
    return -1;
fail2:
    BIGNUM_FREE(&r);
    BIGNUM_FREE(&tmp);
    free(t);
    return -1;
}

int BIGNUM_MOD_MUL(BIGNUM *OUT, const BIGNUM *A, const BIGNUM *B, const BIGNUM *MODULUS) {
    BIGNUM product;
    int rc;
    if (!OUT || !A || !B || !MODULUS || MODULUS->LENGTH == 0) return -1;
    BIGNUM_INIT(&product);
    if (BIGNUM_MUL(&product, A, B) != 0) return -1;
    rc = BIGNUM_MOD(OUT, &product, MODULUS);
    BIGNUM_FREE(&product);
    return rc;
}

int BIGNUM_MOD_EXP(BIGNUM *OUT, const BIGNUM *BASE, const BIGNUM *EXPONENT, const BIGNUM *MODULUS) {
    MONT_CTX ctx;
    BIGNUM base, base_m, acc, one, tmp;
    size_t bits, i;
    int rc = -1;
    if (!OUT || !BASE || !EXPONENT || !MODULUS || MODULUS->LENGTH == 0) return -1;
    if (!(MODULUS->LIMBS[0] & 1u)) {
        BIGNUM result, b, prod;
        BIGNUM_INIT(&result); BIGNUM_INIT(&b); BIGNUM_INIT(&prod);
        if (BIGNUM_SET_U64(&result, 1) != 0 || BIGNUM_MOD(&b, BASE, MODULUS) != 0) goto even_fail;
        bits = BIGNUM_BIT_LENGTH(EXPONENT);
        for (i = 0; i < bits; ++i) {
            if (bignum_get_bit(EXPONENT, i)) {
                if (BIGNUM_MUL(&prod, &result, &b) != 0 || BIGNUM_MOD(&result, &prod, MODULUS) != 0) goto even_fail;
                BIGNUM_FREE(&prod); BIGNUM_INIT(&prod);
            }
            if (i + 1u < bits) {
                if (BIGNUM_MUL(&prod, &b, &b) != 0 || BIGNUM_MOD(&b, &prod, MODULUS) != 0) goto even_fail;
                BIGNUM_FREE(&prod); BIGNUM_INIT(&prod);
            }
        }
        if (BIGNUM_MOD(&result, &result, MODULUS) != 0) goto even_fail;
        BIGNUM_FREE(OUT); *OUT = result; BIGNUM_INIT(&result); rc = 0;
even_fail:
        BIGNUM_FREE(&result); BIGNUM_FREE(&b); BIGNUM_FREE(&prod);
        return rc;
    }

    memset(&ctx, 0, sizeof(ctx));
    BIGNUM_INIT(&base); BIGNUM_INIT(&base_m); BIGNUM_INIT(&acc); BIGNUM_INIT(&one); BIGNUM_INIT(&tmp);
    if (mont_init(&ctx, MODULUS) != 0) goto done;
    if (BIGNUM_MOD(&base, BASE, MODULUS) != 0 || BIGNUM_SET_U64(&one, 1) != 0) goto done;
    if (mont_mul(&base_m, &base, &ctx.r2, &ctx) != 0) goto done;
    if (mont_mul(&acc, &one, &ctx.r2, &ctx) != 0) goto done;
    bits = BIGNUM_BIT_LENGTH(EXPONENT);
    for (i = bits; i > 0; --i) {
        if (mont_mul(&tmp, &acc, &acc, &ctx) != 0) goto done;
        BIGNUM_FREE(&acc); acc = tmp; BIGNUM_INIT(&tmp);
        if (bignum_get_bit(EXPONENT, i - 1u)) {
            if (mont_mul(&tmp, &acc, &base_m, &ctx) != 0) goto done;
            BIGNUM_FREE(&acc); acc = tmp; BIGNUM_INIT(&tmp);
        }
    }
    if (mont_mul(&tmp, &acc, &one, &ctx) != 0) goto done;
    BIGNUM_FREE(OUT); *OUT = tmp; BIGNUM_INIT(&tmp);
    rc = 0;
done:
    mont_clear(&ctx);
    BIGNUM_FREE(&base); BIGNUM_FREE(&base_m); BIGNUM_FREE(&acc); BIGNUM_FREE(&one); BIGNUM_FREE(&tmp);
    return rc;
}

int BIGNUM_RANDOM_BITS(BIGNUM *OUT, size_t BITS, int SET_TOP_BIT, int SET_ODD) {
    uint8_t *buf;
    size_t bytes;
    unsigned unused;
    int rc;
    if (!OUT || BITS == 0) return -1;
    bytes = (BITS + 7u) / 8u;
    buf = (uint8_t *)malloc(bytes);
    if (!buf) return -1;
    if (RANDOM_BYTES(buf, bytes) != 0) { free(buf); return -1; }
    unused = (unsigned)(bytes * 8u - BITS);
    if (unused) buf[0] &= (uint8_t)(0xffu >> unused);
    if (SET_TOP_BIT) buf[0] |= (uint8_t)(1u << (7u - unused));
    if (SET_ODD) buf[bytes - 1u] |= 1u;
    rc = BIGNUM_FROM_BYTES_BE(OUT, buf, bytes);
    memset(buf, 0, bytes);
    free(buf);
    return rc;
}

int BIGNUM_RANDOM_RANGE(BIGNUM *OUT, const BIGNUM *UPPER_EXCLUSIVE) {
    BIGNUM x;
    size_t bits;
    int tries;
    if (!OUT || !UPPER_EXCLUSIVE || UPPER_EXCLUSIVE->LENGTH == 0) return -1;
    bits = BIGNUM_BIT_LENGTH(UPPER_EXCLUSIVE);
    BIGNUM_INIT(&x);
    for (tries = 0; tries < 128; ++tries) {
        if (BIGNUM_RANDOM_BITS(&x, bits, 0, 0) != 0) goto fail;
        if (BIGNUM_COMPARE(&x, UPPER_EXCLUSIVE) < 0) {
            BIGNUM_FREE(OUT); *OUT = x; return 0;
        }
        BIGNUM_FREE(&x); BIGNUM_INIT(&x);
    }
fail:
    BIGNUM_FREE(&x);
    return -1;
}
