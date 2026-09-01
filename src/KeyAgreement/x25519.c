/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "KeyAgreement/key_agreement_internal.h"

#include "RandomNumberGeneration/Noise/random_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"

#include <string.h>

#define X25519_BYTES 32u
#define X25519_LIMBS 16u
#define X25519_RADIX_MASK UINT32_C(0xffff)
#define X25519_TOP_MASK UINT32_C(0x7fff)
#define X25519_A24 UINT32_C(121665)

/* p = 2^255 - 19 in radix 2^16, little endian. */
static const uint32_t X25519_P[X25519_LIMBS] = {
    UINT32_C(0xffed), UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff),
    UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff),
    UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff),
    UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0x7fff)
};

typedef struct X25519FieldElement {
    uint32_t limb[X25519_LIMBS];
} X25519FieldElement;

static void x25519_fe_zero(X25519FieldElement *out) {
    size_t i;
    for (i = 0u; i < X25519_LIMBS; ++i) {
        out->limb[i] = 0u;
    }
}

static void x25519_fe_one(X25519FieldElement *out) {
    x25519_fe_zero(out);
    out->limb[0] = 1u;
}

static void x25519_fe_copy(X25519FieldElement *out,
                           const X25519FieldElement *in) {
    *out = *in;
}

static void x25519_fe_conditional_subtract_p(X25519FieldElement *value) {
    uint32_t difference[X25519_LIMBS];
    uint32_t borrow = 0u;
    uint32_t select_difference;
    size_t i;

    for (i = 0u; i < X25519_LIMBS; ++i) {
        const uint64_t d = (uint64_t)value->limb[i] -
                           (uint64_t)X25519_P[i] - (uint64_t)borrow;
        difference[i] = (uint32_t)d & X25519_RADIX_MASK;
        borrow = (uint32_t)(d >> 63);
    }

    /* Select value - p exactly when the subtraction did not borrow. */
    select_difference = UINT32_C(0) - (borrow ^ UINT32_C(1));
    for (i = 0u; i < X25519_LIMBS; ++i) {
        value->limb[i] =
            (value->limb[i] & ~select_difference) |
            (difference[i] & select_difference);
    }
    crypto_zeroize(difference, sizeof(difference));
}

static void x25519_reduce_16(uint64_t value[X25519_LIMBS],
                             X25519FieldElement *out) {
    size_t round;
    size_t i;

    /*
     * The first pass bounds every radix-2^16 limb. The top limb is radix
     * 2^15 because 2^255 == 19 (mod p). Additional fixed passes propagate the
     * small carry introduced at limb zero by that fold. Four passes are more
     * than sufficient for the bounds produced by the operations below.
     */
    for (round = 0u; round < 4u; ++round) {
        for (i = 0u; i + 1u < X25519_LIMBS; ++i) {
            const uint64_t carry = value[i] >> 16;
            value[i] &= UINT64_C(0xffff);
            value[i + 1u] += carry;
        }
        {
            const uint64_t carry = value[15] >> 15;
            value[15] &= UINT64_C(0x7fff);
            value[0] += carry * UINT64_C(19);
        }
    }

    for (i = 0u; i < X25519_LIMBS; ++i) {
        out->limb[i] = (uint32_t)value[i];
    }
    x25519_fe_conditional_subtract_p(out);
}

static void x25519_fe_add(X25519FieldElement *out,
                          const X25519FieldElement *a,
                          const X25519FieldElement *b) {
    uint64_t value[X25519_LIMBS];
    size_t i;

    for (i = 0u; i < X25519_LIMBS; ++i) {
        value[i] = (uint64_t)a->limb[i] + (uint64_t)b->limb[i];
    }
    x25519_reduce_16(value, out);
    crypto_zeroize(value, sizeof(value));
}

static void x25519_fe_sub(X25519FieldElement *out,
                          const X25519FieldElement *a,
                          const X25519FieldElement *b) {
    uint32_t result[X25519_LIMBS];
    uint32_t borrow = 0u;
    uint32_t carry = 0u;
    uint32_t add_modulus_mask;
    size_t i;

    /* Subtract in radix 2^16, wrapping modulo 2^256. */
    for (i = 0u; i < X25519_LIMBS; ++i) {
        const uint64_t d = (uint64_t)a->limb[i] -
                           (uint64_t)b->limb[i] - (uint64_t)borrow;
        result[i] = (uint32_t)d & X25519_RADIX_MASK;
        borrow = (uint32_t)(d >> 63);
    }

    /* If a < b, add p to the wrapped result and discard the 2^256 carry. */
    add_modulus_mask = UINT32_C(0) - borrow;
    for (i = 0u; i < X25519_LIMBS; ++i) {
        const uint32_t sum = result[i] +
                             (X25519_P[i] & add_modulus_mask) + carry;
        result[i] = sum & X25519_RADIX_MASK;
        carry = sum >> 16;
    }
    for (i = 0u; i < X25519_LIMBS; ++i) {
        out->limb[i] = result[i];
    }
    crypto_zeroize(result, sizeof(result));
}

static void x25519_fe_mul(X25519FieldElement *out,
                          const X25519FieldElement *a,
                          const X25519FieldElement *b) {
    uint64_t product[31];
    uint64_t reduced[X25519_LIMBS];
    size_t i;
    size_t j;

    for (i = 0u; i < 31u; ++i) {
        product[i] = 0u;
    }
    for (i = 0u; i < X25519_LIMBS; ++i) {
        for (j = 0u; j < X25519_LIMBS; ++j) {
            product[i + j] +=
                (uint64_t)a->limb[i] * (uint64_t)b->limb[j];
        }
    }

    /* 2^256 == 38 (mod p), so fold limbs 16..30 into 0..14. */
    i = 31u;
    while (i > X25519_LIMBS) {
        --i;
        product[i - X25519_LIMBS] += product[i] * UINT64_C(38);
    }
    for (i = 0u; i < X25519_LIMBS; ++i) {
        reduced[i] = product[i];
    }
    x25519_reduce_16(reduced, out);
    crypto_zeroize(product, sizeof(product));
    crypto_zeroize(reduced, sizeof(reduced));
}

static void x25519_fe_square(X25519FieldElement *out,
                             const X25519FieldElement *a) {
    x25519_fe_mul(out, a, a);
}

static void x25519_fe_mul_small(X25519FieldElement *out,
                                const X25519FieldElement *a,
                                uint32_t multiplier) {
    uint64_t value[X25519_LIMBS];
    size_t i;

    for (i = 0u; i < X25519_LIMBS; ++i) {
        value[i] = (uint64_t)a->limb[i] * (uint64_t)multiplier;
    }
    x25519_reduce_16(value, out);
    crypto_zeroize(value, sizeof(value));
}

static void x25519_fe_cswap(X25519FieldElement *a,
                            X25519FieldElement *b,
                            uint32_t swap) {
    const uint32_t mask = UINT32_C(0) - (swap & UINT32_C(1));
    size_t i;

    for (i = 0u; i < X25519_LIMBS; ++i) {
        const uint32_t difference = (a->limb[i] ^ b->limb[i]) & mask;
        a->limb[i] ^= difference;
        b->limb[i] ^= difference;
    }
}

static void x25519_fe_from_bytes(X25519FieldElement *out,
                                 const uint8_t input[X25519_BYTES]) {
    size_t i;

    for (i = 0u; i < X25519_LIMBS; ++i) {
        out->limb[i] = (uint32_t)input[2u * i] |
                       ((uint32_t)input[2u * i + 1u] << 8);
    }
    /* RFC 7748 requires X25519 decoders to mask the most significant bit. */
    out->limb[15] &= X25519_TOP_MASK;
    /* Values p..2^255-1 are accepted and interpreted modulo p. */
    x25519_fe_conditional_subtract_p(out);
}

static void x25519_fe_to_bytes(uint8_t output[X25519_BYTES],
                               const X25519FieldElement *input) {
    X25519FieldElement canonical;
    size_t i;

    x25519_fe_copy(&canonical, input);
    x25519_fe_conditional_subtract_p(&canonical);
    for (i = 0u; i < X25519_LIMBS; ++i) {
        output[2u * i] = (uint8_t)canonical.limb[i];
        output[2u * i + 1u] = (uint8_t)(canonical.limb[i] >> 8);
    }
    crypto_zeroize(&canonical, sizeof(canonical));
}

static void x25519_fe_invert(X25519FieldElement *out,
                             const X25519FieldElement *input) {
    X25519FieldElement result;
    X25519FieldElement squared;
    int bit;

    /* input^(p-2), where p-2 = 2^255 - 21. */
    x25519_fe_one(&result);
    for (bit = 254; bit >= 0; --bit) {
        x25519_fe_square(&squared, &result);
        result = squared;
        if (bit >= 8 || ((UINT32_C(0xeb) >> (unsigned)bit) & 1u) != 0u) {
            X25519FieldElement multiplied;
            x25519_fe_mul(&multiplied, &result, input);
            result = multiplied;
            crypto_zeroize(&multiplied, sizeof(multiplied));
        }
    }
    *out = result;
    crypto_zeroize(&result, sizeof(result));
    crypto_zeroize(&squared, sizeof(squared));
}

static void x25519_scalar_multiply(uint8_t output[X25519_BYTES],
                                   const uint8_t scalar_input[X25519_BYTES],
                                   const uint8_t u_input[X25519_BYTES]) {
    uint8_t scalar[X25519_BYTES];
    X25519FieldElement x1;
    X25519FieldElement x2;
    X25519FieldElement z2;
    X25519FieldElement x3;
    X25519FieldElement z3;
    X25519FieldElement a;
    X25519FieldElement aa;
    X25519FieldElement b;
    X25519FieldElement bb;
    X25519FieldElement e;
    X25519FieldElement c;
    X25519FieldElement d;
    X25519FieldElement da;
    X25519FieldElement cb;
    X25519FieldElement temporary0;
    X25519FieldElement temporary1;
    X25519FieldElement inverse;
    uint32_t swap = 0u;
    int bit;

    memcpy(scalar, scalar_input, sizeof(scalar));
    scalar[0] &= UINT8_C(248);
    scalar[31] &= UINT8_C(127);
    scalar[31] |= UINT8_C(64);

    x25519_fe_from_bytes(&x1, u_input);
    x25519_fe_one(&x2);
    x25519_fe_zero(&z2);
    x25519_fe_copy(&x3, &x1);
    x25519_fe_one(&z3);

    for (bit = 254; bit >= 0; --bit) {
        const uint32_t scalar_bit =
            ((uint32_t)scalar[(unsigned)bit >> 3] >> ((unsigned)bit & 7u)) & 1u;
        swap ^= scalar_bit;
        x25519_fe_cswap(&x2, &x3, swap);
        x25519_fe_cswap(&z2, &z3, swap);
        swap = scalar_bit;

        x25519_fe_add(&a, &x2, &z2);
        x25519_fe_square(&aa, &a);
        x25519_fe_sub(&b, &x2, &z2);
        x25519_fe_square(&bb, &b);
        x25519_fe_sub(&e, &aa, &bb);
        x25519_fe_add(&c, &x3, &z3);
        x25519_fe_sub(&d, &x3, &z3);
        x25519_fe_mul(&da, &d, &a);
        x25519_fe_mul(&cb, &c, &b);
        x25519_fe_add(&temporary0, &da, &cb);
        x25519_fe_square(&x3, &temporary0);
        x25519_fe_sub(&temporary0, &da, &cb);
        x25519_fe_square(&temporary1, &temporary0);
        x25519_fe_mul(&z3, &x1, &temporary1);
        x25519_fe_mul(&x2, &aa, &bb);
        x25519_fe_mul_small(&temporary0, &e, X25519_A24);
        x25519_fe_add(&temporary0, &aa, &temporary0);
        x25519_fe_mul(&z2, &e, &temporary0);
    }

    x25519_fe_cswap(&x2, &x3, swap);
    x25519_fe_cswap(&z2, &z3, swap);
    x25519_fe_invert(&inverse, &z2);
    x25519_fe_mul(&x2, &x2, &inverse);
    x25519_fe_to_bytes(output, &x2);

    crypto_zeroize(scalar, sizeof(scalar));
    crypto_zeroize(&x1, sizeof(x1));
    crypto_zeroize(&x2, sizeof(x2));
    crypto_zeroize(&z2, sizeof(z2));
    crypto_zeroize(&x3, sizeof(x3));
    crypto_zeroize(&z3, sizeof(z3));
    crypto_zeroize(&a, sizeof(a));
    crypto_zeroize(&aa, sizeof(aa));
    crypto_zeroize(&b, sizeof(b));
    crypto_zeroize(&bb, sizeof(bb));
    crypto_zeroize(&e, sizeof(e));
    crypto_zeroize(&c, sizeof(c));
    crypto_zeroize(&d, sizeof(d));
    crypto_zeroize(&da, sizeof(da));
    crypto_zeroize(&cb, sizeof(cb));
    crypto_zeroize(&temporary0, sizeof(temporary0));
    crypto_zeroize(&temporary1, sizeof(temporary1));
    crypto_zeroize(&inverse, sizeof(inverse));
}

static int x25519_is_all_zero(const uint8_t value[X25519_BYTES]) {
    uint32_t accumulator = 0u;
    size_t i;
    for (i = 0u; i < X25519_BYTES; ++i) {
        accumulator |= value[i];
    }
    return accumulator == 0u;
}

LiberaCError crypto_x25519_keygen_internal(
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length) {
    static const uint8_t basepoint[X25519_BYTES] = { 9u };
    uint8_t local_private[X25519_BYTES];
    uint8_t local_public[X25519_BYTES];
    LiberaCError error;

    if (public_key == NULL || private_key == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (public_key_length < X25519_BYTES || private_key_length < X25519_BYTES) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(public_key, X25519_BYTES,
                              private_key, X25519_BYTES)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_zeroize(local_private, sizeof(local_private));
    crypto_zeroize(local_public, sizeof(local_public));
    error = crypto_random_bytes_internal(local_private, sizeof(local_private));
    if (error == LIBERAC_SUCCESS) {
        x25519_scalar_multiply(local_public, local_private, basepoint);
        memcpy(private_key, local_private, X25519_BYTES);
        memcpy(public_key, local_public, X25519_BYTES);
    } else {
        crypto_zeroize(private_key, X25519_BYTES);
        crypto_zeroize(public_key, X25519_BYTES);
    }
    crypto_zeroize(local_private, sizeof(local_private));
    crypto_zeroize(local_public, sizeof(local_public));
    return error;
}

LiberaCError crypto_x25519_public_from_private_internal(
    uint8_t *public_key, size_t public_key_length,
    const uint8_t *private_key, size_t private_key_length) {
    static const uint8_t basepoint[X25519_BYTES] = { 9u };
    uint8_t local_public[X25519_BYTES];

    if (public_key == NULL || private_key == NULL ||
        private_key_length != X25519_BYTES) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (public_key_length < X25519_BYTES) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(public_key, X25519_BYTES,
                              private_key, private_key_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    x25519_scalar_multiply(local_public, private_key, basepoint);
    memcpy(public_key, local_public, X25519_BYTES);
    crypto_zeroize(local_public, sizeof(local_public));
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_x25519_shared_secret_internal(
    uint8_t *shared_secret, size_t shared_secret_length,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *peer_public_key, size_t peer_public_key_length) {
    uint8_t local_secret[X25519_BYTES];

    if (shared_secret == NULL || private_key == NULL || peer_public_key == NULL ||
        private_key_length != X25519_BYTES ||
        peer_public_key_length != X25519_BYTES) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (shared_secret_length < X25519_BYTES) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(shared_secret, X25519_BYTES,
                              private_key, private_key_length) ||
        crypto_ranges_overlap(shared_secret, X25519_BYTES,
                              peer_public_key, peer_public_key_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    x25519_scalar_multiply(local_secret, private_key, peer_public_key);
    if (x25519_is_all_zero(local_secret)) {
        crypto_zeroize(shared_secret, X25519_BYTES);
        crypto_zeroize(local_secret, sizeof(local_secret));
        return LIBERAC_ERROR_INVALID_KEY;
    }

    memcpy(shared_secret, local_secret, X25519_BYTES);
    crypto_zeroize(local_secret, sizeof(local_secret));
    return LIBERAC_SUCCESS;
}
