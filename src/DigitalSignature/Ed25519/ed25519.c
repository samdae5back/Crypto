/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "DigitalSignature/Ed25519/ed25519_internal.h"

#include "DigitalSignature.h"
#include "HashFunction/SHA2/sha2_internal.h"
#include "RandomNumberGeneration/Noise/random_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"

#include <string.h>

#define ED25519_BYTES 32u
#define ED25519_SIGNATURE_BYTES 64u
#define ED25519_FIELD_LIMBS 16u
#define ED25519_SCALAR_LIMBS 8u
#define ED25519_PRODUCT_LIMBS 16u
#define ED25519_WINDOW_POINTS 16u
#define ED25519_RADIX_MASK UINT32_C(0xffff)
#define ED25519_TOP_MASK UINT32_C(0x7fff)

typedef struct Ed25519FieldElement {
    uint32_t limb[ED25519_FIELD_LIMBS];
} Ed25519FieldElement;

typedef struct Ed25519Point {
    Ed25519FieldElement x;
    Ed25519FieldElement y;
    Ed25519FieldElement z;
    Ed25519FieldElement t;
} Ed25519Point;

/* p = 2^255 - 19 in radix 2^16, little endian. */
static const uint32_t ED25519_P[ED25519_FIELD_LIMBS] = {
    UINT32_C(0xffed), UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff),
    UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff),
    UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff),
    UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0xffff), UINT32_C(0x7fff)
};

/* d = -121665 / 121666 modulo p. */
static const Ed25519FieldElement ED25519_D = {{
    UINT32_C(0x78a3), UINT32_C(0x1359), UINT32_C(0x4dca),
    UINT32_C(0x75eb), UINT32_C(0xd8ab), UINT32_C(0x4141),
    UINT32_C(0x0a4d), UINT32_C(0x0070), UINT32_C(0xe898),
    UINT32_C(0x7779), UINT32_C(0x4079), UINT32_C(0x8cc7),
    UINT32_C(0xfe73), UINT32_C(0x2b6f), UINT32_C(0x6cee),
    UINT32_C(0x5203)
}};

/* 2d modulo p, used by complete extended-coordinate addition. */
static const Ed25519FieldElement ED25519_D2 = {{
    UINT32_C(0xf159), UINT32_C(0x26b2), UINT32_C(0x9b94),
    UINT32_C(0xebd6), UINT32_C(0xb156), UINT32_C(0x8283),
    UINT32_C(0x149a), UINT32_C(0x00e0), UINT32_C(0xd130),
    UINT32_C(0xeef3), UINT32_C(0x80f2), UINT32_C(0x198e),
    UINT32_C(0xfce7), UINT32_C(0x56df), UINT32_C(0xd9dc),
    UINT32_C(0x2406)
}};

/* sqrt(-1) modulo p. */
static const Ed25519FieldElement ED25519_SQRT_M1 = {{
    UINT32_C(0xa0b0), UINT32_C(0x4a0e), UINT32_C(0x1b27),
    UINT32_C(0xc4ee), UINT32_C(0xe478), UINT32_C(0xad2f),
    UINT32_C(0x1806), UINT32_C(0x2f43), UINT32_C(0xd7a7),
    UINT32_C(0x3dfb), UINT32_C(0x0099), UINT32_C(0x2b4d),
    UINT32_C(0xdf0b), UINT32_C(0x4fc1), UINT32_C(0x2480),
    UINT32_C(0x2b83)
}};

static const Ed25519FieldElement ED25519_BASE_X = {{
    UINT32_C(0xd51a), UINT32_C(0x8f25), UINT32_C(0x2d60),
    UINT32_C(0xc956), UINT32_C(0xa7b2), UINT32_C(0x9525),
    UINT32_C(0xc760), UINT32_C(0x692c), UINT32_C(0xdc5c),
    UINT32_C(0xfdd6), UINT32_C(0xe231), UINT32_C(0xc0a4),
    UINT32_C(0x53fe), UINT32_C(0xcd6e), UINT32_C(0x36d3),
    UINT32_C(0x2169)
}};

static const Ed25519FieldElement ED25519_BASE_Y = {{
    UINT32_C(0x6658), UINT32_C(0x6666), UINT32_C(0x6666),
    UINT32_C(0x6666), UINT32_C(0x6666), UINT32_C(0x6666),
    UINT32_C(0x6666), UINT32_C(0x6666), UINT32_C(0x6666),
    UINT32_C(0x6666), UINT32_C(0x6666), UINT32_C(0x6666),
    UINT32_C(0x6666), UINT32_C(0x6666), UINT32_C(0x6666),
    UINT32_C(0x6666)
}};

static const Ed25519FieldElement ED25519_BASE_T = {{
    UINT32_C(0xdda3), UINT32_C(0xa5b7), UINT32_C(0x8ab3),
    UINT32_C(0x6dde), UINT32_C(0x52f5), UINT32_C(0x7751),
    UINT32_C(0x9f80), UINT32_C(0x20f0), UINT32_C(0xe37d),
    UINT32_C(0x64ab), UINT32_C(0x4e8e), UINT32_C(0x66ea),
    UINT32_C(0x7665), UINT32_C(0xd78b), UINT32_C(0x5f0f),
    UINT32_C(0x6787)
}};

/* L = 2^252 + 27742317777372353535851937790883648493. */
static const uint32_t ED25519_L[ED25519_SCALAR_LIMBS] = {
    UINT32_C(0x5cf5d3ed), UINT32_C(0x5812631a),
    UINT32_C(0xa2f79cd6), UINT32_C(0x14def9de),
    UINT32_C(0x00000000), UINT32_C(0x00000000),
    UINT32_C(0x00000000), UINT32_C(0x10000000)
};

static const uint8_t ED25519_L_BYTES[ED25519_BYTES] = {
    0xedu, 0xd3u, 0xf5u, 0x5cu, 0x1au, 0x63u, 0x12u, 0x58u,
    0xd6u, 0x9cu, 0xf7u, 0xa2u, 0xdeu, 0xf9u, 0xdeu, 0x14u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x10u
};

static const uint8_t ED25519_INVERSE_EXPONENT[ED25519_BYTES] = {
    0xebu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0x7fu
};

static const uint8_t ED25519_SQRT_EXPONENT[ED25519_BYTES] = {
    0xfeu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0x0fu
};

static void ed25519_fe_zero(Ed25519FieldElement *out) {
    size_t i;
    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        out->limb[i] = 0u;
    }
}

static void ed25519_fe_one(Ed25519FieldElement *out) {
    ed25519_fe_zero(out);
    out->limb[0] = 1u;
}

static void ed25519_fe_conditional_subtract_p(Ed25519FieldElement *value) {
    uint32_t difference[ED25519_FIELD_LIMBS];
    uint32_t borrow = 0u;
    uint32_t mask;
    size_t i;

    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        const uint64_t d = (uint64_t)value->limb[i] -
                           (uint64_t)ED25519_P[i] - (uint64_t)borrow;
        difference[i] = (uint32_t)d & ED25519_RADIX_MASK;
        borrow = (uint32_t)(d >> 63);
    }
    mask = UINT32_C(0) - (borrow ^ UINT32_C(1));
    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        value->limb[i] = (value->limb[i] & ~mask) |
                         (difference[i] & mask);
    }
    crypto_zeroize(difference, sizeof(difference));
}

static void ed25519_reduce_16(uint64_t value[ED25519_FIELD_LIMBS],
                              Ed25519FieldElement *out) {
    size_t round;
    size_t i;

    for (round = 0u; round < 4u; ++round) {
        for (i = 0u; i + 1u < ED25519_FIELD_LIMBS; ++i) {
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
    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        out->limb[i] = (uint32_t)value[i];
    }
    ed25519_fe_conditional_subtract_p(out);
}

static void ed25519_fe_add(Ed25519FieldElement *out,
                           const Ed25519FieldElement *a,
                           const Ed25519FieldElement *b) {
    uint64_t value[ED25519_FIELD_LIMBS];
    size_t i;

    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        value[i] = (uint64_t)a->limb[i] + (uint64_t)b->limb[i];
    }
    ed25519_reduce_16(value, out);
    crypto_zeroize(value, sizeof(value));
}

static void ed25519_fe_sub(Ed25519FieldElement *out,
                           const Ed25519FieldElement *a,
                           const Ed25519FieldElement *b) {
    uint32_t result[ED25519_FIELD_LIMBS];
    uint32_t borrow = 0u;
    uint32_t carry = 0u;
    uint32_t add_modulus_mask;
    size_t i;

    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        const uint64_t d = (uint64_t)a->limb[i] -
                           (uint64_t)b->limb[i] - (uint64_t)borrow;
        result[i] = (uint32_t)d & ED25519_RADIX_MASK;
        borrow = (uint32_t)(d >> 63);
    }
    add_modulus_mask = UINT32_C(0) - borrow;
    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        const uint32_t sum = result[i] +
                             (ED25519_P[i] & add_modulus_mask) + carry;
        result[i] = sum & ED25519_RADIX_MASK;
        carry = sum >> 16;
    }
    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        out->limb[i] = result[i];
    }
    crypto_zeroize(result, sizeof(result));
}

static void ed25519_fe_negate(Ed25519FieldElement *out,
                              const Ed25519FieldElement *input) {
    Ed25519FieldElement zero;
    ed25519_fe_zero(&zero);
    ed25519_fe_sub(out, &zero, input);
    crypto_zeroize(&zero, sizeof(zero));
}

static void ed25519_fe_mul(Ed25519FieldElement *out,
                           const Ed25519FieldElement *a,
                           const Ed25519FieldElement *b) {
    uint64_t product[31];
    uint64_t reduced[ED25519_FIELD_LIMBS];
    size_t i;
    size_t j;

    for (i = 0u; i < 31u; ++i) {
        product[i] = 0u;
    }
    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        for (j = 0u; j < ED25519_FIELD_LIMBS; ++j) {
            product[i + j] +=
                (uint64_t)a->limb[i] * (uint64_t)b->limb[j];
        }
    }
    i = 31u;
    while (i > ED25519_FIELD_LIMBS) {
        --i;
        product[i - ED25519_FIELD_LIMBS] += product[i] * UINT64_C(38);
    }
    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        reduced[i] = product[i];
    }
    ed25519_reduce_16(reduced, out);
    crypto_zeroize(product, sizeof(product));
    crypto_zeroize(reduced, sizeof(reduced));
}

static void ed25519_fe_square(Ed25519FieldElement *out,
                              const Ed25519FieldElement *input) {
    ed25519_fe_mul(out, input, input);
}

static void ed25519_fe_to_bytes(uint8_t output[ED25519_BYTES],
                                const Ed25519FieldElement *input) {
    Ed25519FieldElement canonical = *input;
    size_t i;

    ed25519_fe_conditional_subtract_p(&canonical);
    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        output[2u * i] = (uint8_t)canonical.limb[i];
        output[2u * i + 1u] = (uint8_t)(canonical.limb[i] >> 8);
    }
    crypto_zeroize(&canonical, sizeof(canonical));
}

static int ed25519_fe_from_canonical_bytes(
    Ed25519FieldElement *out, const uint8_t input[ED25519_BYTES]) {
    uint8_t masked[ED25519_BYTES];
    uint8_t encoded[ED25519_BYTES];
    size_t i;
    int canonical;

    memcpy(masked, input, sizeof(masked));
    masked[31] &= UINT8_C(0x7f);
    for (i = 0u; i < ED25519_FIELD_LIMBS; ++i) {
        out->limb[i] = (uint32_t)masked[2u * i] |
                       ((uint32_t)masked[2u * i + 1u] << 8);
    }
    ed25519_fe_conditional_subtract_p(out);
    ed25519_fe_to_bytes(encoded, out);
    canonical = crypto_constant_time_equal(masked, encoded, sizeof(masked));
    crypto_zeroize(masked, sizeof(masked));
    crypto_zeroize(encoded, sizeof(encoded));
    if (!canonical) {
        ed25519_fe_zero(out);
    }
    return canonical;
}

static int ed25519_fe_equal(const Ed25519FieldElement *a,
                            const Ed25519FieldElement *b) {
    uint8_t encoded_a[ED25519_BYTES];
    uint8_t encoded_b[ED25519_BYTES];
    int equal;

    ed25519_fe_to_bytes(encoded_a, a);
    ed25519_fe_to_bytes(encoded_b, b);
    equal = crypto_constant_time_equal(
        encoded_a, encoded_b, sizeof(encoded_a));
    crypto_zeroize(encoded_a, sizeof(encoded_a));
    crypto_zeroize(encoded_b, sizeof(encoded_b));
    return equal;
}

static int ed25519_fe_is_zero(const Ed25519FieldElement *value) {
    Ed25519FieldElement zero;
    int result;
    ed25519_fe_zero(&zero);
    result = ed25519_fe_equal(value, &zero);
    crypto_zeroize(&zero, sizeof(zero));
    return result;
}

static int ed25519_fe_is_negative(const Ed25519FieldElement *value) {
    uint8_t encoded[ED25519_BYTES];
    int result;
    ed25519_fe_to_bytes(encoded, value);
    result = (int)(encoded[0] & UINT8_C(1));
    crypto_zeroize(encoded, sizeof(encoded));
    return result;
}

static void ed25519_fe_pow(Ed25519FieldElement *out,
                           const Ed25519FieldElement *input,
                           const uint8_t exponent[ED25519_BYTES],
                           size_t exponent_bits) {
    Ed25519FieldElement result;
    Ed25519FieldElement squared;
    Ed25519FieldElement multiplied;
    size_t bit = exponent_bits;

    ed25519_fe_one(&result);
    ed25519_fe_zero(&squared);
    ed25519_fe_zero(&multiplied);
    while (bit != 0u) {
        --bit;
        ed25519_fe_square(&squared, &result);
        result = squared;
        if (((uint32_t)exponent[bit >> 3] >> (bit & 7u)) & 1u) {
            ed25519_fe_mul(&multiplied, &result, input);
            result = multiplied;
        }
    }
    *out = result;
    crypto_zeroize(&result, sizeof(result));
    crypto_zeroize(&squared, sizeof(squared));
    crypto_zeroize(&multiplied, sizeof(multiplied));
}

static void ed25519_fe_invert(Ed25519FieldElement *out,
                              const Ed25519FieldElement *input) {
    ed25519_fe_pow(
        out, input, ED25519_INVERSE_EXPONENT, 255u);
}

static void ed25519_fe_sqrt_candidate(Ed25519FieldElement *out,
                                      const Ed25519FieldElement *input) {
    ed25519_fe_pow(
        out, input, ED25519_SQRT_EXPONENT, 252u);
}

static void ed25519_point_identity(Ed25519Point *point) {
    ed25519_fe_zero(&point->x);
    ed25519_fe_one(&point->y);
    ed25519_fe_one(&point->z);
    ed25519_fe_zero(&point->t);
}

static void ed25519_point_base(Ed25519Point *point) {
    point->x = ED25519_BASE_X;
    point->y = ED25519_BASE_Y;
    ed25519_fe_one(&point->z);
    point->t = ED25519_BASE_T;
}

static void ed25519_point_add(Ed25519Point *out,
                              const Ed25519Point *left,
                              const Ed25519Point *right) {
    Ed25519FieldElement a;
    Ed25519FieldElement b;
    Ed25519FieldElement c;
    Ed25519FieldElement d;
    Ed25519FieldElement e;
    Ed25519FieldElement f;
    Ed25519FieldElement g;
    Ed25519FieldElement h;
    Ed25519FieldElement temporary0;
    Ed25519FieldElement temporary1;
    Ed25519Point result;

    ed25519_fe_sub(&temporary0, &left->y, &left->x);
    ed25519_fe_sub(&temporary1, &right->y, &right->x);
    ed25519_fe_mul(&a, &temporary0, &temporary1);
    ed25519_fe_add(&temporary0, &left->y, &left->x);
    ed25519_fe_add(&temporary1, &right->y, &right->x);
    ed25519_fe_mul(&b, &temporary0, &temporary1);
    ed25519_fe_mul(&temporary0, &left->t, &right->t);
    ed25519_fe_mul(&c, &temporary0, &ED25519_D2);
    ed25519_fe_mul(&temporary0, &left->z, &right->z);
    ed25519_fe_add(&d, &temporary0, &temporary0);
    ed25519_fe_sub(&e, &b, &a);
    ed25519_fe_sub(&f, &d, &c);
    ed25519_fe_add(&g, &d, &c);
    ed25519_fe_add(&h, &b, &a);
    ed25519_fe_mul(&result.x, &e, &f);
    ed25519_fe_mul(&result.y, &g, &h);
    ed25519_fe_mul(&result.t, &e, &h);
    ed25519_fe_mul(&result.z, &f, &g);
    *out = result;

    crypto_zeroize(&a, sizeof(a));
    crypto_zeroize(&b, sizeof(b));
    crypto_zeroize(&c, sizeof(c));
    crypto_zeroize(&d, sizeof(d));
    crypto_zeroize(&e, sizeof(e));
    crypto_zeroize(&f, sizeof(f));
    crypto_zeroize(&g, sizeof(g));
    crypto_zeroize(&h, sizeof(h));
    crypto_zeroize(&temporary0, sizeof(temporary0));
    crypto_zeroize(&temporary1, sizeof(temporary1));
    crypto_zeroize(&result, sizeof(result));
}

static void ed25519_point_double(Ed25519Point *out,
                                 const Ed25519Point *point) {
    Ed25519FieldElement a;
    Ed25519FieldElement b;
    Ed25519FieldElement c;
    Ed25519FieldElement d;
    Ed25519FieldElement e;
    Ed25519FieldElement f;
    Ed25519FieldElement g;
    Ed25519FieldElement h;
    Ed25519FieldElement temporary;
    Ed25519Point result;

    ed25519_fe_square(&a, &point->x);
    ed25519_fe_square(&b, &point->y);
    ed25519_fe_square(&temporary, &point->z);
    ed25519_fe_add(&c, &temporary, &temporary);
    ed25519_fe_negate(&d, &a);
    ed25519_fe_add(&temporary, &point->x, &point->y);
    ed25519_fe_square(&e, &temporary);
    ed25519_fe_sub(&e, &e, &a);
    ed25519_fe_sub(&e, &e, &b);
    ed25519_fe_add(&g, &d, &b);
    ed25519_fe_sub(&f, &g, &c);
    ed25519_fe_sub(&h, &d, &b);
    ed25519_fe_mul(&result.x, &e, &f);
    ed25519_fe_mul(&result.y, &g, &h);
    ed25519_fe_mul(&result.t, &e, &h);
    ed25519_fe_mul(&result.z, &f, &g);
    *out = result;

    crypto_zeroize(&a, sizeof(a));
    crypto_zeroize(&b, sizeof(b));
    crypto_zeroize(&c, sizeof(c));
    crypto_zeroize(&d, sizeof(d));
    crypto_zeroize(&e, sizeof(e));
    crypto_zeroize(&f, sizeof(f));
    crypto_zeroize(&g, sizeof(g));
    crypto_zeroize(&h, sizeof(h));
    crypto_zeroize(&temporary, sizeof(temporary));
    crypto_zeroize(&result, sizeof(result));
}

static uint32_t ed25519_equal_mask_u32(uint32_t left, uint32_t right) {
    uint32_t difference = left ^ right;
    difference |= UINT32_C(0) - difference;
    return UINT32_C(0) - ((difference >> 31) ^ UINT32_C(1));
}

static void ed25519_point_select(
    Ed25519Point *out,
    const Ed25519Point table[ED25519_WINDOW_POINTS],
    uint32_t index) {
    size_t table_index;
    size_t limb;

    ed25519_point_identity(out);
    for (table_index = 0u;
         table_index < ED25519_WINDOW_POINTS; ++table_index) {
        const uint32_t mask = ed25519_equal_mask_u32(
            (uint32_t)table_index, index);
        for (limb = 0u; limb < ED25519_FIELD_LIMBS; ++limb) {
            out->x.limb[limb] =
                (out->x.limb[limb] & ~mask) |
                (table[table_index].x.limb[limb] & mask);
            out->y.limb[limb] =
                (out->y.limb[limb] & ~mask) |
                (table[table_index].y.limb[limb] & mask);
            out->z.limb[limb] =
                (out->z.limb[limb] & ~mask) |
                (table[table_index].z.limb[limb] & mask);
            out->t.limb[limb] =
                (out->t.limb[limb] & ~mask) |
                (table[table_index].t.limb[limb] & mask);
        }
    }
}

static void ed25519_point_process_window(
    Ed25519Point *accumulator,
    const Ed25519Point table[ED25519_WINDOW_POINTS],
    uint32_t index) {
    Ed25519Point selected;
    Ed25519Point doubled;
    Ed25519Point sum;
    size_t i;

    ed25519_point_identity(&selected);
    ed25519_point_identity(&doubled);
    ed25519_point_identity(&sum);
    for (i = 0u; i < 4u; ++i) {
        ed25519_point_double(&doubled, accumulator);
        *accumulator = doubled;
    }
    ed25519_point_select(&selected, table, index);
    ed25519_point_add(&sum, accumulator, &selected);
    *accumulator = sum;
    crypto_zeroize(&selected, sizeof(selected));
    crypto_zeroize(&doubled, sizeof(doubled));
    crypto_zeroize(&sum, sizeof(sum));
}

static void ed25519_point_scalar_multiply(
    Ed25519Point *out, const Ed25519Point *point,
    const uint8_t scalar[ED25519_BYTES]) {
    Ed25519Point table[ED25519_WINDOW_POINTS];
    Ed25519Point accumulator;
    size_t i;

    ed25519_point_identity(&table[0]);
    table[1] = *point;
    for (i = 2u; i < ED25519_WINDOW_POINTS; ++i) {
        ed25519_point_add(&table[i], &table[i - 1u], point);
    }
    ed25519_point_identity(&accumulator);
    i = ED25519_BYTES;
    while (i != 0u) {
        const uint32_t byte = scalar[--i];
        ed25519_point_process_window(&accumulator, table, byte >> 4);
        ed25519_point_process_window(
            &accumulator, table, byte & UINT32_C(0x0f));
    }
    *out = accumulator;
    crypto_zeroize(table, sizeof(table));
    crypto_zeroize(&accumulator, sizeof(accumulator));
}

static int ed25519_point_is_identity(const Ed25519Point *point) {
    return ed25519_fe_is_zero(&point->x) &&
           ed25519_fe_equal(&point->y, &point->z);
}

static int ed25519_point_equal(const Ed25519Point *left,
                               const Ed25519Point *right) {
    Ed25519FieldElement left_x;
    Ed25519FieldElement right_x;
    Ed25519FieldElement left_y;
    Ed25519FieldElement right_y;
    int equal;

    ed25519_fe_mul(&left_x, &left->x, &right->z);
    ed25519_fe_mul(&right_x, &right->x, &left->z);
    ed25519_fe_mul(&left_y, &left->y, &right->z);
    ed25519_fe_mul(&right_y, &right->y, &left->z);
    equal = ed25519_fe_equal(&left_x, &right_x) &&
            ed25519_fe_equal(&left_y, &right_y);
    crypto_zeroize(&left_x, sizeof(left_x));
    crypto_zeroize(&right_x, sizeof(right_x));
    crypto_zeroize(&left_y, sizeof(left_y));
    crypto_zeroize(&right_y, sizeof(right_y));
    return equal;
}

static void ed25519_point_encode(uint8_t output[ED25519_BYTES],
                                 const Ed25519Point *point) {
    Ed25519FieldElement inverse_z;
    Ed25519FieldElement x;
    Ed25519FieldElement y;

    ed25519_fe_invert(&inverse_z, &point->z);
    ed25519_fe_mul(&x, &point->x, &inverse_z);
    ed25519_fe_mul(&y, &point->y, &inverse_z);
    ed25519_fe_to_bytes(output, &y);
    output[31] |= (uint8_t)((uint32_t)ed25519_fe_is_negative(&x) << 7);
    crypto_zeroize(&inverse_z, sizeof(inverse_z));
    crypto_zeroize(&x, sizeof(x));
    crypto_zeroize(&y, sizeof(y));
}

static int ed25519_point_decode(Ed25519Point *point,
                                const uint8_t input[ED25519_BYTES]) {
    Ed25519FieldElement y;
    Ed25519FieldElement y_squared;
    Ed25519FieldElement u;
    Ed25519FieldElement v;
    Ed25519FieldElement inverse_v;
    Ed25519FieldElement x_squared;
    Ed25519FieldElement x;
    Ed25519FieldElement check;
    Ed25519FieldElement one;
    const uint32_t sign = (uint32_t)(input[31] >> 7);
    int valid = 0;

    ed25519_fe_zero(&y);
    ed25519_fe_zero(&y_squared);
    ed25519_fe_zero(&u);
    ed25519_fe_zero(&v);
    ed25519_fe_zero(&inverse_v);
    ed25519_fe_zero(&x_squared);
    ed25519_fe_zero(&x);
    ed25519_fe_zero(&check);
    ed25519_fe_one(&one);
    ed25519_point_identity(point);

    if (!ed25519_fe_from_canonical_bytes(&y, input)) {
        goto cleanup;
    }
    ed25519_fe_square(&y_squared, &y);
    ed25519_fe_sub(&u, &y_squared, &one);
    ed25519_fe_mul(&v, &ED25519_D, &y_squared);
    ed25519_fe_add(&v, &v, &one);
    ed25519_fe_invert(&inverse_v, &v);
    ed25519_fe_mul(&x_squared, &u, &inverse_v);
    ed25519_fe_sqrt_candidate(&x, &x_squared);
    ed25519_fe_square(&check, &x);
    if (!ed25519_fe_equal(&check, &x_squared)) {
        ed25519_fe_mul(&x, &x, &ED25519_SQRT_M1);
        ed25519_fe_square(&check, &x);
        if (!ed25519_fe_equal(&check, &x_squared)) {
            goto cleanup;
        }
    }
    if (ed25519_fe_is_zero(&x) && sign != 0u) {
        goto cleanup;
    }
    if ((uint32_t)ed25519_fe_is_negative(&x) != sign) {
        ed25519_fe_negate(&x, &x);
    }
    point->x = x;
    point->y = y;
    ed25519_fe_one(&point->z);
    ed25519_fe_mul(&point->t, &x, &y);
    valid = 1;

cleanup:
    crypto_zeroize(&y, sizeof(y));
    crypto_zeroize(&y_squared, sizeof(y_squared));
    crypto_zeroize(&u, sizeof(u));
    crypto_zeroize(&v, sizeof(v));
    crypto_zeroize(&inverse_v, sizeof(inverse_v));
    crypto_zeroize(&x_squared, sizeof(x_squared));
    crypto_zeroize(&x, sizeof(x));
    crypto_zeroize(&check, sizeof(check));
    crypto_zeroize(&one, sizeof(one));
    if (!valid) {
        ed25519_point_identity(point);
    }
    return valid;
}

static int ed25519_point_is_prime_order(const Ed25519Point *point) {
    Ed25519Point multiple;
    int result;
    ed25519_point_identity(&multiple);
    ed25519_point_scalar_multiply(&multiple, point, ED25519_L_BYTES);
    result = !ed25519_point_is_identity(point) &&
             ed25519_point_is_identity(&multiple);
    crypto_zeroize(&multiple, sizeof(multiple));
    return result;
}

static void ed25519_scalar_from_bytes(
    uint32_t output[ED25519_SCALAR_LIMBS],
    const uint8_t input[ED25519_BYTES]) {
    size_t i;
    for (i = 0u; i < ED25519_SCALAR_LIMBS; ++i) {
        output[i] = (uint32_t)input[4u * i] |
                    ((uint32_t)input[4u * i + 1u] << 8) |
                    ((uint32_t)input[4u * i + 2u] << 16) |
                    ((uint32_t)input[4u * i + 3u] << 24);
    }
}

static void ed25519_scalar_to_bytes(
    uint8_t output[ED25519_BYTES],
    const uint32_t input[ED25519_SCALAR_LIMBS]) {
    size_t i;
    for (i = 0u; i < ED25519_SCALAR_LIMBS; ++i) {
        output[4u * i] = (uint8_t)input[i];
        output[4u * i + 1u] = (uint8_t)(input[i] >> 8);
        output[4u * i + 2u] = (uint8_t)(input[i] >> 16);
        output[4u * i + 3u] = (uint8_t)(input[i] >> 24);
    }
}

static void ed25519_scalar_conditional_subtract_l(
    uint32_t value[ED25519_SCALAR_LIMBS]) {
    uint32_t difference[ED25519_SCALAR_LIMBS];
    uint32_t borrow = 0u;
    uint32_t mask;
    size_t i;

    for (i = 0u; i < ED25519_SCALAR_LIMBS; ++i) {
        const uint64_t d = (uint64_t)value[i] -
                           (uint64_t)ED25519_L[i] - (uint64_t)borrow;
        difference[i] = (uint32_t)d;
        borrow = (uint32_t)(d >> 63);
    }
    mask = UINT32_C(0) - (borrow ^ UINT32_C(1));
    for (i = 0u; i < ED25519_SCALAR_LIMBS; ++i) {
        value[i] = (value[i] & ~mask) | (difference[i] & mask);
    }
    crypto_zeroize(difference, sizeof(difference));
}

static void ed25519_scalar_reduce(uint8_t output[ED25519_BYTES],
                                  const uint8_t *input,
                                  size_t input_length) {
    uint32_t remainder[ED25519_SCALAR_LIMBS] = { 0u };
    size_t bit = input_length * 8u;

    while (bit != 0u) {
        uint32_t carry;
        size_t i;
        --bit;
        carry = ((uint32_t)input[bit >> 3] >> (bit & 7u)) & 1u;
        for (i = 0u; i < ED25519_SCALAR_LIMBS; ++i) {
            const uint32_t next = remainder[i] >> 31;
            remainder[i] = (remainder[i] << 1) | carry;
            carry = next;
        }
        ed25519_scalar_conditional_subtract_l(remainder);
    }
    ed25519_scalar_to_bytes(output, remainder);
    crypto_zeroize(remainder, sizeof(remainder));
}

static int ed25519_scalar_is_canonical(
    const uint8_t scalar[ED25519_BYTES]) {
    uint32_t value[ED25519_SCALAR_LIMBS];
    uint32_t borrow = 0u;
    size_t i;

    ed25519_scalar_from_bytes(value, scalar);
    for (i = 0u; i < ED25519_SCALAR_LIMBS; ++i) {
        const uint64_t d = (uint64_t)value[i] -
                           (uint64_t)ED25519_L[i] - (uint64_t)borrow;
        borrow = (uint32_t)(d >> 63);
    }
    crypto_zeroize(value, sizeof(value));
    return borrow != 0u;
}

static void ed25519_scalar_mul_add(
    uint8_t output[ED25519_BYTES],
    const uint8_t left[ED25519_BYTES],
    const uint8_t right[ED25519_BYTES],
    const uint8_t addend[ED25519_BYTES]) {
    uint32_t a[ED25519_SCALAR_LIMBS];
    uint32_t b[ED25519_SCALAR_LIMBS];
    uint32_t c[ED25519_SCALAR_LIMBS];
    uint32_t product[ED25519_PRODUCT_LIMBS] = { 0u };
    uint8_t encoded[2u * ED25519_BYTES];
    uint64_t carry;
    size_t i;
    size_t j;

    ed25519_scalar_from_bytes(a, left);
    ed25519_scalar_from_bytes(b, right);
    ed25519_scalar_from_bytes(c, addend);
    for (i = 0u; i < ED25519_SCALAR_LIMBS; ++i) {
        carry = 0u;
        for (j = 0u; j < ED25519_SCALAR_LIMBS; ++j) {
            const uint64_t value = (uint64_t)product[i + j] +
                (uint64_t)a[i] * (uint64_t)b[j] + carry;
            product[i + j] = (uint32_t)value;
            carry = value >> 32;
        }
        product[i + ED25519_SCALAR_LIMBS] = (uint32_t)carry;
    }
    carry = 0u;
    for (i = 0u; i < ED25519_SCALAR_LIMBS; ++i) {
        const uint64_t value =
            (uint64_t)product[i] + (uint64_t)c[i] + carry;
        product[i] = (uint32_t)value;
        carry = value >> 32;
    }
    for (i = ED25519_SCALAR_LIMBS;
         i < ED25519_PRODUCT_LIMBS; ++i) {
        const uint64_t value = (uint64_t)product[i] + carry;
        product[i] = (uint32_t)value;
        carry = value >> 32;
    }
    for (i = 0u; i < ED25519_PRODUCT_LIMBS; ++i) {
        encoded[4u * i] = (uint8_t)product[i];
        encoded[4u * i + 1u] = (uint8_t)(product[i] >> 8);
        encoded[4u * i + 2u] = (uint8_t)(product[i] >> 16);
        encoded[4u * i + 3u] = (uint8_t)(product[i] >> 24);
    }
    ed25519_scalar_reduce(output, encoded, sizeof(encoded));
    crypto_zeroize(a, sizeof(a));
    crypto_zeroize(b, sizeof(b));
    crypto_zeroize(c, sizeof(c));
    crypto_zeroize(product, sizeof(product));
    crypto_zeroize(encoded, sizeof(encoded));
}

static LiberaCError ed25519_sha512_parts(
    uint8_t output[64],
    const uint8_t *part0, size_t part0_length,
    const uint8_t *part1, size_t part1_length,
    const uint8_t *part2, size_t part2_length) {
    crypto_sha2_context context;
    LiberaCError error;

    crypto_zeroize(&context, sizeof(context));
    error = crypto_sha2_init(&context, LIBERAC_ALG_HASH_SHA2_512);
    if (error == LIBERAC_SUCCESS) {
        error = crypto_sha2_update(&context, part0, part0_length);
    }
    if (error == LIBERAC_SUCCESS) {
        error = crypto_sha2_update(&context, part1, part1_length);
    }
    if (error == LIBERAC_SUCCESS) {
        error = crypto_sha2_update(&context, part2, part2_length);
    }
    if (error == LIBERAC_SUCCESS) {
        crypto_sha2_finalize(&context);
        crypto_sha2_squeeze(
            &context, output, LIBERAC_ALG_HASH_SHA2_512);
    }
    crypto_sha2_clear(&context);
    return error;
}

static LiberaCError ed25519_public_from_seed(
    uint8_t public_key[ED25519_BYTES],
    const uint8_t seed[ED25519_BYTES]) {
    uint8_t expanded[64];
    Ed25519Point base;
    Ed25519Point public_point;
    LiberaCError error;

    crypto_zeroize(expanded, sizeof(expanded));
    ed25519_point_identity(&base);
    ed25519_point_identity(&public_point);
    error = ed25519_sha512_parts(
        expanded, seed, ED25519_BYTES, NULL, 0u, NULL, 0u);
    if (error == LIBERAC_SUCCESS) {
        expanded[0] &= UINT8_C(248);
        expanded[31] &= UINT8_C(63);
        expanded[31] |= UINT8_C(64);
        ed25519_point_base(&base);
        ed25519_point_scalar_multiply(&public_point, &base, expanded);
        ed25519_point_encode(public_key, &public_point);
    }
    crypto_zeroize(expanded, sizeof(expanded));
    crypto_zeroize(&base, sizeof(base));
    crypto_zeroize(&public_point, sizeof(public_point));
    return error;
}

size_t crypto_ed25519_private_key_size_internal(LiberaCAlgID alg) {
    return alg == LIBERAC_ALG_ED25519 ? ED25519_BYTES : 0u;
}

size_t crypto_ed25519_public_key_size_internal(LiberaCAlgID alg) {
    return alg == LIBERAC_ALG_ED25519 ? ED25519_BYTES : 0u;
}

size_t crypto_ed25519_signature_size_internal(LiberaCAlgID alg) {
    return alg == LIBERAC_ALG_ED25519 ? ED25519_SIGNATURE_BYTES : 0u;
}

LiberaCError crypto_ed25519_keygen_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length) {
    uint8_t local_public[ED25519_BYTES];
    uint8_t local_private[ED25519_BYTES];
    LiberaCError error;

    if (alg != LIBERAC_ALG_ED25519) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (public_key == NULL || private_key == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (public_key_length < ED25519_BYTES ||
        private_key_length < ED25519_BYTES) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(public_key, ED25519_BYTES,
                              private_key, ED25519_BYTES)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_zeroize(local_public, sizeof(local_public));
    crypto_zeroize(local_private, sizeof(local_private));
    error = crypto_random_bytes_internal(local_private, sizeof(local_private));
    if (error == LIBERAC_SUCCESS) {
        error = ed25519_public_from_seed(local_public, local_private);
    }
    if (error == LIBERAC_SUCCESS) {
        memcpy(public_key, local_public, ED25519_BYTES);
        memcpy(private_key, local_private, ED25519_BYTES);
    } else {
        crypto_zeroize(public_key, ED25519_BYTES);
        crypto_zeroize(private_key, ED25519_BYTES);
    }
    crypto_zeroize(local_public, sizeof(local_public));
    crypto_zeroize(local_private, sizeof(local_private));
    return error;
}

LiberaCError crypto_ed25519_public_from_private_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    const uint8_t *private_key, size_t private_key_length) {
    uint8_t local_public[ED25519_BYTES];
    LiberaCError error;

    if (alg != LIBERAC_ALG_ED25519) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (public_key == NULL || private_key == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (private_key_length != ED25519_BYTES) {
        return LIBERAC_ERROR_INVALID_KEY;
    }
    if (public_key_length < ED25519_BYTES) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(public_key, ED25519_BYTES,
                              private_key, private_key_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_zeroize(local_public, sizeof(local_public));
    error = ed25519_public_from_seed(local_public, private_key);
    if (error == LIBERAC_SUCCESS) {
        memcpy(public_key, local_public, sizeof(local_public));
    } else {
        crypto_zeroize(public_key, ED25519_BYTES);
    }
    crypto_zeroize(local_public, sizeof(local_public));
    return error;
}

LiberaCError crypto_ed25519_sign_internal(
    LiberaCAlgID alg,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t signature_length) {
    uint8_t expanded[64];
    uint8_t public_key[ED25519_BYTES];
    uint8_t nonce_digest[64];
    uint8_t nonce_scalar[ED25519_BYTES];
    uint8_t challenge_digest[64];
    uint8_t challenge_scalar[ED25519_BYTES];
    uint8_t local_signature[ED25519_SIGNATURE_BYTES];
    Ed25519Point base;
    Ed25519Point public_point;
    Ed25519Point nonce_point;
    LiberaCError error;

    if (alg != LIBERAC_ALG_ED25519) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (private_key == NULL || signature == NULL ||
        (message == NULL && message_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (private_key_length != ED25519_BYTES) {
        return LIBERAC_ERROR_INVALID_KEY;
    }
    if (signature_length < ED25519_SIGNATURE_BYTES) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(signature, ED25519_SIGNATURE_BYTES,
                              private_key, private_key_length) ||
        crypto_ranges_overlap(signature, ED25519_SIGNATURE_BYTES,
                              message, message_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_zeroize(expanded, sizeof(expanded));
    crypto_zeroize(public_key, sizeof(public_key));
    crypto_zeroize(nonce_digest, sizeof(nonce_digest));
    crypto_zeroize(nonce_scalar, sizeof(nonce_scalar));
    crypto_zeroize(challenge_digest, sizeof(challenge_digest));
    crypto_zeroize(challenge_scalar, sizeof(challenge_scalar));
    crypto_zeroize(local_signature, sizeof(local_signature));
    ed25519_point_identity(&base);
    ed25519_point_identity(&public_point);
    ed25519_point_identity(&nonce_point);

    error = ed25519_sha512_parts(
        expanded, private_key, private_key_length, NULL, 0u, NULL, 0u);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    expanded[0] &= UINT8_C(248);
    expanded[31] &= UINT8_C(63);
    expanded[31] |= UINT8_C(64);
    ed25519_point_base(&base);
    ed25519_point_scalar_multiply(&public_point, &base, expanded);
    ed25519_point_encode(public_key, &public_point);

    error = ed25519_sha512_parts(
        nonce_digest, expanded + ED25519_BYTES, ED25519_BYTES,
        message, message_length, NULL, 0u);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    ed25519_scalar_reduce(
        nonce_scalar, nonce_digest, sizeof(nonce_digest));
    ed25519_point_scalar_multiply(&nonce_point, &base, nonce_scalar);
    ed25519_point_encode(local_signature, &nonce_point);

    error = ed25519_sha512_parts(
        challenge_digest, local_signature, ED25519_BYTES,
        public_key, sizeof(public_key), message, message_length);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    ed25519_scalar_reduce(
        challenge_scalar, challenge_digest, sizeof(challenge_digest));
    ed25519_scalar_mul_add(
        local_signature + ED25519_BYTES,
        challenge_scalar, expanded, nonce_scalar);
    memcpy(signature, local_signature, sizeof(local_signature));

cleanup:
    if (error != LIBERAC_SUCCESS) {
        crypto_zeroize(signature, ED25519_SIGNATURE_BYTES);
    }
    crypto_zeroize(expanded, sizeof(expanded));
    crypto_zeroize(public_key, sizeof(public_key));
    crypto_zeroize(nonce_digest, sizeof(nonce_digest));
    crypto_zeroize(nonce_scalar, sizeof(nonce_scalar));
    crypto_zeroize(challenge_digest, sizeof(challenge_digest));
    crypto_zeroize(challenge_scalar, sizeof(challenge_scalar));
    crypto_zeroize(local_signature, sizeof(local_signature));
    crypto_zeroize(&base, sizeof(base));
    crypto_zeroize(&public_point, sizeof(public_point));
    crypto_zeroize(&nonce_point, sizeof(nonce_point));
    return error;
}

LiberaCError crypto_ed25519_verify_internal(
    LiberaCAlgID alg,
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *signature, size_t signature_length) {
    uint8_t challenge_digest[64];
    uint8_t challenge_scalar[ED25519_BYTES];
    Ed25519Point public_point;
    Ed25519Point encoded_r;
    Ed25519Point base;
    Ed25519Point left;
    Ed25519Point challenge_point;
    Ed25519Point right;
    LiberaCError error = LIBERAC_ERROR_SIGNATURE_INVALID;

    if (alg != LIBERAC_ALG_ED25519) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (public_key == NULL || signature == NULL ||
        (message == NULL && message_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (public_key_length != ED25519_BYTES) {
        return LIBERAC_ERROR_INVALID_KEY;
    }
    if (signature_length != ED25519_SIGNATURE_BYTES) {
        return LIBERAC_ERROR_SIGNATURE_INVALID;
    }

    crypto_zeroize(challenge_digest, sizeof(challenge_digest));
    crypto_zeroize(challenge_scalar, sizeof(challenge_scalar));
    ed25519_point_identity(&public_point);
    ed25519_point_identity(&encoded_r);
    ed25519_point_identity(&base);
    ed25519_point_identity(&left);
    ed25519_point_identity(&challenge_point);
    ed25519_point_identity(&right);

    if (!ed25519_point_decode(&public_point, public_key) ||
        !ed25519_point_is_prime_order(&public_point)) {
        error = LIBERAC_ERROR_INVALID_KEY;
        goto cleanup;
    }
    if (!ed25519_scalar_is_canonical(signature + ED25519_BYTES) ||
        !ed25519_point_decode(&encoded_r, signature)) {
        error = LIBERAC_ERROR_SIGNATURE_INVALID;
        goto cleanup;
    }
    error = ed25519_sha512_parts(
        challenge_digest, signature, ED25519_BYTES,
        public_key, public_key_length, message, message_length);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    ed25519_scalar_reduce(
        challenge_scalar, challenge_digest, sizeof(challenge_digest));
    ed25519_point_base(&base);
    ed25519_point_scalar_multiply(
        &left, &base, signature + ED25519_BYTES);
    ed25519_point_scalar_multiply(
        &challenge_point, &public_point, challenge_scalar);
    ed25519_point_add(&right, &encoded_r, &challenge_point);
    error = ed25519_point_equal(&left, &right)
                ? LIBERAC_SUCCESS
                : LIBERAC_ERROR_SIGNATURE_INVALID;

cleanup:
    crypto_zeroize(challenge_digest, sizeof(challenge_digest));
    crypto_zeroize(challenge_scalar, sizeof(challenge_scalar));
    crypto_zeroize(&public_point, sizeof(public_point));
    crypto_zeroize(&encoded_r, sizeof(encoded_r));
    crypto_zeroize(&base, sizeof(base));
    crypto_zeroize(&left, sizeof(left));
    crypto_zeroize(&challenge_point, sizeof(challenge_point));
    crypto_zeroize(&right, sizeof(right));
    return error;
}
