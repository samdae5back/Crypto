/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "bignum_internal.h"

#include <string.h>

static size_t bignum_secret_length_fixed(const uint32_t *limbs,
                                         size_t fixed_limbs) {
    size_t i, length = 0u;
    for (i = 0u; i < fixed_limbs; ++i) {
        uint32_t x = limbs[i];
        uint32_t nonzero = (x | (uint32_t)(0u - x)) >> 31;
        size_t mask = (size_t)0 - (size_t)nonzero;
        length = (length & ~mask) | ((i + 1u) & mask);
    }
    return length;
}

LiberaCError crypto_bignum_copy_secret_fixed_ct(LiberaCBignum *out,
                                                const LiberaCBignum *in,
                                                size_t fixed_limbs) {
    LiberaCBignum tmp;
    size_t i;

    if (!out || !in || in->CAPACITY < fixed_limbs)
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    crypto_bignum_init(&tmp);
    if (fixed_limbs != 0u && bignum_reserve(&tmp, fixed_limbs) != 0)
        return LIBERAC_ERROR_ALLOCATION_FAILED;

    /* Once a secret has been promoted to fixed storage, copy the complete
     * public width.  Neither loop count nor memory indices use in->LENGTH. */
    for (i = 0u; i < fixed_limbs; ++i)
        tmp.LIMBS[i] = in->LIMBS[i];
    tmp.LENGTH = bignum_secret_length_fixed(tmp.LIMBS, fixed_limbs);

    crypto_bignum_free(out);
    *out = tmp;
    return LIBERAC_SUCCESS;
}

static LiberaCError bignum_from_bytes_secret_fixed_ct(
    LiberaCBignum *out, const uint8_t *bytes, size_t input_length,
    size_t fixed_limbs, int big_endian) {
    LiberaCBignum tmp;
    size_t i;

    if (!out || (!bytes && input_length != 0u) ||
        fixed_limbs > SIZE_MAX / 4u || input_length > fixed_limbs * 4u)
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    crypto_bignum_init(&tmp);
    if (fixed_limbs != 0u && bignum_reserve(&tmp, fixed_limbs) != 0)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    if (fixed_limbs != 0u)
        memset(tmp.LIMBS, 0, fixed_limbs * sizeof(uint32_t));

    /* input_length is a protocol/public width.  Byte values do not affect the
     * loop count, branch structure, or destination indices. */
    for (i = 0u; i < input_length; ++i) {
        size_t source = big_endian ? input_length - 1u - i : i;
        tmp.LIMBS[i / 4u] |=
            (uint32_t)bytes[source] << (8u * (i % 4u));
    }
    tmp.LENGTH = bignum_secret_length_fixed(tmp.LIMBS, fixed_limbs);

    crypto_bignum_free(out);
    *out = tmp;
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_bignum_from_bytes_be_secret_fixed_ct(
    LiberaCBignum *out, const uint8_t *bytes, size_t input_length,
    size_t fixed_limbs) {
    return bignum_from_bytes_secret_fixed_ct(
        out, bytes, input_length, fixed_limbs, 1);
}

LiberaCError crypto_bignum_from_bytes_le_secret_fixed_ct(
    LiberaCBignum *out, const uint8_t *bytes, size_t input_length,
    size_t fixed_limbs) {
    return bignum_from_bytes_secret_fixed_ct(
        out, bytes, input_length, fixed_limbs, 0);
}

static LiberaCError bignum_to_bytes_secret_fixed_ct(
    const LiberaCBignum *in, uint8_t *out, size_t output_length,
    int big_endian) {
    size_t needed_limbs, i;

    if (!in || (!out && output_length != 0u))
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (output_length > SIZE_MAX - 3u)
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    needed_limbs = (output_length + 3u) / 4u;
    if (in->CAPACITY < needed_limbs)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;

    /* Serialize exactly the caller-selected public width and ignore LENGTH.
     * Fixed secret storage guarantees that unused high limbs are zero. */
    for (i = 0u; i < output_length; ++i) {
        uint8_t byte =
            (uint8_t)(in->LIMBS[i / 4u] >> (8u * (i % 4u)));
        if (big_endian)
            out[output_length - 1u - i] = byte;
        else
            out[i] = byte;
    }
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_bignum_to_bytes_be_secret_fixed_ct(
    const LiberaCBignum *in, uint8_t *out, size_t output_length) {
    return bignum_to_bytes_secret_fixed_ct(in, out, output_length, 1);
}

LiberaCError crypto_bignum_to_bytes_le_secret_fixed_ct(
    const LiberaCBignum *in, uint8_t *out, size_t output_length) {
    return bignum_to_bytes_secret_fixed_ct(in, out, output_length, 0);
}
