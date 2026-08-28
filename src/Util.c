/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Util.h"

#include "Util/Bignum/bignum_internal.h"
#include "Util/Prime/prime_internal.h"

void LIBERAC_BIGNUM_INIT(LiberaCBignum *value) {
    crypto_bignum_init(value);
}

void LIBERAC_BIGNUM_FREE(LiberaCBignum *value) {
    crypto_bignum_free(value);
}

LiberaCError LIBERAC_BIGNUM_FROM_BYTES_BE(LiberaCBignum *output,
                                         const uint8_t *bytes, size_t length) {
    return crypto_bignum_from_bytes_be(output, bytes, length);
}

LiberaCError LIBERAC_BIGNUM_FROM_BYTES_LE(LiberaCBignum *output,
                                         const uint8_t *bytes, size_t length) {
    return crypto_bignum_from_bytes_le(output, bytes, length);
}

LiberaCError LIBERAC_BIGNUM_TO_BYTES_BE(const LiberaCBignum *input,
                                       uint8_t *output, size_t output_length) {
    return crypto_bignum_to_bytes_be(input, output, output_length);
}

LiberaCError LIBERAC_BIGNUM_TO_BYTES_LE(const LiberaCBignum *input,
                                       uint8_t *output, size_t output_length) {
    return crypto_bignum_to_bytes_le(input, output, output_length);
}

int LIBERAC_PRIME_IS_PROBABLE(const LiberaCBignum *value, uint32_t rounds) {
    return crypto_prime_is_probable_internal(value, rounds);
}

LiberaCError LIBERAC_PRIME_GENERATE(LiberaCBignum *output,
                                   size_t bits, uint32_t rounds) {
    return crypto_prime_generate_internal(output, bits, rounds);
}

LiberaCError LIBERAC_PRIME_GENERATE_SAFE(LiberaCBignum *p, LiberaCBignum *q,
                                        size_t p_bits, uint32_t rounds) {
    return crypto_prime_generate_safe_internal(p, q, p_bits, rounds);
}
