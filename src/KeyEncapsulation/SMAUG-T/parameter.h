/*
 * Copyright (c) 2026 Team SMAUG-T
 * SPDX-License-Identifier: MIT
 */

#ifndef CRYPTO_SMAUG_T_PARAMETER_H
#define CRYPTO_SMAUG_T_PARAMETER_H

#include "KeyEncapsulation.h"

#define CRYPTO_SMAUG_T_N 256u
#define CRYPTO_SMAUG_T_MAX_RANK 4u
#define CRYPTO_SMAUG_T_SEED_BYTES 32u
#define CRYPTO_SMAUG_T_MESSAGE_BYTES 32u
#define CRYPTO_SMAUG_T_SECRET_POLY_BYTES 64u
#define CRYPTO_SMAUG_T_HWT_SEED_BYTES 616u
#define CRYPTO_SMAUG_T_MAX_PUBLIC_POLY_BYTES 352u
#define CRYPTO_SMAUG_T_MAX_CBD_SEED_BYTES 128u
#define CRYPTO_SMAUG_T_MAX_PUBLIC_KEY_BYTES \
    CRYPTO_SMAUG_T_256_PUBLIC_KEY_BYTES
#define CRYPTO_SMAUG_T_MAX_PRIVATE_KEY_BYTES \
    CRYPTO_SMAUG_T_256_PRIVATE_KEY_BYTES
#define CRYPTO_SMAUG_T_MAX_CIPHERTEXT_BYTES \
    CRYPTO_SMAUG_T_256_CIPHERTEXT_BYTES

typedef struct crypto_smaug_t_parameters {
    AlgID algorithm;
    uint8_t rank;
    uint8_t log_q;
    uint8_t log_p;
    uint8_t log_p_prime;
    uint8_t hamming_weight;
    uint16_t round_add;
    uint16_t round_mask;
    uint16_t round_add_prime;
    uint16_t round_mask_prime;
    size_t cbd_seed_bytes;
    size_t public_poly_bytes;
    size_t ciphertext_poly_bytes;
    size_t ciphertext_poly_prime_bytes;
    size_t ciphertext_vector_bytes;
    size_t pke_private_key_bytes;
    size_t public_key_bytes;
    size_t private_key_bytes;
    size_t ciphertext_bytes;
} crypto_smaug_t_parameters;

static const crypto_smaug_t_parameters CRYPTO_SMAUG_T_PARAMETER_SETS[] = {
    {
        ALG_SMAUG_T_128,
        2u, 10u, 8u, 5u, 70u,
        UINT16_C(0x0080), UINT16_C(0xff00),
        UINT16_C(0x0400), UINT16_C(0xf800),
        96u, 320u, 256u, 160u, 512u, 128u,
        CRYPTO_SMAUG_T_128_PUBLIC_KEY_BYTES,
        CRYPTO_SMAUG_T_128_PRIVATE_KEY_BYTES,
        CRYPTO_SMAUG_T_128_CIPHERTEXT_BYTES
    },
    {
        ALG_SMAUG_T_192,
        3u, 11u, 9u, 4u, 88u,
        UINT16_C(0x0040), UINT16_C(0xff80),
        UINT16_C(0x0800), UINT16_C(0xf000),
        64u, 352u, 288u, 128u, 864u, 192u,
        CRYPTO_SMAUG_T_192_PUBLIC_KEY_BYTES,
        CRYPTO_SMAUG_T_192_PRIVATE_KEY_BYTES,
        CRYPTO_SMAUG_T_192_CIPHERTEXT_BYTES
    },
    {
        ALG_SMAUG_T_256,
        4u, 11u, 9u, 7u, 87u,
        UINT16_C(0x0040), UINT16_C(0xff80),
        UINT16_C(0x0100), UINT16_C(0xfe00),
        128u, 352u, 288u, 224u, 1152u, 256u,
        CRYPTO_SMAUG_T_256_PUBLIC_KEY_BYTES,
        CRYPTO_SMAUG_T_256_PRIVATE_KEY_BYTES,
        CRYPTO_SMAUG_T_256_CIPHERTEXT_BYTES
    }
};

#endif
