/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_HAETAE_PARAMETER_H
#define CRYPTO_HAETAE_PARAMETER_H

#include "Def.h"
#include "Util/PQC/pqc_internal.h"

#define CRYPTO_HAETAE_SEED_BYTES 32u
#define CRYPTO_HAETAE_CRH_BYTES 64u
#define CRYPTO_HAETAE_N 256u
#define CRYPTO_HAETAE_LARGE_N 8192u
#define CRYPTO_HAETAE_LARGE_N_BITS 13u
#define CRYPTO_HAETAE_Q 64513
#define CRYPTO_HAETAE_DOUBLE_Q (CRYPTO_HAETAE_Q << 1)
#define CRYPTO_HAETAE_ETA 1

#define CRYPTO_HAETAE_POLY_ETA_PACKED_BYTES 64u
#define CRYPTO_HAETAE_POLY_2ETA_PACKED_BYTES 96u
#define CRYPTO_HAETAE_POLY_CHALLENGE_PACKED_BYTES 32u
#define CRYPTO_HAETAE_POLY_HIGH_BITS_PACKED_BYTES 288u

#define CRYPTO_HAETAE_MAX_K 4u
#define CRYPTO_HAETAE_MAX_L 7u
#define CRYPTO_HAETAE_MAX_M (CRYPTO_HAETAE_MAX_L - 1u)
#define CRYPTO_HAETAE_MAX_D 1u
#define CRYPTO_HAETAE_MIN_TAU 58u
#define CRYPTO_HAETAE_MAX_PUBLIC_KEY_BYTES 2080u
#define CRYPTO_HAETAE_MAX_PRIVATE_KEY_BYTES 2752u
#define CRYPTO_HAETAE_MAX_SIGNATURE_BYTES 2948u
#define CRYPTO_HAETAE_MAX_HIGH_BITS_BUFFER_BYTES \
    (CRYPTO_HAETAE_MAX_K * CRYPTO_HAETAE_POLY_HIGH_BITS_PACKED_BYTES)
#define CRYPTO_HAETAE_MAX_HINT_COEFFICIENTS \
    (CRYPTO_HAETAE_N * CRYPTO_HAETAE_MAX_K)
#define CRYPTO_HAETAE_MAX_Z1_COEFFICIENTS \
    (CRYPTO_HAETAE_N * CRYPTO_HAETAE_MAX_L)

typedef crypto_pqc_poly32 crypto_haetae_poly;
typedef crypto_pqc_polyvecl32 crypto_haetae_polyvecl;
typedef crypto_pqc_polyveck32 crypto_haetae_polyveck;

typedef struct crypto_haetae_polyvecm {
    crypto_haetae_poly vec[CRYPTO_HAETAE_MAX_M];
} crypto_haetae_polyvecm;

typedef struct crypto_haetae_parameters {
    AlgID algorithm;
    size_t public_key_bytes;
    size_t private_key_bytes;
    size_t signature_bytes;
    uint32_t mode;
    uint32_t k;
    uint32_t l;
    uint32_t tau;
    double b0;
    double b1;
    double b2;
    double gamma;
    double sqrt_nm;
    uint32_t d;
    uint32_t base_encoding_high_bits_z1;
    uint32_t base_encoding_hint;
    uint32_t alpha_hint;
    uint32_t log_alpha_hint;
    uint32_t poly_q_packed_bytes;
    uint32_t polyveck_high_bits_packed_bytes;
} crypto_haetae_parameters;

const crypto_haetae_parameters *crypto_haetae_parameters_from_algorithm(
    AlgID algorithm);

#endif
