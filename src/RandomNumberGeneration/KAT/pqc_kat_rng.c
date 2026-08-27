/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "pqc_kat_rng_internal.h"

#include "RandomNumberGeneration/CTR_DRBG/ctr_drbg_internal.h"
#include "RandomNumberGeneration/Noise/random_internal.h"

#if defined(CRYPTO_ENABLE_PQC_KAT)
#if defined(_MSC_VER)
#define CRYPTO_KAT_THREAD_LOCAL __declspec(thread)
#else
#define CRYPTO_KAT_THREAD_LOCAL _Thread_local
#endif

static CRYPTO_KAT_THREAD_LOCAL CRYPTO_CTR_DRBG_CONTEXT pqc_kat_drbg;
static CRYPTO_KAT_THREAD_LOCAL int pqc_kat_active;

CryptoError crypto_pqc_kat_initialize_internal(
    const uint8_t seed[CRYPTO_PQC_KAT_SEED_BYTES]) {
    CryptoError error;

    if (seed == NULL) return CRYPTO_ERROR_INVALID_ARGUMENT;

    crypto_ctr_drbg_clear_internal(&pqc_kat_drbg);
    pqc_kat_active = 0;
    error = crypto_ctr_drbg_instantiate_internal(
        &pqc_kat_drbg, ALG_CTR_DRBG_AES_256_NO_DF,
        seed, CRYPTO_PQC_KAT_SEED_BYTES,
        NULL, 0u, NULL, 0u);
    if (error == CRYPTO_SUCCESS) {
        pqc_kat_active = 1;
    } else {
        crypto_ctr_drbg_clear_internal(&pqc_kat_drbg);
    }
    return error;
}

void crypto_pqc_kat_finalize_internal(void) {
    crypto_ctr_drbg_clear_internal(&pqc_kat_drbg);
    pqc_kat_active = 0;
}
#endif

CryptoError crypto_pqc_random_bytes_internal(
    uint8_t *output, size_t output_length) {
#if defined(CRYPTO_ENABLE_PQC_KAT)
    if (pqc_kat_active != 0) {
        return crypto_ctr_drbg_generate_internal(
            &pqc_kat_drbg, output, output_length,
            NULL, 0u, 0);
    }
#endif
    return crypto_random_bytes_internal(output, output_length);
}
