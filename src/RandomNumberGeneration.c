/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "RandomNumberGeneration.h"

#include "RandomNumberGeneration/CTR_DRBG/ctr_drbg_internal.h"
#include "RandomNumberGeneration/Noise/random_internal.h"

LiberaCError LIBERAC_RANDOM_BYTES(uint8_t *output, size_t output_length) {
    return crypto_random_bytes_internal(output, output_length);
}

size_t LIBERAC_CTR_DRBG_SEED_SIZE(LiberaCAlgID alg) {
    return crypto_ctr_drbg_seed_size_internal(alg);
}

LiberaCError LIBERAC_CTR_DRBG_INSTANTIATE(
    LiberaCCtrDrbgContext *context,
    const uint8_t *entropy, size_t entropy_length,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *personalization, size_t personalization_length,
    LiberaCAlgID alg) {
    return crypto_ctr_drbg_instantiate_internal(
        context, alg, entropy, entropy_length, nonce, nonce_length,
        personalization, personalization_length);
}

LiberaCError LIBERAC_CTR_DRBG_INSTANTIATE_OS(
    LiberaCCtrDrbgContext *context,
    const uint8_t *personalization, size_t personalization_length,
    LiberaCAlgID alg) {
    return crypto_ctr_drbg_instantiate_os_internal(
        context, alg, personalization, personalization_length);
}

LiberaCError LIBERAC_CTR_DRBG_RESEED(
    LiberaCCtrDrbgContext *context,
    const uint8_t *entropy, size_t entropy_length,
    const uint8_t *additional, size_t additional_length) {
    return crypto_ctr_drbg_reseed_internal(
        context, entropy, entropy_length, additional, additional_length);
}

LiberaCError LIBERAC_CTR_DRBG_RESEED_OS(
    LiberaCCtrDrbgContext *context,
    const uint8_t *additional, size_t additional_length) {
    return crypto_ctr_drbg_reseed_os_internal(context, additional,
                                               additional_length);
}

LiberaCError LIBERAC_CTR_DRBG_GENERATE(
    LiberaCCtrDrbgContext *context,
    uint8_t *output, size_t output_length,
    const uint8_t *additional, size_t additional_length,
    int prediction_resistance) {
    return crypto_ctr_drbg_generate_internal(
        context, output, output_length, additional, additional_length,
        prediction_resistance);
}

void LIBERAC_CTR_DRBG_CLEAR(LiberaCCtrDrbgContext *context) {
    crypto_ctr_drbg_clear_internal(context);
}
