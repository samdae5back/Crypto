/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_CTR_DRBG_INTERNAL_H
#define CRYPTO_CTR_DRBG_INTERNAL_H

#include "RandomNumberGeneration.h"

size_t crypto_ctr_drbg_seed_size_internal(LiberaCAlgID alg);
LiberaCError crypto_ctr_drbg_instantiate_internal(
    LiberaCCtrDrbgContext *context, LiberaCAlgID alg,
    const uint8_t *entropy, size_t entropy_length,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *personalization, size_t personalization_length);
LiberaCError crypto_ctr_drbg_instantiate_os_internal(
    LiberaCCtrDrbgContext *context, LiberaCAlgID alg,
    const uint8_t *personalization, size_t personalization_length);
LiberaCError crypto_ctr_drbg_reseed_internal(
    LiberaCCtrDrbgContext *context,
    const uint8_t *entropy, size_t entropy_length,
    const uint8_t *additional, size_t additional_length);
LiberaCError crypto_ctr_drbg_reseed_os_internal(
    LiberaCCtrDrbgContext *context,
    const uint8_t *additional, size_t additional_length);
LiberaCError crypto_ctr_drbg_generate_internal(
    LiberaCCtrDrbgContext *context,
    uint8_t *output, size_t output_length,
    const uint8_t *additional, size_t additional_length,
    int prediction_resistance);
void crypto_ctr_drbg_clear_internal(LiberaCCtrDrbgContext *context);

#endif
