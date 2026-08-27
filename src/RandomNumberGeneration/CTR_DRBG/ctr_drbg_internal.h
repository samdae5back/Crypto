#ifndef CRYPTO_CTR_DRBG_INTERNAL_H
#define CRYPTO_CTR_DRBG_INTERNAL_H

#include "RandomNumberGeneration.h"

size_t crypto_ctr_drbg_seed_size_internal(AlgID alg);
CryptoError crypto_ctr_drbg_instantiate_internal(
    CRYPTO_CTR_DRBG_CONTEXT *context, AlgID alg,
    const uint8_t *entropy, size_t entropy_length,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *personalization, size_t personalization_length);
CryptoError crypto_ctr_drbg_instantiate_os_internal(
    CRYPTO_CTR_DRBG_CONTEXT *context, AlgID alg,
    const uint8_t *personalization, size_t personalization_length);
CryptoError crypto_ctr_drbg_reseed_internal(
    CRYPTO_CTR_DRBG_CONTEXT *context,
    const uint8_t *entropy, size_t entropy_length,
    const uint8_t *additional, size_t additional_length);
CryptoError crypto_ctr_drbg_reseed_os_internal(
    CRYPTO_CTR_DRBG_CONTEXT *context,
    const uint8_t *additional, size_t additional_length);
CryptoError crypto_ctr_drbg_generate_internal(
    CRYPTO_CTR_DRBG_CONTEXT *context,
    uint8_t *output, size_t output_length,
    const uint8_t *additional, size_t additional_length,
    int prediction_resistance);
void crypto_ctr_drbg_clear_internal(CRYPTO_CTR_DRBG_CONTEXT *context);

#endif
