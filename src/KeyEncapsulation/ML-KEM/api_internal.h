#ifndef CRYPTO_ML_KEM_API_INTERNAL_H
#define CRYPTO_ML_KEM_API_INTERNAL_H

#include "KeyEncapsulation.h"

size_t crypto_ml_kem_public_key_size_internal(AlgID alg);
size_t crypto_ml_kem_private_key_size_internal(AlgID alg);
size_t crypto_ml_kem_ciphertext_size_internal(AlgID alg);
CryptoError crypto_ml_kem_keygen_internal(AlgID alg,
                                           uint8_t *public_key, size_t public_key_length,
                                           uint8_t *private_key, size_t private_key_length);
CryptoError crypto_ml_kem_encaps_internal(
    AlgID alg, const uint8_t *public_key, size_t public_key_length,
    uint8_t shared_secret[CRYPTO_ML_KEM_SHARED_SECRET_BYTES],
    uint8_t *ciphertext, size_t ciphertext_length);
CryptoError crypto_ml_kem_decaps_internal(
    AlgID alg, const uint8_t *private_key, size_t private_key_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t shared_secret[CRYPTO_ML_KEM_SHARED_SECRET_BYTES]);

#endif
