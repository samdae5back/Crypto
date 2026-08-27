/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "KeyEncapsulation.h"

#include "KeyEncapsulation/ML-KEM/api_internal.h"

size_t CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(AlgID alg) {
    return crypto_ml_kem_public_key_size_internal(alg);
}

size_t CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(AlgID alg) {
    return crypto_ml_kem_private_key_size_internal(alg);
}

size_t CRYPTO_ML_KEM_CIPHERTEXT_SIZE(AlgID alg) {
    return crypto_ml_kem_ciphertext_size_internal(alg);
}

CryptoError CRYPTO_ML_KEM_KEYGEN(uint8_t *public_key, size_t public_key_length,
                                  uint8_t *private_key, size_t private_key_length,
                                  AlgID alg) {
    return crypto_ml_kem_keygen_internal(alg, public_key, public_key_length,
                                         private_key, private_key_length);
}

CryptoError CRYPTO_ML_KEM_ENCAPS(
    const uint8_t *public_key, size_t public_key_length,
    uint8_t shared_secret[CRYPTO_ML_KEM_SHARED_SECRET_BYTES],
    uint8_t *ciphertext, size_t ciphertext_length,
    AlgID alg) {
    return crypto_ml_kem_encaps_internal(alg, public_key, public_key_length,
                                         shared_secret, ciphertext,
                                         ciphertext_length);
}

CryptoError CRYPTO_ML_KEM_DECAPS(
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t shared_secret[CRYPTO_ML_KEM_SHARED_SECRET_BYTES],
    AlgID alg) {
    return crypto_ml_kem_decaps_internal(alg, private_key, private_key_length,
                                         ciphertext, ciphertext_length,
                                         shared_secret);
}
