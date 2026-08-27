/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "DigitalSignature.h"

#include "DigitalSignature/AIMer/aimer_internal.h"
#include "DigitalSignature/HAETAE/haetae_internal.h"
#include "DigitalSignature/ML-DSA/ml_dsa_internal.h"
#include "DigitalSignature/SLH-DSA/slh_dsa_internal.h"

size_t CRYPTO_ML_DSA_PUBLIC_KEY_SIZE(AlgID alg) {
    return crypto_ml_dsa_public_key_size_internal(alg);
}

size_t CRYPTO_ML_DSA_PRIVATE_KEY_SIZE(AlgID alg) {
    return crypto_ml_dsa_private_key_size_internal(alg);
}

size_t CRYPTO_ML_DSA_SIGNATURE_SIZE(AlgID alg) {
    return crypto_ml_dsa_signature_size_internal(alg);
}

CryptoError CRYPTO_ML_DSA_KEYGEN(uint8_t *public_key, size_t public_key_length,
                                  uint8_t *private_key, size_t private_key_length,
                                  AlgID alg) {
    return crypto_ml_dsa_keygen_internal(alg, public_key, public_key_length,
                                         private_key, private_key_length);
}

CryptoError CRYPTO_ML_DSA_SIGN(
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length,
    AlgID alg) {
    return crypto_ml_dsa_sign_internal(alg, private_key, private_key_length,
                                       message, message_length, context,
                                       context_length, signature,
                                       signature_length);
}

CryptoError CRYPTO_ML_DSA_VERIFY(
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length,
    AlgID alg) {
    return crypto_ml_dsa_verify_internal(alg, public_key, public_key_length,
                                         message, message_length, context,
                                         context_length, signature,
                                         signature_length);
}

size_t CRYPTO_AIMER_PUBLIC_KEY_SIZE(AlgID alg) {
    return crypto_aimer_public_key_size_internal(alg);
}

size_t CRYPTO_AIMER_PRIVATE_KEY_SIZE(AlgID alg) {
    return crypto_aimer_private_key_size_internal(alg);
}

size_t CRYPTO_AIMER_SIGNATURE_SIZE(AlgID alg) {
    return crypto_aimer_signature_size_internal(alg);
}

CryptoError CRYPTO_AIMER_KEYGEN(
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length,
    AlgID alg) {
    return crypto_aimer_keygen_internal(
        alg, public_key, public_key_length,
        private_key, private_key_length);
}

CryptoError CRYPTO_AIMER_SIGN(
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length,
    AlgID alg) {
    return crypto_aimer_sign_internal(
        alg, private_key, private_key_length,
        message, message_length, context, context_length,
        signature, signature_length);
}

CryptoError CRYPTO_AIMER_VERIFY(
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length,
    AlgID alg) {
    return crypto_aimer_verify_internal(
        alg, public_key, public_key_length,
        message, message_length, context, context_length,
        signature, signature_length);
}

size_t CRYPTO_HAETAE_PUBLIC_KEY_SIZE(AlgID alg) {
    return crypto_haetae_public_key_size_internal(alg);
}

size_t CRYPTO_HAETAE_PRIVATE_KEY_SIZE(AlgID alg) {
    return crypto_haetae_private_key_size_internal(alg);
}

size_t CRYPTO_HAETAE_SIGNATURE_SIZE(AlgID alg) {
    return crypto_haetae_signature_size_internal(alg);
}

CryptoError CRYPTO_HAETAE_KEYGEN(
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length,
    AlgID alg) {
    return crypto_haetae_keygen_internal(
        alg, public_key, public_key_length,
        private_key, private_key_length);
}

CryptoError CRYPTO_HAETAE_SIGN(
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length,
    AlgID alg) {
    return crypto_haetae_sign_internal(
        alg, private_key, private_key_length,
        message, message_length, context, context_length,
        signature, signature_length);
}

CryptoError CRYPTO_HAETAE_VERIFY(
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length,
    AlgID alg) {
    return crypto_haetae_verify_internal(
        alg, public_key, public_key_length,
        message, message_length, context, context_length,
        signature, signature_length);
}

size_t CRYPTO_SLH_DSA_PUBLIC_KEY_SIZE(AlgID alg) {
    return crypto_slh_dsa_public_key_size_internal(alg);
}

size_t CRYPTO_SLH_DSA_PRIVATE_KEY_SIZE(AlgID alg) {
    return crypto_slh_dsa_private_key_size_internal(alg);
}

size_t CRYPTO_SLH_DSA_SIGNATURE_SIZE(AlgID alg) {
    return crypto_slh_dsa_signature_size_internal(alg);
}

CryptoError CRYPTO_SLH_DSA_KEYGEN(uint8_t *public_key, size_t public_key_length,
                                   uint8_t *private_key, size_t private_key_length,
                                   AlgID alg) {
    return crypto_slh_dsa_keygen_internal(alg, public_key, public_key_length,
                                          private_key, private_key_length);
}

CryptoError CRYPTO_SLH_DSA_SIGN(
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length,
    AlgID alg) {
    return crypto_slh_dsa_sign_internal(alg, private_key, private_key_length,
                                        message, message_length, context,
                                        context_length, signature,
                                        signature_length);
}

CryptoError CRYPTO_SLH_DSA_VERIFY(
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length,
    AlgID alg) {
    return crypto_slh_dsa_verify_internal(alg, public_key, public_key_length,
                                          message, message_length, context,
                                          context_length, signature,
                                          signature_length);
}
