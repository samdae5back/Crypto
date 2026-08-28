/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "DigitalSignature.h"

#include "DigitalSignature/AIMer/aimer_internal.h"
#include "DigitalSignature/HAETAE/haetae_internal.h"
#include "DigitalSignature/ML-DSA/ml_dsa_internal.h"
#include "DigitalSignature/SLH-DSA/slh_dsa_internal.h"

size_t LIBERAC_ML_DSA_PUBLIC_KEY_SIZE(LiberaCAlgID alg) {
    return crypto_ml_dsa_public_key_size_internal(alg);
}

size_t LIBERAC_ML_DSA_PRIVATE_KEY_SIZE(LiberaCAlgID alg) {
    return crypto_ml_dsa_private_key_size_internal(alg);
}

size_t LIBERAC_ML_DSA_SIGNATURE_SIZE(LiberaCAlgID alg) {
    return crypto_ml_dsa_signature_size_internal(alg);
}

LiberaCError LIBERAC_ML_DSA_KEYGEN(uint8_t *public_key, size_t public_key_length,
                                  uint8_t *private_key, size_t private_key_length,
                                  LiberaCAlgID alg) {
    return crypto_ml_dsa_keygen_internal(alg, public_key, public_key_length,
                                         private_key, private_key_length);
}

LiberaCError LIBERAC_ML_DSA_SIGN(
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length,
    LiberaCAlgID alg) {
    return crypto_ml_dsa_sign_internal(alg, private_key, private_key_length,
                                       message, message_length, context,
                                       context_length, signature,
                                       signature_length);
}

LiberaCError LIBERAC_ML_DSA_VERIFY(
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length,
    LiberaCAlgID alg) {
    return crypto_ml_dsa_verify_internal(alg, public_key, public_key_length,
                                         message, message_length, context,
                                         context_length, signature,
                                         signature_length);
}

size_t LIBERAC_AIMER_PUBLIC_KEY_SIZE(LiberaCAlgID alg) {
    return crypto_aimer_public_key_size_internal(alg);
}

size_t LIBERAC_AIMER_PRIVATE_KEY_SIZE(LiberaCAlgID alg) {
    return crypto_aimer_private_key_size_internal(alg);
}

size_t LIBERAC_AIMER_SIGNATURE_SIZE(LiberaCAlgID alg) {
    return crypto_aimer_signature_size_internal(alg);
}

LiberaCError LIBERAC_AIMER_KEYGEN(
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length,
    LiberaCAlgID alg) {
    return crypto_aimer_keygen_internal(
        alg, public_key, public_key_length,
        private_key, private_key_length);
}

LiberaCError LIBERAC_AIMER_SIGN(
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length,
    LiberaCAlgID alg) {
    return crypto_aimer_sign_internal(
        alg, private_key, private_key_length,
        message, message_length, context, context_length,
        signature, signature_length);
}

LiberaCError LIBERAC_AIMER_VERIFY(
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length,
    LiberaCAlgID alg) {
    return crypto_aimer_verify_internal(
        alg, public_key, public_key_length,
        message, message_length, context, context_length,
        signature, signature_length);
}

size_t LIBERAC_HAETAE_PUBLIC_KEY_SIZE(LiberaCAlgID alg) {
    return crypto_haetae_public_key_size_internal(alg);
}

size_t LIBERAC_HAETAE_PRIVATE_KEY_SIZE(LiberaCAlgID alg) {
    return crypto_haetae_private_key_size_internal(alg);
}

size_t LIBERAC_HAETAE_SIGNATURE_SIZE(LiberaCAlgID alg) {
    return crypto_haetae_signature_size_internal(alg);
}

LiberaCError LIBERAC_HAETAE_KEYGEN(
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length,
    LiberaCAlgID alg) {
    return crypto_haetae_keygen_internal(
        alg, public_key, public_key_length,
        private_key, private_key_length);
}

LiberaCError LIBERAC_HAETAE_SIGN(
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length,
    LiberaCAlgID alg) {
    return crypto_haetae_sign_internal(
        alg, private_key, private_key_length,
        message, message_length, context, context_length,
        signature, signature_length);
}

LiberaCError LIBERAC_HAETAE_VERIFY(
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length,
    LiberaCAlgID alg) {
    return crypto_haetae_verify_internal(
        alg, public_key, public_key_length,
        message, message_length, context, context_length,
        signature, signature_length);
}

size_t LIBERAC_SLH_DSA_PUBLIC_KEY_SIZE(LiberaCAlgID alg) {
    return crypto_slh_dsa_public_key_size_internal(alg);
}

size_t LIBERAC_SLH_DSA_PRIVATE_KEY_SIZE(LiberaCAlgID alg) {
    return crypto_slh_dsa_private_key_size_internal(alg);
}

size_t LIBERAC_SLH_DSA_SIGNATURE_SIZE(LiberaCAlgID alg) {
    return crypto_slh_dsa_signature_size_internal(alg);
}

LiberaCError LIBERAC_SLH_DSA_KEYGEN(uint8_t *public_key, size_t public_key_length,
                                   uint8_t *private_key, size_t private_key_length,
                                   LiberaCAlgID alg) {
    return crypto_slh_dsa_keygen_internal(alg, public_key, public_key_length,
                                          private_key, private_key_length);
}

LiberaCError LIBERAC_SLH_DSA_SIGN(
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length,
    LiberaCAlgID alg) {
    return crypto_slh_dsa_sign_internal(alg, private_key, private_key_length,
                                        message, message_length, context,
                                        context_length, signature,
                                        signature_length);
}

LiberaCError LIBERAC_SLH_DSA_VERIFY(
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length,
    LiberaCAlgID alg) {
    return crypto_slh_dsa_verify_internal(alg, public_key, public_key_length,
                                          message, message_length, context,
                                          context_length, signature,
                                          signature_length);
}
