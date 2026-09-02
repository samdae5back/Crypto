/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "AuthenticatedEncryption.h"
#include "AuthenticatedEncryption/ChaCha20Poly1305/chacha20_poly1305_internal.h"
#include "BlockCipher/AES/aes_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"

typedef enum {
    AEAD_FAMILY_AES_GCM = 1,
    AEAD_FAMILY_AES_CCM = 2,
    AEAD_FAMILY_CHACHA20_POLY1305 = 3
} AeadFamily;

typedef struct {
    size_t KEY_LENGTH;
    AeadFamily FAMILY;
} AeadParameters;

static LiberaCError aead_parameters(LiberaCAlgID alg,
                                    AeadParameters *parameters) {
    AeadParameters result;

    switch (alg) {
        case LIBERAC_ALG_AES_128_GCM:
            result.KEY_LENGTH = 16u;
            result.FAMILY = AEAD_FAMILY_AES_GCM;
            break;
        case LIBERAC_ALG_AES_192_GCM:
            result.KEY_LENGTH = 24u;
            result.FAMILY = AEAD_FAMILY_AES_GCM;
            break;
        case LIBERAC_ALG_AES_256_GCM:
            result.KEY_LENGTH = 32u;
            result.FAMILY = AEAD_FAMILY_AES_GCM;
            break;
        case LIBERAC_ALG_AES_128_CCM:
            result.KEY_LENGTH = 16u;
            result.FAMILY = AEAD_FAMILY_AES_CCM;
            break;
        case LIBERAC_ALG_AES_192_CCM:
            result.KEY_LENGTH = 24u;
            result.FAMILY = AEAD_FAMILY_AES_CCM;
            break;
        case LIBERAC_ALG_AES_256_CCM:
            result.KEY_LENGTH = 32u;
            result.FAMILY = AEAD_FAMILY_AES_CCM;
            break;
        case LIBERAC_ALG_CHACHA20_POLY1305:
            result.KEY_LENGTH = LIBERAC_CHACHA20_POLY1305_KEY_BYTES;
            result.FAMILY = AEAD_FAMILY_CHACHA20_POLY1305;
            break;
        default:
            return LIBERAC_ERROR_INVALID_ALG_ID;
    }

    if (parameters) *parameters = result;
    return LIBERAC_SUCCESS;
}

size_t LIBERAC_AEAD_KEY_SIZE(LiberaCAlgID ALG) {
    AeadParameters parameters;

    if (aead_parameters(ALG, &parameters) != LIBERAC_SUCCESS) return 0u;
    return parameters.KEY_LENGTH;
}

int LIBERAC_AEAD_NONCE_LENGTH_VALID(LiberaCAlgID ALG,
                                    size_t NONCE_LENGTH) {
    AeadParameters parameters;

    if (aead_parameters(ALG, &parameters) != LIBERAC_SUCCESS) return 0;
    switch (parameters.FAMILY) {
        case AEAD_FAMILY_AES_GCM:
            return NONCE_LENGTH != 0u;
        case AEAD_FAMILY_AES_CCM:
            return NONCE_LENGTH >= LIBERAC_AES_CCM_MIN_NONCE_BYTES &&
                   NONCE_LENGTH <= LIBERAC_AES_CCM_MAX_NONCE_BYTES;
        case AEAD_FAMILY_CHACHA20_POLY1305:
            return NONCE_LENGTH == LIBERAC_CHACHA20_POLY1305_NONCE_BYTES;
        default:
            return 0;
    }
}

int LIBERAC_AEAD_TAG_LENGTH_VALID(LiberaCAlgID ALG, size_t TAG_LENGTH) {
    AeadParameters parameters;

    if (aead_parameters(ALG, &parameters) != LIBERAC_SUCCESS) return 0;
    switch (parameters.FAMILY) {
        case AEAD_FAMILY_AES_GCM:
            return TAG_LENGTH == 4u || TAG_LENGTH == 8u ||
                   (TAG_LENGTH >= 12u && TAG_LENGTH <= 16u);
        case AEAD_FAMILY_AES_CCM:
            return TAG_LENGTH >= 4u && TAG_LENGTH <= 16u &&
                   (TAG_LENGTH & 1u) == 0u;
        case AEAD_FAMILY_CHACHA20_POLY1305:
            return TAG_LENGTH == LIBERAC_CHACHA20_POLY1305_TAG_BYTES;
        default:
            return 0;
    }
}

static LiberaCError aead_validate_request(
    const uint8_t *output, size_t output_capacity,
    const uint8_t *tag, size_t tag_length,
    const uint8_t *input, size_t input_length,
    const uint8_t *key, size_t key_length,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *aad, size_t aad_length,
    LiberaCAlgID alg, const AeadParameters *parameters) {
    LiberaCError err;

    if (!tag || !key || !nonce || (!input && input_length != 0u) ||
        (!output && input_length != 0u) || (!aad && aad_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (key_length != parameters->KEY_LENGTH)
        return LIBERAC_ERROR_INVALID_KEY;
    if (!LIBERAC_AEAD_NONCE_LENGTH_VALID(alg, nonce_length) ||
        !LIBERAC_AEAD_TAG_LENGTH_VALID(alg, tag_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (output_capacity < input_length)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;

    if (parameters->FAMILY == AEAD_FAMILY_CHACHA20_POLY1305) {
        err = crypto_chacha20_poly1305_validate_lengths(input_length,
                                                        aad_length);
        if (err != LIBERAC_SUCCESS) return err;
    }

    if (output != input &&
        crypto_ranges_overlap(output, input_length, input, input_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (crypto_ranges_overlap(output, input_length, key, key_length) ||
        crypto_ranges_overlap(output, input_length, nonce, nonce_length) ||
        crypto_ranges_overlap(output, input_length, aad, aad_length) ||
        crypto_ranges_overlap(output, input_length, tag, tag_length) ||
        crypto_ranges_overlap(tag, tag_length, input, input_length) ||
        crypto_ranges_overlap(tag, tag_length, key, key_length) ||
        crypto_ranges_overlap(tag, tag_length, nonce, nonce_length) ||
        crypto_ranges_overlap(tag, tag_length, aad, aad_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    return LIBERAC_SUCCESS;
}

static LiberaCError aead_aes_encrypt(
    AeadFamily family,
    uint8_t *output, uint8_t *tag, size_t tag_length,
    const uint8_t *input, size_t input_length,
    const uint8_t *key, size_t key_length,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *aad, size_t aad_length) {
    AES_CONTEXT context;
    LiberaCError err = crypto_aes_context_init(&context, key, key_length);

    if (err != LIBERAC_SUCCESS) return err;
    if (family == AEAD_FAMILY_AES_GCM) {
        err = crypto_aes_gcm_encrypt(&context, output, tag, tag_length,
                                     input, input_length, nonce, nonce_length,
                                     aad, aad_length);
    } else {
        err = crypto_aes_ccm_encrypt(&context, output, tag, tag_length,
                                     input, input_length, nonce, nonce_length,
                                     aad, aad_length);
    }
    crypto_aes_context_clear(&context);
    return err;
}

static LiberaCError aead_aes_decrypt(
    AeadFamily family,
    uint8_t *output, const uint8_t *tag, size_t tag_length,
    const uint8_t *input, size_t input_length,
    const uint8_t *key, size_t key_length,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *aad, size_t aad_length) {
    AES_CONTEXT context;
    LiberaCError err = crypto_aes_context_init(&context, key, key_length);

    if (err != LIBERAC_SUCCESS) return err;
    if (family == AEAD_FAMILY_AES_GCM) {
        err = crypto_aes_gcm_decrypt(&context, output, tag, tag_length,
                                     input, input_length, nonce, nonce_length,
                                     aad, aad_length);
    } else {
        err = crypto_aes_ccm_decrypt(&context, output, tag, tag_length,
                                     input, input_length, nonce, nonce_length,
                                     aad, aad_length);
    }
    crypto_aes_context_clear(&context);
    return err;
}

LiberaCError LIBERAC_AEAD_ENCRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    uint8_t *TAG, size_t TAG_CAPACITY, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    LiberaCAlgID ALG) {
    AeadParameters parameters;
    LiberaCError err = aead_parameters(ALG, &parameters);

    if (err != LIBERAC_SUCCESS) return err;
    err = aead_validate_request(
        OUTPUT, OUTPUT_CAPACITY, TAG, TAG_LENGTH, INPUT, INPUT_LENGTH,
        KEY, KEY_LENGTH, NONCE, NONCE_LENGTH, AAD, AAD_LENGTH,
        ALG, &parameters);
    if (err != LIBERAC_SUCCESS) return err;
    if (TAG_CAPACITY < TAG_LENGTH) return LIBERAC_ERROR_BUFFER_TOO_SMALL;

    if (parameters.FAMILY == AEAD_FAMILY_CHACHA20_POLY1305) {
        return crypto_chacha20_poly1305_encrypt_internal(
            OUTPUT, TAG, INPUT, INPUT_LENGTH, KEY, NONCE, AAD, AAD_LENGTH);
    }
    err = aead_aes_encrypt(
        parameters.FAMILY, OUTPUT, TAG, TAG_LENGTH, INPUT, INPUT_LENGTH,
        KEY, KEY_LENGTH, NONCE, NONCE_LENGTH, AAD, AAD_LENGTH);
    if (err != LIBERAC_SUCCESS) {
        crypto_zeroize(OUTPUT, INPUT_LENGTH);
        crypto_zeroize(TAG, TAG_LENGTH);
    }
    return err;
}

LiberaCError LIBERAC_AEAD_DECRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *NONCE, size_t NONCE_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    LiberaCAlgID ALG) {
    AeadParameters parameters;
    LiberaCError err = aead_parameters(ALG, &parameters);

    if (err != LIBERAC_SUCCESS) return err;
    err = aead_validate_request(
        OUTPUT, OUTPUT_CAPACITY, TAG, TAG_LENGTH, INPUT, INPUT_LENGTH,
        KEY, KEY_LENGTH, NONCE, NONCE_LENGTH, AAD, AAD_LENGTH,
        ALG, &parameters);
    if (err != LIBERAC_SUCCESS) return err;

    if (parameters.FAMILY == AEAD_FAMILY_CHACHA20_POLY1305) {
        return crypto_chacha20_poly1305_decrypt_internal(
            OUTPUT, TAG, INPUT, INPUT_LENGTH, KEY, NONCE, AAD, AAD_LENGTH);
    }
    err = aead_aes_decrypt(
        parameters.FAMILY, OUTPUT, TAG, TAG_LENGTH, INPUT, INPUT_LENGTH,
        KEY, KEY_LENGTH, NONCE, NONCE_LENGTH, AAD, AAD_LENGTH);
    if (err != LIBERAC_SUCCESS) crypto_zeroize(OUTPUT, INPUT_LENGTH);
    return err;
}
