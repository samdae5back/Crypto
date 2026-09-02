/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "MessageAuthentication.h"

#include "BlockCipher.h"
#include "BlockCipher/AES/aes_internal.h"
#include "BlockCipher/TripleDES/triple_des_internal.h"
#include "HashFunction.h"
#include "MessageAuthentication/Poly1305/poly1305_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"

#include <string.h>

#define HMAC_MAX_BLOCK_BYTES 144u

typedef struct {
    size_t DIGEST_LENGTH;
    size_t BLOCK_LENGTH;
} HmacParameters;

typedef enum {
    CMAC_CIPHER_AES = 1,
    CMAC_CIPHER_TDES = 2
} CmacCipherFamily;

typedef struct {
    size_t BLOCK_LENGTH;
    size_t KEY_LENGTH;
    uint8_t REDUCTION_CONSTANT;
    CmacCipherFamily FAMILY;
} CmacParameters;

static LiberaCError hmac_parameters(
    LiberaCAlgID algorithm, HmacParameters *parameters) {
    HmacParameters selected;

    switch (algorithm) {
        case LIBERAC_ALG_HASH_SHA1:
            selected.DIGEST_LENGTH = LIBERAC_SHA1_DIGEST_BYTES;
            selected.BLOCK_LENGTH = 64u;
            break;
        case LIBERAC_ALG_HASH_SHA2_224:
            selected.DIGEST_LENGTH = LIBERAC_SHA2_224_DIGEST_BYTES;
            selected.BLOCK_LENGTH = 64u;
            break;
        case LIBERAC_ALG_HASH_SHA2_256:
            selected.DIGEST_LENGTH = LIBERAC_SHA2_256_DIGEST_BYTES;
            selected.BLOCK_LENGTH = 64u;
            break;
        case LIBERAC_ALG_HASH_SHA2_384:
            selected.DIGEST_LENGTH = LIBERAC_SHA2_384_DIGEST_BYTES;
            selected.BLOCK_LENGTH = 128u;
            break;
        case LIBERAC_ALG_HASH_SHA2_512:
            selected.DIGEST_LENGTH = LIBERAC_SHA2_512_DIGEST_BYTES;
            selected.BLOCK_LENGTH = 128u;
            break;
        case LIBERAC_ALG_HASH_SHA2_512_224:
            selected.DIGEST_LENGTH = LIBERAC_SHA2_512_224_DIGEST_BYTES;
            selected.BLOCK_LENGTH = 128u;
            break;
        case LIBERAC_ALG_HASH_SHA2_512_256:
            selected.DIGEST_LENGTH = LIBERAC_SHA2_512_256_DIGEST_BYTES;
            selected.BLOCK_LENGTH = 128u;
            break;
        case LIBERAC_ALG_HASH_SHA3_224:
            selected.DIGEST_LENGTH = LIBERAC_SHA3_224_DIGEST_BYTES;
            selected.BLOCK_LENGTH = 144u;
            break;
        case LIBERAC_ALG_HASH_SHA3_256:
            selected.DIGEST_LENGTH = LIBERAC_SHA3_256_DIGEST_BYTES;
            selected.BLOCK_LENGTH = 136u;
            break;
        case LIBERAC_ALG_HASH_SHA3_384:
            selected.DIGEST_LENGTH = LIBERAC_SHA3_384_DIGEST_BYTES;
            selected.BLOCK_LENGTH = 104u;
            break;
        case LIBERAC_ALG_HASH_SHA3_512:
            selected.DIGEST_LENGTH = LIBERAC_SHA3_512_DIGEST_BYTES;
            selected.BLOCK_LENGTH = 72u;
            break;
        default:
            return LIBERAC_ERROR_INVALID_ALG_ID;
    }

    if (parameters != NULL) {
        *parameters = selected;
    }
    return LIBERAC_SUCCESS;
}

size_t LIBERAC_HMAC_TAG_SIZE(LiberaCAlgID ALG) {
    HmacParameters parameters;

    if (hmac_parameters(ALG, &parameters) != LIBERAC_SUCCESS) {
        return 0u;
    }
    return parameters.DIGEST_LENGTH;
}

LiberaCError LIBERAC_HMAC(
    uint8_t *TAG, size_t TAG_CAPACITY, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG) {
    HmacParameters parameters;
    LiberaCHashContext context;
    uint8_t key_block[HMAC_MAX_BLOCK_BYTES];
    uint8_t inner_pad[HMAC_MAX_BLOCK_BYTES];
    uint8_t outer_pad[HMAC_MAX_BLOCK_BYTES];
    uint8_t key_digest[LIBERAC_HMAC_MAX_TAG_BYTES];
    uint8_t inner_digest[LIBERAC_HMAC_MAX_TAG_BYTES];
    uint8_t full_tag[LIBERAC_HMAC_MAX_TAG_BYTES];
    const uint8_t *normalized_key = KEY;
    size_t normalized_key_length = KEY_LENGTH;
    size_t index;
    LiberaCError error;

    error = hmac_parameters(ALG, &parameters);
    if (error != LIBERAC_SUCCESS) {
        return error;
    }
    if (TAG_LENGTH == 0u || TAG_LENGTH > parameters.DIGEST_LENGTH ||
        TAG == NULL || (MESSAGE == NULL && MESSAGE_LENGTH != 0u) ||
        (KEY == NULL && KEY_LENGTH != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (TAG_CAPACITY < TAG_LENGTH) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }

    crypto_zeroize(&context, sizeof(context));
    crypto_zeroize(key_block, sizeof(key_block));
    crypto_zeroize(inner_pad, sizeof(inner_pad));
    crypto_zeroize(outer_pad, sizeof(outer_pad));
    crypto_zeroize(key_digest, sizeof(key_digest));
    crypto_zeroize(inner_digest, sizeof(inner_digest));
    crypto_zeroize(full_tag, sizeof(full_tag));

    if (KEY_LENGTH > parameters.BLOCK_LENGTH) {
        error = LIBERAC_HASH(
            key_digest, parameters.DIGEST_LENGTH, KEY, KEY_LENGTH, ALG);
        if (error != LIBERAC_SUCCESS) {
            goto cleanup;
        }
        normalized_key = key_digest;
        normalized_key_length = parameters.DIGEST_LENGTH;
    }
    if (normalized_key_length != 0u) {
        memcpy(key_block, normalized_key, normalized_key_length);
    }
    for (index = 0u; index < parameters.BLOCK_LENGTH; ++index) {
        inner_pad[index] = (uint8_t)(key_block[index] ^ UINT8_C(0x36));
        outer_pad[index] = (uint8_t)(key_block[index] ^ UINT8_C(0x5c));
    }

    error = LIBERAC_HASH_INIT(&context, ALG);
    if (error == LIBERAC_SUCCESS) {
        error = LIBERAC_HASH_UPDATE(
            &context, inner_pad, parameters.BLOCK_LENGTH);
    }
    if (error == LIBERAC_SUCCESS) {
        error = LIBERAC_HASH_UPDATE(&context, MESSAGE, MESSAGE_LENGTH);
    }
    if (error == LIBERAC_SUCCESS) {
        error = LIBERAC_HASH_FINALIZE(&context);
    }
    if (error == LIBERAC_SUCCESS) {
        error = LIBERAC_HASH_SQUEEZE(
            &context, inner_digest, parameters.DIGEST_LENGTH);
    }
    LIBERAC_HASH_CLEAR(&context);

    if (error == LIBERAC_SUCCESS) {
        error = LIBERAC_HASH_INIT(&context, ALG);
    }
    if (error == LIBERAC_SUCCESS) {
        error = LIBERAC_HASH_UPDATE(
            &context, outer_pad, parameters.BLOCK_LENGTH);
    }
    if (error == LIBERAC_SUCCESS) {
        error = LIBERAC_HASH_UPDATE(
            &context, inner_digest, parameters.DIGEST_LENGTH);
    }
    if (error == LIBERAC_SUCCESS) {
        error = LIBERAC_HASH_FINALIZE(&context);
    }
    if (error == LIBERAC_SUCCESS) {
        error = LIBERAC_HASH_SQUEEZE(
            &context, full_tag, parameters.DIGEST_LENGTH);
    }
    if (error == LIBERAC_SUCCESS) {
        memcpy(TAG, full_tag, TAG_LENGTH);
    }

cleanup:
    LIBERAC_HASH_CLEAR(&context);
    crypto_zeroize(key_block, sizeof(key_block));
    crypto_zeroize(inner_pad, sizeof(inner_pad));
    crypto_zeroize(outer_pad, sizeof(outer_pad));
    crypto_zeroize(key_digest, sizeof(key_digest));
    crypto_zeroize(inner_digest, sizeof(inner_digest));
    crypto_zeroize(full_tag, sizeof(full_tag));
    return error;
}

LiberaCError LIBERAC_HMAC_VERIFY(
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG) {
    uint8_t expected[LIBERAC_HMAC_MAX_TAG_BYTES];
    LiberaCError error;

    if (TAG == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    crypto_zeroize(expected, sizeof(expected));
    error = LIBERAC_HMAC(
        expected, sizeof(expected), TAG_LENGTH,
        MESSAGE, MESSAGE_LENGTH, KEY, KEY_LENGTH, ALG);
    if (error == LIBERAC_SUCCESS &&
        !crypto_constant_time_equal(expected, TAG, TAG_LENGTH)) {
        error = LIBERAC_ERROR_AUTHENTICATION_FAILED;
    }
    crypto_zeroize(expected, sizeof(expected));
    return error;
}

static LiberaCError cmac_parameters(
    LiberaCAlgID algorithm, CmacParameters *parameters) {
    CmacParameters selected;

    switch (algorithm) {
        case LIBERAC_ALG_AES_128_ECB:
            selected.BLOCK_LENGTH = LIBERAC_BLOCK_CIPHER_BLOCK_BYTES;
            selected.KEY_LENGTH = LIBERAC_AES_128_KEY_BYTES;
            selected.REDUCTION_CONSTANT = UINT8_C(0x87);
            selected.FAMILY = CMAC_CIPHER_AES;
            break;
        case LIBERAC_ALG_AES_192_ECB:
            selected.BLOCK_LENGTH = LIBERAC_BLOCK_CIPHER_BLOCK_BYTES;
            selected.KEY_LENGTH = LIBERAC_AES_192_KEY_BYTES;
            selected.REDUCTION_CONSTANT = UINT8_C(0x87);
            selected.FAMILY = CMAC_CIPHER_AES;
            break;
        case LIBERAC_ALG_AES_256_ECB:
            selected.BLOCK_LENGTH = LIBERAC_BLOCK_CIPHER_BLOCK_BYTES;
            selected.KEY_LENGTH = LIBERAC_AES_256_KEY_BYTES;
            selected.REDUCTION_CONSTANT = UINT8_C(0x87);
            selected.FAMILY = CMAC_CIPHER_AES;
            break;
        case LIBERAC_ALG_TDES_EDE3_ECB:
            selected.BLOCK_LENGTH = LIBERAC_TDES_BLOCK_BYTES;
            selected.KEY_LENGTH = LIBERAC_TDES_EDE3_KEY_BYTES;
            selected.REDUCTION_CONSTANT = UINT8_C(0x1b);
            selected.FAMILY = CMAC_CIPHER_TDES;
            break;
        default:
            return LIBERAC_ERROR_INVALID_ALG_ID;
    }

    if (parameters != NULL) {
        *parameters = selected;
    }
    return LIBERAC_SUCCESS;
}

size_t LIBERAC_CMAC_TAG_SIZE(LiberaCAlgID ALG) {
    CmacParameters parameters;

    if (cmac_parameters(ALG, &parameters) != LIBERAC_SUCCESS) {
        return 0u;
    }
    return parameters.BLOCK_LENGTH;
}

static void cmac_double(
    uint8_t *output, const uint8_t *input,
    size_t block_length, uint8_t reduction_constant) {
    uint8_t carry = 0u;
    uint8_t most_significant_bit = (uint8_t)(input[0] >> 7);
    size_t index;

    for (index = block_length; index > 0u; --index) {
        const uint8_t value = input[index - 1u];
        output[index - 1u] = (uint8_t)((value << 1) | carry);
        carry = (uint8_t)(value >> 7);
    }
    output[block_length - 1u] ^=
        (uint8_t)(reduction_constant &
                  (uint8_t)(0u - most_significant_bit));
}

static void cmac_xor_block(
    uint8_t *output, const uint8_t *left, const uint8_t *right,
    size_t block_length) {
    size_t index;

    for (index = 0u; index < block_length; ++index) {
        output[index] = (uint8_t)(left[index] ^ right[index]);
    }
}

static LiberaCError cmac_encrypt_block(
    const CmacParameters *parameters,
    const AES_CONTEXT *aes_context,
    const uint8_t *key, size_t key_length,
    const uint8_t *input, uint8_t *output) {
    if (parameters->FAMILY == CMAC_CIPHER_AES) {
        return crypto_aes_encrypt_block(aes_context, input, output);
    }
    return crypto_tdes_ede3_crypt(
        output, parameters->BLOCK_LENGTH,
        input, parameters->BLOCK_LENGTH,
        key, key_length, NULL, 0u,
        CRYPTO_TDES_MODE_ECB, 1);
}

LiberaCError LIBERAC_CMAC(
    uint8_t *TAG, size_t TAG_CAPACITY, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG) {
    CmacParameters parameters;
    AES_CONTEXT aes_context;
    uint8_t zero[LIBERAC_CMAC_MAX_TAG_BYTES];
    uint8_t state[LIBERAC_CMAC_MAX_TAG_BYTES];
    uint8_t work[LIBERAC_CMAC_MAX_TAG_BYTES];
    uint8_t subkey1[LIBERAC_CMAC_MAX_TAG_BYTES];
    uint8_t subkey2[LIBERAC_CMAC_MAX_TAG_BYTES];
    uint8_t last_block[LIBERAC_CMAC_MAX_TAG_BYTES];
    const uint8_t *cursor = MESSAGE;
    size_t remaining = MESSAGE_LENGTH;
    size_t index;
    int aes_ready = 0;
    LiberaCError error;

    error = cmac_parameters(ALG, &parameters);
    if (error != LIBERAC_SUCCESS) {
        return error;
    }
    if (TAG_LENGTH == 0u || TAG_LENGTH > parameters.BLOCK_LENGTH ||
        TAG == NULL || KEY == NULL ||
        (MESSAGE == NULL && MESSAGE_LENGTH != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (TAG_CAPACITY < TAG_LENGTH) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (KEY_LENGTH != parameters.KEY_LENGTH) {
        return LIBERAC_ERROR_INVALID_KEY;
    }

    crypto_zeroize(&aes_context, sizeof(aes_context));
    crypto_zeroize(zero, sizeof(zero));
    crypto_zeroize(state, sizeof(state));
    crypto_zeroize(work, sizeof(work));
    crypto_zeroize(subkey1, sizeof(subkey1));
    crypto_zeroize(subkey2, sizeof(subkey2));
    crypto_zeroize(last_block, sizeof(last_block));

    if (parameters.FAMILY == CMAC_CIPHER_AES) {
        error = crypto_aes_context_init(&aes_context, KEY, KEY_LENGTH);
        if (error != LIBERAC_SUCCESS) {
            goto cleanup;
        }
        aes_ready = 1;
    }

    error = cmac_encrypt_block(
        &parameters, &aes_context, KEY, KEY_LENGTH, zero, work);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    cmac_double(
        subkey1, work, parameters.BLOCK_LENGTH,
        parameters.REDUCTION_CONSTANT);
    cmac_double(
        subkey2, subkey1, parameters.BLOCK_LENGTH,
        parameters.REDUCTION_CONSTANT);

    while (remaining > parameters.BLOCK_LENGTH) {
        cmac_xor_block(
            work, state, cursor, parameters.BLOCK_LENGTH);
        error = cmac_encrypt_block(
            &parameters, &aes_context, KEY, KEY_LENGTH, work, state);
        if (error != LIBERAC_SUCCESS) {
            goto cleanup;
        }
        cursor += parameters.BLOCK_LENGTH;
        remaining -= parameters.BLOCK_LENGTH;
    }

    if (remaining == parameters.BLOCK_LENGTH) {
        memcpy(last_block, cursor, parameters.BLOCK_LENGTH);
        for (index = 0u; index < parameters.BLOCK_LENGTH; ++index) {
            last_block[index] ^= subkey1[index];
        }
    } else {
        if (remaining != 0u) {
            memcpy(last_block, cursor, remaining);
        }
        last_block[remaining] = UINT8_C(0x80);
        for (index = 0u; index < parameters.BLOCK_LENGTH; ++index) {
            last_block[index] ^= subkey2[index];
        }
    }

    cmac_xor_block(
        work, state, last_block, parameters.BLOCK_LENGTH);
    error = cmac_encrypt_block(
        &parameters, &aes_context, KEY, KEY_LENGTH, work, state);
    if (error == LIBERAC_SUCCESS) {
        memcpy(TAG, state, TAG_LENGTH);
    }

cleanup:
    if (aes_ready != 0) {
        crypto_aes_context_clear(&aes_context);
    } else {
        crypto_zeroize(&aes_context, sizeof(aes_context));
    }
    crypto_zeroize(zero, sizeof(zero));
    crypto_zeroize(state, sizeof(state));
    crypto_zeroize(work, sizeof(work));
    crypto_zeroize(subkey1, sizeof(subkey1));
    crypto_zeroize(subkey2, sizeof(subkey2));
    crypto_zeroize(last_block, sizeof(last_block));
    return error;
}

LiberaCError LIBERAC_CMAC_VERIFY(
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG) {
    uint8_t expected[LIBERAC_CMAC_MAX_TAG_BYTES];
    LiberaCError error;

    if (TAG == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    crypto_zeroize(expected, sizeof(expected));
    error = LIBERAC_CMAC(
        expected, sizeof(expected), TAG_LENGTH,
        MESSAGE, MESSAGE_LENGTH, KEY, KEY_LENGTH, ALG);
    if (error == LIBERAC_SUCCESS &&
        !crypto_constant_time_equal(expected, TAG, TAG_LENGTH)) {
        error = LIBERAC_ERROR_AUTHENTICATION_FAILED;
    }
    crypto_zeroize(expected, sizeof(expected));
    return error;
}

static int gmac_algorithm_valid(LiberaCAlgID algorithm) {
    return algorithm == LIBERAC_ALG_AES_128_GCM ||
           algorithm == LIBERAC_ALG_AES_192_GCM ||
           algorithm == LIBERAC_ALG_AES_256_GCM;
}

static int gmac_tag_length_valid(size_t tag_length) {
    switch (tag_length) {
        case 4u:
        case 8u:
        case 12u:
        case 13u:
        case 14u:
        case 15u:
        case 16u:
            return 1;
        default:
            return 0;
    }
}

LiberaCError LIBERAC_GMAC(
    uint8_t *TAG, size_t TAG_CAPACITY, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    LiberaCAlgID ALG) {
    if (!gmac_algorithm_valid(ALG)) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (!gmac_tag_length_valid(TAG_LENGTH) || TAG == NULL || KEY == NULL ||
        IV == NULL || IV_LENGTH == 0u ||
        (MESSAGE == NULL && MESSAGE_LENGTH != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (TAG_CAPACITY < TAG_LENGTH) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }

    return LIBERAC_BLOCK_CIPHER_ENCRYPT(
        NULL, 0u, TAG, TAG_LENGTH,
        NULL, 0u, KEY, KEY_LENGTH,
        IV, IV_LENGTH, MESSAGE, MESSAGE_LENGTH, ALG);
}

LiberaCError LIBERAC_GMAC_VERIFY(
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    LiberaCAlgID ALG) {
    if (!gmac_algorithm_valid(ALG)) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (!gmac_tag_length_valid(TAG_LENGTH) || TAG == NULL || KEY == NULL ||
        IV == NULL || IV_LENGTH == 0u ||
        (MESSAGE == NULL && MESSAGE_LENGTH != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    return LIBERAC_BLOCK_CIPHER_DECRYPT(
        NULL, 0u, TAG, TAG_LENGTH,
        NULL, 0u, KEY, KEY_LENGTH,
        IV, IV_LENGTH, MESSAGE, MESSAGE_LENGTH, ALG);
}

size_t LIBERAC_POLY1305_TAG_SIZE(LiberaCAlgID ALG) {
    return ALG == LIBERAC_ALG_POLY1305 ? LIBERAC_POLY1305_TAG_BYTES : 0u;
}

LiberaCError LIBERAC_POLY1305(
    uint8_t *TAG, size_t TAG_CAPACITY,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG) {
    uint8_t complete_tag[LIBERAC_POLY1305_TAG_BYTES];

    if (ALG != LIBERAC_ALG_POLY1305)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!TAG || !KEY || (!MESSAGE && MESSAGE_LENGTH != 0u))
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (KEY_LENGTH != LIBERAC_POLY1305_KEY_BYTES)
        return LIBERAC_ERROR_INVALID_KEY;
    if (TAG_CAPACITY < LIBERAC_POLY1305_TAG_BYTES)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;

    crypto_poly1305_internal(complete_tag, MESSAGE, MESSAGE_LENGTH, KEY);
    memcpy(TAG, complete_tag, sizeof(complete_tag));
    crypto_zeroize(complete_tag, sizeof(complete_tag));
    return LIBERAC_SUCCESS;
}

LiberaCError LIBERAC_POLY1305_VERIFY(
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    LiberaCAlgID ALG) {
    uint8_t expected[LIBERAC_POLY1305_TAG_BYTES];
    LiberaCError err;

    if (ALG != LIBERAC_ALG_POLY1305)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!TAG || !KEY || (!MESSAGE && MESSAGE_LENGTH != 0u) ||
        TAG_LENGTH != LIBERAC_POLY1305_TAG_BYTES) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (KEY_LENGTH != LIBERAC_POLY1305_KEY_BYTES)
        return LIBERAC_ERROR_INVALID_KEY;

    crypto_poly1305_internal(expected, MESSAGE, MESSAGE_LENGTH, KEY);
    err = crypto_constant_time_equal(expected, TAG, sizeof(expected))
              ? LIBERAC_SUCCESS
              : LIBERAC_ERROR_AUTHENTICATION_FAILED;
    crypto_zeroize(expected, sizeof(expected));
    return err;
}
