/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "KeyDerivation.h"

#include "MessageAuthentication.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"

#include <stdlib.h>
#include <string.h>

static void kdf_secure_free(uint8_t *buffer, size_t length) {
    if (buffer != NULL) {
        crypto_zeroize(buffer, length);
        free(buffer);
    }
}

static int kdf_optional_input_valid(const uint8_t *input, size_t length) {
    return input != NULL || length == 0u;
}

size_t LIBERAC_HKDF_PRK_SIZE(LiberaCAlgID ALG) {
    return LIBERAC_HMAC_TAG_SIZE(ALG);
}

LiberaCError LIBERAC_HKDF_EXTRACT(
    uint8_t *PRK, size_t PRK_CAPACITY,
    const uint8_t *IKM, size_t IKM_LENGTH,
    const uint8_t *SALT, size_t SALT_LENGTH,
    LiberaCAlgID ALG) {
    uint8_t default_salt[LIBERAC_HMAC_MAX_TAG_BYTES];
    const uint8_t *effective_salt = SALT;
    size_t effective_salt_length = SALT_LENGTH;
    const size_t digest_length = LIBERAC_HMAC_TAG_SIZE(ALG);
    LiberaCError error;

    if (digest_length == 0u) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (PRK == NULL ||
        !kdf_optional_input_valid(IKM, IKM_LENGTH) ||
        !kdf_optional_input_valid(SALT, SALT_LENGTH)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (PRK_CAPACITY < digest_length) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(PRK, digest_length, IKM, IKM_LENGTH) ||
        crypto_ranges_overlap(PRK, digest_length, SALT, SALT_LENGTH)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_zeroize(default_salt, sizeof(default_salt));
    if (SALT_LENGTH == 0u) {
        effective_salt = default_salt;
        effective_salt_length = digest_length;
    }

    error = LIBERAC_HMAC(
        PRK, PRK_CAPACITY, digest_length,
        IKM, IKM_LENGTH,
        effective_salt, effective_salt_length,
        ALG);
    crypto_zeroize(default_salt, sizeof(default_salt));
    return error;
}

LiberaCError LIBERAC_HKDF_EXPAND(
    uint8_t *OKM, size_t OKM_CAPACITY, size_t OKM_LENGTH,
    const uint8_t *PRK, size_t PRK_LENGTH,
    const uint8_t *INFO, size_t INFO_LENGTH,
    LiberaCAlgID ALG) {
    uint8_t previous[LIBERAC_HMAC_MAX_TAG_BYTES];
    uint8_t *message = NULL;
    size_t message_capacity;
    size_t previous_length = 0u;
    size_t produced = 0u;
    uint32_t block_index = 1u;
    const size_t digest_length = LIBERAC_HMAC_TAG_SIZE(ALG);
    LiberaCError error = LIBERAC_SUCCESS;

    if (digest_length == 0u) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (PRK == NULL || PRK_LENGTH < digest_length ||
        !kdf_optional_input_valid(INFO, INFO_LENGTH) ||
        (OKM == NULL && OKM_LENGTH != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (OKM_LENGTH > 255u * digest_length) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }
    if (OKM_CAPACITY < OKM_LENGTH) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(OKM, OKM_LENGTH, PRK, PRK_LENGTH) ||
        crypto_ranges_overlap(OKM, OKM_LENGTH, INFO, INFO_LENGTH)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (OKM_LENGTH == 0u) {
        return LIBERAC_SUCCESS;
    }
    if (INFO_LENGTH > SIZE_MAX - digest_length - 1u) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }

    message_capacity = digest_length + INFO_LENGTH + 1u;
    message = (uint8_t *)malloc(message_capacity);
    if (message == NULL) {
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    }
    crypto_zeroize(previous, sizeof(previous));
    crypto_zeroize(message, message_capacity);

    while (produced < OKM_LENGTH) {
        size_t message_length = 0u;
        size_t copy_length;

        if (previous_length != 0u) {
            memcpy(message, previous, previous_length);
            message_length = previous_length;
        }
        if (INFO_LENGTH != 0u) {
            memcpy(message + message_length, INFO, INFO_LENGTH);
            message_length += INFO_LENGTH;
        }
        message[message_length++] = (uint8_t)block_index;

        error = LIBERAC_HMAC(
            previous, sizeof(previous), digest_length,
            message, message_length,
            PRK, PRK_LENGTH,
            ALG);
        if (error != LIBERAC_SUCCESS) {
            break;
        }

        copy_length = OKM_LENGTH - produced;
        if (copy_length > digest_length) {
            copy_length = digest_length;
        }
        memcpy(OKM + produced, previous, copy_length);
        produced += copy_length;
        previous_length = digest_length;
        ++block_index;
    }

    if (error != LIBERAC_SUCCESS && produced != 0u) {
        crypto_zeroize(OKM, produced);
    }
    crypto_zeroize(previous, sizeof(previous));
    kdf_secure_free(message, message_capacity);
    return error;
}

LiberaCError LIBERAC_HKDF(
    uint8_t *OKM, size_t OKM_CAPACITY, size_t OKM_LENGTH,
    const uint8_t *IKM, size_t IKM_LENGTH,
    const uint8_t *SALT, size_t SALT_LENGTH,
    const uint8_t *INFO, size_t INFO_LENGTH,
    LiberaCAlgID ALG) {
    uint8_t prk[LIBERAC_HMAC_MAX_TAG_BYTES];
    const size_t digest_length = LIBERAC_HMAC_TAG_SIZE(ALG);
    LiberaCError error;

    if (digest_length == 0u) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }

    crypto_zeroize(prk, sizeof(prk));
    error = LIBERAC_HKDF_EXTRACT(
        prk, sizeof(prk),
        IKM, IKM_LENGTH,
        SALT, SALT_LENGTH,
        ALG);
    if (error == LIBERAC_SUCCESS) {
        error = LIBERAC_HKDF_EXPAND(
            OKM, OKM_CAPACITY, OKM_LENGTH,
            prk, digest_length,
            INFO, INFO_LENGTH,
            ALG);
    }
    crypto_zeroize(prk, sizeof(prk));
    return error;
}

LiberaCError LIBERAC_PBKDF2_HMAC(
    uint8_t *DERIVED_KEY, size_t DERIVED_KEY_CAPACITY,
    size_t DERIVED_KEY_LENGTH,
    const uint8_t *PASSWORD, size_t PASSWORD_LENGTH,
    const uint8_t *SALT, size_t SALT_LENGTH,
    uint64_t ITERATION_COUNT,
    LiberaCAlgID ALG) {
    uint8_t u_a[LIBERAC_HMAC_MAX_TAG_BYTES];
    uint8_t u_b[LIBERAC_HMAC_MAX_TAG_BYTES];
    uint8_t accumulator[LIBERAC_HMAC_MAX_TAG_BYTES];
    uint8_t *current = u_a;
    uint8_t *next = u_b;
    uint8_t *salt_block = NULL;
    size_t salt_block_length;
    size_t block_count;
    size_t produced = 0u;
    size_t block_number;
    const size_t digest_length = LIBERAC_HMAC_TAG_SIZE(ALG);
    LiberaCError error = LIBERAC_SUCCESS;

    if (digest_length == 0u) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (DERIVED_KEY == NULL || DERIVED_KEY_LENGTH == 0u ||
        !kdf_optional_input_valid(PASSWORD, PASSWORD_LENGTH) ||
        !kdf_optional_input_valid(SALT, SALT_LENGTH) ||
        ITERATION_COUNT == 0u) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (DERIVED_KEY_CAPACITY < DERIVED_KEY_LENGTH) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    block_count = ((DERIVED_KEY_LENGTH - 1u) / digest_length) + 1u;
    if (block_count > (size_t)UINT32_MAX) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }
    if (SALT_LENGTH > SIZE_MAX - 4u) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }
    if (crypto_ranges_overlap(
            DERIVED_KEY, DERIVED_KEY_LENGTH,
            PASSWORD, PASSWORD_LENGTH) ||
        crypto_ranges_overlap(
            DERIVED_KEY, DERIVED_KEY_LENGTH,
            SALT, SALT_LENGTH)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    salt_block_length = SALT_LENGTH + 4u;
    salt_block = (uint8_t *)malloc(salt_block_length);
    if (salt_block == NULL) {
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    }
    if (SALT_LENGTH != 0u) {
        memcpy(salt_block, SALT, SALT_LENGTH);
    }
    crypto_zeroize(u_a, sizeof(u_a));
    crypto_zeroize(u_b, sizeof(u_b));
    crypto_zeroize(accumulator, sizeof(accumulator));

    for (block_number = 1u; block_number <= block_count; ++block_number) {
        const uint32_t encoded_block_number = (uint32_t)block_number;
        uint64_t iteration;
        size_t index;
        size_t copy_length;

        salt_block[SALT_LENGTH] =
            (uint8_t)(encoded_block_number >> 24);
        salt_block[SALT_LENGTH + 1u] =
            (uint8_t)(encoded_block_number >> 16);
        salt_block[SALT_LENGTH + 2u] =
            (uint8_t)(encoded_block_number >> 8);
        salt_block[SALT_LENGTH + 3u] =
            (uint8_t)encoded_block_number;

        current = u_a;
        next = u_b;
        error = LIBERAC_HMAC(
            current, LIBERAC_HMAC_MAX_TAG_BYTES, digest_length,
            salt_block, salt_block_length,
            PASSWORD, PASSWORD_LENGTH,
            ALG);
        if (error != LIBERAC_SUCCESS) {
            break;
        }
        memcpy(accumulator, current, digest_length);

        for (iteration = 1u; iteration < ITERATION_COUNT; ++iteration) {
            uint8_t *swap;
            error = LIBERAC_HMAC(
                next, LIBERAC_HMAC_MAX_TAG_BYTES, digest_length,
                current, digest_length,
                PASSWORD, PASSWORD_LENGTH,
                ALG);
            if (error != LIBERAC_SUCCESS) {
                break;
            }
            for (index = 0u; index < digest_length; ++index) {
                accumulator[index] ^= next[index];
            }
            swap = current;
            current = next;
            next = swap;
        }
        if (error != LIBERAC_SUCCESS) {
            break;
        }

        copy_length = DERIVED_KEY_LENGTH - produced;
        if (copy_length > digest_length) {
            copy_length = digest_length;
        }
        memcpy(DERIVED_KEY + produced, accumulator, copy_length);
        produced += copy_length;
    }

    if (error != LIBERAC_SUCCESS && produced != 0u) {
        crypto_zeroize(DERIVED_KEY, produced);
    }
    crypto_zeroize(u_a, sizeof(u_a));
    crypto_zeroize(u_b, sizeof(u_b));
    crypto_zeroize(accumulator, sizeof(accumulator));
    kdf_secure_free(salt_block, salt_block_length);
    return error;
}
