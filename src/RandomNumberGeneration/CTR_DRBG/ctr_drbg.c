/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "ctr_drbg_internal.h"
#include "BlockCipher/AES/aes_internal.h"
#include "BlockCipher/TripleDES/triple_des_internal.h"
#include "RandomNumberGeneration/Noise/random_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/Endian/endian_internal.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
    CTR_DRBG_CIPHER_AES = 1,
    CTR_DRBG_CIPHER_TDEA = 2
} CtrDrbgCipherFamily;

typedef struct {
    size_t KEY_LENGTH;
    size_t BLOCK_LENGTH;
    size_t SECURITY_BYTES;
    size_t MAX_REQUEST_BYTES;
    uint64_t RESEED_INTERVAL;
    int USE_DF;
    CtrDrbgCipherFamily FAMILY;
} CtrDrbgParameters;

typedef struct {
    CtrDrbgCipherFamily FAMILY;
    AES_CONTEXT AES;
    CryptoTdesEde3Context TDEA;
} CtrDrbgBlockContext;

static LiberaCError ctr_drbg_parameters(
    LiberaCAlgID alg, CtrDrbgParameters *parameters) {
    CtrDrbgParameters selected;

    crypto_zeroize(&selected, sizeof(selected));
    selected.BLOCK_LENGTH = LIBERAC_CTR_DRBG_BLOCK_BYTES;
    selected.MAX_REQUEST_BYTES = LIBERAC_CTR_DRBG_MAX_REQUEST_BYTES;
    selected.RESEED_INTERVAL = UINT64_C(1) << 48;
    selected.FAMILY = CTR_DRBG_CIPHER_AES;

    switch (alg) {
        case LIBERAC_ALG_CTR_DRBG_AES_128_DF:
        case LIBERAC_ALG_CTR_DRBG_AES_128_NO_DF:
            selected.KEY_LENGTH = LIBERAC_AES_128_KEY_BYTES;
            selected.SECURITY_BYTES = LIBERAC_AES_128_KEY_BYTES;
            selected.USE_DF =
                (alg == LIBERAC_ALG_CTR_DRBG_AES_128_DF);
            break;
        case LIBERAC_ALG_CTR_DRBG_AES_192_DF:
        case LIBERAC_ALG_CTR_DRBG_AES_192_NO_DF:
            selected.KEY_LENGTH = LIBERAC_AES_192_KEY_BYTES;
            selected.SECURITY_BYTES = LIBERAC_AES_192_KEY_BYTES;
            selected.USE_DF =
                (alg == LIBERAC_ALG_CTR_DRBG_AES_192_DF);
            break;
        case LIBERAC_ALG_CTR_DRBG_AES_256_DF:
        case LIBERAC_ALG_CTR_DRBG_AES_256_NO_DF:
            selected.KEY_LENGTH = LIBERAC_AES_256_KEY_BYTES;
            selected.SECURITY_BYTES = LIBERAC_AES_256_KEY_BYTES;
            selected.USE_DF =
                (alg == LIBERAC_ALG_CTR_DRBG_AES_256_DF);
            break;
        case LIBERAC_ALG_CTR_DRBG_TDEA_DF:
        case LIBERAC_ALG_CTR_DRBG_TDEA_NO_DF:
            selected.KEY_LENGTH = LIBERAC_CTR_DRBG_TDEA_KEY_BYTES;
            selected.BLOCK_LENGTH = LIBERAC_TDES_BLOCK_BYTES;
            selected.SECURITY_BYTES = 14u;
            selected.MAX_REQUEST_BYTES =
                LIBERAC_CTR_DRBG_TDEA_MAX_REQUEST_BYTES;
            selected.RESEED_INTERVAL = UINT64_C(1) << 32;
            selected.USE_DF = (alg == LIBERAC_ALG_CTR_DRBG_TDEA_DF);
            selected.FAMILY = CTR_DRBG_CIPHER_TDEA;
            break;
        default:
            return LIBERAC_ERROR_INVALID_ALG_ID;
    }

    if (parameters != NULL) {
        *parameters = selected;
    }
    crypto_zeroize(&selected, sizeof(selected));
    return LIBERAC_SUCCESS;
}

static LiberaCError ctr_drbg_context_parameters(
    const LiberaCCtrDrbgContext *context,
    CtrDrbgParameters *parameters) {
    CtrDrbgParameters selected;
    LiberaCError err;

    err = ctr_drbg_parameters(context->ALG, &selected);
    if (err != LIBERAC_SUCCESS) {
        return err;
    }
    if ((size_t)context->KEY_LENGTH != selected.KEY_LENGTH ||
        (context->USE_DF != 0u) != (selected.USE_DF != 0)) {
        crypto_zeroize(&selected, sizeof(selected));
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (parameters != NULL) {
        *parameters = selected;
    }
    crypto_zeroize(&selected, sizeof(selected));
    return LIBERAC_SUCCESS;
}

size_t crypto_ctr_drbg_seed_size_internal(LiberaCAlgID alg) {
    CtrDrbgParameters parameters;

    if (ctr_drbg_parameters(alg, &parameters) != LIBERAC_SUCCESS) {
        return 0u;
    }
    return parameters.KEY_LENGTH + parameters.BLOCK_LENGTH;
}

/* V is secret state, so every byte is visited even after the carry clears. */
static void increment_v(uint8_t *v, size_t block_length) {
    uint16_t carry = 1u;
    size_t index;

    for (index = block_length; index > 0u; --index) {
        const uint16_t sum = (uint16_t)v[index - 1u] + carry;
        v[index - 1u] = (uint8_t)sum;
        carry = (uint16_t)(sum >> 8);
    }
    crypto_zeroize(&carry, sizeof(carry));
}

static uint8_t set_odd_parity(uint8_t value) {
    uint8_t parity = value;

    parity ^= (uint8_t)(parity >> 4);
    parity ^= (uint8_t)(parity >> 2);
    parity ^= (uint8_t)(parity >> 1);
    return (uint8_t)((value & UINT8_C(0xfe)) |
                     ((parity ^ UINT8_C(1)) & UINT8_C(1)));
}

/* SP 800-90A stores 168 effective TDEA key bits. Insert each DES parity bit
   before passing the three 64-bit key blocks to the TDEA engine. */
static void expand_tdea_key(
    const uint8_t key[LIBERAC_CTR_DRBG_TDEA_KEY_BYTES],
    uint8_t engine_key[LIBERAC_TDES_EDE3_KEY_BYTES]) {
    size_t group;

    for (group = 0u; group < 3u; ++group) {
        uint64_t packed = 0u;
        size_t index;

        for (index = 0u; index < 7u; ++index) {
            packed = (packed << 8) | key[7u * group + index];
        }
        for (index = 0u; index < 8u; ++index) {
            const unsigned int shift =
                (unsigned int)(49u - 7u * index);
            const uint8_t seven_bits =
                (uint8_t)((packed >> shift) & UINT64_C(0x7f));
            engine_key[8u * group + index] =
                set_odd_parity((uint8_t)(seven_bits << 1));
        }
        crypto_zeroize(&packed, sizeof(packed));
    }
}

static LiberaCError ctr_block_context_init(
    CtrDrbgBlockContext *context,
    const CtrDrbgParameters *parameters,
    const uint8_t *key) {
    uint8_t engine_key[LIBERAC_TDES_EDE3_KEY_BYTES];
    LiberaCError err;

    crypto_zeroize(context, sizeof(*context));
    crypto_zeroize(engine_key, sizeof(engine_key));
    if (parameters->FAMILY == CTR_DRBG_CIPHER_AES) {
        err = crypto_aes_context_init(
            &context->AES, key, parameters->KEY_LENGTH);
    } else {
        expand_tdea_key(key, engine_key);
        err = crypto_tdes_ede3_context_init(
            &context->TDEA, engine_key, sizeof(engine_key));
    }
    crypto_zeroize(engine_key, sizeof(engine_key));
    if (err == LIBERAC_SUCCESS) {
        context->FAMILY = parameters->FAMILY;
    } else {
        crypto_zeroize(context, sizeof(*context));
    }
    return err;
}

static LiberaCError ctr_block_encrypt(
    CtrDrbgBlockContext *context,
    const uint8_t *input, uint8_t *output) {
    if (context->FAMILY == CTR_DRBG_CIPHER_AES) {
        return crypto_aes_encrypt_block(&context->AES, input, output);
    }
    if (context->FAMILY == CTR_DRBG_CIPHER_TDEA) {
        return crypto_tdes_ede3_encrypt_block(
            &context->TDEA, input, output);
    }
    return LIBERAC_ERROR_INVALID_ARGUMENT;
}

static void ctr_block_context_clear(CtrDrbgBlockContext *context) {
    if (context->FAMILY == CTR_DRBG_CIPHER_AES) {
        crypto_aes_context_clear(&context->AES);
    } else if (context->FAMILY == CTR_DRBG_CIPHER_TDEA) {
        crypto_tdes_ede3_context_clear(&context->TDEA);
    }
    crypto_zeroize(context, sizeof(*context));
}

static LiberaCError bcc(
    const CtrDrbgParameters *parameters,
    CtrDrbgBlockContext *context,
    const uint8_t *iv,
    const uint8_t *string, size_t string_length,
    uint8_t *output) {
    uint8_t chain[LIBERAC_CTR_DRBG_BLOCK_BYTES] = {0};
    uint8_t x[LIBERAC_CTR_DRBG_BLOCK_BYTES];
    size_t offset;
    size_t index;
    LiberaCError err;

    for (index = 0u; index < parameters->BLOCK_LENGTH; ++index) {
        x[index] = (uint8_t)(chain[index] ^ iv[index]);
    }
    err = ctr_block_encrypt(context, x, chain);
    if (err != LIBERAC_SUCCESS) {
        goto done;
    }
    for (offset = 0u; offset < string_length;
         offset += parameters->BLOCK_LENGTH) {
        for (index = 0u; index < parameters->BLOCK_LENGTH; ++index) {
            x[index] = (uint8_t)(chain[index] ^ string[offset + index]);
        }
        err = ctr_block_encrypt(context, x, chain);
        if (err != LIBERAC_SUCCESS) {
            goto done;
        }
    }
    memcpy(output, chain, parameters->BLOCK_LENGTH);

done:
    crypto_zeroize(x, sizeof(x));
    crypto_zeroize(chain, sizeof(chain));
    return err;
}

static LiberaCError block_cipher_df(
    const CtrDrbgParameters *parameters,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_length) {
    CtrDrbgBlockContext context;
    uint8_t initial_key[LIBERAC_CTR_DRBG_MAX_KEY_BYTES];
    uint8_t temp[LIBERAC_CTR_DRBG_MAX_SEED_BYTES];
    uint8_t iv[LIBERAC_CTR_DRBG_BLOCK_BYTES];
    uint8_t block[LIBERAC_CTR_DRBG_BLOCK_BYTES];
    uint8_t x[LIBERAC_CTR_DRBG_BLOCK_BYTES];
    uint8_t *string = NULL;
    size_t string_length;
    size_t seed_length = parameters->KEY_LENGTH + parameters->BLOCK_LENGTH;
    size_t used = 0u;
    size_t generated = 0u;
    size_t index;
    uint32_t counter = 0u;
    const size_t uint32_max = (size_t)UINT32_MAX;
    int context_ready = 0;
    LiberaCError err = LIBERAC_SUCCESS;

    crypto_zeroize(&context, sizeof(context));
    crypto_zeroize(initial_key, sizeof(initial_key));
    crypto_zeroize(temp, sizeof(temp));
    crypto_zeroize(iv, sizeof(iv));
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(x, sizeof(x));

    if ((input == NULL && input_length != 0u) || output == NULL ||
        output_length == 0u ||
        output_length > LIBERAC_CTR_DRBG_MAX_SEED_BYTES) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (input_length > uint32_max || output_length > uint32_max) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }
    if (input_length > SIZE_MAX - 9u) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }
    string_length = 8u + input_length + 1u;
    if (string_length > SIZE_MAX - (parameters->BLOCK_LENGTH - 1u)) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }
    string_length =
        (string_length + parameters->BLOCK_LENGTH - 1u) &
        ~(parameters->BLOCK_LENGTH - 1u);
    string = (uint8_t *)calloc(1u, string_length);
    if (string == NULL) {
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    }

    /* Block_Cipher_df encodes L and N as 32-bit big-endian byte counts. */
    crypto_store32_be(string, (uint32_t)input_length);
    crypto_store32_be(string + 4u, (uint32_t)output_length);
    if (input_length != 0u) {
        memcpy(string + 8u, input, input_length);
    }
    string[8u + input_length] = UINT8_C(0x80);
    for (index = 0u; index < parameters->KEY_LENGTH; ++index) {
        initial_key[index] = (uint8_t)index;
    }

    err = ctr_block_context_init(&context, parameters, initial_key);
    if (err != LIBERAC_SUCCESS) {
        goto done;
    }
    context_ready = 1;
    while (used < seed_length) {
        size_t copy_length;

        crypto_zeroize(iv, sizeof(iv));
        crypto_store32_be(iv, counter);
        ++counter;
        err = bcc(
            parameters, &context, iv, string, string_length, block);
        if (err != LIBERAC_SUCCESS) {
            goto done;
        }
        copy_length = seed_length - used;
        if (copy_length > parameters->BLOCK_LENGTH) {
            copy_length = parameters->BLOCK_LENGTH;
        }
        memcpy(temp + used, block, copy_length);
        used += copy_length;
    }
    ctr_block_context_clear(&context);
    context_ready = 0;

    memcpy(x, temp + parameters->KEY_LENGTH, parameters->BLOCK_LENGTH);
    err = ctr_block_context_init(&context, parameters, temp);
    if (err != LIBERAC_SUCCESS) {
        goto done;
    }
    context_ready = 1;
    while (generated < output_length) {
        size_t copy_length;

        err = ctr_block_encrypt(&context, x, x);
        if (err != LIBERAC_SUCCESS) {
            goto done;
        }
        copy_length = output_length - generated;
        if (copy_length > parameters->BLOCK_LENGTH) {
            copy_length = parameters->BLOCK_LENGTH;
        }
        memcpy(output + generated, x, copy_length);
        generated += copy_length;
    }

done:
    if (context_ready != 0) {
        ctr_block_context_clear(&context);
    }
    if (err != LIBERAC_SUCCESS && output != NULL) {
        crypto_zeroize(output, output_length);
    }
    if (string != NULL) {
        crypto_zeroize(string, string_length);
        free(string);
    }
    crypto_zeroize(initial_key, sizeof(initial_key));
    crypto_zeroize(temp, sizeof(temp));
    crypto_zeroize(iv, sizeof(iv));
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(x, sizeof(x));
    crypto_zeroize(&context, sizeof(context));
    crypto_zeroize(&counter, sizeof(counter));
    return err;
}

static LiberaCError ctr_drbg_update(
    LiberaCCtrDrbgContext *context, const uint8_t *provided_data) {
    CtrDrbgParameters parameters;
    CtrDrbgBlockContext cipher;
    uint8_t temp[LIBERAC_CTR_DRBG_MAX_SEED_BYTES];
    uint8_t block[LIBERAC_CTR_DRBG_BLOCK_BYTES];
    size_t seed_length;
    size_t used = 0u;
    size_t index;
    LiberaCError err;

    crypto_zeroize(&cipher, sizeof(cipher));
    err = ctr_drbg_context_parameters(context, &parameters);
    if (err != LIBERAC_SUCCESS) {
        return err;
    }
    seed_length = parameters.KEY_LENGTH + parameters.BLOCK_LENGTH;
    err = ctr_block_context_init(&cipher, &parameters, context->KEY);
    if (err != LIBERAC_SUCCESS) {
        goto done;
    }
    while (used < seed_length) {
        size_t copy_length;

        increment_v(context->V, parameters.BLOCK_LENGTH);
        err = ctr_block_encrypt(&cipher, context->V, block);
        if (err != LIBERAC_SUCCESS) {
            goto clear_cipher;
        }
        copy_length = seed_length - used;
        if (copy_length > parameters.BLOCK_LENGTH) {
            copy_length = parameters.BLOCK_LENGTH;
        }
        memcpy(temp + used, block, copy_length);
        used += copy_length;
    }
    if (provided_data != NULL) {
        for (index = 0u; index < seed_length; ++index) {
            temp[index] ^= provided_data[index];
        }
    }
    crypto_zeroize(context->KEY, sizeof(context->KEY));
    memcpy(context->KEY, temp, parameters.KEY_LENGTH);
    crypto_zeroize(context->V, sizeof(context->V));
    memcpy(
        context->V, temp + parameters.KEY_LENGTH,
        parameters.BLOCK_LENGTH);

clear_cipher:
    ctr_block_context_clear(&cipher);

done:
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(temp, sizeof(temp));
    crypto_zeroize(&parameters, sizeof(parameters));
    return err;
}

static LiberaCError make_df_seed(
    LiberaCCtrDrbgContext *context,
    const uint8_t *a, size_t a_length,
    const uint8_t *b, size_t b_length,
    const uint8_t *c, size_t c_length,
    uint8_t seed[LIBERAC_CTR_DRBG_MAX_SEED_BYTES]) {
    CtrDrbgParameters parameters;
    size_t total;
    uint8_t *joined = NULL;
    const size_t uint32_max = (size_t)UINT32_MAX;
    LiberaCError err;

    if (a_length > SIZE_MAX - b_length ||
        a_length + b_length > SIZE_MAX - c_length) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }
    total = a_length + b_length + c_length;
    if (total > uint32_max) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }
    if (total != 0u) {
        joined = (uint8_t *)malloc(total);
        if (joined == NULL) {
            return LIBERAC_ERROR_ALLOCATION_FAILED;
        }
        if (a_length != 0u) {
            memcpy(joined, a, a_length);
        }
        if (b_length != 0u) {
            memcpy(joined + a_length, b, b_length);
        }
        if (c_length != 0u) {
            memcpy(joined + a_length + b_length, c, c_length);
        }
    }

    err = ctr_drbg_context_parameters(context, &parameters);
    if (err == LIBERAC_SUCCESS) {
        err = block_cipher_df(
            &parameters, joined, total, seed,
            parameters.KEY_LENGTH + parameters.BLOCK_LENGTH);
    }
    if (joined != NULL) {
        crypto_zeroize(joined, total);
        free(joined);
    }
    crypto_zeroize(&parameters, sizeof(parameters));
    return err;
}

static LiberaCError prepare_additional(
    LiberaCCtrDrbgContext *context,
    const uint8_t *additional, size_t additional_length,
    uint8_t seed[LIBERAC_CTR_DRBG_MAX_SEED_BYTES]) {
    CtrDrbgParameters parameters;
    size_t seed_length;
    LiberaCError err;

    if (additional == NULL && additional_length != 0u) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    crypto_zeroize(seed, LIBERAC_CTR_DRBG_MAX_SEED_BYTES);
    err = ctr_drbg_context_parameters(context, &parameters);
    if (err != LIBERAC_SUCCESS) {
        return err;
    }
    if (additional_length == 0u) {
        return LIBERAC_SUCCESS;
    }
    if (parameters.USE_DF != 0) {
        return make_df_seed(
            context, additional, additional_length,
            NULL, 0u, NULL, 0u, seed);
    }
    seed_length = parameters.KEY_LENGTH + parameters.BLOCK_LENGTH;
    if (additional_length > seed_length) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    memcpy(seed, additional, additional_length);
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_ctr_drbg_instantiate_internal(
    LiberaCCtrDrbgContext *context, LiberaCAlgID alg,
    const uint8_t *entropy, size_t entropy_length,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *personalization, size_t personalization_length) {
    CtrDrbgParameters parameters;
    size_t seed_length;
    size_t required_total;
    size_t index;
    uint8_t seed[LIBERAC_CTR_DRBG_MAX_SEED_BYTES];
    LiberaCError err;

    if (context == NULL || entropy == NULL ||
        (nonce == NULL && nonce_length != 0u) ||
        (personalization == NULL && personalization_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    err = ctr_drbg_parameters(alg, &parameters);
    if (err != LIBERAC_SUCCESS) {
        return err;
    }
    seed_length = parameters.KEY_LENGTH + parameters.BLOCK_LENGTH;
    required_total = parameters.SECURITY_BYTES +
                     (parameters.SECURITY_BYTES + 1u) / 2u;
    crypto_zeroize(context, sizeof(*context));
    context->ALG = alg;
    context->KEY_LENGTH = (uint8_t)parameters.KEY_LENGTH;
    context->USE_DF = (uint8_t)(parameters.USE_DF != 0);

    if (parameters.USE_DF != 0) {
        if (entropy_length < parameters.SECURITY_BYTES ||
            (entropy_length < required_total &&
             nonce_length < required_total - entropy_length)) {
            crypto_ctr_drbg_clear_internal(context);
            return LIBERAC_ERROR_INVALID_ARGUMENT;
        }
        err = make_df_seed(
            context, entropy, entropy_length, nonce, nonce_length,
            personalization, personalization_length, seed);
    } else {
        if (entropy_length != seed_length || nonce_length != 0u ||
            personalization_length > seed_length) {
            crypto_ctr_drbg_clear_internal(context);
            return LIBERAC_ERROR_INVALID_ARGUMENT;
        }
        memcpy(seed, entropy, seed_length);
        for (index = 0u; index < personalization_length; ++index) {
            seed[index] ^= personalization[index];
        }
        err = LIBERAC_SUCCESS;
    }
    if (err == LIBERAC_SUCCESS) {
        err = ctr_drbg_update(context, seed);
    }
    if (err == LIBERAC_SUCCESS) {
        context->RESEED_COUNTER = 1u;
        context->INSTANTIATED = 1u;
    } else {
        crypto_ctr_drbg_clear_internal(context);
    }
    crypto_zeroize(seed, sizeof(seed));
    crypto_zeroize(&parameters, sizeof(parameters));
    return err;
}

LiberaCError crypto_ctr_drbg_reseed_internal(
    LiberaCCtrDrbgContext *context,
    const uint8_t *entropy, size_t entropy_length,
    const uint8_t *additional, size_t additional_length) {
    CtrDrbgParameters parameters;
    size_t seed_length;
    size_t index;
    uint8_t seed[LIBERAC_CTR_DRBG_MAX_SEED_BYTES];
    LiberaCError err;

    if (context == NULL || context->INSTANTIATED == 0u || entropy == NULL ||
        (additional == NULL && additional_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    err = ctr_drbg_context_parameters(context, &parameters);
    if (err != LIBERAC_SUCCESS) {
        return err;
    }
    seed_length = parameters.KEY_LENGTH + parameters.BLOCK_LENGTH;
    if (parameters.USE_DF != 0) {
        if (entropy_length < parameters.SECURITY_BYTES) {
            return LIBERAC_ERROR_INVALID_ARGUMENT;
        }
        err = make_df_seed(
            context, entropy, entropy_length,
            additional, additional_length, NULL, 0u, seed);
    } else {
        if (entropy_length != seed_length ||
            additional_length > seed_length) {
            return LIBERAC_ERROR_INVALID_ARGUMENT;
        }
        memcpy(seed, entropy, seed_length);
        for (index = 0u; index < additional_length; ++index) {
            seed[index] ^= additional[index];
        }
        err = LIBERAC_SUCCESS;
    }
    if (err == LIBERAC_SUCCESS) {
        err = ctr_drbg_update(context, seed);
    }
    if (err == LIBERAC_SUCCESS) {
        context->RESEED_COUNTER = 1u;
    }
    crypto_zeroize(seed, sizeof(seed));
    crypto_zeroize(&parameters, sizeof(parameters));
    return err;
}

LiberaCError crypto_ctr_drbg_instantiate_os_internal(
    LiberaCCtrDrbgContext *context, LiberaCAlgID alg,
    const uint8_t *personalization, size_t personalization_length) {
    CtrDrbgParameters parameters;
    size_t seed_length;
    size_t nonce_length;
    size_t entropy_length;
    uint8_t entropy[LIBERAC_CTR_DRBG_MAX_SEED_BYTES];
    uint8_t nonce[16];
    LiberaCError err;

    if (context == NULL ||
        (personalization == NULL && personalization_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    err = ctr_drbg_parameters(alg, &parameters);
    if (err != LIBERAC_SUCCESS) {
        return err;
    }
    seed_length = parameters.KEY_LENGTH + parameters.BLOCK_LENGTH;
    entropy_length =
        parameters.USE_DF != 0 ? parameters.SECURITY_BYTES : seed_length;
    nonce_length = parameters.USE_DF != 0
                       ? (parameters.SECURITY_BYTES + 1u) / 2u
                       : 0u;
    err = crypto_random_bytes_internal(entropy, entropy_length);
    if (err == LIBERAC_SUCCESS && nonce_length != 0u) {
        err = crypto_random_bytes_internal(nonce, nonce_length);
    }
    if (err == LIBERAC_SUCCESS) {
        err = crypto_ctr_drbg_instantiate_internal(
            context, alg, entropy, entropy_length,
            nonce_length != 0u ? nonce : NULL, nonce_length,
            personalization, personalization_length);
    }
    crypto_zeroize(entropy, sizeof(entropy));
    crypto_zeroize(nonce, sizeof(nonce));
    crypto_zeroize(&parameters, sizeof(parameters));
    return err;
}

LiberaCError crypto_ctr_drbg_reseed_os_internal(
    LiberaCCtrDrbgContext *context,
    const uint8_t *additional, size_t additional_length) {
    CtrDrbgParameters parameters;
    size_t seed_length;
    size_t entropy_length;
    uint8_t entropy[LIBERAC_CTR_DRBG_MAX_SEED_BYTES];
    LiberaCError err;

    if (context == NULL || context->INSTANTIATED == 0u ||
        (additional == NULL && additional_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    err = ctr_drbg_context_parameters(context, &parameters);
    if (err != LIBERAC_SUCCESS) {
        return err;
    }
    seed_length = parameters.KEY_LENGTH + parameters.BLOCK_LENGTH;
    entropy_length =
        parameters.USE_DF != 0 ? parameters.SECURITY_BYTES : seed_length;
    err = crypto_random_bytes_internal(entropy, entropy_length);
    if (err == LIBERAC_SUCCESS) {
        err = crypto_ctr_drbg_reseed_internal(
            context, entropy, entropy_length,
            additional, additional_length);
    }
    crypto_zeroize(entropy, sizeof(entropy));
    crypto_zeroize(&parameters, sizeof(parameters));
    return err;
}

LiberaCError crypto_ctr_drbg_generate_internal(
    LiberaCCtrDrbgContext *context,
    uint8_t *output, size_t output_length,
    const uint8_t *additional, size_t additional_length,
    int prediction_resistance) {
    CtrDrbgParameters parameters;
    CtrDrbgBlockContext cipher;
    uint8_t provided[LIBERAC_CTR_DRBG_MAX_SEED_BYTES];
    uint8_t block[LIBERAC_CTR_DRBG_BLOCK_BYTES];
    size_t offset = 0u;
    int cipher_ready = 0;
    LiberaCError err;

    crypto_zeroize(&cipher, sizeof(cipher));
    if (context == NULL || context->INSTANTIATED == 0u ||
        (output == NULL && output_length != 0u) ||
        (additional == NULL && additional_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    err = ctr_drbg_context_parameters(context, &parameters);
    if (err != LIBERAC_SUCCESS) {
        return err;
    }
    if (output_length > parameters.MAX_REQUEST_BYTES) {
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    }

    if (prediction_resistance != 0) {
        err = crypto_ctr_drbg_reseed_os_internal(
            context, additional, additional_length);
        if (err != LIBERAC_SUCCESS) {
            return err;
        }
        additional = NULL;
        additional_length = 0u;
    }
    if (context->RESEED_COUNTER > parameters.RESEED_INTERVAL) {
        return LIBERAC_ERROR_RESEED_REQUIRED;
    }

    err = prepare_additional(
        context, additional, additional_length, provided);
    if (err != LIBERAC_SUCCESS) {
        goto done;
    }
    if (additional_length != 0u) {
        err = ctr_drbg_update(context, provided);
        if (err != LIBERAC_SUCCESS) {
            goto done;
        }
    }
    err = ctr_block_context_init(&cipher, &parameters, context->KEY);
    if (err != LIBERAC_SUCCESS) {
        goto done;
    }
    cipher_ready = 1;
    while (offset < output_length) {
        size_t copy_length;

        increment_v(context->V, parameters.BLOCK_LENGTH);
        err = ctr_block_encrypt(&cipher, context->V, block);
        if (err != LIBERAC_SUCCESS) {
            goto done;
        }
        copy_length = output_length - offset;
        if (copy_length > parameters.BLOCK_LENGTH) {
            copy_length = parameters.BLOCK_LENGTH;
        }
        memcpy(output + offset, block, copy_length);
        offset += copy_length;
    }
    ctr_block_context_clear(&cipher);
    cipher_ready = 0;
    err = ctr_drbg_update(context, provided);
    if (err == LIBERAC_SUCCESS) {
        ++context->RESEED_COUNTER;
    }

done:
    if (cipher_ready != 0) {
        ctr_block_context_clear(&cipher);
    }
    if (err != LIBERAC_SUCCESS && output != NULL && output_length != 0u) {
        crypto_zeroize(output, output_length);
    }
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(provided, sizeof(provided));
    crypto_zeroize(&cipher, sizeof(cipher));
    crypto_zeroize(&parameters, sizeof(parameters));
    return err;
}

void crypto_ctr_drbg_clear_internal(LiberaCCtrDrbgContext *context) {
    if (context != NULL) {
        crypto_zeroize(context, sizeof(*context));
    }
}
