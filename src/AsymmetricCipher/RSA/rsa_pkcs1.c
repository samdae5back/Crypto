/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "rsa_internal.h"

#include "HashFunction.h"
#include "RandomNumberGeneration/Noise/random_internal.h"
#include "Util/Bignum/bignum_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RSA_PSS_TRAILER UINT8_C(0xbc)

static size_t rsa_hash_length(LiberaCAlgID hash_alg) {
    switch (hash_alg) {
        case LIBERAC_ALG_HASH_SHA1:
            return LIBERAC_SHA1_DIGEST_BYTES;
        case LIBERAC_ALG_HASH_SHA2_224:
            return LIBERAC_SHA2_224_DIGEST_BYTES;
        case LIBERAC_ALG_HASH_SHA2_256:
            return LIBERAC_SHA2_256_DIGEST_BYTES;
        case LIBERAC_ALG_HASH_SHA2_384:
            return LIBERAC_SHA2_384_DIGEST_BYTES;
        case LIBERAC_ALG_HASH_SHA2_512:
            return LIBERAC_SHA2_512_DIGEST_BYTES;
        case LIBERAC_ALG_HASH_SHA2_512_224:
            return LIBERAC_SHA2_512_224_DIGEST_BYTES;
        case LIBERAC_ALG_HASH_SHA2_512_256:
            return LIBERAC_SHA2_512_256_DIGEST_BYTES;
        default:
            return 0u;
    }
}

static int rsa_bignum_well_formed(const LiberaCBignum *value) {
    if (!value || value->LENGTH > value->CAPACITY)
        return 0;
    if (value->LENGTH == 0u)
        return 1;
    if (!value->LIMBS || value->LIMBS[value->LENGTH - 1u] == 0u)
        return 0;
    return 1;
}

static int rsa_public_key_valid(const LiberaCRsaPublicKey *key) {
    if (!key || !rsa_bignum_well_formed(&key->N) ||
        !rsa_bignum_well_formed(&key->E) ||
        key->N.LENGTH == 0u || key->E.LENGTH == 0u ||
        key->N.LENGTH > SIZE_MAX / 32u ||
        !(key->N.LIMBS[0] & 1u) || !(key->E.LIMBS[0] & 1u) ||
        crypto_bignum_compare(&key->E, &key->N) >= 0)
        return 0;
    if (key->E.LENGTH == 1u && key->E.LIMBS[0] < 3u)
        return 0;
    return 1;
}

static int rsa_private_key_valid(const LiberaCRsaPrivateKey *key) {
    uint32_t nonzero = 0u;
    uint32_t borrow = 0u;
    size_t i;

    if (!key || !rsa_bignum_well_formed(&key->N) ||
        key->N.LENGTH == 0u || key->N.LENGTH > SIZE_MAX / 32u ||
        !(key->N.LIMBS[0] & 1u) ||
        key->D.LENGTH > key->D.CAPACITY ||
        !key->D.LIMBS || key->D.CAPACITY < key->N.LENGTH)
        return 0;

    /* D is stored at the public modulus width. Validate nonzero and D < N
     * with one fixed-width scan rather than normalizing or comparing early. */
    for (i = 0u; i < key->N.LENGTH; ++i) {
        uint64_t subtrahend = (uint64_t)key->N.LIMBS[i] + borrow;
        uint64_t minuend = key->D.LIMBS[i];
        nonzero |= key->D.LIMBS[i];
        borrow = (uint32_t)(minuend < subtrahend);
    }
    return nonzero != 0u && borrow != 0u;
}

static size_t rsa_modulus_size(const LiberaCBignum *modulus) {
    size_t bits = crypto_bignum_bit_length(modulus);
    return bits / 8u + (bits % 8u != 0u ? 1u : 0u);
}

size_t crypto_rsa_public_modulus_size_internal(
    const LiberaCRsaPublicKey *public_key) {
    if (!rsa_public_key_valid(public_key))
        return 0u;
    return rsa_modulus_size(&public_key->N);
}

size_t crypto_rsa_private_modulus_size_internal(
    const LiberaCRsaPrivateKey *private_key) {
    if (!rsa_private_key_valid(private_key))
        return 0u;
    return rsa_modulus_size(&private_key->N);
}

size_t crypto_rsa_oaep_max_message_size_internal(
    size_t modulus_bytes, LiberaCAlgID hash_alg, LiberaCAlgID alg) {
    size_t hash_length = rsa_hash_length(hash_alg);
    if (alg != LIBERAC_ALG_RSA_OAEP || hash_length == 0u ||
        hash_length > (SIZE_MAX - 2u) / 2u ||
        modulus_bytes < 2u * hash_length + 2u)
        return 0u;
    return modulus_bytes - 2u * hash_length - 2u;
}

static LiberaCError rsa_hash_three(
    uint8_t *output, size_t output_length, LiberaCAlgID hash_alg,
    const uint8_t *first, size_t first_length,
    const uint8_t *second, size_t second_length,
    const uint8_t *third, size_t third_length) {
    LiberaCHashContext context;
    LiberaCError error;

    error = LIBERAC_HASH_INIT(&context, hash_alg);
    if (error == LIBERAC_SUCCESS)
        error = LIBERAC_HASH_UPDATE(&context, first, first_length);
    if (error == LIBERAC_SUCCESS)
        error = LIBERAC_HASH_UPDATE(&context, second, second_length);
    if (error == LIBERAC_SUCCESS)
        error = LIBERAC_HASH_UPDATE(&context, third, third_length);
    if (error == LIBERAC_SUCCESS)
        error = LIBERAC_HASH_FINALIZE(&context);
    if (error == LIBERAC_SUCCESS)
        error = LIBERAC_HASH_SQUEEZE(&context, output, output_length);
    LIBERAC_HASH_CLEAR(&context);
    return error;
}

static LiberaCError rsa_mgf1_xor(
    uint8_t *output, size_t output_length,
    const uint8_t *seed, size_t seed_length,
    LiberaCAlgID hash_alg, size_t hash_length) {
    uint8_t digest[LIBERAC_HASH_MAX_DIGEST_BYTES];
    uint8_t counter_bytes[4];
    uint64_t block_count;
    uint64_t block;
    size_t offset = 0u;
    LiberaCError error = LIBERAC_SUCCESS;

    if ((!output && output_length != 0u) ||
        (!seed && seed_length != 0u) || hash_length == 0u)
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    block_count = (uint64_t)(output_length / hash_length);
    if (output_length % hash_length != 0u)
        ++block_count;
    if (block_count > UINT64_C(0x100000000))
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;

    crypto_zeroize(digest, sizeof(digest));
    for (block = 0u; block < block_count; ++block) {
        uint32_t counter = (uint32_t)block;
        size_t take;
        size_t i;

        counter_bytes[0] = (uint8_t)(counter >> 24);
        counter_bytes[1] = (uint8_t)(counter >> 16);
        counter_bytes[2] = (uint8_t)(counter >> 8);
        counter_bytes[3] = (uint8_t)counter;
        error = rsa_hash_three(
            digest, hash_length, hash_alg,
            seed, seed_length, counter_bytes, sizeof(counter_bytes),
            NULL, 0u);
        if (error != LIBERAC_SUCCESS)
            break;
        take = output_length - offset;
        if (take > hash_length)
            take = hash_length;
        for (i = 0u; i < take; ++i)
            output[offset + i] ^= digest[i];
        offset += take;
    }

    crypto_zeroize(digest, sizeof(digest));
    crypto_zeroize(counter_bytes, sizeof(counter_bytes));
    return error;
}

static uint32_t rsa_ct_is_zero_u8(uint8_t value) {
    uint32_t x = value;
    return ((x | (0u - x)) >> 31) ^ 1u;
}

static size_t rsa_ct_select_size(
    size_t zero_choice, size_t one_choice, uint32_t choose_one) {
    size_t mask = (size_t)0 - (size_t)(choose_one & 1u);
    return (zero_choice & ~mask) | (one_choice & mask);
}

static LiberaCError rsa_resolve_salt_length(
    size_t requested, size_t hash_length, size_t *resolved) {
    if (!resolved)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    *resolved = requested == LIBERAC_RSA_PSS_SALT_LENGTH_DIGEST
                    ? hash_length
                    : requested;
    return LIBERAC_SUCCESS;
}

static LiberaCError rsa_public_secret_operation(
    uint8_t *output, size_t output_length,
    const uint8_t *input, size_t input_length,
    const LiberaCRsaPublicKey *public_key) {
    LiberaCBignum encoded;
    LiberaCBignum transformed;
    LiberaCError error;

    crypto_bignum_init(&encoded);
    crypto_bignum_init(&transformed);
    error = crypto_bignum_from_bytes_be_secret_fixed_ct(
        &encoded, input, input_length, public_key->N.LENGTH);
    if (error == LIBERAC_SUCCESS)
        error = crypto_bignum_mod_exp_public_fixed_base(
            &transformed, &encoded, &public_key->E, &public_key->N);
    if (error == LIBERAC_SUCCESS)
        error = crypto_bignum_to_bytes_be_secret_fixed_ct(
            &transformed, output, output_length);
    crypto_bignum_free(&encoded);
    crypto_bignum_free(&transformed);
    return error;
}

static LiberaCError rsa_private_operation(
    uint8_t *output, size_t output_length,
    const uint8_t *input, size_t input_length,
    const LiberaCRsaPrivateKey *private_key,
    int input_is_secret) {
    LiberaCBignum encoded;
    LiberaCBignum transformed;
    LiberaCError error;

    crypto_bignum_init(&encoded);
    crypto_bignum_init(&transformed);
    if (input_is_secret) {
        error = crypto_bignum_from_bytes_be_secret_fixed_ct(
            &encoded, input, input_length, private_key->N.LENGTH);
    } else {
        error = crypto_bignum_from_bytes_be(
            &encoded, input, input_length);
    }
    if (error == LIBERAC_SUCCESS) {
        if (input_is_secret) {
            /* EMSA-PSS construction guarantees its representative is below N.
             * Bypass the raw API's public-input comparison for this secret
             * encoded value and enter the fixed-schedule exponentiation. */
            error = crypto_bignum_mod_exp_ct_fixed_base(
                &transformed, &encoded, &private_key->D, &private_key->N);
        } else {
            error = crypto_rsa_decrypt_internal(
                LIBERAC_ALG_RSA_RAW, &transformed, &encoded, private_key);
        }
    }
    if (error == LIBERAC_SUCCESS)
        error = crypto_bignum_to_bytes_be_secret_fixed_ct(
            &transformed, output, output_length);
    crypto_bignum_free(&encoded);
    crypto_bignum_free(&transformed);
    return error;
}

static LiberaCError rsa_public_verify_operation(
    uint8_t *output, size_t output_length,
    const uint8_t *signature, size_t signature_length,
    const LiberaCRsaPublicKey *public_key) {
    LiberaCBignum encoded;
    LiberaCBignum transformed;
    LiberaCError error;

    crypto_bignum_init(&encoded);
    crypto_bignum_init(&transformed);
    error = crypto_bignum_from_bytes_be(
        &encoded, signature, signature_length);
    if (error == LIBERAC_SUCCESS &&
        crypto_bignum_compare(&encoded, &public_key->N) >= 0)
        error = LIBERAC_ERROR_SIGNATURE_INVALID;
    if (error == LIBERAC_SUCCESS)
        error = crypto_rsa_encrypt_internal(
            LIBERAC_ALG_RSA_RAW, &transformed, &encoded, public_key);
    if (error == LIBERAC_SUCCESS) {
        error = crypto_bignum_to_bytes_be(
            &transformed, output, output_length);
        if (error == LIBERAC_ERROR_BUFFER_TOO_SMALL)
            error = LIBERAC_ERROR_SIGNATURE_INVALID;
    }
    crypto_bignum_free(&encoded);
    crypto_bignum_free(&transformed);
    return error;
}

LiberaCError crypto_rsa_oaep_encrypt_internal(
    LiberaCAlgID alg, LiberaCAlgID hash_alg,
    uint8_t *ciphertext, size_t ciphertext_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *label, size_t label_length,
    const LiberaCRsaPublicKey *public_key) {
    uint8_t *encoded = NULL;
    uint8_t *seed;
    uint8_t *data_block;
    size_t hash_length;
    size_t modulus_bytes;
    size_t data_block_length;
    size_t maximum_message;
    size_t delimiter;
    LiberaCError error = LIBERAC_ERROR_INTERNAL;

    if (alg != LIBERAC_ALG_RSA_OAEP)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    hash_length = rsa_hash_length(hash_alg);
    if (hash_length == 0u)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!rsa_public_key_valid(public_key))
        return LIBERAC_ERROR_INVALID_KEY;
    if (!ciphertext || (!message && message_length != 0u) ||
        (!label && label_length != 0u))
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    modulus_bytes = rsa_modulus_size(&public_key->N);
    if (hash_length > (SIZE_MAX - 2u) / 2u ||
        modulus_bytes < 2u * hash_length + 2u)
        return LIBERAC_ERROR_INVALID_KEY;
    maximum_message = modulus_bytes - 2u * hash_length - 2u;
    if (ciphertext_length < modulus_bytes)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (message_length > maximum_message)
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    if (crypto_ranges_overlap(
            ciphertext, modulus_bytes, message, message_length) ||
        crypto_ranges_overlap(
            ciphertext, modulus_bytes, label, label_length))
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    encoded = (uint8_t *)calloc(modulus_bytes, 1u);
    if (!encoded)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    seed = encoded + 1u;
    data_block = seed + hash_length;
    data_block_length = modulus_bytes - hash_length - 1u;

    error = LIBERAC_HASH(
        data_block, hash_length, label, label_length, hash_alg);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;
    delimiter = data_block_length - message_length - 1u;
    data_block[delimiter] = 1u;
    if (message_length != 0u)
        memcpy(data_block + delimiter + 1u, message, message_length);

    error = crypto_random_bytes_internal(seed, hash_length);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;
    error = rsa_mgf1_xor(
        data_block, data_block_length,
        seed, hash_length, hash_alg, hash_length);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;
    error = rsa_mgf1_xor(
        seed, hash_length,
        data_block, data_block_length, hash_alg, hash_length);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;

    error = rsa_public_secret_operation(
        ciphertext, modulus_bytes, encoded, modulus_bytes, public_key);

cleanup:
    if (error != LIBERAC_SUCCESS)
        crypto_zeroize(ciphertext, modulus_bytes);
    crypto_zeroize(encoded, modulus_bytes);
    free(encoded);
    return error;
}

LiberaCError crypto_rsa_oaep_decrypt_internal(
    LiberaCAlgID alg, LiberaCAlgID hash_alg,
    uint8_t *message, size_t message_capacity, size_t *message_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    const uint8_t *label, size_t label_length,
    const LiberaCRsaPrivateKey *private_key) {
    uint8_t *encoded = NULL;
    uint8_t label_hash[LIBERAC_HASH_MAX_DIGEST_BYTES];
    uint8_t *seed;
    uint8_t *data_block;
    size_t hash_length;
    size_t modulus_bytes;
    size_t maximum_message;
    size_t data_block_length;
    size_t message_index;
    size_t recovered_length;
    size_t i;
    uint32_t bad = 0u;
    uint32_t seeking = 1u;
    LiberaCError error = LIBERAC_ERROR_INTERNAL;

    if (alg != LIBERAC_ALG_RSA_OAEP)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    hash_length = rsa_hash_length(hash_alg);
    if (hash_length == 0u)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!rsa_private_key_valid(private_key))
        return LIBERAC_ERROR_INVALID_KEY;
    if (!message_length || !ciphertext ||
        (!label && label_length != 0u))
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    modulus_bytes = rsa_modulus_size(&private_key->N);
    if (hash_length > (SIZE_MAX - 2u) / 2u ||
        modulus_bytes < 2u * hash_length + 2u)
        return LIBERAC_ERROR_INVALID_KEY;
    maximum_message = modulus_bytes - 2u * hash_length - 2u;
    if (!message && maximum_message != 0u)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (message_capacity < maximum_message)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (crypto_ranges_overlap(
            message, maximum_message, ciphertext, ciphertext_length) ||
        crypto_ranges_overlap(
            message, maximum_message, label, label_length))
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    *message_length = 0u;
    if (maximum_message != 0u)
        crypto_zeroize(message, maximum_message);
    if (ciphertext_length != modulus_bytes)
        return LIBERAC_ERROR_AUTHENTICATION_FAILED;

    encoded = (uint8_t *)malloc(modulus_bytes);
    if (!encoded)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    crypto_zeroize(label_hash, sizeof(label_hash));

    error = rsa_private_operation(
        encoded, modulus_bytes, ciphertext, ciphertext_length,
        private_key, 0);
    if (error == LIBERAC_ERROR_INVALID_ARGUMENT) {
        error = LIBERAC_ERROR_AUTHENTICATION_FAILED;
        goto cleanup;
    }
    if (error != LIBERAC_SUCCESS)
        goto cleanup;

    seed = encoded + 1u;
    data_block = seed + hash_length;
    data_block_length = modulus_bytes - hash_length - 1u;
    bad |= (uint32_t)encoded[0];

    error = rsa_mgf1_xor(
        seed, hash_length,
        data_block, data_block_length, hash_alg, hash_length);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;
    error = rsa_mgf1_xor(
        data_block, data_block_length,
        seed, hash_length, hash_alg, hash_length);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;
    error = LIBERAC_HASH(
        label_hash, hash_length, label, label_length, hash_alg);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;
    if (!crypto_constant_time_equal(data_block, label_hash, hash_length))
        bad |= 1u;

    message_index = data_block_length;
    for (i = hash_length; i < data_block_length; ++i) {
        uint32_t is_zero = rsa_ct_is_zero_u8(data_block[i]);
        uint32_t is_one = rsa_ct_is_zero_u8(
            (uint8_t)(data_block[i] ^ 1u));
        uint32_t take = seeking & is_one;
        uint32_t acceptable = is_zero | is_one;

        message_index = rsa_ct_select_size(
            message_index, i + 1u, take);
        bad |= seeking & (acceptable ^ 1u);
        seeking &= is_one ^ 1u;
    }
    bad |= seeking;

    if (bad != 0u) {
        error = LIBERAC_ERROR_AUTHENTICATION_FAILED;
        goto cleanup;
    }

    recovered_length = data_block_length - message_index;
    if (recovered_length != 0u)
        memcpy(message, data_block + message_index, recovered_length);
    *message_length = recovered_length;
    error = LIBERAC_SUCCESS;

cleanup:
    if (error != LIBERAC_SUCCESS) {
        *message_length = 0u;
        if (maximum_message != 0u)
            crypto_zeroize(message, maximum_message);
    }
    crypto_zeroize(label_hash, sizeof(label_hash));
    if (encoded) {
        crypto_zeroize(encoded, modulus_bytes);
        free(encoded);
    }
    return error;
}

LiberaCError crypto_rsa_pss_sign_internal(
    LiberaCAlgID alg, LiberaCAlgID hash_alg,
    const LiberaCRsaPrivateKey *private_key,
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t signature_length, size_t salt_length) {
    static const uint8_t zero_prefix[8] = {0u};
    uint8_t message_hash[LIBERAC_HASH_MAX_DIGEST_BYTES];
    uint8_t *encoded = NULL;
    uint8_t *salt = NULL;
    uint8_t *encoded_hash;
    size_t hash_length;
    size_t modulus_bits;
    size_t modulus_bytes;
    size_t encoded_bits;
    size_t encoded_length;
    size_t data_block_length;
    size_t padding_length;
    size_t unused_bits;
    LiberaCError error;

    if (alg != LIBERAC_ALG_RSA_PSS)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    hash_length = rsa_hash_length(hash_alg);
    if (hash_length == 0u)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!rsa_private_key_valid(private_key))
        return LIBERAC_ERROR_INVALID_KEY;
    if (!signature || (!message && message_length != 0u))
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    modulus_bits = crypto_bignum_bit_length(&private_key->N);
    modulus_bytes = rsa_modulus_size(&private_key->N);
    if (modulus_bits < 2u)
        return LIBERAC_ERROR_INVALID_KEY;
    encoded_bits = modulus_bits - 1u;
    encoded_length = encoded_bits / 8u +
                     (encoded_bits % 8u != 0u ? 1u : 0u);
    error = rsa_resolve_salt_length(
        salt_length, hash_length, &salt_length);
    if (error != LIBERAC_SUCCESS)
        return error;
    if (salt_length > SIZE_MAX - hash_length - 2u ||
        encoded_length < hash_length + salt_length + 2u)
        return LIBERAC_ERROR_MESSAGE_TOO_LARGE;
    if (signature_length < modulus_bytes)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (crypto_ranges_overlap(
            signature, modulus_bytes, message, message_length))
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    encoded = (uint8_t *)calloc(encoded_length, 1u);
    if (!encoded)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    if (salt_length != 0u) {
        salt = (uint8_t *)malloc(salt_length);
        if (!salt) {
            error = LIBERAC_ERROR_ALLOCATION_FAILED;
            goto cleanup;
        }
    }
    crypto_zeroize(message_hash, sizeof(message_hash));

    error = LIBERAC_HASH(
        message_hash, hash_length, message, message_length, hash_alg);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;
    error = crypto_random_bytes_internal(salt, salt_length);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;

    data_block_length = encoded_length - hash_length - 1u;
    padding_length = data_block_length - salt_length - 1u;
    encoded[padding_length] = 1u;
    if (salt_length != 0u)
        memcpy(encoded + padding_length + 1u, salt, salt_length);
    encoded_hash = encoded + data_block_length;

    error = rsa_hash_three(
        encoded_hash, hash_length, hash_alg,
        zero_prefix, sizeof(zero_prefix),
        message_hash, hash_length, salt, salt_length);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;
    error = rsa_mgf1_xor(
        encoded, data_block_length,
        encoded_hash, hash_length, hash_alg, hash_length);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;

    unused_bits = 8u * encoded_length - encoded_bits;
    encoded[0] &= (uint8_t)(UINT8_C(0xff) >> unused_bits);
    encoded[encoded_length - 1u] = RSA_PSS_TRAILER;

    error = rsa_private_operation(
        signature, modulus_bytes, encoded, encoded_length,
        private_key, 1);

cleanup:
    if (error != LIBERAC_SUCCESS)
        crypto_zeroize(signature, modulus_bytes);
    crypto_zeroize(message_hash, sizeof(message_hash));
    if (salt) {
        crypto_zeroize(salt, salt_length);
        free(salt);
    }
    if (encoded) {
        crypto_zeroize(encoded, encoded_length);
        free(encoded);
    }
    return error;
}

LiberaCError crypto_rsa_pss_verify_internal(
    LiberaCAlgID alg, LiberaCAlgID hash_alg,
    const LiberaCRsaPublicKey *public_key,
    const uint8_t *message, size_t message_length,
    const uint8_t *signature, size_t signature_length, size_t salt_length) {
    static const uint8_t zero_prefix[8] = {0u};
    uint8_t message_hash[LIBERAC_HASH_MAX_DIGEST_BYTES];
    uint8_t comparison_hash[LIBERAC_HASH_MAX_DIGEST_BYTES];
    uint8_t *encoded = NULL;
    uint8_t *encoded_hash;
    const uint8_t *salt;
    size_t hash_length;
    size_t modulus_bits;
    size_t modulus_bytes;
    size_t encoded_bits;
    size_t encoded_length;
    size_t data_block_length;
    size_t padding_length;
    size_t unused_bits;
    size_t i;
    uint8_t allowed_mask;
    uint32_t bad = 0u;
    LiberaCError error;

    if (alg != LIBERAC_ALG_RSA_PSS)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    hash_length = rsa_hash_length(hash_alg);
    if (hash_length == 0u)
        return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!rsa_public_key_valid(public_key))
        return LIBERAC_ERROR_INVALID_KEY;
    if (!signature || (!message && message_length != 0u))
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    modulus_bits = crypto_bignum_bit_length(&public_key->N);
    modulus_bytes = rsa_modulus_size(&public_key->N);
    if (signature_length != modulus_bytes)
        return LIBERAC_ERROR_SIGNATURE_INVALID;
    if (modulus_bits < 2u)
        return LIBERAC_ERROR_INVALID_KEY;
    encoded_bits = modulus_bits - 1u;
    encoded_length = encoded_bits / 8u +
                     (encoded_bits % 8u != 0u ? 1u : 0u);
    error = rsa_resolve_salt_length(
        salt_length, hash_length, &salt_length);
    if (error != LIBERAC_SUCCESS)
        return error;
    if (salt_length > SIZE_MAX - hash_length - 2u ||
        encoded_length < hash_length + salt_length + 2u)
        return LIBERAC_ERROR_INVALID_ARGUMENT;

    encoded = (uint8_t *)malloc(encoded_length);
    if (!encoded)
        return LIBERAC_ERROR_ALLOCATION_FAILED;
    crypto_zeroize(message_hash, sizeof(message_hash));
    crypto_zeroize(comparison_hash, sizeof(comparison_hash));

    error = rsa_public_verify_operation(
        encoded, encoded_length, signature, signature_length, public_key);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;

    data_block_length = encoded_length - hash_length - 1u;
    encoded_hash = encoded + data_block_length;
    unused_bits = 8u * encoded_length - encoded_bits;
    allowed_mask = (uint8_t)(UINT8_C(0xff) >> unused_bits);
    bad |= (uint32_t)(encoded[0] & (uint8_t)~allowed_mask);
    bad |= (uint32_t)(encoded[encoded_length - 1u] ^ RSA_PSS_TRAILER);

    error = rsa_mgf1_xor(
        encoded, data_block_length,
        encoded_hash, hash_length, hash_alg, hash_length);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;
    encoded[0] &= allowed_mask;

    padding_length = data_block_length - salt_length - 1u;
    for (i = 0u; i < padding_length; ++i)
        bad |= (uint32_t)encoded[i];
    bad |= (uint32_t)(encoded[padding_length] ^ 1u);
    salt = encoded + padding_length + 1u;

    error = LIBERAC_HASH(
        message_hash, hash_length, message, message_length, hash_alg);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;
    error = rsa_hash_three(
        comparison_hash, hash_length, hash_alg,
        zero_prefix, sizeof(zero_prefix),
        message_hash, hash_length, salt, salt_length);
    if (error != LIBERAC_SUCCESS)
        goto cleanup;
    if (!crypto_constant_time_equal(
            encoded_hash, comparison_hash, hash_length))
        bad |= 1u;

    error = bad == 0u
                ? LIBERAC_SUCCESS
                : LIBERAC_ERROR_SIGNATURE_INVALID;

cleanup:
    crypto_zeroize(message_hash, sizeof(message_hash));
    crypto_zeroize(comparison_hash, sizeof(comparison_hash));
    if (encoded) {
        crypto_zeroize(encoded, encoded_length);
        free(encoded);
    }
    return error;
}
