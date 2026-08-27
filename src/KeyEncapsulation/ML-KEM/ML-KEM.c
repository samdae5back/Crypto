/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdint.h>
#include <string.h>

#include "K-PKE.h"
#include "ML-KEM.h"
#include "hash.h"
#include "parameter.h"
#include "Util/Core/secure_zero.h"

CryptoError ML_KEM_KeyGen_internal(const unsigned char seed[32],
                                   const unsigned char rejection_seed[32],
                                   unsigned char *public_key,
                                   unsigned char *private_key) {
    unsigned char public_key_hash[32] = { 0 };
    CryptoError result;

    result = K_PKE_KeyGen(seed, public_key, private_key);
    if (result != CRYPTO_SUCCESS) goto cleanup;

    memcpy(private_key + 384u * (size_t)k, public_key,
           384u * (size_t)k + 32u);
    H(public_key, 384u * (size_t)k + 32u, public_key_hash);
    memcpy(private_key + 768u * (size_t)k + 32u, public_key_hash, 32u);
    memcpy(private_key + 768u * (size_t)k + 64u, rejection_seed, 32u);

cleanup:
    if (result != CRYPTO_SUCCESS) {
        crypto_zeroize(public_key, 384u * (size_t)k + 32u);
        crypto_zeroize(private_key, 768u * (size_t)k + 96u);
    }
    crypto_zeroize(public_key_hash, sizeof(public_key_hash));
    return result;
}

CryptoError ML_KEM_Encaps_internal(const unsigned char *public_key,
                                   const unsigned char message[32],
                                   unsigned char shared_secret[32],
                                   unsigned char *ciphertext) {
    unsigned char hash_input[64] = { 0 };
    unsigned char randomness[32] = { 0 };
    CryptoError result;

    memcpy(hash_input, message, 32u);
    H(public_key, 384u * (size_t)k + 32u, hash_input + 32u);
    G(hash_input, sizeof(hash_input), shared_secret, randomness);
    result = K_PKE_Enc(public_key, message, randomness, ciphertext);

    if (result != CRYPTO_SUCCESS) {
        crypto_zeroize(shared_secret, 32u);
        crypto_zeroize(ciphertext, 32u * (size_t)(d_u * k + d_v));
    }
    crypto_zeroize(hash_input, sizeof(hash_input));
    crypto_zeroize(randomness, sizeof(randomness));
    return result;
}

CryptoError ML_KEM_Decaps_internal(const unsigned char *private_key,
                                   const unsigned char *ciphertext,
                                   unsigned char shared_secret[32]) {
    unsigned char public_key[MLKEM_MAX_PUBLIC_KEY_BYTES] = { 0 };
    unsigned char pke_private_key[384u * MLKEM_MAX_K] = { 0 };
    unsigned char public_key_hash[32] = { 0 };
    unsigned char rejection_seed[32] = { 0 };
    unsigned char message[32] = { 0 };
    unsigned char hash_input[MLKEM_MAX_CIPHERTEXT_BYTES + 32u] = { 0 };
    unsigned char randomness[32] = { 0 };
    unsigned char rejected_secret[32] = { 0 };
    unsigned char expected_ciphertext[MLKEM_MAX_CIPHERTEXT_BYTES] = { 0 };
    size_t ciphertext_length = 32u * (size_t)(d_u * k + d_v);
    CryptoError result;

    memcpy(pke_private_key, private_key, 384u * (size_t)k);
    memcpy(public_key, private_key + 384u * (size_t)k,
           384u * (size_t)k + 32u);
    memcpy(public_key_hash, private_key + 768u * (size_t)k + 32u, 32u);
    memcpy(rejection_seed, private_key + 768u * (size_t)k + 64u, 32u);

    result = K_PKE_Dec(pke_private_key, ciphertext, message);
    if (result != CRYPTO_SUCCESS) goto cleanup;

    memcpy(hash_input, message, 32u);
    memcpy(hash_input + 32u, public_key_hash, 32u);
    G(hash_input, 64u, shared_secret, randomness);

    memcpy(hash_input, rejection_seed, 32u);
    memcpy(hash_input + 32u, ciphertext, ciphertext_length);
    J(hash_input, ciphertext_length + 32u, rejected_secret);

    result = K_PKE_Enc(public_key, message, randomness,
                       expected_ciphertext);
    if (result != CRYPTO_SUCCESS) goto cleanup;

    {
        uint32_t mismatch = 0u;
        uint8_t rejection_mask;
        size_t i;

        for (i = 0u; i < ciphertext_length; ++i)
            mismatch |= (uint32_t)(ciphertext[i] ^ expected_ciphertext[i]);
        mismatch = (mismatch | (0u - mismatch)) >> 31;
        rejection_mask = (uint8_t)(0u - mismatch);
        for (i = 0u; i < 32u; ++i) {
            shared_secret[i] =
                (uint8_t)((shared_secret[i] & (uint8_t)~rejection_mask) |
                          (rejected_secret[i] & rejection_mask));
        }
    }
    result = CRYPTO_SUCCESS;

cleanup:
    if (result != CRYPTO_SUCCESS) crypto_zeroize(shared_secret, 32u);
    crypto_zeroize(public_key, sizeof(public_key));
    crypto_zeroize(pke_private_key, sizeof(pke_private_key));
    crypto_zeroize(public_key_hash, sizeof(public_key_hash));
    crypto_zeroize(rejection_seed, sizeof(rejection_seed));
    crypto_zeroize(message, sizeof(message));
    crypto_zeroize(hash_input, sizeof(hash_input));
    crypto_zeroize(randomness, sizeof(randomness));
    crypto_zeroize(rejected_secret, sizeof(rejected_secret));
    crypto_zeroize(expected_ciphertext, sizeof(expected_ciphertext));
    return result;
}

CryptoError ML_KEM_KeyGen(unsigned char *public_key,
                          unsigned char *private_key) {
    unsigned char seed[32] = { 0 };
    unsigned char rejection_seed[32] = { 0 };
    CryptoError result;

    result = RBG(seed, sizeof(seed));
    if (result != CRYPTO_SUCCESS) goto cleanup;
    result = RBG(rejection_seed, sizeof(rejection_seed));
    if (result != CRYPTO_SUCCESS) goto cleanup;
    result = ML_KEM_KeyGen_internal(seed, rejection_seed, public_key,
                                    private_key);

cleanup:
    if (result != CRYPTO_SUCCESS) {
        crypto_zeroize(public_key, 384u * (size_t)k + 32u);
        crypto_zeroize(private_key, 768u * (size_t)k + 96u);
    }
    crypto_zeroize(seed, sizeof(seed));
    crypto_zeroize(rejection_seed, sizeof(rejection_seed));
    return result;
}

CryptoError ML_KEM_Encaps(const unsigned char *public_key,
                          unsigned char shared_secret[32],
                          unsigned char *ciphertext) {
    unsigned char message[32] = { 0 };
    CryptoError result;

    result = RBG(message, sizeof(message));
    if (result == CRYPTO_SUCCESS)
        result = ML_KEM_Encaps_internal(public_key, message, shared_secret,
                                        ciphertext);
    if (result != CRYPTO_SUCCESS) {
        crypto_zeroize(shared_secret, 32u);
        crypto_zeroize(ciphertext, 32u * (size_t)(d_u * k + d_v));
    }
    crypto_zeroize(message, sizeof(message));
    return result;
}

CryptoError ML_KEM_Decaps(const unsigned char *private_key,
                          const unsigned char *ciphertext,
                          unsigned char shared_secret[32]) {
    return ML_KEM_Decaps_internal(private_key, ciphertext, shared_secret);
}
