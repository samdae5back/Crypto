/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdint.h>

#include "api_internal.h"
#include "hash.h"
#include "parameter.h"
#include "ML-KEM.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"

MLKEM_THREAD_LOCAL const mlkem_parameters *mlkem_active_parameters;

static int mlkem_public_key_is_canonical(const uint8_t *public_key,
                                         size_t public_key_length) {
    size_t encoded_polynomial_length = public_key_length - 32u;
    size_t offset;
    uint32_t invalid = 0u;

    for (offset = 0u; offset < encoded_polynomial_length; offset += 3u) {
        uint32_t first = (uint32_t)public_key[offset] |
                         (((uint32_t)public_key[offset + 1u] & 0x0fu) << 8);
        uint32_t second = ((uint32_t)public_key[offset + 1u] >> 4) |
                          ((uint32_t)public_key[offset + 2u] << 4);
        invalid |= ((uint32_t)MLKEM_Q - 1u - first) >> 31;
        invalid |= ((uint32_t)MLKEM_Q - 1u - second) >> 31;
    }
    return invalid == 0u;
}

static int mlkem_private_key_hash_is_valid(const uint8_t *private_key,
                                           size_t public_key_length,
                                           size_t private_key_length) {
    size_t pke_private_key_length =
        private_key_length - public_key_length - 64u;
    const uint8_t *embedded_public_key =
        private_key + pke_private_key_length;
    const uint8_t *stored_hash = private_key + private_key_length - 64u;
    uint8_t computed_hash[32];
    int valid;

    H(embedded_public_key, public_key_length, computed_hash);
    valid = crypto_constant_time_equal(
        computed_hash, stored_hash, sizeof(computed_hash));
    crypto_zeroize(computed_hash, sizeof(computed_hash));
    return valid;
}

const mlkem_parameters *mlkem_parameters_for(LiberaCAlgID alg) {
    size_t i;
    for (i = 0; i < sizeof(MLKEM_PARAMETER_SETS) / sizeof(MLKEM_PARAMETER_SETS[0]); ++i)
        if (MLKEM_PARAMETER_SETS[i].alg == alg) return &MLKEM_PARAMETER_SETS[i];
    return NULL;
}

size_t crypto_ml_kem_public_key_size_internal(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ML_KEM_512: return LIBERAC_ML_KEM_512_PUBLIC_KEY_BYTES;
        case LIBERAC_ALG_ML_KEM_768: return LIBERAC_ML_KEM_768_PUBLIC_KEY_BYTES;
        case LIBERAC_ALG_ML_KEM_1024: return LIBERAC_ML_KEM_1024_PUBLIC_KEY_BYTES;
        default: return 0;
    }
}

size_t crypto_ml_kem_private_key_size_internal(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ML_KEM_512: return LIBERAC_ML_KEM_512_PRIVATE_KEY_BYTES;
        case LIBERAC_ALG_ML_KEM_768: return LIBERAC_ML_KEM_768_PRIVATE_KEY_BYTES;
        case LIBERAC_ALG_ML_KEM_1024: return LIBERAC_ML_KEM_1024_PRIVATE_KEY_BYTES;
        default: return 0;
    }
}

size_t crypto_ml_kem_ciphertext_size_internal(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ML_KEM_512: return LIBERAC_ML_KEM_512_CIPHERTEXT_BYTES;
        case LIBERAC_ALG_ML_KEM_768: return LIBERAC_ML_KEM_768_CIPHERTEXT_BYTES;
        case LIBERAC_ALG_ML_KEM_1024: return LIBERAC_ML_KEM_1024_CIPHERTEXT_BYTES;
        default: return 0;
    }
}

LiberaCError crypto_ml_kem_keygen_internal(LiberaCAlgID alg, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len) {
    size_t need_pk = crypto_ml_kem_public_key_size_internal(alg);
    size_t need_sk = crypto_ml_kem_private_key_size_internal(alg);
    LiberaCError result;
    if (!need_pk || !need_sk) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!pk || !sk) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (pk_len < need_pk || sk_len < need_sk) return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (crypto_ranges_overlap(pk, need_pk, sk, need_sk))
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    mlkem_active_parameters = mlkem_parameters_for(alg);
    result = ML_KEM_KeyGen(pk, sk);
    if (result != LIBERAC_SUCCESS) {
        crypto_zeroize(pk, need_pk);
        crypto_zeroize(sk, need_sk);
    }
    return result;
}

LiberaCError crypto_ml_kem_encaps_internal(LiberaCAlgID alg, const uint8_t *pk, size_t pk_len, uint8_t ss[LIBERAC_ML_KEM_SHARED_SECRET_BYTES], uint8_t *ct, size_t ct_len) {
    size_t need_pk = crypto_ml_kem_public_key_size_internal(alg);
    size_t need_ct = crypto_ml_kem_ciphertext_size_internal(alg);
    LiberaCError result;
    if (!need_pk || !need_ct) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!pk || !ss || !ct) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (pk_len < need_pk || ct_len < need_ct) return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (crypto_ranges_overlap(pk, need_pk, ss,
                             LIBERAC_ML_KEM_SHARED_SECRET_BYTES) ||
        crypto_ranges_overlap(pk, need_pk, ct, need_ct) ||
        crypto_ranges_overlap(ss, LIBERAC_ML_KEM_SHARED_SECRET_BYTES,
                             ct, need_ct))
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (!mlkem_public_key_is_canonical(pk, need_pk)) {
        crypto_zeroize(ss, LIBERAC_ML_KEM_SHARED_SECRET_BYTES);
        crypto_zeroize(ct, need_ct);
        return LIBERAC_ERROR_INVALID_KEY;
    }
    mlkem_active_parameters = mlkem_parameters_for(alg);
    result = ML_KEM_Encaps(pk, ss, ct);
    if (result != LIBERAC_SUCCESS) {
        crypto_zeroize(ss, LIBERAC_ML_KEM_SHARED_SECRET_BYTES);
        crypto_zeroize(ct, need_ct);
    }
    return result;
}

LiberaCError crypto_ml_kem_decaps_internal(LiberaCAlgID alg, const uint8_t *sk, size_t sk_len, const uint8_t *ct, size_t ct_len, uint8_t ss[LIBERAC_ML_KEM_SHARED_SECRET_BYTES]) {
    size_t need_pk = crypto_ml_kem_public_key_size_internal(alg);
    size_t need_sk = crypto_ml_kem_private_key_size_internal(alg);
    size_t need_ct = crypto_ml_kem_ciphertext_size_internal(alg);
    LiberaCError result;
    if (!need_sk || !need_ct) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!sk || !ct || !ss) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (sk_len < need_sk || ct_len < need_ct) return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if (crypto_ranges_overlap(sk, need_sk, ss,
                             LIBERAC_ML_KEM_SHARED_SECRET_BYTES) ||
        crypto_ranges_overlap(ct, need_ct, ss,
                             LIBERAC_ML_KEM_SHARED_SECRET_BYTES))
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (!mlkem_private_key_hash_is_valid(sk, need_pk, need_sk)) {
        crypto_zeroize(ss, LIBERAC_ML_KEM_SHARED_SECRET_BYTES);
        return LIBERAC_ERROR_INVALID_KEY;
    }
    mlkem_active_parameters = mlkem_parameters_for(alg);
    result = ML_KEM_Decaps(sk, ct, ss);
    if (result != LIBERAC_SUCCESS)
        crypto_zeroize(ss, LIBERAC_ML_KEM_SHARED_SECRET_BYTES);
    return result;
}
