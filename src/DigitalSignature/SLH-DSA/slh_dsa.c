/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "slh_dsa_internal.h"
#include "RandomNumberGeneration/KAT/pqc_kat_rng_internal.h"
#include "Util/Core/secure_zero.h"
#include "Backend/slh_dsa.h"

static const slh_param_t *slh_dsa_parameters(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_SLH_DSA_SHA2_128S: return &slh_dsa_sha2_128s;
        case LIBERAC_ALG_SLH_DSA_SHA2_128F: return &slh_dsa_sha2_128f;
        case LIBERAC_ALG_SLH_DSA_SHA2_192S: return &slh_dsa_sha2_192s;
        case LIBERAC_ALG_SLH_DSA_SHA2_192F: return &slh_dsa_sha2_192f;
        case LIBERAC_ALG_SLH_DSA_SHA2_256S: return &slh_dsa_sha2_256s;
        case LIBERAC_ALG_SLH_DSA_SHA2_256F: return &slh_dsa_sha2_256f;
        case LIBERAC_ALG_SLH_DSA_SHAKE_128S: return &slh_dsa_shake_128s;
        case LIBERAC_ALG_SLH_DSA_SHAKE_128F: return &slh_dsa_shake_128f;
        case LIBERAC_ALG_SLH_DSA_SHAKE_192S: return &slh_dsa_shake_192s;
        case LIBERAC_ALG_SLH_DSA_SHAKE_192F: return &slh_dsa_shake_192f;
        case LIBERAC_ALG_SLH_DSA_SHAKE_256S: return &slh_dsa_shake_256s;
        case LIBERAC_ALG_SLH_DSA_SHAKE_256F: return &slh_dsa_shake_256f;
        default: return NULL;
    }
}

size_t crypto_slh_dsa_public_key_size_internal(LiberaCAlgID ALG) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    return prm ? slh_pk_sz(prm) : 0u;
}

size_t crypto_slh_dsa_private_key_size_internal(LiberaCAlgID ALG) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    return prm ? slh_sk_sz(prm) : 0u;
}

size_t crypto_slh_dsa_signature_size_internal(LiberaCAlgID ALG) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    return prm ? slh_sig_sz(prm) : 0u;
}

LiberaCError crypto_slh_dsa_keygen_seeded_internal(
                           LiberaCAlgID ALG,
                           const uint8_t *SEED, size_t SEED_LENGTH,
                           uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
                           uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    size_t pk_length, sk_length, n;
    int rc;

    if (!prm) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!SEED || !PUBLIC_KEY || !PRIVATE_KEY)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    pk_length = slh_pk_sz(prm);
    sk_length = slh_sk_sz(prm);
    if (PUBLIC_KEY_LENGTH < pk_length || PRIVATE_KEY_LENGTH < sk_length)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    n = pk_length / 2u;
    if (SEED_LENGTH != 3u * n) return LIBERAC_ERROR_INVALID_ARGUMENT;

    rc = slh_keygen_internal(PRIVATE_KEY, PUBLIC_KEY,
                             SEED, SEED + n, SEED + 2u * n, prm);
    if (rc != 0) {
        crypto_zeroize(PUBLIC_KEY, pk_length);
        crypto_zeroize(PRIVATE_KEY, sk_length);
        return LIBERAC_ERROR_INTERNAL;
    }
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_slh_dsa_keygen_internal(LiberaCAlgID ALG,
                           uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
                           uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    uint8_t seed[96];
    size_t pk_length, sk_length, n;
    LiberaCError err;

    if (!prm) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!PUBLIC_KEY || !PRIVATE_KEY) return LIBERAC_ERROR_INVALID_ARGUMENT;
    pk_length = slh_pk_sz(prm);
    sk_length = slh_sk_sz(prm);
    if (PUBLIC_KEY_LENGTH < pk_length || PRIVATE_KEY_LENGTH < sk_length)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    n = pk_length / 2u;

    err = crypto_pqc_random_bytes_internal(seed, 3u * n);
    if (err == LIBERAC_SUCCESS) {
        err = crypto_slh_dsa_keygen_seeded_internal(
            ALG, seed, 3u * n, PUBLIC_KEY, PUBLIC_KEY_LENGTH,
            PRIVATE_KEY, PRIVATE_KEY_LENGTH);
    } else {
        crypto_zeroize(PUBLIC_KEY, pk_length);
        crypto_zeroize(PRIVATE_KEY, sk_length);
    }
    crypto_zeroize(seed, sizeof(seed));
    return err;
}

LiberaCError crypto_slh_dsa_sign_seeded_internal(
                         LiberaCAlgID ALG,
                         const uint8_t *RANDOMNESS, size_t RANDOMNESS_LENGTH,
                         const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
                         const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
                         const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
                         uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    size_t sk_length, sig_length, n, written;

    if (!prm) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!RANDOMNESS || !PRIVATE_KEY || (!MESSAGE && MESSAGE_LENGTH) ||
        (!CONTEXT && CONTEXT_LENGTH) || !SIGNATURE)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (CONTEXT_LENGTH > LIBERAC_SIGNATURE_CONTEXT_MAX_BYTES) return LIBERAC_ERROR_INVALID_ARGUMENT;
    sk_length = slh_sk_sz(prm);
    sig_length = slh_sig_sz(prm);
    if (PRIVATE_KEY_LENGTH != sk_length) return LIBERAC_ERROR_INVALID_KEY;
    if (SIGNATURE_LENGTH < sig_length) return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    n = slh_pk_sz(prm) / 2u;
    if (RANDOMNESS_LENGTH != n) return LIBERAC_ERROR_INVALID_ARGUMENT;

    written = slh_sign(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                       CONTEXT, CONTEXT_LENGTH, PRIVATE_KEY, RANDOMNESS, prm);
    if (written != sig_length) {
        crypto_zeroize(SIGNATURE, sig_length);
        return LIBERAC_ERROR_INTERNAL;
    }
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_slh_dsa_sign_internal(LiberaCAlgID ALG,
                         const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
                         const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
                         const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
                         uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    uint8_t addrnd[32];
    size_t sk_length, sig_length, n;
    LiberaCError err;

    if (!prm) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!PRIVATE_KEY || (!MESSAGE && MESSAGE_LENGTH) ||
        (!CONTEXT && CONTEXT_LENGTH) || !SIGNATURE)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (CONTEXT_LENGTH > LIBERAC_SIGNATURE_CONTEXT_MAX_BYTES)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    sk_length = slh_sk_sz(prm);
    sig_length = slh_sig_sz(prm);
    if (PRIVATE_KEY_LENGTH != sk_length) return LIBERAC_ERROR_INVALID_KEY;
    if (SIGNATURE_LENGTH < sig_length) return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    n = slh_pk_sz(prm) / 2u;

    err = crypto_pqc_random_bytes_internal(addrnd, n);
    if (err == LIBERAC_SUCCESS) {
        err = crypto_slh_dsa_sign_seeded_internal(
            ALG, addrnd, n, PRIVATE_KEY, PRIVATE_KEY_LENGTH,
            MESSAGE, MESSAGE_LENGTH, CONTEXT, CONTEXT_LENGTH,
            SIGNATURE, SIGNATURE_LENGTH);
    } else {
        crypto_zeroize(SIGNATURE, sig_length);
    }
    crypto_zeroize(addrnd, sizeof(addrnd));
    return err;
}

LiberaCError crypto_slh_dsa_verify_internal(LiberaCAlgID ALG,
                           const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
                           const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
                           const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
                           const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    size_t pk_length, sig_length;

    if (!prm) return LIBERAC_ERROR_INVALID_ALG_ID;
    if (!PUBLIC_KEY || (!MESSAGE && MESSAGE_LENGTH) || (!CONTEXT && CONTEXT_LENGTH) || !SIGNATURE)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (CONTEXT_LENGTH > LIBERAC_SIGNATURE_CONTEXT_MAX_BYTES) return LIBERAC_ERROR_INVALID_ARGUMENT;
    pk_length = slh_pk_sz(prm);
    sig_length = slh_sig_sz(prm);
    if (PUBLIC_KEY_LENGTH != pk_length) return LIBERAC_ERROR_INVALID_KEY;
    if (SIGNATURE_LENGTH != sig_length) return LIBERAC_ERROR_SIGNATURE_INVALID;

    return slh_verify(MESSAGE, MESSAGE_LENGTH, SIGNATURE, SIGNATURE_LENGTH,
                      CONTEXT, CONTEXT_LENGTH, PUBLIC_KEY, prm)
               ? LIBERAC_SUCCESS
               : LIBERAC_ERROR_SIGNATURE_INVALID;
}
