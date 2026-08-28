/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "ml_dsa_internal.h"
#include "RandomNumberGeneration/KAT/pqc_kat_rng_internal.h"
#include "Util/Core/secure_zero.h"
#include "mldsa_native_all.h"

#include <string.h>

#define ML_DSA_SEED_BYTES 32u
#define ML_DSA_RANDOM_BYTES 32u

_Static_assert(ML_DSA_44_PUBLIC_KEY_BYTES == LIBERAC_ML_DSA_44_PUBLIC_KEY_BYTES, "ML-DSA-44 public-key size mismatch");
_Static_assert(ML_DSA_44_PRIVATE_KEY_BYTES == LIBERAC_ML_DSA_44_PRIVATE_KEY_BYTES, "ML-DSA-44 private-key size mismatch");
_Static_assert(ML_DSA_44_SIGNATURE_BYTES == LIBERAC_ML_DSA_44_SIGNATURE_BYTES, "ML-DSA-44 signature size mismatch");
_Static_assert(ML_DSA_65_PUBLIC_KEY_BYTES == LIBERAC_ML_DSA_65_PUBLIC_KEY_BYTES, "ML-DSA-65 public-key size mismatch");
_Static_assert(ML_DSA_65_PRIVATE_KEY_BYTES == LIBERAC_ML_DSA_65_PRIVATE_KEY_BYTES, "ML-DSA-65 private-key size mismatch");
_Static_assert(ML_DSA_65_SIGNATURE_BYTES == LIBERAC_ML_DSA_65_SIGNATURE_BYTES, "ML-DSA-65 signature size mismatch");
_Static_assert(ML_DSA_87_PUBLIC_KEY_BYTES == LIBERAC_ML_DSA_87_PUBLIC_KEY_BYTES, "ML-DSA-87 public-key size mismatch");
_Static_assert(ML_DSA_87_PRIVATE_KEY_BYTES == LIBERAC_ML_DSA_87_PRIVATE_KEY_BYTES, "ML-DSA-87 private-key size mismatch");
_Static_assert(ML_DSA_87_SIGNATURE_BYTES == LIBERAC_ML_DSA_87_SIGNATURE_BYTES, "ML-DSA-87 signature size mismatch");

static LiberaCError ml_dsa_sizes(LiberaCAlgID alg, size_t *pk, size_t *sk, size_t *sig) {
    switch (alg) {
        case LIBERAC_ALG_ML_DSA_44:
            if (pk) *pk = LIBERAC_ML_DSA_44_PUBLIC_KEY_BYTES;
            if (sk) *sk = LIBERAC_ML_DSA_44_PRIVATE_KEY_BYTES;
            if (sig) *sig = LIBERAC_ML_DSA_44_SIGNATURE_BYTES;
            return LIBERAC_SUCCESS;
        case LIBERAC_ALG_ML_DSA_65:
            if (pk) *pk = LIBERAC_ML_DSA_65_PUBLIC_KEY_BYTES;
            if (sk) *sk = LIBERAC_ML_DSA_65_PRIVATE_KEY_BYTES;
            if (sig) *sig = LIBERAC_ML_DSA_65_SIGNATURE_BYTES;
            return LIBERAC_SUCCESS;
        case LIBERAC_ALG_ML_DSA_87:
            if (pk) *pk = LIBERAC_ML_DSA_87_PUBLIC_KEY_BYTES;
            if (sk) *sk = LIBERAC_ML_DSA_87_PRIVATE_KEY_BYTES;
            if (sig) *sig = LIBERAC_ML_DSA_87_SIGNATURE_BYTES;
            return LIBERAC_SUCCESS;
        default:
            return LIBERAC_ERROR_INVALID_ALG_ID;
    }
}

static LiberaCError ml_dsa_backend_error(int rc) {
    if (rc == 0) return LIBERAC_SUCCESS;
    if (rc == -2) return LIBERAC_ERROR_ALLOCATION_FAILED;
    if (rc == -7) return LIBERAC_ERROR_INVALID_KEY;
    if (rc == -9) return LIBERAC_ERROR_INVALID_ARGUMENT;
    return LIBERAC_ERROR_INTERNAL;
}

size_t crypto_ml_dsa_public_key_size_internal(LiberaCAlgID ALG) {
    size_t value = 0u;
    return ml_dsa_sizes(ALG, &value, NULL, NULL) == LIBERAC_SUCCESS ? value : 0u;
}

size_t crypto_ml_dsa_private_key_size_internal(LiberaCAlgID ALG) {
    size_t value = 0u;
    return ml_dsa_sizes(ALG, NULL, &value, NULL) == LIBERAC_SUCCESS ? value : 0u;
}

size_t crypto_ml_dsa_signature_size_internal(LiberaCAlgID ALG) {
    size_t value = 0u;
    return ml_dsa_sizes(ALG, NULL, NULL, &value) == LIBERAC_SUCCESS ? value : 0u;
}

LiberaCError crypto_ml_dsa_keygen_seeded_internal(
                          LiberaCAlgID ALG, const uint8_t SEED[ML_DSA_SEED_BYTES],
                          uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
                          uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH) {
    size_t pk_length, sk_length;
    LiberaCError err;
    int rc = -1;

    if (!SEED || !PUBLIC_KEY || !PRIVATE_KEY)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    err = ml_dsa_sizes(ALG, &pk_length, &sk_length, NULL);
    if (err != LIBERAC_SUCCESS) return err;
    if (PUBLIC_KEY_LENGTH < pk_length || PRIVATE_KEY_LENGTH < sk_length)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;

    switch (ALG) {
        case LIBERAC_ALG_ML_DSA_44: rc = mldsa44_keypair_internal(PUBLIC_KEY, PRIVATE_KEY, SEED); break;
        case LIBERAC_ALG_ML_DSA_65: rc = mldsa65_keypair_internal(PUBLIC_KEY, PRIVATE_KEY, SEED); break;
        case LIBERAC_ALG_ML_DSA_87: rc = mldsa87_keypair_internal(PUBLIC_KEY, PRIVATE_KEY, SEED); break;
        default: rc = -9; break;
    }
    err = ml_dsa_backend_error(rc);
    if (err != LIBERAC_SUCCESS) {
        crypto_zeroize(PUBLIC_KEY, pk_length);
        crypto_zeroize(PRIVATE_KEY, sk_length);
    }
    return err;
}

LiberaCError crypto_ml_dsa_keygen_internal(LiberaCAlgID ALG,
                          uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
                          uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH) {
    uint8_t seed[ML_DSA_SEED_BYTES];
    size_t pk_length, sk_length;
    LiberaCError err;

    if (!PUBLIC_KEY || !PRIVATE_KEY) return LIBERAC_ERROR_INVALID_ARGUMENT;
    err = ml_dsa_sizes(ALG, &pk_length, &sk_length, NULL);
    if (err != LIBERAC_SUCCESS) return err;
    if (PUBLIC_KEY_LENGTH < pk_length || PRIVATE_KEY_LENGTH < sk_length)
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;

    err = crypto_pqc_random_bytes_internal(seed, sizeof(seed));
    if (err == LIBERAC_SUCCESS) {
        err = crypto_ml_dsa_keygen_seeded_internal(
            ALG, seed, PUBLIC_KEY, PUBLIC_KEY_LENGTH,
            PRIVATE_KEY, PRIVATE_KEY_LENGTH);
    } else {
        crypto_zeroize(PUBLIC_KEY, pk_length);
        crypto_zeroize(PRIVATE_KEY, sk_length);
    }
    crypto_zeroize(seed, sizeof(seed));
    return err;
}

LiberaCError crypto_ml_dsa_sign_seeded_internal(
                        LiberaCAlgID ALG,
                        const uint8_t RANDOMNESS[ML_DSA_RANDOM_BYTES],
                        const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
                        const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
                        const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
                        uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH) {
    uint8_t prefix[MLD_DOMAIN_SEPARATION_MAX_BYTES];
    size_t sk_length, sig_length, prefix_length = 0u;
    LiberaCError err;
    int rc = -1;

    if (!RANDOMNESS || !PRIVATE_KEY || (!MESSAGE && MESSAGE_LENGTH) ||
        (!CONTEXT && CONTEXT_LENGTH) || !SIGNATURE)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (CONTEXT_LENGTH > LIBERAC_SIGNATURE_CONTEXT_MAX_BYTES) return LIBERAC_ERROR_INVALID_ARGUMENT;
    err = ml_dsa_sizes(ALG, NULL, &sk_length, &sig_length);
    if (err != LIBERAC_SUCCESS) return err;
    if (PRIVATE_KEY_LENGTH != sk_length) return LIBERAC_ERROR_INVALID_KEY;
    if (SIGNATURE_LENGTH < sig_length) return LIBERAC_ERROR_BUFFER_TOO_SMALL;

    switch (ALG) {
        case LIBERAC_ALG_ML_DSA_44:
            prefix_length = mldsa44_prepare_domain_separation_prefix(
                prefix, NULL, 0u, CONTEXT, CONTEXT_LENGTH, MLD_PREHASH_NONE);
            if (prefix_length != 0u)
                rc = mldsa44_signature_internal(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                                prefix, prefix_length, RANDOMNESS, PRIVATE_KEY, 0);
            break;
        case LIBERAC_ALG_ML_DSA_65:
            prefix_length = mldsa65_prepare_domain_separation_prefix(
                prefix, NULL, 0u, CONTEXT, CONTEXT_LENGTH, MLD_PREHASH_NONE);
            if (prefix_length != 0u)
                rc = mldsa65_signature_internal(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                                prefix, prefix_length, RANDOMNESS, PRIVATE_KEY, 0);
            break;
        case LIBERAC_ALG_ML_DSA_87:
            prefix_length = mldsa87_prepare_domain_separation_prefix(
                prefix, NULL, 0u, CONTEXT, CONTEXT_LENGTH, MLD_PREHASH_NONE);
            if (prefix_length != 0u)
                rc = mldsa87_signature_internal(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                                prefix, prefix_length, RANDOMNESS, PRIVATE_KEY, 0);
            break;
        default:
            rc = -9;
            break;
    }

    crypto_zeroize(prefix, sizeof(prefix));
    if (prefix_length == 0u) err = LIBERAC_ERROR_INVALID_ARGUMENT;
    else err = ml_dsa_backend_error(rc);
    if (err != LIBERAC_SUCCESS) crypto_zeroize(SIGNATURE, sig_length);
    return err;
}

LiberaCError crypto_ml_dsa_sign_internal(LiberaCAlgID ALG,
                        const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
                        const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
                        const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
                        uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH) {
    uint8_t rnd[ML_DSA_RANDOM_BYTES];
    size_t sk_length, sig_length;
    LiberaCError err;

    if (!PRIVATE_KEY || (!MESSAGE && MESSAGE_LENGTH) ||
        (!CONTEXT && CONTEXT_LENGTH) || !SIGNATURE)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (CONTEXT_LENGTH > LIBERAC_SIGNATURE_CONTEXT_MAX_BYTES)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    err = ml_dsa_sizes(ALG, NULL, &sk_length, &sig_length);
    if (err != LIBERAC_SUCCESS) return err;
    if (PRIVATE_KEY_LENGTH != sk_length) return LIBERAC_ERROR_INVALID_KEY;
    if (SIGNATURE_LENGTH < sig_length) return LIBERAC_ERROR_BUFFER_TOO_SMALL;

    err = crypto_pqc_random_bytes_internal(rnd, sizeof(rnd));
    if (err == LIBERAC_SUCCESS) {
        err = crypto_ml_dsa_sign_seeded_internal(
            ALG, rnd, PRIVATE_KEY, PRIVATE_KEY_LENGTH,
            MESSAGE, MESSAGE_LENGTH, CONTEXT, CONTEXT_LENGTH,
            SIGNATURE, SIGNATURE_LENGTH);
    } else {
        crypto_zeroize(SIGNATURE, sig_length);
    }
    crypto_zeroize(rnd, sizeof(rnd));
    return err;
}

LiberaCError crypto_ml_dsa_verify_internal(LiberaCAlgID ALG,
                          const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
                          const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
                          const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
                          const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH) {
    size_t pk_length, sig_length;
    LiberaCError err;
    int rc;

    if (!PUBLIC_KEY || (!MESSAGE && MESSAGE_LENGTH) || (!CONTEXT && CONTEXT_LENGTH) || !SIGNATURE)
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (CONTEXT_LENGTH > LIBERAC_SIGNATURE_CONTEXT_MAX_BYTES) return LIBERAC_ERROR_INVALID_ARGUMENT;
    err = ml_dsa_sizes(ALG, &pk_length, NULL, &sig_length);
    if (err != LIBERAC_SUCCESS) return err;
    if (PUBLIC_KEY_LENGTH != pk_length) return LIBERAC_ERROR_INVALID_KEY;
    if (SIGNATURE_LENGTH != sig_length) return LIBERAC_ERROR_SIGNATURE_INVALID;

    switch (ALG) {
        case LIBERAC_ALG_ML_DSA_44:
            rc = mldsa44_verify(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                CONTEXT, CONTEXT_LENGTH, PUBLIC_KEY);
            break;
        case LIBERAC_ALG_ML_DSA_65:
            rc = mldsa65_verify(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                CONTEXT, CONTEXT_LENGTH, PUBLIC_KEY);
            break;
        case LIBERAC_ALG_ML_DSA_87:
            rc = mldsa87_verify(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                CONTEXT, CONTEXT_LENGTH, PUBLIC_KEY);
            break;
        default:
            return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    return rc == 0 ? LIBERAC_SUCCESS : LIBERAC_ERROR_SIGNATURE_INVALID;
}
