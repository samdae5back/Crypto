/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "ml_dsa_internal.h"
#include "RandomNumberGeneration/Noise/random_internal.h"
#include "Util/Core/secure_zero.h"
#include "mldsa_native_all.h"

#include <string.h>

#define ML_DSA_SEED_BYTES 32u
#define ML_DSA_RANDOM_BYTES 32u

_Static_assert(ML_DSA_44_PUBLIC_KEY_BYTES == CRYPTO_ML_DSA_44_PUBLIC_KEY_BYTES, "ML-DSA-44 public-key size mismatch");
_Static_assert(ML_DSA_44_PRIVATE_KEY_BYTES == CRYPTO_ML_DSA_44_PRIVATE_KEY_BYTES, "ML-DSA-44 private-key size mismatch");
_Static_assert(ML_DSA_44_SIGNATURE_BYTES == CRYPTO_ML_DSA_44_SIGNATURE_BYTES, "ML-DSA-44 signature size mismatch");
_Static_assert(ML_DSA_65_PUBLIC_KEY_BYTES == CRYPTO_ML_DSA_65_PUBLIC_KEY_BYTES, "ML-DSA-65 public-key size mismatch");
_Static_assert(ML_DSA_65_PRIVATE_KEY_BYTES == CRYPTO_ML_DSA_65_PRIVATE_KEY_BYTES, "ML-DSA-65 private-key size mismatch");
_Static_assert(ML_DSA_65_SIGNATURE_BYTES == CRYPTO_ML_DSA_65_SIGNATURE_BYTES, "ML-DSA-65 signature size mismatch");
_Static_assert(ML_DSA_87_PUBLIC_KEY_BYTES == CRYPTO_ML_DSA_87_PUBLIC_KEY_BYTES, "ML-DSA-87 public-key size mismatch");
_Static_assert(ML_DSA_87_PRIVATE_KEY_BYTES == CRYPTO_ML_DSA_87_PRIVATE_KEY_BYTES, "ML-DSA-87 private-key size mismatch");
_Static_assert(ML_DSA_87_SIGNATURE_BYTES == CRYPTO_ML_DSA_87_SIGNATURE_BYTES, "ML-DSA-87 signature size mismatch");

static CryptoError ml_dsa_sizes(AlgID alg, size_t *pk, size_t *sk, size_t *sig) {
    switch (alg) {
        case ALG_ML_DSA_44:
            if (pk) *pk = CRYPTO_ML_DSA_44_PUBLIC_KEY_BYTES;
            if (sk) *sk = CRYPTO_ML_DSA_44_PRIVATE_KEY_BYTES;
            if (sig) *sig = CRYPTO_ML_DSA_44_SIGNATURE_BYTES;
            return CRYPTO_SUCCESS;
        case ALG_ML_DSA_65:
            if (pk) *pk = CRYPTO_ML_DSA_65_PUBLIC_KEY_BYTES;
            if (sk) *sk = CRYPTO_ML_DSA_65_PRIVATE_KEY_BYTES;
            if (sig) *sig = CRYPTO_ML_DSA_65_SIGNATURE_BYTES;
            return CRYPTO_SUCCESS;
        case ALG_ML_DSA_87:
            if (pk) *pk = CRYPTO_ML_DSA_87_PUBLIC_KEY_BYTES;
            if (sk) *sk = CRYPTO_ML_DSA_87_PRIVATE_KEY_BYTES;
            if (sig) *sig = CRYPTO_ML_DSA_87_SIGNATURE_BYTES;
            return CRYPTO_SUCCESS;
        default:
            return CRYPTO_ERROR_INVALID_ALG_ID;
    }
}

static CryptoError ml_dsa_backend_error(int rc) {
    if (rc == 0) return CRYPTO_SUCCESS;
    if (rc == -2) return CRYPTO_ERROR_ALLOCATION_FAILED;
    if (rc == -7) return CRYPTO_ERROR_INVALID_KEY;
    if (rc == -9) return CRYPTO_ERROR_INVALID_ARGUMENT;
    return CRYPTO_ERROR_INTERNAL;
}

size_t crypto_ml_dsa_public_key_size_internal(AlgID ALG) {
    size_t value = 0u;
    return ml_dsa_sizes(ALG, &value, NULL, NULL) == CRYPTO_SUCCESS ? value : 0u;
}

size_t crypto_ml_dsa_private_key_size_internal(AlgID ALG) {
    size_t value = 0u;
    return ml_dsa_sizes(ALG, NULL, &value, NULL) == CRYPTO_SUCCESS ? value : 0u;
}

size_t crypto_ml_dsa_signature_size_internal(AlgID ALG) {
    size_t value = 0u;
    return ml_dsa_sizes(ALG, NULL, NULL, &value) == CRYPTO_SUCCESS ? value : 0u;
}

CryptoError crypto_ml_dsa_keygen_internal(AlgID ALG,
                          uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
                          uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH) {
    uint8_t seed[ML_DSA_SEED_BYTES];
    size_t pk_length, sk_length;
    CryptoError err;
    int rc = -1;

    if (!PUBLIC_KEY || !PRIVATE_KEY) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ml_dsa_sizes(ALG, &pk_length, &sk_length, NULL);
    if (err != CRYPTO_SUCCESS) return err;
    if (PUBLIC_KEY_LENGTH < pk_length || PRIVATE_KEY_LENGTH < sk_length)
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;

    err = crypto_random_bytes_internal(seed, sizeof(seed));
    if (err != CRYPTO_SUCCESS) {
        crypto_zeroize(PUBLIC_KEY, pk_length);
        crypto_zeroize(PRIVATE_KEY, sk_length);
        crypto_zeroize(seed, sizeof(seed));
        return err;
    }

    switch (ALG) {
        case ALG_ML_DSA_44: rc = mldsa44_keypair_internal(PUBLIC_KEY, PRIVATE_KEY, seed); break;
        case ALG_ML_DSA_65: rc = mldsa65_keypair_internal(PUBLIC_KEY, PRIVATE_KEY, seed); break;
        case ALG_ML_DSA_87: rc = mldsa87_keypair_internal(PUBLIC_KEY, PRIVATE_KEY, seed); break;
        default: rc = -9; break;
    }
    crypto_zeroize(seed, sizeof(seed));
    err = ml_dsa_backend_error(rc);
    if (err != CRYPTO_SUCCESS) {
        crypto_zeroize(PUBLIC_KEY, pk_length);
        crypto_zeroize(PRIVATE_KEY, sk_length);
    }
    return err;
}

CryptoError crypto_ml_dsa_sign_internal(AlgID ALG,
                        const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
                        const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
                        const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
                        uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH) {
    uint8_t rnd[ML_DSA_RANDOM_BYTES];
    uint8_t prefix[MLD_DOMAIN_SEPARATION_MAX_BYTES];
    size_t sk_length, sig_length, prefix_length = 0u;
    CryptoError err;
    int rc = -1;

    if (!PRIVATE_KEY || (!MESSAGE && MESSAGE_LENGTH) || (!CONTEXT && CONTEXT_LENGTH) || !SIGNATURE)
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (CONTEXT_LENGTH > CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ml_dsa_sizes(ALG, NULL, &sk_length, &sig_length);
    if (err != CRYPTO_SUCCESS) return err;
    if (PRIVATE_KEY_LENGTH != sk_length) return CRYPTO_ERROR_INVALID_KEY;
    if (SIGNATURE_LENGTH < sig_length) return CRYPTO_ERROR_BUFFER_TOO_SMALL;

    err = crypto_random_bytes_internal(rnd, sizeof(rnd));
    if (err != CRYPTO_SUCCESS) {
        crypto_zeroize(SIGNATURE, sig_length);
        crypto_zeroize(rnd, sizeof(rnd));
        return err;
    }

    switch (ALG) {
        case ALG_ML_DSA_44:
            prefix_length = mldsa44_prepare_domain_separation_prefix(
                prefix, NULL, 0u, CONTEXT, CONTEXT_LENGTH, MLD_PREHASH_NONE);
            if (prefix_length != 0u)
                rc = mldsa44_signature_internal(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                                prefix, prefix_length, rnd, PRIVATE_KEY, 0);
            break;
        case ALG_ML_DSA_65:
            prefix_length = mldsa65_prepare_domain_separation_prefix(
                prefix, NULL, 0u, CONTEXT, CONTEXT_LENGTH, MLD_PREHASH_NONE);
            if (prefix_length != 0u)
                rc = mldsa65_signature_internal(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                                prefix, prefix_length, rnd, PRIVATE_KEY, 0);
            break;
        case ALG_ML_DSA_87:
            prefix_length = mldsa87_prepare_domain_separation_prefix(
                prefix, NULL, 0u, CONTEXT, CONTEXT_LENGTH, MLD_PREHASH_NONE);
            if (prefix_length != 0u)
                rc = mldsa87_signature_internal(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                                prefix, prefix_length, rnd, PRIVATE_KEY, 0);
            break;
        default:
            rc = -9;
            break;
    }

    crypto_zeroize(prefix, sizeof(prefix));
    crypto_zeroize(rnd, sizeof(rnd));
    if (prefix_length == 0u) err = CRYPTO_ERROR_INVALID_ARGUMENT;
    else err = ml_dsa_backend_error(rc);
    if (err != CRYPTO_SUCCESS) crypto_zeroize(SIGNATURE, sig_length);
    return err;
}

CryptoError crypto_ml_dsa_verify_internal(AlgID ALG,
                          const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
                          const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
                          const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
                          const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH) {
    size_t pk_length, sig_length;
    CryptoError err;
    int rc;

    if (!PUBLIC_KEY || (!MESSAGE && MESSAGE_LENGTH) || (!CONTEXT && CONTEXT_LENGTH) || !SIGNATURE)
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (CONTEXT_LENGTH > CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES) return CRYPTO_ERROR_INVALID_ARGUMENT;
    err = ml_dsa_sizes(ALG, &pk_length, NULL, &sig_length);
    if (err != CRYPTO_SUCCESS) return err;
    if (PUBLIC_KEY_LENGTH != pk_length) return CRYPTO_ERROR_INVALID_KEY;
    if (SIGNATURE_LENGTH != sig_length) return CRYPTO_ERROR_SIGNATURE_INVALID;

    switch (ALG) {
        case ALG_ML_DSA_44:
            rc = mldsa44_verify(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                CONTEXT, CONTEXT_LENGTH, PUBLIC_KEY);
            break;
        case ALG_ML_DSA_65:
            rc = mldsa65_verify(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                CONTEXT, CONTEXT_LENGTH, PUBLIC_KEY);
            break;
        case ALG_ML_DSA_87:
            rc = mldsa87_verify(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                                CONTEXT, CONTEXT_LENGTH, PUBLIC_KEY);
            break;
        default:
            return CRYPTO_ERROR_INVALID_ALG_ID;
    }
    return rc == 0 ? CRYPTO_SUCCESS : CRYPTO_ERROR_SIGNATURE_INVALID;
}
