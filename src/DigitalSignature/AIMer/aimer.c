/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "aimer_internal.h"
#include "aimer_params.h"
#include "Backend/aimer_backend.h"
#include "RandomNumberGeneration/KAT/pqc_kat_rng_internal.h"
#include "Util/Core/secure_zero.h"

#include <string.h>

#define CRYPTO_AIMER_PARAMETER_ENTRY(alg_id, pk, sk, sig, bits, bytes, boxes, tau, n, logn, prefix) \
    { (alg_id), (pk), (sk), (sig), (bits), (bytes), (bits), (bytes), \
      (bytes) / 8u, (bytes), (boxes), (bytes), (bytes), 2u * (bytes), \
      (boxes), (tau), (n), (logn), (prefix) },

static const crypto_aimer_params crypto_aimer_parameter_table[] = {
    CRYPTO_AIMER_PARAMETER_LIST(CRYPTO_AIMER_PARAMETER_ENTRY)
};

#undef CRYPTO_AIMER_PARAMETER_ENTRY

static const crypto_aimer_params *crypto_aimer_get_params(AlgID alg) {
    size_t i;
    for (i = 0u;
         i < sizeof(crypto_aimer_parameter_table) /
                 sizeof(crypto_aimer_parameter_table[0]);
         ++i) {
        if (crypto_aimer_parameter_table[i].alg == alg) {
            return &crypto_aimer_parameter_table[i];
        }
    }
    return NULL;
}

size_t crypto_aimer_public_key_size_internal(AlgID alg) {
    const crypto_aimer_params *params = crypto_aimer_get_params(alg);
    return params ? params->public_key_bytes : 0u;
}

size_t crypto_aimer_private_key_size_internal(AlgID alg) {
    const crypto_aimer_params *params = crypto_aimer_get_params(alg);
    return params ? params->private_key_bytes : 0u;
}

size_t crypto_aimer_signature_size_internal(AlgID alg) {
    const crypto_aimer_params *params = crypto_aimer_get_params(alg);
    return params ? params->signature_bytes : 0u;
}

CryptoError crypto_aimer_keygen_internal(
    AlgID alg,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length) {
    const crypto_aimer_params *params = crypto_aimer_get_params(alg);
    uint8_t plaintext[CRYPTO_AIMER_MAX_FIELD_BYTES];
    uint8_t iv[CRYPTO_AIMER_MAX_FIELD_BYTES];
    CryptoError error;

    if (!params) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!public_key || !private_key) return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (public_key_length < params->public_key_bytes ||
        private_key_length < params->private_key_bytes) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    error = crypto_pqc_random_bytes_internal(plaintext, params->field_bytes);
    if (error == CRYPTO_SUCCESS) {
        /* This second request is intentionally separate for NIST KAT replay. */
        error = crypto_pqc_random_bytes_internal(iv, params->iv_bytes);
    }
    if (error == CRYPTO_SUCCESS) {
        error = crypto_aimer_backend_keypair(
            public_key, private_key, plaintext, iv, params);
    }
    if (error != CRYPTO_SUCCESS) {
        crypto_zeroize(public_key, params->public_key_bytes);
        crypto_zeroize(private_key, params->private_key_bytes);
    }
    crypto_zeroize(plaintext, sizeof(plaintext));
    crypto_zeroize(iv, sizeof(iv));
    return error;
}

CryptoError crypto_aimer_sign_internal(
    AlgID alg,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_length) {
    const crypto_aimer_params *params = crypto_aimer_get_params(alg);
    uint8_t prefix[CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES + 1u];
    uint8_t randomness[CRYPTO_AIMER_MAX_SECURITY_BYTES];
    CryptoError error;

    if (!params) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!private_key || (!message && message_length != 0u) ||
        (!context && context_length != 0u) || !signature) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    if (context_length > CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    if (private_key_length != params->private_key_bytes) {
        return CRYPTO_ERROR_INVALID_KEY;
    }
    if (signature_length < params->signature_bytes) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    prefix[0] = (uint8_t)context_length;
    if (context_length != 0u) {
        memcpy(prefix + 1u, context, context_length);
    }

    error = crypto_pqc_random_bytes_internal(
        randomness, params->security_bytes);
    if (error == CRYPTO_SUCCESS) {
        error = crypto_aimer_backend_sign(
            signature, message, message_length, prefix, context_length + 1u,
            randomness, private_key, params);
    }
    if (error != CRYPTO_SUCCESS) {
        crypto_zeroize(signature, params->signature_bytes);
    }
    crypto_zeroize(prefix, sizeof(prefix));
    crypto_zeroize(randomness, sizeof(randomness));
    return error;
}

CryptoError crypto_aimer_verify_internal(
    AlgID alg,
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length) {
    const crypto_aimer_params *params = crypto_aimer_get_params(alg);
    uint8_t prefix[CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES + 1u];
    CryptoError error;

    if (!params) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!public_key || (!message && message_length != 0u) ||
        (!context && context_length != 0u) || !signature) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    if (context_length > CRYPTO_SIGNATURE_CONTEXT_MAX_BYTES) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    if (public_key_length != params->public_key_bytes) {
        return CRYPTO_ERROR_INVALID_KEY;
    }
    if (signature_length != params->signature_bytes) {
        return CRYPTO_ERROR_SIGNATURE_INVALID;
    }

    prefix[0] = (uint8_t)context_length;
    if (context_length != 0u) {
        memcpy(prefix + 1u, context, context_length);
    }
    error = crypto_aimer_backend_verify(
        signature, signature_length, message, message_length,
        prefix, context_length + 1u, public_key, params);
    crypto_zeroize(prefix, sizeof(prefix));
    return error;
}
