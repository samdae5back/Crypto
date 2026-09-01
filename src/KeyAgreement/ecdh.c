/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "KeyAgreement/key_agreement_internal.h"

#include "RandomNumberGeneration/Noise/random_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/ECC/ecc_internal.h"

#include <string.h>

#define CRYPTO_ECDH_MAX_PRIVATE_BYTES 66u
#define CRYPTO_ECDH_MAX_PUBLIC_BYTES 133u
#define CRYPTO_ECDH_MAX_SHARED_BYTES 66u
#define CRYPTO_ECDH_KEYGEN_ATTEMPTS 128u

static const CryptoEcCurve *ecdh_curve_from_alg(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ECDH_P256:
            return crypto_ec_curve_get(CRYPTO_EC_CURVE_P256);
        case LIBERAC_ALG_ECDH_P384:
            return crypto_ec_curve_get(CRYPTO_EC_CURVE_P384);
        case LIBERAC_ALG_ECDH_P521:
            return crypto_ec_curve_get(CRYPTO_EC_CURVE_P521);
        default:
            return NULL;
    }
}

static size_t ecdh_uncompressed_public_size(const CryptoEcCurve *curve) {
    return 1u + 2u * curve->field_bytes;
}

static int ecdh_peer_public_length_valid(const CryptoEcCurve *curve,
                                         size_t length) {
    return length == 1u + curve->field_bytes ||
           length == ecdh_uncompressed_public_size(curve);
}

static void ecdh_clear_outputs(uint8_t *public_key, size_t public_length,
                               uint8_t *private_key, size_t private_length) {
    if (public_key != NULL) {
        crypto_zeroize(public_key, public_length);
    }
    if (private_key != NULL) {
        crypto_zeroize(private_key, private_length);
    }
}

LiberaCError crypto_ecdh_keygen_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length) {
    const CryptoEcCurve *curve = ecdh_curve_from_alg(alg);
    uint8_t candidate[CRYPTO_ECDH_MAX_PRIVATE_BYTES];
    uint8_t encoded_public[CRYPTO_ECDH_MAX_PUBLIC_BYTES];
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint public_point;
    size_t required_public;
    size_t encoded_length;
    size_t attempt;
    size_t excess_bits;
    LiberaCError error = LIBERAC_SUCCESS;
    int valid_scalar = 0;

    if (curve == NULL) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    required_public = ecdh_uncompressed_public_size(curve);
    if (public_key == NULL || private_key == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (public_key_length < required_public ||
        private_key_length < curve->scalar_bytes) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(public_key, required_public,
                              private_key, curve->scalar_bytes)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_zeroize(candidate, sizeof(candidate));
    crypto_zeroize(encoded_public, sizeof(encoded_public));
    crypto_ec_affine_set_infinity(&generator);
    crypto_ec_affine_set_infinity(&public_point);

    excess_bits = curve->scalar_bytes * 8u - curve->scalar_bits;
    for (attempt = 0u; attempt < CRYPTO_ECDH_KEYGEN_ATTEMPTS; ++attempt) {
        error = crypto_random_bytes_internal(candidate, curve->scalar_bytes);
        if (error != LIBERAC_SUCCESS) {
            break;
        }
        if (excess_bits != 0u) {
            candidate[0] &= (uint8_t)(UINT32_C(0xff) >> excess_bits);
        }
        valid_scalar = crypto_ec_scalar_is_valid_ct(
            curve, candidate, curve->scalar_bytes);
        if (valid_scalar != 0) {
            break;
        }
    }
    if (error == LIBERAC_SUCCESS && valid_scalar == 0) {
        error = LIBERAC_ERROR_RANDOM_FAILED;
    }

    if (error == LIBERAC_SUCCESS) {
        crypto_ec_affine_generator(curve, &generator);
        error = crypto_ec_scalar_multiply_ct(
            curve, &public_point, &generator,
            candidate, curve->scalar_bytes);
    }
    if (error == LIBERAC_SUCCESS) {
        encoded_length = sizeof(encoded_public);
        error = crypto_ec_point_encode(
            curve, &public_point, 0,
            encoded_public, &encoded_length);
        if (error == LIBERAC_SUCCESS && encoded_length != required_public) {
            error = LIBERAC_ERROR_INTERNAL;
        }
    }

    if (error == LIBERAC_SUCCESS) {
        memcpy(private_key, candidate, curve->scalar_bytes);
        memcpy(public_key, encoded_public, required_public);
    } else {
        ecdh_clear_outputs(public_key, required_public,
                           private_key, curve->scalar_bytes);
    }

    crypto_zeroize(candidate, sizeof(candidate));
    crypto_zeroize(encoded_public, sizeof(encoded_public));
    crypto_zeroize(&generator, sizeof(generator));
    crypto_zeroize(&public_point, sizeof(public_point));
    return error;
}

LiberaCError crypto_ecdh_public_from_private_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    const uint8_t *private_key, size_t private_key_length) {
    const CryptoEcCurve *curve = ecdh_curve_from_alg(alg);
    uint8_t encoded_public[CRYPTO_ECDH_MAX_PUBLIC_BYTES];
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint public_point;
    size_t required_public;
    size_t encoded_length;
    LiberaCError error;

    if (curve == NULL) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    required_public = ecdh_uncompressed_public_size(curve);
    if (public_key == NULL || private_key == NULL ||
        private_key_length != curve->scalar_bytes) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (public_key_length < required_public) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(public_key, required_public,
                              private_key, private_key_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_zeroize(encoded_public, sizeof(encoded_public));
    crypto_ec_affine_set_infinity(&generator);
    crypto_ec_affine_set_infinity(&public_point);

    if (!crypto_ec_scalar_is_valid_ct(curve, private_key, private_key_length)) {
        crypto_zeroize(public_key, required_public);
        return LIBERAC_ERROR_INVALID_KEY;
    }

    crypto_ec_affine_generator(curve, &generator);
    error = crypto_ec_scalar_multiply_ct(
        curve, &public_point, &generator,
        private_key, private_key_length);
    if (error == LIBERAC_SUCCESS) {
        encoded_length = sizeof(encoded_public);
        error = crypto_ec_point_encode(
            curve, &public_point, 0,
            encoded_public, &encoded_length);
        if (error == LIBERAC_SUCCESS && encoded_length != required_public) {
            error = LIBERAC_ERROR_INTERNAL;
        }
    }

    if (error == LIBERAC_SUCCESS) {
        memcpy(public_key, encoded_public, required_public);
    } else {
        crypto_zeroize(public_key, required_public);
    }

    crypto_zeroize(encoded_public, sizeof(encoded_public));
    crypto_zeroize(&generator, sizeof(generator));
    crypto_zeroize(&public_point, sizeof(public_point));
    return error;
}

LiberaCError crypto_ecdh_shared_secret_internal(
    LiberaCAlgID alg,
    uint8_t *shared_secret, size_t shared_secret_length,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *peer_public_key, size_t peer_public_key_length) {
    const CryptoEcCurve *curve = ecdh_curve_from_alg(alg);
    uint8_t secret[CRYPTO_ECDH_MAX_SHARED_BYTES];
    CryptoEcAffinePoint peer_point;
    CryptoEcAffinePoint shared_point;
    LiberaCError error;

    if (curve == NULL) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (shared_secret == NULL || private_key == NULL || peer_public_key == NULL ||
        private_key_length != curve->scalar_bytes ||
        !ecdh_peer_public_length_valid(curve, peer_public_key_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (shared_secret_length < curve->field_bytes) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(shared_secret, curve->field_bytes,
                              private_key, private_key_length) ||
        crypto_ranges_overlap(shared_secret, curve->field_bytes,
                              peer_public_key, peer_public_key_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_zeroize(secret, sizeof(secret));
    crypto_ec_affine_set_infinity(&peer_point);
    crypto_ec_affine_set_infinity(&shared_point);

    if (!crypto_ec_scalar_is_valid_ct(curve, private_key, private_key_length)) {
        crypto_zeroize(shared_secret, curve->field_bytes);
        return LIBERAC_ERROR_INVALID_KEY;
    }

    error = crypto_ec_point_decode(
        curve, &peer_point,
        peer_public_key, peer_public_key_length, 0);
    if (error != LIBERAC_SUCCESS) {
        crypto_zeroize(shared_secret, curve->field_bytes);
        crypto_zeroize(&peer_point, sizeof(peer_point));
        return LIBERAC_ERROR_INVALID_KEY;
    }

    error = crypto_ec_scalar_multiply_ct(
        curve, &shared_point, &peer_point,
        private_key, private_key_length);
    if (error == LIBERAC_SUCCESS) {
        if (crypto_ec_affine_is_infinity(&shared_point)) {
            error = LIBERAC_ERROR_INVALID_KEY;
        } else {
            crypto_ec_field_to_bytes(curve, secret, &shared_point.x);
        }
    }

    if (error == LIBERAC_SUCCESS) {
        memcpy(shared_secret, secret, curve->field_bytes);
    } else {
        crypto_zeroize(shared_secret, curve->field_bytes);
    }

    crypto_zeroize(secret, sizeof(secret));
    crypto_zeroize(&peer_point, sizeof(peer_point));
    crypto_zeroize(&shared_point, sizeof(shared_point));
    return error;
}
