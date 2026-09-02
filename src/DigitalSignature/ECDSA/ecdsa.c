/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "DigitalSignature/ECDSA/ecdsa_internal.h"

#include "DigitalSignature.h"
#include "HashFunction.h"
#include "MessageAuthentication.h"
#include "RandomNumberGeneration/Noise/random_internal.h"
#include "Util/Core/memory_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/ECC/ecc_internal.h"

#include <string.h>

#define CRYPTO_ECDSA_MAX_SCALAR_BYTES 66u
#define CRYPTO_ECDSA_MAX_PUBLIC_BYTES 133u
#define CRYPTO_ECDSA_MAX_DIGEST_BYTES 64u
#define CRYPTO_ECDSA_RFC6979_INPUT_BYTES 197u
#define CRYPTO_ECDSA_KEYGEN_ATTEMPTS 128u
#define CRYPTO_ECDSA_RFC6979_CANDIDATES 16u

static const CryptoEcCurve *ecdsa_curve_from_alg(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ECDSA_P256:
            return crypto_ec_curve_get(CRYPTO_EC_CURVE_P256);
        case LIBERAC_ALG_ECDSA_P384:
            return crypto_ec_curve_get(CRYPTO_EC_CURVE_P384);
        case LIBERAC_ALG_ECDSA_P521:
            return crypto_ec_curve_get(CRYPTO_EC_CURVE_P521);
        default:
            return NULL;
    }
}

static size_t ecdsa_public_size(const CryptoEcCurve *curve) {
    return 1u + 2u * curve->field_bytes;
}

static size_t ecdsa_signature_size(const CryptoEcCurve *curve) {
    return 2u * curve->scalar_bytes;
}

static int ecdsa_public_length_valid(const CryptoEcCurve *curve,
                                     size_t public_key_length) {
    return public_key_length == 1u + curve->field_bytes ||
           public_key_length == ecdsa_public_size(curve);
}

static LiberaCError ecdsa_hash_parameters(const CryptoEcCurve *curve,
                                          LiberaCAlgID hash_alg,
                                          size_t *digest_length) {
    size_t selected_length;
    unsigned strength;
    unsigned required_strength;

    switch (hash_alg) {
        case LIBERAC_ALG_HASH_SHA2_256:
        case LIBERAC_ALG_HASH_SHA2_512_256:
        case LIBERAC_ALG_HASH_SHA3_256:
            selected_length = 32u;
            strength = 128u;
            break;
        case LIBERAC_ALG_HASH_SHA2_384:
        case LIBERAC_ALG_HASH_SHA3_384:
            selected_length = 48u;
            strength = 192u;
            break;
        case LIBERAC_ALG_HASH_SHA2_512:
        case LIBERAC_ALG_HASH_SHA3_512:
            selected_length = 64u;
            strength = 256u;
            break;
        default:
            return LIBERAC_ERROR_INVALID_ALG_ID;
    }

    switch (curve->id) {
        case CRYPTO_EC_CURVE_P256:
            required_strength = 128u;
            break;
        case CRYPTO_EC_CURVE_P384:
            required_strength = 192u;
            break;
        case CRYPTO_EC_CURVE_P521:
            required_strength = 256u;
            break;
        default:
            return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (strength < required_strength) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (digest_length != NULL) {
        *digest_length = selected_length;
    }
    return LIBERAC_SUCCESS;
}

static void ecdsa_shift_right_big_endian(uint8_t *value, size_t length,
                                         unsigned shift) {
    uint8_t carry = 0u;
    uint8_t carry_mask;
    size_t index;

    if (shift == 0u) {
        return;
    }
    carry_mask = (uint8_t)((UINT32_C(1) << shift) - 1u);
    for (index = 0u; index < length; ++index) {
        const uint8_t current = value[index];
        value[index] = (uint8_t)(
            ((uint32_t)carry << (8u - shift)) | (current >> shift));
        carry = (uint8_t)(current & carry_mask);
    }
}

static LiberaCError ecdsa_digest_to_scalar(
    const CryptoEcCurve *curve,
    const uint8_t *digest, size_t digest_length,
    CryptoEcScalar *scalar, uint8_t *canonical_octets) {
    uint8_t encoded[CRYPTO_ECDSA_MAX_SCALAR_BYTES];
    const size_t digest_bits = digest_length * 8u;
    const size_t excess_bits = curve->scalar_bytes * 8u - curve->scalar_bits;
    LiberaCError error;

    crypto_zeroize(encoded, sizeof(encoded));
    if (digest_bits > curve->scalar_bits) {
        memcpy(encoded, digest, curve->scalar_bytes);
        if (excess_bits != 0u) {
            ecdsa_shift_right_big_endian(
                encoded, curve->scalar_bytes, (unsigned)excess_bits);
        }
    } else {
        memcpy(encoded + curve->scalar_bytes - digest_length,
               digest, digest_length);
    }

    error = crypto_ec_scalar_from_bytes_reduced(
        curve, scalar, encoded, curve->scalar_bytes);
    if (error == LIBERAC_SUCCESS && canonical_octets != NULL) {
        crypto_ec_scalar_to_bytes(curve, canonical_octets, scalar);
    }
    crypto_zeroize(encoded, sizeof(encoded));
    return error;
}

static LiberaCError ecdsa_hmac(
    LiberaCAlgID hash_alg, size_t digest_length,
    uint8_t *output, const uint8_t *key,
    const uint8_t *message, size_t message_length) {
    return LIBERAC_HMAC(
        output, CRYPTO_ECDSA_MAX_DIGEST_BYTES, digest_length,
        message, message_length, key, digest_length, hash_alg);
}

static LiberaCError ecdsa_rfc6979_initialize(
    const CryptoEcCurve *curve,
    LiberaCAlgID hash_alg, size_t digest_length,
    const uint8_t *private_key,
    const uint8_t *digest,
    uint8_t *key, uint8_t *value) {
    uint8_t digest_octets[CRYPTO_ECDSA_MAX_SCALAR_BYTES];
    uint8_t input[CRYPTO_ECDSA_RFC6979_INPUT_BYTES];
    uint8_t next[CRYPTO_ECDSA_MAX_DIGEST_BYTES];
    CryptoEcScalar digest_scalar;
    size_t input_length;
    LiberaCError error;

    crypto_zeroize(digest_octets, sizeof(digest_octets));
    crypto_zeroize(input, sizeof(input));
    crypto_zeroize(next, sizeof(next));
    crypto_ec_scalar_zero(&digest_scalar);

    error = ecdsa_digest_to_scalar(
        curve, digest, digest_length, &digest_scalar, digest_octets);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }

    memset(key, 0, digest_length);
    memset(value, 1, digest_length);
    input_length = digest_length + 1u + 2u * curve->scalar_bytes;

    memcpy(input, value, digest_length);
    input[digest_length] = 0u;
    memcpy(input + digest_length + 1u,
           private_key, curve->scalar_bytes);
    memcpy(input + digest_length + 1u + curve->scalar_bytes,
           digest_octets, curve->scalar_bytes);
    error = ecdsa_hmac(
        hash_alg, digest_length, next, key, input, input_length);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    memcpy(key, next, digest_length);

    error = ecdsa_hmac(
        hash_alg, digest_length, next, key, value, digest_length);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    memcpy(value, next, digest_length);

    memcpy(input, value, digest_length);
    input[digest_length] = 1u;
    memcpy(input + digest_length + 1u,
           private_key, curve->scalar_bytes);
    memcpy(input + digest_length + 1u + curve->scalar_bytes,
           digest_octets, curve->scalar_bytes);
    error = ecdsa_hmac(
        hash_alg, digest_length, next, key, input, input_length);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    memcpy(key, next, digest_length);

    error = ecdsa_hmac(
        hash_alg, digest_length, next, key, value, digest_length);
    if (error == LIBERAC_SUCCESS) {
        memcpy(value, next, digest_length);
    }

cleanup:
    crypto_zeroize(digest_octets, sizeof(digest_octets));
    crypto_zeroize(input, sizeof(input));
    crypto_zeroize(next, sizeof(next));
    crypto_zeroize(&digest_scalar, sizeof(digest_scalar));
    return error;
}

static LiberaCError ecdsa_rfc6979_rejection_update(
    LiberaCAlgID hash_alg, size_t digest_length,
    uint8_t *key, uint8_t *value) {
    uint8_t input[CRYPTO_ECDSA_MAX_DIGEST_BYTES + 1u];
    uint8_t next[CRYPTO_ECDSA_MAX_DIGEST_BYTES];
    LiberaCError error;

    crypto_zeroize(input, sizeof(input));
    crypto_zeroize(next, sizeof(next));
    memcpy(input, value, digest_length);
    input[digest_length] = 0u;
    error = ecdsa_hmac(
        hash_alg, digest_length, next, key, input, digest_length + 1u);
    if (error == LIBERAC_SUCCESS) {
        memcpy(key, next, digest_length);
        error = ecdsa_hmac(
            hash_alg, digest_length, next, key, value, digest_length);
    }
    if (error == LIBERAC_SUCCESS) {
        memcpy(value, next, digest_length);
    }
    crypto_zeroize(input, sizeof(input));
    crypto_zeroize(next, sizeof(next));
    return error;
}

static LiberaCError ecdsa_rfc6979_generate(
    const CryptoEcCurve *curve,
    LiberaCAlgID hash_alg, size_t digest_length,
    uint8_t *key, uint8_t *value,
    uint8_t *nonce) {
    uint8_t generated[CRYPTO_ECDSA_MAX_SCALAR_BYTES];
    uint8_t candidate[CRYPTO_ECDSA_MAX_SCALAR_BYTES];
    uint8_t next[CRYPTO_ECDSA_MAX_DIGEST_BYTES];
    uint32_t found = 0u;
    size_t attempt;
    LiberaCError error = LIBERAC_SUCCESS;

    crypto_zeroize(generated, sizeof(generated));
    crypto_zeroize(candidate, sizeof(candidate));
    crypto_zeroize(next, sizeof(next));
    crypto_zeroize(nonce, curve->scalar_bytes);

    /*
     * RFC 6979 normally stops at the first in-range candidate. Generate a
     * fixed batch and mask-select that same first candidate so the normal
     * signing schedule does not reveal whether an earlier candidate was
     * rejected. For P-256, the worst supported case, exhausting all sixteen
     * candidates has probability below 2^-512.
     */
    for (attempt = 0u;
         attempt < CRYPTO_ECDSA_RFC6979_CANDIDATES;
         ++attempt) {
        size_t generated_length = 0u;
        uint32_t valid;
        uint32_t select_mask;
        size_t index;

        crypto_zeroize(generated, sizeof(generated));
        while (generated_length < curve->scalar_bytes) {
            size_t take = digest_length;
            error = ecdsa_hmac(
                hash_alg, digest_length, next, key, value, digest_length);
            if (error != LIBERAC_SUCCESS) {
                goto cleanup;
            }
            memcpy(value, next, digest_length);
            if (take > curve->scalar_bytes - generated_length) {
                take = curve->scalar_bytes - generated_length;
            }
            memcpy(generated + generated_length, value, take);
            generated_length += take;
        }

        memcpy(candidate, generated, curve->scalar_bytes);
        if (curve->scalar_bytes * 8u != curve->scalar_bits) {
            ecdsa_shift_right_big_endian(
                candidate, curve->scalar_bytes,
                (unsigned)(curve->scalar_bytes * 8u - curve->scalar_bits));
        }
        valid = (uint32_t)crypto_ec_scalar_is_valid_ct(
            curve, candidate, curve->scalar_bytes);
        select_mask = UINT32_C(0) - (valid & (found ^ 1u));
        for (index = 0u; index < curve->scalar_bytes; ++index) {
            nonce[index] = (uint8_t)(
                (nonce[index] & (uint8_t)~select_mask) |
                (candidate[index] & (uint8_t)select_mask));
        }
        found |= valid;

        error = ecdsa_rfc6979_rejection_update(
            hash_alg, digest_length, key, value);
        if (error != LIBERAC_SUCCESS) {
            goto cleanup;
        }
    }
    if (found == 0u) {
        error = LIBERAC_ERROR_INTERNAL;
    }

cleanup:
    crypto_zeroize(generated, sizeof(generated));
    crypto_zeroize(candidate, sizeof(candidate));
    crypto_zeroize(next, sizeof(next));
    return error;
}

static void ecdsa_clear_keypair_outputs(
    uint8_t *public_key, size_t public_length,
    uint8_t *private_key, size_t private_length) {
    if (public_key != NULL) {
        crypto_zeroize(public_key, public_length);
    }
    if (private_key != NULL) {
        crypto_zeroize(private_key, private_length);
    }
}

size_t crypto_ecdsa_private_key_size_internal(LiberaCAlgID alg) {
    const CryptoEcCurve *curve = ecdsa_curve_from_alg(alg);
    return curve != NULL ? curve->scalar_bytes : 0u;
}

size_t crypto_ecdsa_public_key_size_internal(LiberaCAlgID alg) {
    const CryptoEcCurve *curve = ecdsa_curve_from_alg(alg);
    return curve != NULL ? ecdsa_public_size(curve) : 0u;
}

size_t crypto_ecdsa_signature_size_internal(LiberaCAlgID alg) {
    const CryptoEcCurve *curve = ecdsa_curve_from_alg(alg);
    return curve != NULL ? ecdsa_signature_size(curve) : 0u;
}

LiberaCError crypto_ecdsa_keygen_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length) {
    const CryptoEcCurve *curve = ecdsa_curve_from_alg(alg);
    uint8_t candidate[CRYPTO_ECDSA_MAX_SCALAR_BYTES];
    uint8_t encoded_public[CRYPTO_ECDSA_MAX_PUBLIC_BYTES];
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint public_point;
    size_t required_public;
    size_t encoded_length;
    size_t attempt;
    size_t excess_bits;
    int valid_scalar = 0;
    LiberaCError error = LIBERAC_SUCCESS;

    if (curve == NULL) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    required_public = ecdsa_public_size(curve);
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
    for (attempt = 0u; attempt < CRYPTO_ECDSA_KEYGEN_ATTEMPTS; ++attempt) {
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
            curve, &public_point, 0, encoded_public, &encoded_length);
        if (error == LIBERAC_SUCCESS && encoded_length != required_public) {
            error = LIBERAC_ERROR_INTERNAL;
        }
    }
    if (error == LIBERAC_SUCCESS) {
        memcpy(private_key, candidate, curve->scalar_bytes);
        memcpy(public_key, encoded_public, required_public);
    } else {
        ecdsa_clear_keypair_outputs(
            public_key, required_public, private_key, curve->scalar_bytes);
    }

    crypto_zeroize(candidate, sizeof(candidate));
    crypto_zeroize(encoded_public, sizeof(encoded_public));
    crypto_zeroize(&generator, sizeof(generator));
    crypto_zeroize(&public_point, sizeof(public_point));
    return error;
}

LiberaCError crypto_ecdsa_public_from_private_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    const uint8_t *private_key, size_t private_key_length) {
    const CryptoEcCurve *curve = ecdsa_curve_from_alg(alg);
    uint8_t encoded_public[CRYPTO_ECDSA_MAX_PUBLIC_BYTES];
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint public_point;
    size_t required_public;
    size_t encoded_length;
    LiberaCError error;

    if (curve == NULL) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    required_public = ecdsa_public_size(curve);
    if (public_key == NULL || private_key == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (private_key_length != curve->scalar_bytes) {
        return LIBERAC_ERROR_INVALID_KEY;
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
    if (!crypto_ec_scalar_is_valid_ct(
            curve, private_key, private_key_length)) {
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
            curve, &public_point, 0, encoded_public, &encoded_length);
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

LiberaCError crypto_ecdsa_sign_internal(
    LiberaCAlgID alg, LiberaCAlgID hash_alg,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t signature_length) {
    const CryptoEcCurve *curve = ecdsa_curve_from_alg(alg);
    uint8_t digest[CRYPTO_ECDSA_MAX_DIGEST_BYTES];
    uint8_t nonce[CRYPTO_ECDSA_MAX_SCALAR_BYTES];
    uint8_t x_coordinate[CRYPTO_ECDSA_MAX_SCALAR_BYTES];
    uint8_t rfc_key[CRYPTO_ECDSA_MAX_DIGEST_BYTES];
    uint8_t rfc_value[CRYPTO_ECDSA_MAX_DIGEST_BYTES];
    CryptoEcScalar d;
    CryptoEcScalar e;
    CryptoEcScalar k;
    CryptoEcScalar k_inverse;
    CryptoEcScalar r;
    CryptoEcScalar s;
    CryptoEcScalar product;
    CryptoEcScalar sum;
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint nonce_point;
    size_t digest_length;
    size_t required_signature;
    LiberaCError error;

    if (curve == NULL) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    error = ecdsa_hash_parameters(curve, hash_alg, &digest_length);
    if (error != LIBERAC_SUCCESS) {
        return error;
    }
    if (private_key == NULL || signature == NULL ||
        (message == NULL && message_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (private_key_length != curve->scalar_bytes) {
        return LIBERAC_ERROR_INVALID_KEY;
    }
    required_signature = ecdsa_signature_size(curve);
    if (signature_length < required_signature) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (crypto_ranges_overlap(signature, required_signature,
                              private_key, private_key_length) ||
        crypto_ranges_overlap(signature, required_signature,
                              message, message_length)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }

    crypto_zeroize(digest, sizeof(digest));
    crypto_zeroize(nonce, sizeof(nonce));
    crypto_zeroize(x_coordinate, sizeof(x_coordinate));
    crypto_zeroize(rfc_key, sizeof(rfc_key));
    crypto_zeroize(rfc_value, sizeof(rfc_value));
    crypto_ec_scalar_zero(&d);
    crypto_ec_scalar_zero(&e);
    crypto_ec_scalar_zero(&k);
    crypto_ec_scalar_zero(&k_inverse);
    crypto_ec_scalar_zero(&r);
    crypto_ec_scalar_zero(&s);
    crypto_ec_scalar_zero(&product);
    crypto_ec_scalar_zero(&sum);
    crypto_ec_affine_set_infinity(&generator);
    crypto_ec_affine_set_infinity(&nonce_point);

    if (!crypto_ec_scalar_is_valid_ct(
            curve, private_key, private_key_length)) {
        error = LIBERAC_ERROR_INVALID_KEY;
        goto cleanup;
    }
    error = crypto_ec_scalar_from_bytes(
        curve, &d, private_key, private_key_length);
    if (error != LIBERAC_SUCCESS) {
        error = LIBERAC_ERROR_INVALID_KEY;
        goto cleanup;
    }
    error = LIBERAC_HASH(
        digest, digest_length, message, message_length, hash_alg);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    error = ecdsa_digest_to_scalar(
        curve, digest, digest_length, &e, NULL);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    error = ecdsa_rfc6979_initialize(
        curve, hash_alg, digest_length,
        private_key, digest, rfc_key, rfc_value);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    error = ecdsa_rfc6979_generate(
        curve, hash_alg, digest_length,
        rfc_key, rfc_value, nonce);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    error = crypto_ec_scalar_from_bytes(
        curve, &k, nonce, curve->scalar_bytes);
    if (error != LIBERAC_SUCCESS) {
        error = LIBERAC_ERROR_INTERNAL;
        goto cleanup;
    }

    crypto_ec_affine_generator(curve, &generator);
    error = crypto_ec_scalar_multiply_ct(
        curve, &nonce_point, &generator, nonce, curve->scalar_bytes);
    if (error != LIBERAC_SUCCESS ||
        crypto_ec_affine_is_infinity(&nonce_point)) {
        error = LIBERAC_ERROR_INTERNAL;
        goto cleanup;
    }
    crypto_ec_field_to_bytes(curve, x_coordinate, &nonce_point.x);
    error = crypto_ec_scalar_from_bytes_reduced(
        curve, &r, x_coordinate, curve->scalar_bytes);
    if (error != LIBERAC_SUCCESS ||
        crypto_ec_scalar_zero_mask(curve, &r) != 0u) {
        error = LIBERAC_ERROR_INTERNAL;
        goto cleanup;
    }

    crypto_ec_scalar_invert_fixed(curve, &k_inverse, &k);
    crypto_ec_scalar_multiply(curve, &product, &r, &d);
    crypto_ec_scalar_add(curve, &sum, &e, &product);
    crypto_ec_scalar_multiply(curve, &s, &k_inverse, &sum);
    if (crypto_ec_scalar_zero_mask(curve, &s) != 0u) {
        error = LIBERAC_ERROR_INTERNAL;
        goto cleanup;
    }

    crypto_ec_scalar_to_bytes(curve, signature, &r);
    crypto_ec_scalar_to_bytes(curve, signature + curve->scalar_bytes, &s);
    error = LIBERAC_SUCCESS;

cleanup:
    if (error != LIBERAC_SUCCESS) {
        crypto_zeroize(signature, required_signature);
    }
    crypto_zeroize(digest, sizeof(digest));
    crypto_zeroize(nonce, sizeof(nonce));
    crypto_zeroize(x_coordinate, sizeof(x_coordinate));
    crypto_zeroize(rfc_key, sizeof(rfc_key));
    crypto_zeroize(rfc_value, sizeof(rfc_value));
    crypto_zeroize(&d, sizeof(d));
    crypto_zeroize(&e, sizeof(e));
    crypto_zeroize(&k, sizeof(k));
    crypto_zeroize(&k_inverse, sizeof(k_inverse));
    crypto_zeroize(&r, sizeof(r));
    crypto_zeroize(&s, sizeof(s));
    crypto_zeroize(&product, sizeof(product));
    crypto_zeroize(&sum, sizeof(sum));
    crypto_zeroize(&generator, sizeof(generator));
    crypto_zeroize(&nonce_point, sizeof(nonce_point));
    return error;
}

LiberaCError crypto_ecdsa_verify_internal(
    LiberaCAlgID alg, LiberaCAlgID hash_alg,
    const uint8_t *public_key, size_t public_key_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *signature, size_t signature_length) {
    const CryptoEcCurve *curve = ecdsa_curve_from_alg(alg);
    uint8_t digest[CRYPTO_ECDSA_MAX_DIGEST_BYTES];
    uint8_t u_bytes[CRYPTO_ECDSA_MAX_SCALAR_BYTES];
    uint8_t v_bytes[CRYPTO_ECDSA_MAX_SCALAR_BYTES];
    uint8_t x_coordinate[CRYPTO_ECDSA_MAX_SCALAR_BYTES];
    CryptoEcScalar e;
    CryptoEcScalar r;
    CryptoEcScalar s;
    CryptoEcScalar inverse;
    CryptoEcScalar u;
    CryptoEcScalar v;
    CryptoEcScalar x_reduced;
    CryptoEcAffinePoint public_point;
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint u_point;
    CryptoEcAffinePoint v_point;
    CryptoEcAffinePoint result_point;
    CryptoEcJacobianPoint u_jacobian;
    CryptoEcJacobianPoint v_jacobian;
    CryptoEcJacobianPoint result_jacobian;
    size_t digest_length;
    LiberaCError error;

    if (curve == NULL) {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    error = ecdsa_hash_parameters(curve, hash_alg, &digest_length);
    if (error != LIBERAC_SUCCESS) {
        return error;
    }
    if (public_key == NULL || signature == NULL ||
        (message == NULL && message_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (!ecdsa_public_length_valid(curve, public_key_length)) {
        return LIBERAC_ERROR_INVALID_KEY;
    }
    if (signature_length != ecdsa_signature_size(curve)) {
        return LIBERAC_ERROR_SIGNATURE_INVALID;
    }

    crypto_zeroize(digest, sizeof(digest));
    crypto_zeroize(u_bytes, sizeof(u_bytes));
    crypto_zeroize(v_bytes, sizeof(v_bytes));
    crypto_zeroize(x_coordinate, sizeof(x_coordinate));
    crypto_ec_scalar_zero(&e);
    crypto_ec_scalar_zero(&r);
    crypto_ec_scalar_zero(&s);
    crypto_ec_scalar_zero(&inverse);
    crypto_ec_scalar_zero(&u);
    crypto_ec_scalar_zero(&v);
    crypto_ec_scalar_zero(&x_reduced);
    crypto_ec_affine_set_infinity(&public_point);
    crypto_ec_affine_set_infinity(&generator);
    crypto_ec_affine_set_infinity(&u_point);
    crypto_ec_affine_set_infinity(&v_point);
    crypto_ec_affine_set_infinity(&result_point);
    crypto_zeroize(&u_jacobian, sizeof(u_jacobian));
    crypto_zeroize(&v_jacobian, sizeof(v_jacobian));
    crypto_zeroize(&result_jacobian, sizeof(result_jacobian));

    error = crypto_ec_point_decode(
        curve, &public_point, public_key, public_key_length, 0);
    if (error != LIBERAC_SUCCESS) {
        error = LIBERAC_ERROR_INVALID_KEY;
        goto cleanup;
    }
    error = crypto_ec_scalar_from_bytes(
        curve, &r, signature, curve->scalar_bytes);
    if (error != LIBERAC_SUCCESS ||
        crypto_ec_scalar_zero_mask(curve, &r) != 0u) {
        error = LIBERAC_ERROR_SIGNATURE_INVALID;
        goto cleanup;
    }
    error = crypto_ec_scalar_from_bytes(
        curve, &s, signature + curve->scalar_bytes,
        curve->scalar_bytes);
    if (error != LIBERAC_SUCCESS ||
        crypto_ec_scalar_zero_mask(curve, &s) != 0u) {
        error = LIBERAC_ERROR_SIGNATURE_INVALID;
        goto cleanup;
    }

    error = LIBERAC_HASH(
        digest, digest_length, message, message_length, hash_alg);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    error = ecdsa_digest_to_scalar(
        curve, digest, digest_length, &e, NULL);
    if (error != LIBERAC_SUCCESS) {
        goto cleanup;
    }
    crypto_ec_scalar_invert_fixed(curve, &inverse, &s);
    crypto_ec_scalar_multiply(curve, &u, &e, &inverse);
    crypto_ec_scalar_multiply(curve, &v, &r, &inverse);
    crypto_ec_scalar_to_bytes(curve, u_bytes, &u);
    crypto_ec_scalar_to_bytes(curve, v_bytes, &v);

    crypto_ec_affine_generator(curve, &generator);
    error = crypto_ec_scalar_multiply_vartime(
        curve, &u_point, &generator, u_bytes, curve->scalar_bytes);
    if (error != LIBERAC_SUCCESS) {
        error = LIBERAC_ERROR_INTERNAL;
        goto cleanup;
    }
    error = crypto_ec_scalar_multiply_vartime(
        curve, &v_point, &public_point, v_bytes, curve->scalar_bytes);
    if (error != LIBERAC_SUCCESS) {
        error = LIBERAC_ERROR_INTERNAL;
        goto cleanup;
    }
    crypto_ec_affine_to_jacobian(curve, &u_jacobian, &u_point);
    crypto_ec_affine_to_jacobian(curve, &v_jacobian, &v_point);
    crypto_ec_jacobian_add_complete(
        curve, &result_jacobian, &u_jacobian, &v_jacobian);
    crypto_ec_jacobian_to_affine(curve, &result_point, &result_jacobian);
    if (crypto_ec_affine_is_infinity(&result_point)) {
        error = LIBERAC_ERROR_SIGNATURE_INVALID;
        goto cleanup;
    }

    crypto_ec_field_to_bytes(curve, x_coordinate, &result_point.x);
    error = crypto_ec_scalar_from_bytes_reduced(
        curve, &x_reduced, x_coordinate, curve->scalar_bytes);
    if (error != LIBERAC_SUCCESS) {
        error = LIBERAC_ERROR_INTERNAL;
        goto cleanup;
    }
    error = crypto_ec_scalar_equal_mask(curve, &x_reduced, &r) != 0u
                ? LIBERAC_SUCCESS
                : LIBERAC_ERROR_SIGNATURE_INVALID;

cleanup:
    crypto_zeroize(digest, sizeof(digest));
    crypto_zeroize(u_bytes, sizeof(u_bytes));
    crypto_zeroize(v_bytes, sizeof(v_bytes));
    crypto_zeroize(x_coordinate, sizeof(x_coordinate));
    crypto_zeroize(&e, sizeof(e));
    crypto_zeroize(&r, sizeof(r));
    crypto_zeroize(&s, sizeof(s));
    crypto_zeroize(&inverse, sizeof(inverse));
    crypto_zeroize(&u, sizeof(u));
    crypto_zeroize(&v, sizeof(v));
    crypto_zeroize(&x_reduced, sizeof(x_reduced));
    crypto_zeroize(&public_point, sizeof(public_point));
    crypto_zeroize(&generator, sizeof(generator));
    crypto_zeroize(&u_point, sizeof(u_point));
    crypto_zeroize(&v_point, sizeof(v_point));
    crypto_zeroize(&result_point, sizeof(result_point));
    crypto_zeroize(&u_jacobian, sizeof(u_jacobian));
    crypto_zeroize(&v_jacobian, sizeof(v_jacobian));
    crypto_zeroize(&result_jacobian, sizeof(result_jacobian));
    return error;
}
