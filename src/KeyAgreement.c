/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "KeyAgreement.h"
#include "KeyAgreement/key_agreement_internal.h"

size_t crypto_key_agreement_private_key_size_internal(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ECDH_P256:
            return LIBERAC_ECDH_P256_PRIVATE_KEY_BYTES;
        case LIBERAC_ALG_ECDH_P384:
            return LIBERAC_ECDH_P384_PRIVATE_KEY_BYTES;
        case LIBERAC_ALG_ECDH_P521:
            return LIBERAC_ECDH_P521_PRIVATE_KEY_BYTES;
        case LIBERAC_ALG_X25519:
            return LIBERAC_X25519_PRIVATE_KEY_BYTES;
        default:
            return 0u;
    }
}

size_t crypto_key_agreement_public_key_size_internal(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ECDH_P256:
            return LIBERAC_ECDH_P256_PUBLIC_KEY_BYTES;
        case LIBERAC_ALG_ECDH_P384:
            return LIBERAC_ECDH_P384_PUBLIC_KEY_BYTES;
        case LIBERAC_ALG_ECDH_P521:
            return LIBERAC_ECDH_P521_PUBLIC_KEY_BYTES;
        case LIBERAC_ALG_X25519:
            return LIBERAC_X25519_PUBLIC_KEY_BYTES;
        default:
            return 0u;
    }
}

size_t crypto_key_agreement_shared_secret_size_internal(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ECDH_P256:
            return LIBERAC_ECDH_P256_SHARED_SECRET_BYTES;
        case LIBERAC_ALG_ECDH_P384:
            return LIBERAC_ECDH_P384_SHARED_SECRET_BYTES;
        case LIBERAC_ALG_ECDH_P521:
            return LIBERAC_ECDH_P521_SHARED_SECRET_BYTES;
        case LIBERAC_ALG_X25519:
            return LIBERAC_X25519_SHARED_SECRET_BYTES;
        default:
            return 0u;
    }
}

LiberaCError crypto_key_agreement_keygen_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length) {
    switch (alg) {
        case LIBERAC_ALG_ECDH_P256:
        case LIBERAC_ALG_ECDH_P384:
        case LIBERAC_ALG_ECDH_P521:
            return crypto_ecdh_keygen_internal(
                alg, public_key, public_key_length,
                private_key, private_key_length);
        case LIBERAC_ALG_X25519:
            return crypto_x25519_keygen_internal(
                public_key, public_key_length,
                private_key, private_key_length);
        default:
            return LIBERAC_ERROR_INVALID_ALG_ID;
    }
}

LiberaCError crypto_key_agreement_public_from_private_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    const uint8_t *private_key, size_t private_key_length) {
    switch (alg) {
        case LIBERAC_ALG_ECDH_P256:
        case LIBERAC_ALG_ECDH_P384:
        case LIBERAC_ALG_ECDH_P521:
            return crypto_ecdh_public_from_private_internal(
                alg, public_key, public_key_length,
                private_key, private_key_length);
        case LIBERAC_ALG_X25519:
            return crypto_x25519_public_from_private_internal(
                public_key, public_key_length,
                private_key, private_key_length);
        default:
            return LIBERAC_ERROR_INVALID_ALG_ID;
    }
}

LiberaCError crypto_key_agreement_shared_secret_internal(
    LiberaCAlgID alg,
    uint8_t *shared_secret, size_t shared_secret_length,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *peer_public_key, size_t peer_public_key_length) {
    switch (alg) {
        case LIBERAC_ALG_ECDH_P256:
        case LIBERAC_ALG_ECDH_P384:
        case LIBERAC_ALG_ECDH_P521:
            return crypto_ecdh_shared_secret_internal(
                alg, shared_secret, shared_secret_length,
                private_key, private_key_length,
                peer_public_key, peer_public_key_length);
        case LIBERAC_ALG_X25519:
            return crypto_x25519_shared_secret_internal(
                shared_secret, shared_secret_length,
                private_key, private_key_length,
                peer_public_key, peer_public_key_length);
        default:
            return LIBERAC_ERROR_INVALID_ALG_ID;
    }
}

size_t LIBERAC_KEY_AGREEMENT_PRIVATE_KEY_SIZE(LiberaCAlgID alg) {
    return crypto_key_agreement_private_key_size_internal(alg);
}

size_t LIBERAC_KEY_AGREEMENT_PUBLIC_KEY_SIZE(LiberaCAlgID alg) {
    return crypto_key_agreement_public_key_size_internal(alg);
}

size_t LIBERAC_KEY_AGREEMENT_SHARED_SECRET_SIZE(LiberaCAlgID alg) {
    return crypto_key_agreement_shared_secret_size_internal(alg);
}

LiberaCError LIBERAC_KEY_AGREEMENT_KEYGEN(
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length,
    LiberaCAlgID alg) {
    return crypto_key_agreement_keygen_internal(
        alg, public_key, public_key_length,
        private_key, private_key_length);
}

LiberaCError LIBERAC_KEY_AGREEMENT_PUBLIC_FROM_PRIVATE(
    uint8_t *public_key, size_t public_key_length,
    const uint8_t *private_key, size_t private_key_length,
    LiberaCAlgID alg) {
    return crypto_key_agreement_public_from_private_internal(
        alg, public_key, public_key_length,
        private_key, private_key_length);
}

LiberaCError LIBERAC_KEY_AGREEMENT_SHARED_SECRET(
    uint8_t *shared_secret, size_t shared_secret_length,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *peer_public_key, size_t peer_public_key_length,
    LiberaCAlgID alg) {
    return crypto_key_agreement_shared_secret_internal(
        alg, shared_secret, shared_secret_length,
        private_key, private_key_length,
        peer_public_key, peer_public_key_length);
}
