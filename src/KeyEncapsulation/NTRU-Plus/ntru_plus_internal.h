/*
 * Internal NTRU+ API for the Crypto key-encapsulation facade.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_NTRU_PLUS_INTERNAL_H
#define CRYPTO_NTRU_PLUS_INTERNAL_H

#include "Def.h"

size_t crypto_ntru_plus_public_key_size_internal(LiberaCAlgID alg);
size_t crypto_ntru_plus_private_key_size_internal(LiberaCAlgID alg);
size_t crypto_ntru_plus_ciphertext_size_internal(LiberaCAlgID alg);

LiberaCError crypto_ntru_plus_keygen_internal(
    LiberaCAlgID alg,
    uint8_t *public_key, size_t public_key_length,
    uint8_t *private_key, size_t private_key_length);
LiberaCError crypto_ntru_plus_encaps_internal(
    LiberaCAlgID alg,
    const uint8_t *public_key, size_t public_key_length,
    uint8_t shared_secret[32],
    uint8_t *ciphertext, size_t ciphertext_length);
LiberaCError crypto_ntru_plus_decaps_internal(
    LiberaCAlgID alg,
    const uint8_t *private_key, size_t private_key_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t shared_secret[32]);

#endif
