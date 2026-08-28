/* SPDX-License-Identifier: MIT */

#ifndef CRYPTO_AIMER_BACKEND_H
#define CRYPTO_AIMER_BACKEND_H

#include "../aimer_params.h"

LiberaCError crypto_aimer_backend_keypair(
    uint8_t *public_key, uint8_t *private_key,
    const uint8_t *plaintext, const uint8_t *iv,
    const crypto_aimer_params *params);

LiberaCError crypto_aimer_backend_sign(
    uint8_t *signature,
    const uint8_t *message, size_t message_length,
    const uint8_t *prefix, size_t prefix_length,
    const uint8_t *randomness, const uint8_t *private_key,
    const crypto_aimer_params *params);

LiberaCError crypto_aimer_backend_verify(
    const uint8_t *signature, size_t signature_length,
    const uint8_t *message, size_t message_length,
    const uint8_t *prefix, size_t prefix_length,
    const uint8_t *public_key,
    const crypto_aimer_params *params);

#endif
