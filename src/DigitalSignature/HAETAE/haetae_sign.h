// SPDX-License-Identifier: MIT

#ifndef CRYPTO_HAETAE_SIGN_H
#define CRYPTO_HAETAE_SIGN_H


#include "haetae.h"

LiberaCError crypto_haetae_sign_core(
    uint8_t *signature,
    const uint8_t *message,
    size_t message_length,
    const uint8_t *prefix,
    size_t prefix_length,
    const uint8_t randomness[CRYPTO_HAETAE_SEED_BYTES],
    const uint8_t *private_key,
    const crypto_haetae_parameters *parameters);

LiberaCError crypto_haetae_verify_core(
    const uint8_t *signature,
    size_t signature_length,
    const uint8_t *message,
    size_t message_length,
    const uint8_t *prefix,
    size_t prefix_length,
    const uint8_t *public_key,
    const crypto_haetae_parameters *parameters);


#endif
