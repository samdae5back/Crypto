/* SPDX-License-Identifier: MIT */

#ifndef CRYPTO_AIMER_PARAMS_H
#define CRYPTO_AIMER_PARAMS_H

#include "DigitalSignature.h"

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_AIMER_MAX_SECURITY_BYTES 32u
#define CRYPTO_AIMER_MAX_FIELD_BITS 256u
#define CRYPTO_AIMER_MAX_FIELD_BYTES 32u
#define CRYPTO_AIMER_MAX_FIELD_WORDS 4u
#define CRYPTO_AIMER_MAX_INPUT_SBOXES 3u
#define CRYPTO_AIMER_MAX_SALT_BYTES 32u
#define CRYPTO_AIMER_MAX_SEED_BYTES 32u
#define CRYPTO_AIMER_MAX_COMMIT_BYTES 64u
#define CRYPTO_AIMER_MAX_REPETITIONS 65u
#define CRYPTO_AIMER_MAX_PARTIES 256u
#define CRYPTO_AIMER_MAX_LOG_PARTIES 8u

#define CRYPTO_AIMER_HASH_PREFIX_1 0x01u
#define CRYPTO_AIMER_HASH_PREFIX_2 0x02u
#define CRYPTO_AIMER_HASH_PREFIX_3 0x03u
#define CRYPTO_AIMER_HASH_PREFIX_4 0x04u
#define CRYPTO_AIMER_HASH_PREFIX_5 0x05u

typedef struct crypto_aimer_params {
    LiberaCAlgID alg;
    size_t public_key_bytes;
    size_t private_key_bytes;
    size_t signature_bytes;
    size_t security_bits;
    size_t security_bytes;
    size_t field_bits;
    size_t field_bytes;
    size_t field_words;
    size_t iv_bytes;
    size_t input_sboxes;
    size_t salt_bytes;
    size_t seed_bytes;
    size_t commit_bytes;
    size_t multiplications;
    size_t repetitions;
    size_t parties;
    size_t log_parties;
    uint8_t hash_prefix_0;
} crypto_aimer_params;

/*
 * This is the complete AIMer v2.1 runtime parameter table.  The final five
 * arguments are the number of S-boxes, repetitions, parties, log2(parties),
 * and the parameter-set-specific domain-separation byte.
 */
#define CRYPTO_AIMER_PARAMETER_LIST(X) \
    X(LIBERAC_ALG_AIMER_128F, LIBERAC_AIMER_128F_PUBLIC_KEY_BYTES, \
      LIBERAC_AIMER_128F_PRIVATE_KEY_BYTES, LIBERAC_AIMER_128F_SIGNATURE_BYTES, \
      128u, 16u, 2u, 33u, 16u, 4u, 0x00u) \
    X(LIBERAC_ALG_AIMER_128S, LIBERAC_AIMER_128S_PUBLIC_KEY_BYTES, \
      LIBERAC_AIMER_128S_PRIVATE_KEY_BYTES, LIBERAC_AIMER_128S_SIGNATURE_BYTES, \
      128u, 16u, 2u, 17u, 256u, 8u, 0x10u) \
    X(LIBERAC_ALG_AIMER_192F, LIBERAC_AIMER_192F_PUBLIC_KEY_BYTES, \
      LIBERAC_AIMER_192F_PRIVATE_KEY_BYTES, LIBERAC_AIMER_192F_SIGNATURE_BYTES, \
      192u, 24u, 2u, 49u, 16u, 4u, 0x20u) \
    X(LIBERAC_ALG_AIMER_192S, LIBERAC_AIMER_192S_PUBLIC_KEY_BYTES, \
      LIBERAC_AIMER_192S_PRIVATE_KEY_BYTES, LIBERAC_AIMER_192S_SIGNATURE_BYTES, \
      192u, 24u, 2u, 25u, 256u, 8u, 0x30u) \
    X(LIBERAC_ALG_AIMER_256F, LIBERAC_AIMER_256F_PUBLIC_KEY_BYTES, \
      LIBERAC_AIMER_256F_PRIVATE_KEY_BYTES, LIBERAC_AIMER_256F_SIGNATURE_BYTES, \
      256u, 32u, 3u, 65u, 16u, 4u, 0x40u) \
    X(LIBERAC_ALG_AIMER_256S, LIBERAC_AIMER_256S_PUBLIC_KEY_BYTES, \
      LIBERAC_AIMER_256S_PRIVATE_KEY_BYTES, LIBERAC_AIMER_256S_SIGNATURE_BYTES, \
      256u, 32u, 3u, 33u, 256u, 8u, 0x50u)

#endif
