/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "HashFunction.h"

#include "HashFunction/LSH/lsh_internal.h"
#include "HashFunction/SHA2/sha2_internal.h"
#include "HashFunction/SHA3/sha3_internal.h"
#include "Util/Core/secure_zero.h"

#include <string.h>

#define CRYPTO_HASH_CONTEXT_MAGIC UINT32_C(0x43524853)

typedef enum crypto_hash_family {
    CRYPTO_HASH_FAMILY_NONE = 0,
    CRYPTO_HASH_FAMILY_SHA2,
    CRYPTO_HASH_FAMILY_SHA3,
    CRYPTO_HASH_FAMILY_LSH
} crypto_hash_family;

typedef enum crypto_hash_phase {
    CRYPTO_HASH_PHASE_ABSORBING = 1,
    CRYPTO_HASH_PHASE_FINALIZED,
    CRYPTO_HASH_PHASE_SQUEEZING,
    CRYPTO_HASH_PHASE_CONSUMED
} crypto_hash_phase;

typedef union crypto_hash_algorithm_state {
    crypto_sha2_context SHA2;
    crypto_sha3_context SHA3;
    crypto_lsh_context LSH;
} crypto_hash_algorithm_state;

typedef struct crypto_hash_context_impl {
    uint32_t MAGIC;
    AlgID ALG;
    uint8_t PHASE;
    crypto_hash_algorithm_state STATE;
} crypto_hash_context_impl;

_Static_assert(sizeof(crypto_hash_context_impl) <= CRYPTO_HASH_CONTEXT_BYTES,
               "CRYPTO_HASH_CONTEXT_BYTES is too small");

static crypto_hash_family hash_family(AlgID algorithm) {
    switch (algorithm) {
        case ALG_HASH_SHA2_224:
        case ALG_HASH_SHA2_256:
        case ALG_HASH_SHA2_384:
        case ALG_HASH_SHA2_512:
        case ALG_HASH_SHA2_512_224:
        case ALG_HASH_SHA2_512_256:
            return CRYPTO_HASH_FAMILY_SHA2;

        case ALG_HASH_SHA3_224:
        case ALG_HASH_SHA3_256:
        case ALG_HASH_SHA3_384:
        case ALG_HASH_SHA3_512:
        case ALG_HASH_SHAKE128:
        case ALG_HASH_SHAKE256:
            return CRYPTO_HASH_FAMILY_SHA3;

        case ALG_HASH_LSH_256_224:
        case ALG_HASH_LSH_256_256:
        case ALG_HASH_LSH_512_224:
        case ALG_HASH_LSH_512_256:
        case ALG_HASH_LSH_512_384:
        case ALG_HASH_LSH_512_512:
            return CRYPTO_HASH_FAMILY_LSH;

        default:
            return CRYPTO_HASH_FAMILY_NONE;
    }
}

static int is_shake(AlgID algorithm) {
    return algorithm == ALG_HASH_SHAKE128 ||
           algorithm == ALG_HASH_SHAKE256;
}

static size_t fixed_digest_length(AlgID algorithm) {
    switch (algorithm) {
        case ALG_HASH_SHA2_224:
        case ALG_HASH_SHA2_512_224:
        case ALG_HASH_LSH_256_224:
        case ALG_HASH_LSH_512_224:
        case ALG_HASH_SHA3_224:
            return 28u;
        case ALG_HASH_SHA2_256:
        case ALG_HASH_SHA2_512_256:
        case ALG_HASH_LSH_256_256:
        case ALG_HASH_LSH_512_256:
        case ALG_HASH_SHA3_256:
            return 32u;
        case ALG_HASH_SHA2_384:
        case ALG_HASH_LSH_512_384:
        case ALG_HASH_SHA3_384:
            return 48u;
        case ALG_HASH_SHA2_512:
        case ALG_HASH_LSH_512_512:
        case ALG_HASH_SHA3_512:
            return 64u;
        default:
            return 0u;
    }
}

static int hash_context_load(
    crypto_hash_context_impl *implementation,
    const CRYPTO_HASH_CONTEXT *context) {
    if (implementation == NULL || context == NULL) {
        return 0;
    }
    memcpy(implementation, context->INTERNAL, sizeof(*implementation));
    if (implementation->MAGIC != CRYPTO_HASH_CONTEXT_MAGIC ||
        hash_family(implementation->ALG) == CRYPTO_HASH_FAMILY_NONE ||
        implementation->PHASE < CRYPTO_HASH_PHASE_ABSORBING ||
        implementation->PHASE > CRYPTO_HASH_PHASE_CONSUMED) {
        return 0;
    }
    return 1;
}

static void hash_context_save(
    CRYPTO_HASH_CONTEXT *context,
    const crypto_hash_context_impl *implementation) {
    crypto_zeroize(context, sizeof(*context));
    memcpy(context->INTERNAL, implementation, sizeof(*implementation));
}

CryptoError CRYPTO_HASH_INIT(
    CRYPTO_HASH_CONTEXT *CONTEXT,
    AlgID ALG) {
    crypto_hash_context_impl implementation;
    const crypto_hash_family family = hash_family(ALG);
    CryptoError error;

    if (CONTEXT == NULL) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    CRYPTO_HASH_CLEAR(CONTEXT);
    crypto_zeroize(&implementation, sizeof(implementation));

    switch (family) {
        case CRYPTO_HASH_FAMILY_SHA2:
            error = crypto_sha2_init(&implementation.STATE.SHA2, ALG);
            break;
        case CRYPTO_HASH_FAMILY_SHA3:
            error = crypto_sha3_init(&implementation.STATE.SHA3, ALG);
            break;
        case CRYPTO_HASH_FAMILY_LSH:
            error = crypto_lsh_init(&implementation.STATE.LSH, ALG);
            break;
        default:
            error = CRYPTO_ERROR_INVALID_ALG_ID;
            break;
    }
    if (error == CRYPTO_SUCCESS) {
        implementation.MAGIC = CRYPTO_HASH_CONTEXT_MAGIC;
        implementation.ALG = ALG;
        implementation.PHASE = CRYPTO_HASH_PHASE_ABSORBING;
        hash_context_save(CONTEXT, &implementation);
    }
    crypto_zeroize(&implementation, sizeof(implementation));
    return error;
}

CryptoError CRYPTO_HASH_UPDATE(
    CRYPTO_HASH_CONTEXT *CONTEXT,
    const uint8_t *INPUT, size_t INPUT_LENGTH) {
    crypto_hash_context_impl implementation;
    CryptoError error;

    crypto_zeroize(&implementation, sizeof(implementation));
    if ((INPUT == NULL && INPUT_LENGTH != 0u) ||
        !hash_context_load(&implementation, CONTEXT) ||
        implementation.PHASE != CRYPTO_HASH_PHASE_ABSORBING) {
        crypto_zeroize(&implementation, sizeof(implementation));
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }

    switch (hash_family(implementation.ALG)) {
        case CRYPTO_HASH_FAMILY_SHA2:
            error = crypto_sha2_update(
                &implementation.STATE.SHA2, INPUT, INPUT_LENGTH);
            break;
        case CRYPTO_HASH_FAMILY_SHA3:
            crypto_sha3_update(
                &implementation.STATE.SHA3, INPUT, INPUT_LENGTH);
            error = CRYPTO_SUCCESS;
            break;
        case CRYPTO_HASH_FAMILY_LSH:
            error = crypto_lsh_update(
                &implementation.STATE.LSH, INPUT, INPUT_LENGTH);
            break;
        default:
            error = CRYPTO_ERROR_INVALID_ARGUMENT;
            break;
    }
    if (error == CRYPTO_SUCCESS) {
        hash_context_save(CONTEXT, &implementation);
    }
    crypto_zeroize(&implementation, sizeof(implementation));
    return error;
}

CryptoError CRYPTO_HASH_FINALIZE(CRYPTO_HASH_CONTEXT *CONTEXT) {
    crypto_hash_context_impl implementation;

    crypto_zeroize(&implementation, sizeof(implementation));
    if (!hash_context_load(&implementation, CONTEXT) ||
        implementation.PHASE != CRYPTO_HASH_PHASE_ABSORBING) {
        crypto_zeroize(&implementation, sizeof(implementation));
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }

    switch (hash_family(implementation.ALG)) {
        case CRYPTO_HASH_FAMILY_SHA2:
            crypto_sha2_finalize(&implementation.STATE.SHA2);
            break;
        case CRYPTO_HASH_FAMILY_SHA3:
            crypto_sha3_finalize(&implementation.STATE.SHA3);
            break;
        case CRYPTO_HASH_FAMILY_LSH:
            crypto_lsh_finalize(&implementation.STATE.LSH);
            break;
        default:
            crypto_zeroize(&implementation, sizeof(implementation));
            return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    implementation.PHASE = CRYPTO_HASH_PHASE_FINALIZED;
    hash_context_save(CONTEXT, &implementation);
    crypto_zeroize(&implementation, sizeof(implementation));
    return CRYPTO_SUCCESS;
}

CryptoError CRYPTO_HASH_SQUEEZE(
    CRYPTO_HASH_CONTEXT *CONTEXT,
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH) {
    crypto_hash_context_impl implementation;
    size_t digest_length;

    crypto_zeroize(&implementation, sizeof(implementation));
    if ((OUTPUT == NULL && OUTPUT_LENGTH != 0u) ||
        !hash_context_load(&implementation, CONTEXT)) {
        crypto_zeroize(&implementation, sizeof(implementation));
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }

    if (is_shake(implementation.ALG)) {
        if (implementation.PHASE != CRYPTO_HASH_PHASE_FINALIZED &&
            implementation.PHASE != CRYPTO_HASH_PHASE_SQUEEZING) {
            crypto_zeroize(&implementation, sizeof(implementation));
            return CRYPTO_ERROR_INVALID_ARGUMENT;
        }
        crypto_sha3_squeeze(
            &implementation.STATE.SHA3, OUTPUT, OUTPUT_LENGTH);
        implementation.PHASE = CRYPTO_HASH_PHASE_SQUEEZING;
        hash_context_save(CONTEXT, &implementation);
        crypto_zeroize(&implementation, sizeof(implementation));
        return CRYPTO_SUCCESS;
    }

    if (implementation.PHASE != CRYPTO_HASH_PHASE_FINALIZED) {
        crypto_zeroize(&implementation, sizeof(implementation));
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    digest_length = fixed_digest_length(implementation.ALG);
    if (OUTPUT_LENGTH < digest_length) {
        crypto_zeroize(&implementation, sizeof(implementation));
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }
    if (OUTPUT == NULL) {
        crypto_zeroize(&implementation, sizeof(implementation));
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }

    switch (hash_family(implementation.ALG)) {
        case CRYPTO_HASH_FAMILY_SHA2:
            crypto_sha2_squeeze(
                &implementation.STATE.SHA2, OUTPUT, implementation.ALG);
            break;
        case CRYPTO_HASH_FAMILY_SHA3:
            crypto_sha3_squeeze(
                &implementation.STATE.SHA3, OUTPUT, digest_length);
            break;
        case CRYPTO_HASH_FAMILY_LSH:
            crypto_lsh_squeeze(
                &implementation.STATE.LSH, OUTPUT, implementation.ALG);
            break;
        default:
            crypto_zeroize(&implementation, sizeof(implementation));
            return CRYPTO_ERROR_INVALID_ARGUMENT;
    }

    crypto_zeroize(&implementation.STATE, sizeof(implementation.STATE));
    implementation.PHASE = CRYPTO_HASH_PHASE_CONSUMED;
    hash_context_save(CONTEXT, &implementation);
    crypto_zeroize(&implementation, sizeof(implementation));
    return CRYPTO_SUCCESS;
}

void CRYPTO_HASH_CLEAR(CRYPTO_HASH_CONTEXT *CONTEXT) {
    if (CONTEXT != NULL) {
        crypto_zeroize(CONTEXT, sizeof(*CONTEXT));
    }
}

CryptoError CRYPTO_HASH(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    AlgID ALG) {
    CRYPTO_HASH_CONTEXT context;
    const size_t digest_length = fixed_digest_length(ALG);
    CryptoError error;

    if ((INPUT == NULL && INPUT_LENGTH != 0u) ||
        (OUTPUT == NULL && OUTPUT_LENGTH != 0u)) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }
    if (!is_shake(ALG)) {
        if (digest_length == 0u) {
            return CRYPTO_ERROR_INVALID_ALG_ID;
        }
        if (OUTPUT_LENGTH < digest_length) {
            return CRYPTO_ERROR_BUFFER_TOO_SMALL;
        }
    }

    error = CRYPTO_HASH_INIT(&context, ALG);
    if (error == CRYPTO_SUCCESS) {
        error = CRYPTO_HASH_UPDATE(&context, INPUT, INPUT_LENGTH);
    }
    if (error == CRYPTO_SUCCESS) {
        error = CRYPTO_HASH_FINALIZE(&context);
    }
    if (error == CRYPTO_SUCCESS) {
        error = CRYPTO_HASH_SQUEEZE(&context, OUTPUT, OUTPUT_LENGTH);
    }
    CRYPTO_HASH_CLEAR(&context);
    return error;
}
